// TODO:
// * Does ASYNC flag help performance?
// * buffers?
// * fixed file thingy?
//
//
// On my laptop, the best performance is:
// * --threads=2
// * --accept-multi=false (otherwise all goes to first thread)
// * --cpu-affinity=false (not sure why, but CPU affinity hurts a lot)

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Error, Result};
use arrayvec::ArrayVec;
use clap::Parser;
use log::{debug, error, info, trace, warn};
use rtsan_standalone::nonblocking;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

type FixedFile = io_uring::types::Fixed;

// We don't use file descriptors for our io_uring operations. We use offsets
// into the io_uring fixed file table.
//
// The index for new accepted connections are automatically picked by the
// kernel, except for our listening socket which is number 0.
const LISTEN_FIXED_FILE: FixedFile = io_uring::types::Fixed(0);

// The maximum number of concurrent connections. This is only set to 100 because
// ulimit tends to be much lower than that.
//
// TODO: turn this into a flag.
const MAX_CONNECTIONS: usize = 100;

// 10MiB stack size per thread.
//
// There's only one thread per core, so not really anything to optimize.
const THREAD_STACK_SIZE: usize = 10 * 1048576;

// Every io_uring op has a "handle" of sorts. We use it to stuff the connection
// ID, and the operation.
// This mask allows for 2^32 concurrent connections.
const USER_DATA_CON_MASK: u64 = 0xffffffff;

// Special user data "handle" to indicate a new connection coming in.
const USER_DATA_LISTENER: u64 = u64::MAX;

// Special user data "handle" to indicate timeout. At timeout, we do some
// housekeeping.
const USER_DATA_TIMEOUT: u64 = USER_DATA_LISTENER - 1;

// This is the op type part of the user data "handle".
// If more ops are added, add them to make_ops_cancel for !modern path.
const USER_DATA_OP_MASK: u64 = 0xf00000000;
const USER_DATA_OP_WRITE: u64 = 0x100000000;
const USER_DATA_OP_CLOSE: u64 = 0x200000000;
const USER_DATA_OP_READ: u64 = 0x300000000;
const USER_DATA_OP_CANCEL: u64 = 0x400000000;
const USER_DATA_OP_SETSOCKOPT: u64 = 0x800000000;

// Max milliseconds that a connection is allowed to be idle, before we close it.
const MAX_IDLE: u128 = 5000;

// Every connection has a fixed read buffer (for the request). This is the
// size.
const MAX_READ_BUF: usize = 1024;

const MAX_WRITE_BUF: usize = 1024;

// Outgoing headers max size.
const MAX_HEADER_BUF: usize = 1024;

// TODO: panics if squeue is full. There's a better way, surely.
type SQueue = ArrayVec<io_uring::squeue::Entry, 10_000>;
type ReadBuf = [u8; MAX_READ_BUF];
type HeaderBuf = ArrayVec<u8, MAX_HEADER_BUF>;

#[derive(Debug)]
struct HandshakeData {
    fixed: FixedFile,
    tls: rustls::ServerConnection,
}

impl HandshakeData {
    fn new(fixed: FixedFile, tls: rustls::ServerConnection) -> Self {
        Self { fixed, tls }
    }
    fn received(&mut self, data: &[u8]) -> Result<rustls::IoState, rustls::Error> {
        debug!("Got some handshaky data: {data:?}");
        let mut reader = std::io::Cursor::new(data);
        self.tls.read_tls(&mut reader).unwrap();
        self.tls.process_new_packets()
    }
}

#[derive(Debug)]
enum State {
    Idle,

    // rustls handshaking happening.
    Handshaking(HandshakeData),

    // KTLS setsockopt()s in flight. Awaiting their completion.
    //
    // The associated buffers are not part of the state, in order to ensure
    // nothing outstanding points to it, even if we go to Closing state.
    EnablingKtls(FixedFile),

    // Reading new request. Note that because of pipelining, we may enter this
    // state with a nonzero read_buf, and may exit it with more full requests
    // ready to go.
    //
    // This state means no pending Write or Close, at least.
    Reading(FixedFile),

    // header_buf could be inside this enum, but I'm not sure I can create it on
    // state change without copying it. No placement new.
    //
    // This state has a pending Write.
    WritingHeaders(FixedFile, usize, usize),

    // This state has a pending Write.
    //
    // TODO: add data file.
    WritingData(FixedFile, usize, usize),

    // Close and possibly Cancel has been sent, but we don't reuse the
    // connection object until all ops have completed. (`outstdanding == 0`)
    Closing,
}

struct Connection {
    id: usize,
    state: State,

    // Crypto key info. Set once, before firing off setsockopts.
    tls_rx: Option<ktls::CryptoInfo>,
    tls_tx: Option<ktls::CryptoInfo>,

    // Outstanding number of io_uring ops. Don't GC the connection until it's
    // zero.
    outstanding: usize,

    // Last time anything happened. Used to time out the connection.
    last_action: std::time::Instant,

    // Next position incoming data should be appended at. Once a full request is
    // processed, any tail is copied to the beginning.
    read_buf_pos: usize,
    read_buf: ReadBuf,

    // TODO: merge these buffers. We're either reading or writing.
    write_buf: [u8; MAX_WRITE_BUF],
    header_buf: HeaderBuf,
    _pin: std::marker::PhantomPinned,
}

impl Connection {
    #[must_use]
    fn new(id: usize) -> Self {
        Self {
            id,
            state: State::Idle,
            read_buf: [0; MAX_READ_BUF],
            write_buf: [0; MAX_WRITE_BUF],
            read_buf_pos: 0,
            outstanding: 0,
            header_buf: Default::default(),
            last_action: std::time::Instant::now(),
            _pin: std::marker::PhantomPinned,
            tls_rx: None,
            tls_tx: None,
        }
    }
    fn init(&mut self, fixed: FixedFile, tls: rustls::ServerConnection) {
        self.state = State::Handshaking(HandshakeData::new(fixed, tls));
        self.last_action = std::time::Instant::now();
    }
    fn deinit(&mut self) {
        assert_eq!(self.outstanding, 0);
        self.state = State::Idle;
        use zeroize::Zeroize;
        self.read_buf.zeroize();
        self.read_buf_pos = 0;
        self.header_buf.zeroize();
        self.header_buf.clear();
        self.outstanding = 0;
    }
    fn close(&mut self, modern: bool, ops: &mut SQueue) {
        if self.closing() {
            return;
        }
        if self.outstanding > 0 {
            self.outstanding += make_ops_cancel(self.fd().unwrap(), self.id as u64, modern, ops);
        }
        self.outstanding += 1;
        ops.push(make_op_close(self.fd().unwrap(), self.id));
        self.state = State::Closing;
    }
    fn io_completed(&mut self) {
        self.last_action = std::time::Instant::now();
        self.outstanding -= 1;
    }
    fn fd(&self) -> Option<FixedFile> {
        match self.state {
            State::Idle => None,
            State::Handshaking(ref data) => Some(data.fixed),
            State::EnablingKtls(fd) => Some(fd),
            State::Reading(fd) => Some(fd),
            State::WritingHeaders(fd, _, _) => Some(fd),
            State::WritingData(fd, _, _) => Some(fd),
            State::Closing => None,
        }
    }
    fn closing(&self) -> bool {
        matches![self.state, State::Closing]
    }

    fn write_header_bytes(&mut self, ops: &mut SQueue, msg: &[u8], pos: usize, len: usize) {
        let State::Reading(fd) = self.state else {
            panic!("Called write_header in state {:?}", self.state);
        };
        assert!(self.header_buf.is_empty());

        // TODO: anything we can do about this copy? Create headers in-place?
        self.header_buf.extend(msg.iter().copied());
        self.write_headers(ops, fd, pos, len);
    }

    fn write_headers(&mut self, ops: &mut SQueue, fd: FixedFile, pos: usize, len: usize) {
        // TODO: change to SendZc?
        // Or in some cases Splice?
        // Surely at least writev()
        // If writev, make sure to handle the over-consumption in write_done()
        self.outstanding += 1;
        let op =
            io_uring::opcode::Write::new(fd, self.header_buf.as_ptr(), self.header_buf.len() as _)
                .build()
                .user_data((self.id as u64) | USER_DATA_OP_WRITE);
        ops.push(op);
        self.state = State::WritingHeaders(fd, pos, len);
    }

    fn write_data(
        &mut self,
        ops: &mut SQueue,
        archive: &Archive,
        fd: FixedFile,
        pos: usize,
        len: usize,
    ) {
        let msg = archive.get_slice(pos, len);
        self.state = State::WritingData(fd, pos, len);
        self.outstanding += 1;
        let op = io_uring::opcode::Write::new(fd, msg.as_ptr(), msg.len() as _)
            .build()
            .user_data((self.id as u64) | USER_DATA_OP_WRITE);
        ops.push(op);
    }

    fn write_done(&mut self, ops: &mut SQueue, archive: &Archive, wrote: usize) -> bool {
        match &self.state {
            State::WritingHeaders(fd, pos, len) => {
                let fd = *fd;
                self.header_buf.drain(..wrote);
                if self.header_buf.is_empty() {
                    self.write_data(ops, archive, fd, *pos, *len);
                } else {
                    self.write_headers(ops, fd, *pos, *len);
                }
                false
            }
            State::WritingData(fd, pos, len) => {
                let fd = *fd as FixedFile;
                let pos = *pos + wrote;
                let len = *len - wrote;
                if len == 0 {
                    self.state = State::Reading(fd);
                    true
                } else {
                    self.write_data(ops, archive, fd, pos, len);
                    false
                }
            }
            other => {
                panic!(
                    "Write completed, but state {other:?} should not have any outstanding write"
                );
            }
        }
    }

    fn must_get_fd(&self) -> FixedFile {
        (match &self.state {
            State::Reading(fd) => *fd,
            State::Handshaking(data) => data.fixed,
            State::EnablingKtls(fd) => *fd,
            _ => panic!("get fd in wrong state"),
        }) as _
    }

    fn write(&mut self, n: usize, ops: &mut SQueue) {
        let data = &self.write_buf[..n];
        self.outstanding += 1;
        ops.push(
            io_uring::opcode::Write::new(self.must_get_fd(), data.as_ptr(), data.len() as _)
                .build()
                .user_data((self.id as u64) | USER_DATA_OP_WRITE),
        );
    }

    fn setsockopt_ulp(&mut self, fd: FixedFile, ops: &mut SQueue) {
        self.outstanding += 1;
        ops.push(
            io_uring::opcode::SetSockOpt::new(
                fd,
                libc::SOL_TCP as u32,
                libc::TCP_ULP as u32,
                TLS_STR.as_ptr() as _,
                3,
            )
            .build()
            .flags(io_uring::squeue::Flags::IO_LINK)
            .user_data((self.id as u64) | USER_DATA_OP_SETSOCKOPT),
        );
    }

    fn enable_ktls(&mut self, fd: FixedFile, ops: &mut SQueue, new_state: State) -> Result<()> {
        // Extract secrets.
        //
        // We need to set the new state here already, because extracting secrets
        // consumes tls, partially moving out of the old state.
        let t = std::mem::replace(&mut self.state, new_state);
        let State::Handshaking(d) = t else {
            panic!("tried to enable kTLS while in state other than Handshaking")
        };
        let suite = d.tls.negotiated_cipher_suite().unwrap();
        debug!(
            "Cipher suite: {suite:?} {:?}",
            d.tls.negotiated_key_exchange_group().unwrap()
        );
        let keys = d.tls.dangerous_extract_secrets()?;
        self.tls_rx = Some(ktls::CryptoInfo::from_rustls(suite, keys.rx)?);
        self.tls_tx = Some(ktls::CryptoInfo::from_rustls(suite, keys.tx)?);

        // Enable TLS RX and TX.
        self.setsockopt_ktls(
            fd,
            libc::TLS_RX as u32,
            self.tls_rx.as_ref().unwrap(),
            true,
            ops,
        );
        self.setsockopt_ktls(
            fd,
            libc::TLS_TX as u32,
            self.tls_tx.as_ref().unwrap(),
            false,
            ops,
        );
        self.outstanding += 2;
        Ok(())
    }

    fn setsockopt_ktls(
        &self,
        fd: FixedFile,
        dir: u32,
        ci: &ktls::CryptoInfo,
        link: bool,
        ops: &mut SQueue,
    ) {
        let op = io_uring::opcode::SetSockOpt::new(
            fd,
            libc::SOL_TLS as u32,
            dir,
            ci.as_ptr() as _,
            ci.size() as u32,
        )
        .build();
        let op = if link {
            op.flags(io_uring::squeue::Flags::IO_LINK)
        } else {
            op
        };
        ops.push(op.user_data(self.id as u64 | USER_DATA_OP_SETSOCKOPT));
    }

    // Queue up a read.
    fn read(&mut self, ops: &mut SQueue) {
        let read_buf = &mut self.read_buf[self.read_buf_pos..];
        let fd = match &self.state {
            State::Reading(fd) => *fd,
            State::Handshaking(data) => data.fixed,
            State::EnablingKtls(fd) => *fd,
            _ => panic!("read in wrong state"),
        };
        // Try RecvMulti/RecvMsgMulti/RecvMultiBundle?
        self.outstanding += 1;
        trace!(
            "Issuing read to {:?} {}",
            read_buf.as_mut_ptr(),
            read_buf.len()
        );
        ops.push(
            io_uring::opcode::Read::new(fd, read_buf.as_mut_ptr(), read_buf.len() as _)
                .build()
                .user_data((self.id as u64) | USER_DATA_OP_READ),
        );
    }

    // Get the read buffer.
    fn get_read_buf(&self) -> &[u8] {
        &self.read_buf[self.read_buf_pos..]
    }
}

struct Connections {
    // Always size MAX_CONNECTIONS.
    //
    // I'd like for this to be an array, but it can't be constructed directly on
    // the heap. https://github.com/rust-lang/rust/issues/53827
    //
    // No box syntax?
    // So… how am I supposed to do this?
    cons: Vec<Connection>,
}

impl Connections {
    #[must_use]
    fn new() -> Self {
        Self {
            cons: (0..MAX_CONNECTIONS).map(Connection::new).collect(),
        }
    }
    #[must_use]
    fn get(&mut self, id: usize) -> &mut Connection {
        self.cons.get_mut(id).unwrap()
    }
}

struct PoolTracker {
    // Same as Connections, I'd like this to be an array.
    free: Vec<usize>,
}

impl PoolTracker {
    #[must_use]
    fn new() -> Self {
        Self {
            free: (0..MAX_CONNECTIONS).rev().collect(),
        }
    }
    #[must_use]
    fn alloc(&mut self) -> Option<usize> {
        self.free.pop()
    }
    fn dealloc(&mut self, n: usize) {
        self.free.push(n);
    }
}

#[must_use]
fn make_op_close(fd: FixedFile, con_id: usize) -> io_uring::squeue::Entry {
    io_uring::opcode::Close::new(fd)
        .build()
        .user_data((con_id as u64) | USER_DATA_OP_CLOSE)
}

#[must_use]
fn make_ops_cancel(fd: FixedFile, id: u64, modern: bool, ops: &mut SQueue) -> usize {
    trace!("Cancelling connection");
    let mut outstanding = 0;
    if modern {
        outstanding += 1;
        ops.push(
            io_uring::opcode::AsyncCancel2::new(io_uring::types::CancelBuilder::fd(fd))
                .build()
                .user_data(id | USER_DATA_OP_CANCEL),
        );
    } else {
        for opname in [USER_DATA_OP_WRITE, USER_DATA_OP_READ] {
            outstanding += 1;
            ops.push(
                io_uring::opcode::AsyncCancel::new(id | opname)
                    .build()
                    .user_data(id | USER_DATA_OP_CANCEL),
            );
        }
    }
    outstanding
}

fn disable_nodelay(fd: i32) -> std::io::Result<()> {
    use libc;
    use std::mem;
    let flag: libc::c_int = 1; // Enable TCP_NODELAY (disable Nagle)
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP, // Protocol
            libc::TCP_NODELAY, // Option
            &flag as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[derive(Debug, PartialEq)]
enum UserDataOp {
    Write,
    Read,
    Close,
    Cancel,
    SetSockOpt,
}

struct Hook<'a> {
    // Raw io_uring "user data".
    raw: u64,

    // Associated connectio.
    con: &'a mut Connection,

    // Operation that finished.
    op: UserDataOp,

    // Result of the syscall.
    result: i32,
}

impl std::fmt::Debug for Hook<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let strerror = if self.result < 0 {
            format!(
                " ({})",
                std::io::Error::from_raw_os_error(self.result.abs())
            )
        } else {
            "".into()
        };
        write!(
            f,
            "Op={op:?} result={result}{strerror} fixed={fd} raw={raw:x} Con={id} ({state:?})",
            raw = self.raw,
            op = self.op,
            result = self.result,
            id = self.con.id,
            state = self.con.state,
            fd = self
                .con
                .fd()
                .map(|x| format!("{}", x.0))
                .unwrap_or("<none>".to_string()),
        )
    }
}

struct Request<'a> {
    path: &'a str,
    len: usize,
}

// Return error if a request is bad.
// Some(req) if it's a good request.
// None if more data is needed.
fn parse_request(heads: &[u8]) -> Result<Option<Request>> {
    let s = std::str::from_utf8(heads)?;

    let Some(end) = s.find("\r\n\r\n") else {
        return Ok(None);
    };
    let s = &s[..end];
    trace!("Found req len {end}: {s:?}");

    let mut lines = s.split("\r\n");
    let mut first = lines.next().ok_or(Error::msg("no first line"))?.split(' ');
    let method = first.next().ok_or(Error::msg("no method"))?;
    if method != "GET" {
        return Err(Error::msg(format!("Invalid HTTP method {method}")));
    }
    let path = first.next().ok_or(Error::msg("no path"))?;
    let _version = first.next().ok_or(Error::msg("no version"))?;

    // Headers ignored.
    Ok(Some(Request { path, len: end }))
}

#[must_use]
fn decode_user_data(user_data: u64, result: i32, cons: &mut Connections) -> Hook {
    let op = match user_data & USER_DATA_OP_MASK {
        USER_DATA_OP_WRITE => UserDataOp::Write,
        USER_DATA_OP_READ => UserDataOp::Read,
        USER_DATA_OP_CLOSE => UserDataOp::Close,
        USER_DATA_OP_CANCEL => UserDataOp::Cancel,
        USER_DATA_OP_SETSOCKOPT => UserDataOp::SetSockOpt,
        _ => panic!("Invalid op {user_data:x} result {result}"),
    };
    assert_eq!(user_data & !(USER_DATA_CON_MASK | USER_DATA_OP_MASK), 0);
    Hook {
        raw: user_data,
        con: cons.get((user_data & USER_DATA_CON_MASK) as usize),
        op,
        result,
    }
}

// This function ends with an error, or a submitted read() or write().
fn maybe_answer_req(hook: &mut Hook, ops: &mut SQueue, archive: &Archive) -> Result<()> {
    let data = &hook.con.read_buf[..hook.con.read_buf_pos];
    let s = std::str::from_utf8(data)?;
    trace!("Let's see if there's a request in {:?}", s);
    let req = parse_request(data)?;
    let Some(req) = req else {
        // No full request yet.
        hook.con.read(ops);
        return Ok(());
    };
    debug!("Got request for path {}", req.path);
    // TODO: replace with writev?
    let len = req.len + 4;
    if let Some((pos, resp_len)) = archive.get_ofs(req.path) {
        hook.con.write_header_bytes(
            ops,
            format!(
                "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: {resp_len}\r\n\r\n"
            )
            .as_bytes(),
            pos,
            resp_len,
        );
    } else {
        let msg404 = "Not found\n";
        let len404 = msg404.len();
        hook.con.write_header_bytes(
            ops,
            format!("HTTP/1.1 404 Not Found\r\nConnection: keep-alive\r\nContent-Length: {len404}\r\n\r\n{msg404}").as_bytes(),
            0,
            0,
        );
    };
    hook.con.read_buf.copy_within(len.., 0);
    hook.con.read_buf_pos -= len;
    Ok(())
}

fn handle_connection(
    hook: &mut Hook,
    archive: &Archive,
    modern: bool,
    ops: &mut SQueue,
) -> Result<()> {
    {
        let Some(_) = hook.con.fd() else {
            return Err(Error::msg("invalid fd on completed fd"));
        };
    }
    match hook.op {
        UserDataOp::SetSockOpt => {
            debug!("Setsockopt returned {}", hook.result);
            assert_eq!(hook.result, 0);
        }
        UserDataOp::Read => {
            if hook.result < 0 {
                if hook.result.abs() == libc::EIO {
                    // TODO: for some reason I'm getting EIO after curl is done.
                    trace!("Got EIO on read");
                    hook.con.close(modern, ops);
                    return Ok(());
                }
                return Err(Error::msg(format!(
                    "read() failed: {}",
                    std::io::Error::from_raw_os_error(hook.result.abs())
                )));
            }
            if hook.result == 0 {
                if hook.con.read_buf_pos == 0 {
                    // Normal EOF.
                    hook.con.close(modern, ops);
                    return Ok(());
                } else {
                    return Err(Error::msg(format!(
                        "client disconnected with partial request: {:?}",
                        &hook.con.read_buf[..hook.con.read_buf_pos]
                    )));
                }
            }
            hook.con.read_buf_pos += hook.result as usize;
            maybe_answer_req(hook, ops, archive)?;
        }
        UserDataOp::Write => {
            if hook.result < 0 {
                return Err(Error::msg(format!(
                    "write() failed: {}",
                    std::io::Error::from_raw_os_error(hook.result.abs())
                )));
            }
            // TODO: ensure write is complete. Else re-issue the write.

            if hook.con.write_done(ops, archive, hook.result as usize) {
                // Process any further requests, or re-issue a read.
                maybe_answer_req(hook, ops, archive)?;
            }
        }
        UserDataOp::Close => {
            assert_eq!(hook.result, 0);
        }
        UserDataOp::Cancel => {
            if hook.result != 0 {
                debug!(
                    "Cancel return nonzero: {} {}",
                    hook.result,
                    std::io::Error::from_raw_os_error(hook.result.abs())
                );
            }
        }
    }
    Ok(())
}

#[must_use]
fn make_op_accept(multi: bool) -> io_uring::squeue::Entry {
    if multi {
        io_uring::opcode::AcceptMulti::new(LISTEN_FIXED_FILE)
            .build()
            .user_data(USER_DATA_LISTENER)
    } else {
        // TODO: add multiple accept ops is flight?
        io_uring::opcode::Accept::new(
            LISTEN_FIXED_FILE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
        .file_index(Some(io_uring::types::DestinationSlot::auto_target()))
        .build()
        .user_data(USER_DATA_LISTENER)
    }
}

#[must_use]
fn make_op_timeout(ts: Pin<&io_uring::types::Timespec>) -> io_uring::squeue::Entry {
    io_uring::opcode::Timeout::new(&*ts)
        .build()
        .user_data(USER_DATA_TIMEOUT)
}
fn load_certs<P: AsRef<std::path::Path>>(
    filename: P,
) -> std::io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key<P: AsRef<std::path::Path>>(
    filename: P,
) -> std::io::Result<PrivateKeyDer<'static>> {
    let keyfile = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

fn op_completion(
    mut data: &mut Hook,
    mut ops: &mut SQueue,
    opt: &Opt,
    pooltracker: &mut PoolTracker,
    archive: &Archive,
) -> Result<()> {
    debug!("Op completed: {data:?}");
    data.con.io_completed();

    trace!("Read buf pos: {}", data.con.read_buf_pos);
    match data.con.state {
        State::EnablingKtls(fd) => {
            assert!(matches![data.op, UserDataOp::SetSockOpt]);
            if data.result != 0 {
                return Err(Error::msg(format!(
                    "setsockopt(): {}",
                    std::io::Error::from_raw_os_error(data.result.abs())
                )));
            }
            if data.con.outstanding == 0 {
                data.con.read(ops);
                data.con.state = State::Reading(fd);
                data.con.read_buf_pos = 0;
            } else {
                debug!("EnablingKtls: still waiting for {}", data.con.outstanding);
            }
            return Ok(());
        }
        _ => {}
    }

    if let State::Handshaking(d) = &mut data.con.state {
        match &data.op {
            UserDataOp::Read => {
                if data.result == 0 {
                    data.con.close(opt.async_cancel2, &mut ops);
                    return Ok(());
                }
                if data.result < 0 {
                    warn!("Read error: {}", data.result);
                    data.con.close(opt.async_cancel2, &mut ops);
                    return Ok(());
                }

                let io = d
                    .received(&data.con.read_buf[..data.result as usize])
                    .unwrap();
                debug!("rustls op: {io:?}");
                let nw = io.tls_bytes_to_write();
                if nw > 0 {
                    let v = [0u8; MAX_WRITE_BUF];
                    let mut c = std::io::Cursor::new(v);
                    let n = d.tls.write_tls(&mut c)?;
                    // TODO: fix needless copy.
                    data.con.write_buf = c.into_inner();
                    debug!("Handshaking: still handshaking: {}", d.tls.is_handshaking());
                    data.con.write(n, &mut ops);
                } else {
                    // Read completed, nothing to write. Must mean we need to
                    // read more.
                    data.con.read(&mut ops);
                }
                return Ok(());
            }
            UserDataOp::Write => {
                // If there's more to write, write it.
                let v = [0u8; MAX_WRITE_BUF];
                let mut c = std::io::Cursor::new(v);
                let n = d.tls.write_tls(&mut c)?;
                if n > 0 {
                    // TODO: fix needless copy.
                    data.con.write_buf = c.into_inner();
                    debug!("Handshaking: Need to write {n} more");
                    data.con.write(n, &mut ops);
                    return Ok(());
                }

                // If handshake is not done, queue more reading.
                trace!(
                    "Handshaking: finished writing write buffer. Handshaking done: {}",
                    !d.tls.is_handshaking()
                );
                if d.tls.is_handshaking() {
                    // Not done. Read more.
                    data.con.read(&mut ops);
                    return Ok(());
                }

                let fd = d.fixed;

                // Set SOL_TCP/TCP_ULP to "tls", a prereq for enalbing kTLS.
                data.con.setsockopt_ulp(fd, &mut ops);

                // Extract TLS secrets.
                data.con
                    .enable_ktls(fd, &mut ops, State::EnablingKtls(fd))?;
                return Ok(());
            }
            op => panic!("bad op in Handshaking: {op:?}"),
        }
    }

    if !matches![data.op, UserDataOp::Close] {
        if let Err(e) = handle_connection(&mut data, archive, opt.async_cancel2, ops) {
            info!("Error handling connection: {e:?}");
            data.con.close(opt.async_cancel2, ops);
        }
    }
    if data.con.closing() && data.con.outstanding == 0 {
        data.con.deinit();
        pooltracker.dealloc(data.con.id);
        debug!("Deallocated {}", data.con.id);
    }
    Ok(())
}

#[nonblocking]
fn mainloop(
    mut ring: io_uring::IoUring,
    timeout: Pin<&io_uring::types::Timespec>,
    connections: &mut Connections,
    opt: &Opt,
    archive: &Archive,
) -> Result<()> {
    eprintln!("Thread main");
    let mut pooltracker = PoolTracker::new();
    let mut ops: SQueue = ArrayVec::new();
    let mut last_submit = std::time::Instant::now();
    let mut syscalls = 0;
    debug!("Loading certs");
    let certs = load_certs(&opt.tls_cert)?;
    // Load private key.
    debug!("Loading key");
    let key = load_private_key(&opt.tls_key)?;
    debug!("Creating TLS config");
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    config.enable_secret_extraction = true;
    let config = Arc::new(config);
    eprintln!("Starting main thread loop");
    loop {
        let mut cq = ring.completion();
        assert_eq!(cq.overflow(), 0);
        cq.sync();
        if cq.is_empty() {
            drop(cq);
            if last_submit.elapsed() > opt.busyloop {
                syscalls += 1;
                // Nothing has completed, so submit anything pending, and sleep.
                if let Err(ref e) = ring.submit_and_wait(1) {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        debug!("Interrupted system call for submit_and_wait");
                    }
                    warn!("io_uring submit_and_wait(): {e}");
                }
            }
            continue;
        }

        // We got stuff from the kernel, so reset idle timer.
        last_submit = std::time::Instant::now();

        for cqe in cq {
            let user_data = cqe.user_data();
            // If SendZc, then either
            //   io_uring::cqueue::more(cqe.flags());
            //   io_uring::cqueue::notif(cqe.flags());
            let result = cqe.result();
            //println!("Got some user_data: {user_data:?} {result:?}");
            match user_data {
                USER_DATA_LISTENER => {
                    if opt.accept_multi {
                        assert!(io_uring::cqueue::more(cqe.flags()));
                    } else {
                        ops.push(make_op_accept(opt.accept_multi));
                    }
                    if result < 0 {
                        warn!(
                            "Accept failed! {}",
                            std::io::Error::from_raw_os_error(result.abs())
                        );
                        continue;
                    }
                    let fixed = io_uring::types::Fixed(result as u32);
                    // disable_nodelay(result);
                    let id = pooltracker.alloc().unwrap();
                    debug!("Allocated {id} result {result}");
                    let new_conn = connections.get(id);
                    let tls = rustls::ServerConnection::new(config.clone())?;
                    new_conn.init(fixed, tls);
                    new_conn.read(&mut ops);
                }
                USER_DATA_TIMEOUT => {
                    // TODO: expire old connections.
                    ops.push(make_op_timeout(timeout));
                    connections.cons.iter_mut().for_each(|con| {
                        if con.fd().is_some() && con.last_action.elapsed().as_millis() > MAX_IDLE {
                            con.close(opt.async_cancel2, &mut ops);
                        }
                    });
                    trace!("Timeout: Syscalls: {syscalls}");
                    syscalls = 0;
                }
                _ => {
                    let mut data = decode_user_data(user_data, result, connections);
                    if let Err(e) =
                        op_completion(&mut data, &mut ops, opt, &mut pooltracker, archive)
                    {
                        warn!("Op error: {e:?}");
                        data.con.close(opt.async_cancel2, &mut ops);
                    }
                }
            }
        }
        let mut sq = ring.submission();
        assert_eq!(sq.dropped(), 0);
        assert!(!sq.cq_overflow());
        let to_push = std::cmp::min(sq.capacity() - sq.len(), ops.len());
        if to_push > 0 {
            let res = unsafe { sq.push_multiple(&ops[..to_push]) };
            res.expect("Can't happen: no room, but we checked");
            ops.drain(..to_push);
            drop(sq);
            // This will only trigger a syscall if the kernel thread went to
            // sleep.
            //
            // There doesn't seem to be a way to know if it in fact did trigger
            // a syscall.
            ring.submit()?;
        }
    }
}

#[derive(Parser)]
struct Opt {
    #[arg(
        long,
        short,
        help = "Verbosity level. Can be error, warn info, debug, or trace.",
        default_value = "error"
    )]
    verbose: String,

    #[arg(long, default_value_t = 1, help = "Number of userspace threads to run")]
    threads: usize,

    #[arg(long, help = "Enable CPU affinity 1:1 for threads")]
    cpu_affinity: bool,

    #[arg(long, default_value_t = 10, help = "Kernel side polling time.")]
    sqpoll_ms: u32,

    #[arg(long, default_value = "50ms", value_parser = parse_duration, help = "User side polling time.")]
    busyloop: std::time::Duration,

    #[arg(long, default_value = "1s", value_parser = parse_duration, help = "Periodic wakeup.")]
    periodic_wakeup: std::time::Duration,

    #[arg(long, default_value_t = true, value_parser = parse_bool, help = "Enable single issuer, supported in modern kernels.")]
    single_issuer: std::primitive::bool,

    #[arg(long, default_value_t = 1024, help = "io_uring ring size")]
    ring_size: u32,

    #[arg(long, default_value_t = true, value_parser = parse_bool, help = "Enable AsyncCancel2.")]
    async_cancel2: std::primitive::bool,

    #[arg(long, default_value_t = false, value_parser = parse_bool, help = "Enable AcceptMulti.")]
    accept_multi: std::primitive::bool,

    #[arg(long, short, default_value = "[::]:8080", help = "Listen address.")]
    listen: String,

    #[arg(long, default_value = "", help = "Strip prefix before looking in tar")]
    prefix: String,

    #[arg(long, short = 'P', help = "TLS private key")]
    tls_key: String,

    #[arg(long, short = 'C', help = "TLS certificate chain")]
    tls_cert: String,

    tarfile: String,
}

#[derive(Default)]
#[repr(C)]
struct SetSockOptTls {
    level: u32,
    optname: u32,
    optval: u64,
    optlen: u32,
    _pad: u32,
}

use lazy_static::lazy_static;
lazy_static! {
    static ref SETSOCKOPT_TLS: SetSockOptTls = SetSockOptTls {
        level: libc::SOL_TCP as u32,
        optname: libc::TCP_ULP as u32,
        optval: "tls".as_ptr() as u64,
        optlen: 3,
        _pad: 0,
    };
}

const TLS_STR: &str = "tls";

fn parse_bool(input: &str) -> Result<bool, String> {
    match input.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("Invalid value for flag: {}", input)),
    }
}
fn parse_duration(time_str: &str) -> Result<std::time::Duration, String> {
    if time_str.ends_with("ms") {
        let ms = time_str
            .trim_end_matches("ms")
            .parse::<u64>()
            .map_err(|_| "Invalid milliseconds")?;
        Ok(std::time::Duration::from_millis(ms))
    } else if time_str.ends_with("s") {
        let secs = time_str
            .trim_end_matches("s")
            .parse::<f64>()
            .map_err(|_| "Invalid seconds")?;
        let secs_whole = secs.trunc() as u64;
        let nanos = (secs.fract() * 1_000_000_000.0) as u32;
        Ok(std::time::Duration::new(secs_whole, nanos))
    } else {
        Err("Invalid format. Use 'Xs' or 'Yms' (e.g., '1.5s', '500ms')".to_string())
    }
}

struct Archive {
    mmap: memmap2::Mmap,
    content: HashMap<String, (u64, u64)>,
}

impl Archive {
    fn new(filename: &str, prefix: &str) -> Result<Self> {
        let file = std::fs::File::open(filename)?;
        let mut archive = tar::Archive::new(&file);
        let mut content = HashMap::new();
        for e in archive.entries()? {
            let e = e?;
            if let tar::EntryType::Regular = e.header().entry_type() {
            } else {
                continue;
            }
            let name = e.path()?;
            let name = name.to_string_lossy();
            let name = name.strip_prefix(prefix).unwrap_or(name.as_ref());
            content.insert(name.to_string(), (e.raw_file_position(), e.size()));
        }
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Ok(Self { content, mmap })
    }
    #[must_use]
    fn get_ofs(&self, filename: &str) -> Option<(usize, usize)> {
        use std::borrow::Cow;
        if filename.is_empty() {
            return None;
        }
        // Strip initial slash.
        let filename = filename.strip_prefix("/").unwrap_or(filename);

        // Add index.html to directory paths.
        let filename = if filename.is_empty() || filename.ends_with('/') {
            Cow::Owned(filename.to_owned() + "index.html")
        } else {
            Cow::Borrowed(filename)
        };

        trace!("Looking up {filename}");
        self.content
            .get(filename.as_ref())
            .copied()
            .map(|(a, b)| (a as usize, b as usize))
    }
    #[must_use]
    fn get_slice(&self, pos: usize, len: usize) -> &[u8] {
        let data: &[u8] = &self.mmap;
        &data[pos..(pos + len)]
    }
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    use std::str::FromStr;
    stderrlog::new()
        .module(module_path!())
        .module("rtweb")
        .quiet(false)
        .verbosity(
            log::LevelFilter::from_str(&opt.verbose)
                .map_err(|_| Error::msg(format!("Invalid verbosity string {:?}", opt.verbose)))?
                as usize
                - 1,
        )
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()?;
    trace!("AsyncCancel2: {}", opt.async_cancel2);
    trace!("Ring size: {}", opt.ring_size);
    trace!("Single issuer: {}", opt.single_issuer);

    let archive = Archive::new(&opt.tarfile, &opt.prefix)?;

    let listener = std::net::TcpListener::bind(&opt.listen)?;
    // The Rust API doesn't allow it, but setting TCP_NODELAY on a listening socket seems to set
    // that option on all incoming connections, which is what we want.
    {
        use std::os::fd::AsRawFd;
        disable_nodelay(listener.as_raw_fd())?;
    }

    let ret = std::thread::scope(|s| -> Result<()> {
        let mut handles = Vec::new();
        for n in 0..opt.threads {
            let listener = listener.try_clone()?;
            let opt = &opt;
            let archive = &archive;
            handles.push(
                std::thread::Builder::new()
                    .name(format!("handler/{n}").to_string())
                    .stack_size(THREAD_STACK_SIZE)
                    .spawn_scoped(s, move || -> Result<()> {
                        if opt.cpu_affinity {
                            // Set affinity mapping 1:1.
                            if !core_affinity::set_for_current(core_affinity::CoreId { id: 2 * n })
                            {
                                error!("Failed to bind to core {n}");
                            }
                        }
                        let mut ring = io_uring::IoUring::builder();
                        let mut ring = ring
                            .dontfork()
                            // .setup_sqpoll_cpu()
                            // .setup_cqsize()
                            .setup_sqpoll(opt.sqpoll_ms);
                        if opt.single_issuer {
                            ring = ring.setup_single_issuer();
                        }
                        let mut ring = ring.build(opt.ring_size)?;

                        // TODO: Apparently, this pin is ineffective because timespec is Unpin.
                        // Needs a wrapping struct that is not Unpin, apparently.
                        let timeout = opt.periodic_wakeup.into();
                        let timeout = Pin::new(&timeout);
                        let init_ops = [make_op_accept(opt.accept_multi), make_op_timeout(timeout)];
                        use std::os::fd::AsRawFd;
                        let mut registered = vec![-1i32; MAX_CONNECTIONS];
                        registered[0] = listener.as_raw_fd();
                        ring.submitter().register_files(&registered)?;
                        unsafe {
                            for op in init_ops {
                                ring.submission()
                                    .push(&op)
                                    .expect("submission queue is full");
                            }
                        }
                        ring.submit()?; // Or sq.sync?
                        eprintln!("Running thread {n}");
                        let mut connections = Connections::new();
                        mainloop(ring, timeout, &mut connections, opt, archive)?;
                        eprintln!("Exiting thread {n}");
                        Ok(())
                    })?,
            );
        }
        for handle in handles {
            handle.join().expect("foo")?;
        }
        debug!("All threads joined!");
        Ok(())
    })?;
    debug!("All threads done: {ret:?}");
    Ok(())
}
/* vim: textwidth=80
 */
