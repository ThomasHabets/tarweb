// ## ASYNC flag
//
// TODO: does ASYNC flag help performance?
//
// ## buffers
//
// TODO: Experiment with io-uring buffers.
//
// ## sendfile
//
// io_uring doesn't support sendfile. It does support splice, so one could
// create a pipe, and splice into it, and then splice from it to the socket.
//
// This would consume two extra file handles per connection, which is not very
// neat.
//
// Conclusion: Wait for direct kernel support for io_uring sendfile.
//
// ## Other TODOs
// * Ranged get
// * The code has no real structure. It's an experiment and I've banged on it
//   until it worked. Fix that.
//
// On my laptop, the best performance is:
// * --threads=2
// * --accept-multi=false (otherwise all goes to first thread)
// * --cpu-affinity=false (not sure why, but CPU affinity hurts a lot)

use std::io::Read;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Error, Result, anyhow};
use arrayvec::ArrayVec;
use clap::Parser;
use rtsan_standalone::nonblocking;
use tracing::{debug, error, info, trace, warn};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

mod archive;
use archive::Archive;

type FixedFile = io_uring::types::Fixed;

// Cache max age.
const CACHE_AGE_SECS: u64 = 300;

// If enabled, skip some accounting not needed for functionality.
const FULL_SPEED: bool = false;

// We don't use file descriptors for our io_uring operations. We use offsets
// into the io_uring fixed file table.
//
// The index for new accepted connections are automatically picked by the
// kernel, except for our listening socket which is number 0.
const LISTEN_FIXED_FILE: FixedFile = io_uring::types::Fixed(0);
const RESERVED_FIXED_SLOTS: usize = 1;

// 10MiB stack size per thread.
//
// There's only one thread per core, so not really anything to optimize.
const THREAD_STACK_SIZE: usize = 10 * 1048576;

// Every io_uring op has a "handle" of sorts. We use it to stuff the connection
// ID, and the operation.
// This mask allows for 2^32 concurrent connections.
const USER_DATA_CON_MASK: u64 = 0xffff_ffff;

// Special user data "handle" to indicate a new connection coming in.
const USER_DATA_LISTENER: u64 = u64::MAX;

// Special user data "handle" to indicate timeout. At timeout, we do some
// housekeeping.
const USER_DATA_TIMEOUT: u64 = USER_DATA_LISTENER - 1;

// Special user data "handle" to indicate passed fd.
const USER_DATA_PASSED_FD: u64 = USER_DATA_LISTENER - 2;

// This is the op type part of the user data "handle".
// If more ops are added, add them to make_ops_cancel for !modern path.
const USER_DATA_OP_MASK: u64 = 0xff_0000_0000;
const USER_DATA_OP_WRITE: u64 = 0x1_0000_0000;
const USER_DATA_OP_CLOSE: u64 = 0x2_0000_0000;
const USER_DATA_OP_READ: u64 = 0x3_0000_0000;
const USER_DATA_OP_CANCEL: u64 = 0x4_0000_0000;
const USER_DATA_OP_SETSOCKOPT: u64 = 0x8_0000_0000;
const USER_DATA_OP_FILES_UPDATE: u64 = 0x10_0000_0000;
const USER_DATA_OP_CLOSE_RAW: u64 = 0x20_0000_0000;
// TODO: NOP is an ugly hack to trigger Reading to look for a request. It should
// just trigger it some other way.
const USER_DATA_OP_NOP: u64 = 0x40_0000_0000;

// Max milliseconds that a connection is allowed to be idle, before we close it.
const MAX_IDLE: u128 = 5000;

// Every connection has a fixed read buffer (for the request). This is the
// size.
const MAX_READ_BUF: usize = 1024;

// This is also used for TLS writing, and a ServerHello can exceed 1KiB.
// In any case it should be at least one MSS/MTU.
const MAX_WRITE_BUF: usize = 2048;

// Outgoing headers max size.
const MAX_HEADER_BUF: usize = 1024;

// TODO: panics if squeue is full. There's a better way, surely.
type SQueue = ArrayVec<io_uring::squeue::Entry, 10_000>;
type ReadBuf = [u8; MAX_READ_BUF];
type HeaderBuf = ArrayVec<u8, MAX_HEADER_BUF>;

// State only needed during handshake.
//
// After handshake is completed, we'll enable kernel TLS, and won't need to use
// any state.
#[derive(Debug)]
struct HandshakeData {
    fixed: FixedFile,
    tls: rustls::ServerConnection,
}

impl HandshakeData {
    #[must_use]
    fn new(fixed: FixedFile, tls: rustls::ServerConnection) -> Self {
        Self { fixed, tls }
    }
    // We have received handshake data from the remote end.
    // send it on to rustls for processing.
    fn received(&mut self, data: &[u8]) -> Result<rustls::IoState, rustls::Error> {
        debug!("Got some handshaky data len {}: {data:?}", data.len());
        let mut reader = std::io::Cursor::new(data);
        self.tls.read_tls(&mut reader).unwrap();
        self.tls.process_new_packets()
    }
}

#[derive(Debug)]
struct RegisteringData {
    fd: FixedFile,
    raw_fd: i32,
    clienthello: Vec<u8>,
    tls: rustls::ServerConnection,
}

// State of a connection.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum State {
    // This connection is currently not in use.
    Idle,

    // Registering FD as a fixed file.
    //
    // This is used when passed a file descriptor over a unix socket. It'll be a
    // real one, so in this state we are waiting for FilesUpdate to register it
    // as a FixedFile. After that we'll close the original (real) file
    // descriptor.
    Registering(RegisteringData),

    // rustls handshaking happening.
    //
    // This is the big enum variant. Over a kB.
    //
    // When handshake completes, we send off setsockopt()s and go to
    // EnablingKtls.
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
    //
    // Reads are issued until a request is found. When found, state moves on to
    // WritingHeaders.
    Reading(FixedFile),

    // header_buf could be inside this enum, but I'm not sure I can create it on
    // state change without copying it. No placement new.
    //
    // This state has a pending Write.
    //
    // When writing headers finishes, state goes to WritingData.
    WritingHeaders(FixedFile, usize, usize),

    // This state has a pending Write.
    //
    // TODO: add data file.
    WritingData(FixedFile, usize, usize),

    // Close and possibly Cancel has been sent, but we don't reuse the
    // connection object until all ops have completed. (`outstdanding == 0`)
    //
    // When outstanding goes to 0, we go back to state Idle.
    Closing,
}

// Connection slot. There is a fixed number of them for the lifetime of the
// process.
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
    /// Create a new Connection "slot" in Idle state.
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

    /// Init a new connection.
    ///
    /// We reuse `Connection` objects between connections, which is why this is
    /// not just part of `new()`.
    fn init(&mut self, fixed: FixedFile, tls: rustls::ServerConnection) {
        debug_assert!(matches![self.state, State::Idle]);
        self.state = State::Handshaking(HandshakeData::new(fixed, tls));
        self.last_action = std::time::Instant::now();
    }

    /// Init a new connection from fd.
    ///
    /// We reuse `Connection` objects between connections, which is why this is
    /// not just part of `new()`.
    fn init_fd(
        &mut self,
        raw_fd: i32,
        fd: FixedFile,
        bytes: Vec<u8>,
        tls: rustls::ServerConnection,
        ops: &mut SQueue,
    ) {
        debug_assert!(matches![self.state, State::Idle]);
        self.state = State::Registering(RegisteringData {
            fd,
            raw_fd,
            clienthello: bytes,
            tls,
        });
        let State::Registering(ref reg) = self.state else {
            unreachable!()
        };
        self.last_action = std::time::Instant::now();
        self.make_op_files_update(&reg.raw_fd, reg.fd, ops);
    }

    /// Put the Connection object back in Idle state.
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

    /// Issue `CLOSE`, and wait for all outstanding ops to complete.
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

    /// Register that an operation has completed.
    fn io_completed(&mut self) {
        self.last_action = std::time::Instant::now();
        assert!(
            self.outstanding > 0,
            "IO underflow for connection {}",
            self.id
        );
        self.outstanding -= 1;
    }

    /// If the Connection is active, return the file handle.
    fn fd(&self) -> Option<FixedFile> {
        match self.state {
            State::Idle => None,
            State::Handshaking(ref data) => Some(data.fixed),
            State::EnablingKtls(fd) => Some(fd),
            State::Reading(fd) => Some(fd),
            State::WritingHeaders(fd, _, _) => Some(fd),
            State::WritingData(fd, _, _) => Some(fd),
            State::Registering(RegisteringData { fd, .. }) => Some(fd),
            State::Closing => None,
        }
    }

    #[must_use]
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

    // Writing headers has finished. Now we send data.
    //
    // This call may or may not be the first bytes of writing data.
    //
    // `pos` is position in the tar file.
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

    #[must_use]
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

    #[must_use]
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

    fn make_op_files_update(&mut self, raw_fd: *const i32, fd: FixedFile, ops: &mut SQueue) {
        ops.push(
            io_uring::opcode::FilesUpdate::new(raw_fd, 1)
                .offset(fd.0 as i32)
                .build()
                .user_data((self.id as u64) | USER_DATA_OP_FILES_UPDATE),
        );
        self.outstanding += 1;
    }

    fn enable_ktls(&mut self, fd: FixedFile, ops: &mut SQueue, new_state: State) -> Result<()> {
        // Set SOL_TCP/TCP_ULP to "tls", a prereq for enalbing kTLS.
        self.setsockopt_ulp(fd, ops);
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

    // Perform fake synchronous read. This will never be a syscall, because
    // rustls promises it already has the data.
    fn read_sync(&mut self, buf: &[u8], ops: &mut SQueue) -> Result<()> {
        self.read_buf[self.read_buf_pos..(self.read_buf_pos + buf.len())].copy_from_slice(buf);
        self.read_buf_pos += buf.len();
        if false {
            self.outstanding += 1;
            ops.push(
                io_uring::opcode::Nop::new()
                    .build()
                    .user_data((self.id as u64) | USER_DATA_OP_NOP),
            );
        }
        Ok(())
    }

    fn issue_nop(&mut self, ops: &mut SQueue) {
        self.outstanding += 1;
        ops.push(
            io_uring::opcode::Nop::new()
                .build()
                .user_data((self.id as u64) | USER_DATA_OP_NOP),
        );
    }

    /// Initialize the connection with some bytes already having been read from
    /// the client.
    ///
    /// This is used if connections come over a unix socket, where we are passed
    /// the data and initial TLS bytes (importantly the ClientHello).
    fn pre_read(
        &mut self,
        fixed: FixedFile,
        tls: rustls::ServerConnection,
        data: &[u8],
        ops: &mut SQueue,
    ) -> Result<()> {
        let mut d = HandshakeData { fixed, tls };
        trace!("Giving {} bytes to rustls", data.len());
        let io = d.received(data)?;
        let bytes_to_write = io.tls_bytes_to_write();
        trace!(
            "Given those {} bytes, rustls needs to send {bytes_to_write} bytes over the wire",
            data.len()
        );
        if bytes_to_write > 0 {
            let write_buf = [0u8; MAX_WRITE_BUF];
            let mut cur = std::io::Cursor::new(write_buf);
            let written = d.tls.write_tls(&mut cur)?;
            self.write_buf = cur.into_inner();
            self.state = State::Handshaking(d);
            self.write(written, ops);
        } else {
            self.state = State::Handshaking(d);
            self.read(ops);
        }
        Ok(())
    }

    // Queue up a read.
    fn read(&mut self, ops: &mut SQueue) {
        let read_buf = &mut self.read_buf[self.read_buf_pos..];
        let fd = match &self.state {
            State::Reading(fd) => *fd,
            State::Handshaking(data) => data.fixed,
            State::EnablingKtls(fd) => *fd,
            s => panic!("read in wrong state {s:?}"),
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
    #[must_use]
    #[allow(dead_code)]
    fn get_read_buf(&self) -> &[u8] {
        &self.read_buf[self.read_buf_pos..]
    }
}

struct Connections {
    // Allocated at start to be exactly the max number of connections.
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
    fn new(n: usize) -> Self {
        Self {
            cons: (0..n).map(Connection::new).collect(),
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
    fn new(n: usize) -> Self {
        Self {
            free: (0..n).rev().collect(),
        }
    }
    #[must_use]
    fn alloc(&mut self) -> Option<usize> {
        self.free.pop()
    }
    fn dealloc(&mut self, n: usize) {
        self.free.push(n);
    }
    #[must_use]
    fn free(&self) -> usize {
        self.free.len()
    }
    #[must_use]
    fn is_empty(&self) -> bool {
        self.free() == 0
    }
}

/// Given a `msghdr`, extract both the file descriptor and the payload data.
///
/// The payload data contains the clienthello (and possibly more bytes, but we
/// just send them on to rustls).
fn receive_passed_connection(
    passfd_msghdr: &libc::msghdr,
    nbytes: usize,
) -> Result<(libc::c_int, Vec<u8>)> {
    assert_eq!(passfd_msghdr.msg_iovlen, 1);
    let iov = passfd_msghdr.msg_iov;
    let clienthello: &[u8] =
        unsafe { std::slice::from_raw_parts((*iov).iov_base as *const u8, nbytes) };
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(passfd_msghdr as *const libc::msghdr) };
    while !cmsg.is_null() {
        // trace!("Control message!");
        let level = unsafe { (*cmsg).cmsg_level };
        let typ = unsafe { (*cmsg).cmsg_type };
        if (level, typ) != (libc::SOL_SOCKET, libc::SCM_RIGHTS) {
            cmsg = unsafe { libc::CMSG_NXTHDR(passfd_msghdr as *const libc::msghdr, cmsg) };
            continue;
        }
        // trace!("Control message: file descriptor!");
        let data = unsafe {
            let data_ptr = libc::CMSG_DATA(cmsg) as *const u8;
            let cmsg_len = (*cmsg).cmsg_len as usize;
            let header_size = std::mem::size_of::<libc::cmsghdr>();
            let data_len = cmsg_len.saturating_sub(header_size);
            if data_len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(data_ptr, data_len)
            }
        };
        assert_eq!(data.len(), std::mem::size_of::<libc::c_int>());
        let fd = libc::c_int::from_ne_bytes(data.try_into().unwrap());
        return Ok((fd, clienthello.to_vec()));
    }
    Err(anyhow!("Failed to extract file descriptor from passfd"))
}

#[must_use]
fn make_op_close(fd: FixedFile, con_id: usize) -> io_uring::squeue::Entry {
    io_uring::opcode::Close::new(fd)
        .build()
        .user_data((con_id as u64) | USER_DATA_OP_CLOSE)
}

#[must_use]
fn make_op_close_raw(fd: i32, con_id: usize) -> io_uring::squeue::Entry {
    io_uring::opcode::Close::new(io_uring::types::Fd(fd))
        .build()
        .user_data((con_id as u64) | USER_DATA_OP_CLOSE_RAW)
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

fn set_nodelay(fd: i32) -> std::io::Result<()> {
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
    CloseRaw,
    Cancel,
    SetSockOpt,
    FilesUpdate,
    Nop,
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
                .map_or("<none>".to_string(), |x| format!("{}", x.0)),
        )
    }
}

struct Request<'a> {
    path: &'a str,
    len: usize,
    encoding_gzip: bool,
    encoding_brotli: bool,
    encoding_zstd: bool,
    if_modified_since: Option<std::time::SystemTime>,
    if_none_match: Option<std::str::Split<'a, char>>,
}

impl Request<'_> {
    // Return error if a request is bad.
    // Some(req) if it's a good request.
    // None if more data is needed.
    fn parse(heads: &[u8]) -> Result<Option<Request<'_>>> {
        let s = std::str::from_utf8(heads)?;

        let Some(end) = s.find("\r\n\r\n") else {
            return Ok(None);
        };
        let s = &s[..end];
        debug!("Found req len {end}: {s:?}");

        let mut lines = s.split("\r\n");
        let mut first = lines.next().ok_or(Error::msg("no first line"))?.split(' ');
        let mut encoding_gzip = false;
        let mut encoding_brotli = false;
        let mut encoding_zstd = false;
        let mut if_modified_since = None;
        let mut if_none_match = None;
        for header in lines {
            let mut kv = header.splitn(2, ' ');
            let k = kv.next().unwrap_or("").to_lowercase();
            let v = kv.next().unwrap_or("");
            match k.as_str() {
                "accept-encoding:" => {
                    for enc in v.split(", ") {
                        match enc {
                            "gzip" => encoding_gzip = true,
                            "br" => encoding_brotli = true,
                            "zstd" => encoding_zstd = true,
                            _ => {}
                        }
                    }
                }
                "if-modified-since:" => {
                    if let Ok(ims) = httpdate::parse_http_date(v) {
                        debug!("If modified since: {ims:?}");
                        if_modified_since = Some(ims);
                    }
                }
                "if-none-match:" => {
                    if_none_match = Some(v.split(','));
                }
                _ => {}
            }
        }
        let method = first.next().ok_or(Error::msg("no method"))?;
        if method != "GET" {
            return Err(Error::msg(format!("Invalid HTTP method {method}")));
        }
        let path = first.next().ok_or(Error::msg("no path"))?;
        let _version = first.next().ok_or(Error::msg("no version"))?;

        // Headers ignored.
        Ok(Some(Request {
            path,
            len: end,
            encoding_gzip,
            encoding_zstd,
            encoding_brotli,
            if_modified_since,
            if_none_match,
        }))
    }
}

#[must_use]
fn decode_user_data(user_data: u64, result: i32, cons: &mut Connections) -> Hook<'_> {
    let op = match user_data & USER_DATA_OP_MASK {
        USER_DATA_OP_WRITE => UserDataOp::Write,
        USER_DATA_OP_READ => UserDataOp::Read,
        USER_DATA_OP_CLOSE => UserDataOp::Close,
        USER_DATA_OP_CANCEL => UserDataOp::Cancel,
        USER_DATA_OP_SETSOCKOPT => UserDataOp::SetSockOpt,
        USER_DATA_OP_FILES_UPDATE => UserDataOp::FilesUpdate,
        USER_DATA_OP_CLOSE_RAW => UserDataOp::CloseRaw,
        USER_DATA_OP_NOP => UserDataOp::Nop,
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
    trace!("Let's see if there's a request in {s:?}");
    let req = Request::parse(data)?;
    let Some(req) = req else {
        // No full request yet.
        hook.con.read(ops);
        return Ok(());
    };
    debug!("Got request for path {}", req.path);
    // TODO: replace with writev?
    let len = req.len + 4;

    if let Some(entry) = archive.entry(req.path) {
        // TODO: actually, go with the smallest option. My experience just is
        // that it's always this order.
        let (subentry, encoding) = if req.encoding_brotli
            && let Some(e) = entry.brotli()
        {
            (e, "Content-Encoding: br\r\n")
        } else if req.encoding_zstd
            && let Some(e) = entry.zstd()
        {
            (e, "Content-Encoding: zstd\r\n")
        } else if req.encoding_gzip
            && let Some(e) = entry.gzip()
        {
            (e, "Content-Encoding: gzip\r\n")
        } else {
            (entry.plain(), "")
        };
        // TODO: pre-calculate many of these headers.
        let mtime = entry.modified().map_or("".to_string(), |mtime| {
            format!("Last-Modified: {}\r\n", httpdate::fmt_http_date(*mtime))
        });
        let caching = if CACHE_AGE_SECS > 0 {
            // Expires header is ignored when providing max-age.
            &format!("Cache-Control: public, max-age={CACHE_AGE_SECS}\r\n")
        } else {
            ""
        };
        let etag = if let Some(e) = entry.etag() {
            &format!("ETag: {e}\r\n")
        } else {
            ""
        };
        let common = format!(
            "Connection: keep-alive\r\nDate: {}\r\nVary: accept-encoding\r\n{caching}{etag}{mtime}",
            httpdate::fmt_http_date(std::time::SystemTime::now()),
        );

        if req.if_modified_since.zip(entry.modified()).is_some_and(|(h,e)| *e <= h)
            // Split can only be iterated once, hence mut here.
            || req.if_none_match.zip(entry.etag()).is_some_and(|(mut h,e)| {
                h.any(|x| x.trim() == e)
            })
        {
            hook.con.write_header_bytes(
                ops,
                format!("HTTP/1.1 304 Not Modified\r\n{common}Content-Length: 0\r\n\r\n")
                    .as_bytes(),
                subentry.pos,
                subentry.len,
            );
        } else {
            hook.con.write_header_bytes(
                ops,
                format!(
                    "HTTP/1.1 200 OK\r\n{common}{encoding}Content-Length: {}\r\n\r\n",
                    subentry.len,
                )
                .as_bytes(),
                subentry.pos,
                subentry.len,
            );
        }
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
    let is_nop = matches![hook.op, UserDataOp::Nop];
    match hook.op {
        UserDataOp::SetSockOpt => {
            debug!("Setsockopt returned {}", hook.result);
            assert_eq!(hook.result, 0);
        }
        UserDataOp::Read | UserDataOp::Nop => {
            if hook.result < 0 {
                if hook.result.abs() == libc::EIO {
                    // TODO: for some reason I'm getting EIO after curl is done.
                    trace!("Got EIO on read");
                    hook.con.close(modern, ops);
                    return Ok(());
                }
                // TODO: create an error type so that we have bubble up the
                // severity. This, for example, is triggered by the client
                // disconnecting in the middle of a request, which should be
                // debug level logging.
                return Err(Error::msg(format!(
                    "read() failed: {}",
                    std::io::Error::from_raw_os_error(hook.result.abs())
                )));
            }
            if !is_nop && hook.result == 0 {
                // EOF.
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
            panic!("Nothing here, right?)");
        }
        UserDataOp::FilesUpdate => {
            assert!(hook.result >= 0, "FilesUpdate returned {}", hook.result);
            trace!("FilesUpdate done returning {}", hook.result);
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
        UserDataOp::CloseRaw => {
            assert_eq!(hook.result, 0);
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

#[must_use]
fn make_op_recvmsg_fixed(hdr: *mut libc::msghdr) -> io_uring::squeue::Entry {
    io_uring::opcode::RecvMsg::new(LISTEN_FIXED_FILE, hdr)
        .build()
        .user_data(USER_DATA_PASSED_FD)
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
    hook: &mut Hook,
    ops: &mut SQueue,
    opt: &Opt,
    pooltracker: &mut PoolTracker,
    archive: &Archive,
) -> Result<()> {
    debug!("Op completed: {hook:?}");
    hook.con.io_completed();

    //trace!("Read buf pos: {}", data.con.read_buf_pos);
    match &mut hook.con.state {
        State::Idle => panic!("Can't happen: op {hook:?} on Idle connection"),
        State::Closing => {}

        // Post-handshake states handled below.
        State::Reading(_) => {}
        State::WritingData(_, _, _) => {}
        State::WritingHeaders(_, _, _) => {}

        // Handshake states.
        State::EnablingKtls(fd) => {
            assert!(
                matches![hook.op, UserDataOp::SetSockOpt],
                "Expected SetSockOpt, got {:?}",
                hook.op
            );
            if hook.result != 0 {
                return Err(Error::msg(format!(
                    "setsockopt(): {}",
                    std::io::Error::from_raw_os_error(hook.result.abs())
                )));
            }
            let fd = *fd;
            if hook.con.outstanding == 0 {
                if hook.con.read_buf_pos == 0 {
                    hook.con.read(ops);
                } else {
                    hook.con.issue_nop(ops);
                }
                hook.con.state = State::Reading(fd);
            } else {
                debug!("EnablingKtls: still waiting for {}", hook.con.outstanding);
            }
            return Ok(());
        }

        State::Handshaking(d) => {
            match &hook.op {
                UserDataOp::Read => {
                    if hook.result == 0 {
                        hook.con.close(opt.async_cancel2, ops);
                        return Ok(());
                    }
                    if hook.result < 0 {
                        warn!("Read error: {}", hook.result);
                        hook.con.close(opt.async_cancel2, ops);
                        return Ok(());
                    }

                    let io = d.received(&hook.con.read_buf[..hook.result as usize])?;
                    let still_handshaking = d.tls.is_handshaking();
                    let fd = d.fixed;
                    debug!("rustls op: {io:?}");

                    // Handle bytes write.
                    // TODO: fix needless copy.
                    let bytes_to_write = io.tls_bytes_to_write();
                    let write_buf = [0u8; MAX_WRITE_BUF];
                    let mut write_cursor = std::io::Cursor::new(write_buf);
                    let bytes_written = if bytes_to_write > 0 {
                        d.tls.write_tls(&mut write_cursor)?
                    } else {
                        0
                    };

                    // Handle bytes read.
                    // TODO: fix needless copy.
                    let bytes_to_read = io.plaintext_bytes_to_read();
                    let mut read_buf = [0u8; MAX_READ_BUF];
                    let bytes_read = if bytes_to_read > 0 {
                        trace!("Early plaintext bytes: {bytes_to_read}");
                        assert!(!still_handshaking);
                        d.tls.reader().read(&mut read_buf[..bytes_to_read])?
                    } else {
                        0
                    };

                    // `d` implicitly dropped here.

                    if bytes_written > 0 {
                        hook.con.write_buf = write_cursor.into_inner();
                        debug!("Handshaking: still handshaking: {}", d.tls.is_handshaking());
                        hook.con.write(bytes_written, ops);
                    }
                    if bytes_read > 0 {
                        hook.con.read_sync(&read_buf[..bytes_read], ops)?;
                    }

                    if bytes_to_write == 0 && !still_handshaking {
                        // If handshake is finished, but there's still bytes to
                        // write, then we wait for the Write to complete.
                        assert_eq!(bytes_to_read, bytes_read);
                        // Nothing to write, handshake is done. Let's go to enable
                        // kTLS.
                        hook.con.enable_ktls(fd, ops, State::EnablingKtls(fd))?;
                    } else if bytes_to_write == 0 {
                        // Read completed, nothing to write. Must mean we need to
                        // read more.
                        hook.con.read(ops);
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
                        hook.con.write_buf = c.into_inner();
                        debug!("Handshaking: Need to write {n} more");
                        hook.con.write(n, ops);
                        return Ok(());
                    }

                    // If handshake is not done, queue more reading.
                    trace!(
                        "Handshaking: finished writing write buffer. Handshaking done: {}",
                        !d.tls.is_handshaking()
                    );
                    if d.tls.is_handshaking() {
                        // Not done. Read more.
                        hook.con.read(ops);
                        return Ok(());
                    }

                    let fd = d.fixed;
                    hook.con.enable_ktls(fd, ops, State::EnablingKtls(fd))?;
                    return Ok(());
                }
                UserDataOp::CloseRaw => {
                    assert_eq!(
                        hook.result, 0,
                        "close() passed real fd failed with code {}",
                        hook.result
                    );
                    trace!("CloseRaw completed");
                }
                op => panic!("bad op in Handshaking: {op:?}"),
            }
        }
        State::Registering(_) => {
            let State::Registering(RegisteringData {
                raw_fd,
                fd,
                tls,
                clienthello,
                ..
            }) = std::mem::replace(&mut hook.con.state, State::Idle)
            else {
                unreachable!();
            };
            trace!("Fixed file FilesUpdate registration finished");
            assert_eq!(hook.op, UserDataOp::FilesUpdate);
            assert_eq!(
                hook.result,
                1,
                "FilesUpdate failed returning {}, which is system error {}",
                hook.result,
                std::io::Error::from_raw_os_error(hook.result.abs())
            );
            ops.push(make_op_close_raw(raw_fd, hook.con.id));
            hook.con.outstanding += 1;
            hook.con.pre_read(fd, tls, &clienthello, ops)?;
            trace!("Now in state {:?}", hook.con.state);
        }
    }

    if hook.con.fd().is_none() {
        debug!("Operation completed on a nonexisting fd (happens during close): {hook:?}");
        return Ok(());
    } else if let Err(e) = handle_connection(hook, archive, opt.async_cancel2, ops) {
        info!("Error handling connection: {e:?}");
        hook.con.close(opt.async_cancel2, ops);
    }
    if hook.con.closing() && hook.con.outstanding == 0 {
        hook.con.deinit();
        pooltracker.dealloc(hook.con.id);
        debug!("Deallocated");
    }
    Ok(())
}

#[nonblocking]
fn mainloop(
    mut ring: io_uring::IoUring,
    timeout: Pin<&io_uring::types::Timespec>,
    passfd_msghdr: &mut libc::msghdr,
    connections: &mut Connections,
    opt: &Opt,
    archive: &Archive,
) -> Result<()> {
    info!("Thread main");
    let mut pooltracker = PoolTracker::new(opt.max_connections);
    let mut ops: SQueue = ArrayVec::new();
    let mut last_submit = std::time::Instant::now();
    let mut syscalls = 0;
    debug!("Loading certs");
    let certs = load_certs(&opt.tls_cert)
        .with_context(|| format!("Loading certs from {}", opt.tls_cert.display()))?;
    // Load private key.
    debug!("Loading key");
    let key = load_private_key(&opt.tls_key)
        .with_context(|| format!("Loading private key from {}", opt.tls_key.display()))?;
    debug!("Creating TLS config");
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    config.enable_secret_extraction = true;
    let config = Arc::new(config);
    info!("Starting main thread loop");
    loop {
        let mut cq = ring.completion();
        assert_eq!(cq.overflow(), 0);
        cq.sync();
        if cq.is_empty() {
            drop(cq);
            if opt.busyloop.as_millis() == 0 || last_submit.elapsed() > opt.busyloop {
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
            if io_uring::cqueue::notif(cqe.flags()) {
                info!("Got io-uring notification");
                continue;
            }
            //println!("Got some user_data: {user_data:?} {result:?}");
            match user_data {
                USER_DATA_LISTENER => {
                    if opt.accept_multi {
                        assert!(io_uring::cqueue::more(cqe.flags()));
                    } else if pooltracker.free() > 1 {
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
                    // set_nodelay(result);
                    let id = pooltracker.alloc().unwrap();
                    debug!("Allocated connection {id} when accept()={result}");
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
                USER_DATA_PASSED_FD => {
                    trace!("Incoming passfd message with code {result}");
                    if pooltracker.free() > 1 {
                        // Issue a new receive.
                        ops.push(make_op_recvmsg_fixed(passfd_msghdr as *mut libc::msghdr));
                    }
                    if result == 0 {
                        warn!("Received empty passed fd");
                    } else if result > 0 {
                        match receive_passed_connection(passfd_msghdr, result as usize) {
                            Ok((fd, clienthello)) => {
                                trace!(
                                    "Passfd extracted: fd={fd} clienthello {} bytes",
                                    clienthello.len()
                                );
                                let id = pooltracker.alloc().unwrap();
                                let fixed =
                                    io_uring::types::Fixed((RESERVED_FIXED_SLOTS + id) as u32);
                                debug!("Allocated {id} with passfd");
                                let new_conn = connections.get(id);
                                new_conn.init_fd(
                                    fd,
                                    fixed,
                                    clienthello.to_vec(),
                                    rustls::ServerConnection::new(config.clone())?,
                                    &mut ops,
                                );
                            }
                            Err(e) => error!("Receiving passed connection: {e}"),
                        }
                    } else {
                        error!(
                            "recvmsg() error on passed fd, error {}",
                            std::io::Error::from_raw_os_error(result.abs())
                        );
                    }
                }
                _ => {
                    let mut data = decode_user_data(user_data, result, connections);
                    let span = tracing::info_span!("conn", id = data.con.id);
                    let _guard = span.enter();
                    let was_full = pooltracker.is_empty();
                    if let Err(e) =
                        op_completion(&mut data, &mut ops, opt, &mut pooltracker, archive)
                    {
                        warn!("Op error: {e:?}");
                        data.con.close(opt.async_cancel2, &mut ops);
                    }
                    if was_full && !pooltracker.is_empty() {
                        if opt.listen.is_some() {
                            // TODO: no good way to prevent overflow with multi
                            // accept.
                            if !opt.accept_multi {
                                ops.push(make_op_accept(opt.accept_multi));
                            }
                        } else {
                            ops.push(make_op_recvmsg_fixed(passfd_msghdr as *mut libc::msghdr));
                        }
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

            if !FULL_SPEED && sq.need_wakeup() {
                // Disable in full speed mode because of a memory fence.
                syscalls += 1;
            }
            drop(sq);
            // This will only trigger a syscall if the kernel thread went to
            // sleep.
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

    // Huge page support. Requires reserving some huge pages in the kernel via:
    //
    // `sudo sysctl -w vm.nr_hugepages=100`
    //
    // Hugepages imply anonymous mapping, so this means the tarfile will no longer
    // be file-backed. This means even cold parts will take up RAM.
    //
    // On x86_64 21 (2MiB) and 30 (1GiB) should be possible.
    //
    // Disabled by default since hugepages may not be enabled.
    #[arg(
        long,
        help = "If set, use hugepages of this bit length. (21 or 30 on x86)"
    )]
    hugepages: Option<u8>,

    /// Enable etags (requires indexing at startup).
    #[arg(long)]
    etags: bool,

    /// Max concurrent connections.
    #[arg(long, default_value_t = 100)]
    max_connections: usize,

    #[arg(long, help = "Enable CPU affinity 1:1 for threads")]
    cpu_affinity: bool,

    #[arg(long, default_value_t = 10, help = "Kernel side polling time.")]
    sqpoll_ms: u32,

    #[arg(long, default_value = "0ms", value_parser = parse_duration, help = "User side polling time.")]
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

    #[arg(long, short, help = "Listen address.")]
    listen: Option<String>,

    /// Get passed file descriptors on a unix socket.
    #[arg(long)]
    passfd: Option<std::path::PathBuf>,

    #[arg(long, default_value = "", help = "Strip prefix before looking in tar")]
    prefix: String,

    #[arg(long, short = 'P', help = "TLS private key")]
    tls_key: std::path::PathBuf,

    #[arg(long, short = 'C', help = "TLS certificate chain")]
    tls_cert: std::path::PathBuf,

    tarfile: std::path::PathBuf,
}

const TLS_STR: &[u8; 4] = b"tls\0";

fn parse_bool(input: &str) -> Result<bool, String> {
    match input.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("Invalid value for flag: {input}")),
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

fn is_setsockopt_supported() -> Result<bool> {
    // Set up a TCP connection.
    let listener = std::net::TcpListener::bind("[::1]:0")?;
    let addr = listener.local_addr()?;
    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
    });
    let stream = std::net::TcpStream::connect(addr)?;
    let _server_stream = handle.join().unwrap();

    // Set up io_uring.
    let mut ring: io_uring::IoUring = io_uring::IoUring::builder().dontfork().build(10)?;

    // Step 4: Try to set TCP_ULP on the client socket
    let op = io_uring::opcode::SetSockOpt::new(
        io_uring::types::Fd(stream.as_raw_fd()),
        libc::SOL_TCP as u32,
        libc::TCP_ULP as u32,
        TLS_STR.as_ptr() as *const libc::c_void,
        3,
    )
    .build();
    unsafe {
        ring.submission().push(&op)?;
    }
    loop {
        ring.submit_and_wait(1)?;
        let cqes: Vec<io_uring::cqueue::Entry> = ring.completion().collect();
        if cqes.is_empty() {
            continue;
        }
        let rc = cqes[0].result();
        if rc == 0 {
            return Ok(true);
        }
        return Ok(false);
    }
}

fn is_ktls_loaded() -> Result<bool> {
    // Step 1: Bind a local listener to a free port
    let listener = std::net::TcpListener::bind("[::1]:0")?;
    let addr = listener.local_addr()?;

    // Step 2: Spawn a thread to accept the connection
    let handle = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
    });

    // Step 3: Connect as a client
    let stream = std::net::TcpStream::connect(addr)?;
    let _server_stream = handle.join().unwrap();

    // Step 4: Try to set TCP_ULP on the client socket
    let fd = stream.as_raw_fd();
    let ulp_name = b"tls\0";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_ULP,
            ulp_name.as_ptr() as *const libc::c_void,
            ulp_name.len() as libc::socklen_t,
        )
    };

    Ok(if ret == 0 {
        trace!("Successfully set TCP_ULP to 'tls' as a test");
        true
    } else {
        let err = std::io::Error::last_os_error();
        debug!("Failed to set TCP_ULP on client socket: {err}");
        false
    })
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    tracing_subscriber::fmt()
        .with_env_filter(format!("tarweb={}", opt.verbose))
        .with_writer(std::io::stderr)
        .init();
    trace!("AsyncCancel2: {}", opt.async_cancel2);
    trace!("Ring size: {}", opt.ring_size);
    trace!("Single issuer: {}", opt.single_issuer);

    if !is_ktls_loaded()? {
        return Err(Error::msg(
            "Kernel TLS does not seem to be supported. Either CONFIG_TLS=n, or you need to load the `tls` module using `modprobe tls`",
        ));
    }
    trace!("Kernel TLS seems supported");
    if !is_setsockopt_supported()? {
        return Err(Error::msg(
            "io-uring setsockopt not supported. Support was added in Linux kernel 6.7, so this must be older than that.",
        ));
    }

    let archive = {
        Archive::builder()
            .etags(opt.etags)
            .hugepages(opt.hugepages)
            .build(&opt.tarfile, &opt.prefix)
            .with_context(|| format!("Memory mapping file {:?}.", opt.tarfile.display()))?
    };

    if opt.listen.is_some() && opt.passfd.is_some() {
        return Err(anyhow!(
            "Can't use both -listen and --passfd at the same time."
        ));
    }

    let listener = opt
        .listen
        .as_ref()
        .map(|l| {
            let listen =
                std::net::TcpListener::bind(l).with_context(|| format!("Binding to {l}"))?;
            // The Rust API doesn't allow it, but setting TCP_NODELAY on a listening socket seems to set
            // that option on all incoming connections, which is what we want.
            set_nodelay(listen.as_raw_fd())?;
            Ok::<_, Error>(listen)
        })
        .transpose()?;

    let passer = opt
        .passfd
        .as_ref()
        .map(|pass| {
            let _ = std::fs::remove_file(pass);
            std::os::unix::net::UnixDatagram::bind(pass).context("binding passfd")
        })
        .transpose()?;

    std::thread::scope(|s| -> Result<()> {
        let mut handles = Vec::new();
        for n in 0..opt.threads {
            let listener = listener.as_ref().map(|l| l.try_clone()).transpose()?;
            let passer = passer.as_ref().map(|p| p.try_clone()).transpose()?;
            let opt = &opt;
            let archive = &archive;
            handles.push(
                std::thread::Builder::new()
                    .name(format!("handler/{n}").to_string())
                    .stack_size(THREAD_STACK_SIZE)
                    .spawn_scoped(s, move || -> Result<()> {
                        if opt.cpu_affinity {
                            // Set affinity mapping 1:1.
                            if !core_affinity::set_for_current(core_affinity::CoreId { id: n }) {
                                error!("Failed to bind thread {n} to core {n}");
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

                        let mut cmsgspace = vec![0u8; 128];
                        trace!("Configured cmsg space: {}", cmsgspace.len());
                        let mut iov_space = [0u8; 2048];
                        let mut iov = libc::iovec {
                            iov_len: iov_space.len(),
                            iov_base: iov_space.as_mut_ptr() as *mut libc::c_void,
                        };
                        let mut passfd_msghdr = libc::msghdr {
                            msg_name: std::ptr::null_mut(),
                            msg_namelen: 0,
                            msg_iov: &mut iov as *mut libc::iovec,
                            msg_iovlen: 1,
                            msg_control: cmsgspace.as_mut_ptr() as *mut libc::c_void,
                            msg_controllen: cmsgspace.len(),
                            msg_flags: 0,
                        };
                        let init_ops = {
                            let mut ops = Vec::new();
                            if listener.is_some() {
                                ops.push(make_op_accept(opt.accept_multi));
                            }
                            ops.push(make_op_timeout(timeout));
                            if passer.is_some() {
                                ops.push(make_op_recvmsg_fixed(
                                    &mut passfd_msghdr as *mut libc::msghdr,
                                ));
                            }
                            ops
                        };
                        let mut registered = vec![-1i32; opt.max_connections];
                        if let Some(ref l) = listener {
                            registered[LISTEN_FIXED_FILE.0 as usize] = l.as_raw_fd();
                        }
                        if let Some(ref p) = passer {
                            registered[LISTEN_FIXED_FILE.0 as usize] = p.as_raw_fd();
                        }
                        ring.submitter().register_files(&registered)?;
                        unsafe {
                            for op in init_ops {
                                ring.submission()
                                    .push(&op)
                                    .expect("submission queue is full");
                            }
                        }
                        ring.submit()?; // Or sq.sync?
                        drop(listener);
                        drop(passer);
                        info!("Running thread {n}");
                        let mut connections = Connections::new(opt.max_connections);
                        mainloop(
                            ring,
                            timeout,
                            &mut passfd_msghdr,
                            &mut connections,
                            opt,
                            archive,
                        )?;
                        info!("Exiting thread {n}");
                        Ok(())
                    })?,
            );
        }
        drop(listener);
        drop(passer);
        for handle in handles {
            handle.join().expect("foo")?;
        }
        debug!("All threads joined!");
        Ok(())
    })?;
    debug!("All threads done");
    Ok(())
}
/* vim: textwidth=80
 */
