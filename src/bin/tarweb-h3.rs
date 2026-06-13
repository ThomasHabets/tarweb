//! LLM-coded HTTP/3 version of tarweb.
//!
//! Things to sort out:
//! * Do we really need custom hpack/qpack code?
//! * Add the allocation tripwire.
//! * Preallocate all buffers.
//! * Landlock.
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

#[path = "tarweb_h3/qpack.rs"]
mod qpack;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use clap::Parser;
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, EndpointEvent,
    Event, ReadError, ServerConfig, StreamEvent, StreamId, Transmit, TransportConfig, WriteError,
};
use tarweb::archive::Archive;
use tracing::{debug, info, trace, warn};

const USER_DATA_RECV: u64 = 1;
const USER_DATA_TIMEOUT: u64 = 2;
const USER_DATA_SEND_BASE: u64 = 1_000_000;

type FixedFile = io_uring::types::Fixed;
const SOCKET_FIXED_FILE: FixedFile = io_uring::types::Fixed(0);

const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_STREAM_CONTROL: u64 = 0x00;

const RECV_BUF_SIZE: usize = 65_536;
const MAX_SEND_DATAGRAMS: usize = 1;

#[derive(Parser)]
struct Opt {
    #[arg(
        long,
        short,
        help = "Verbosity level. Can be error, warn info, debug, or trace.",
        default_value = "error"
    )]
    verbose: String,

    #[arg(
        long,
        short,
        default_value = "[::1]:4433",
        help = "UDP listen address."
    )]
    listen: SocketAddr,

    #[arg(long, default_value_t = 1024, help = "io_uring ring size")]
    ring_size: u32,

    #[arg(long, default_value = "10ms", value_parser = parse_duration, help = "QUIC timer poll interval.")]
    periodic_wakeup: Duration,

    /// Enable etags while indexing the archive.
    #[arg(long)]
    etags: bool,

    #[arg(
        long,
        help = "If set, use hugepages of this bit length. (21 or 30 on x86)"
    )]
    hugepages: Option<u8>,

    /// Strip prefix before looking in tar.
    #[arg(long, default_value = "")]
    prefix: String,

    #[arg(long, short = 'P', help = "TLS private key")]
    tls_key: std::path::PathBuf,

    #[arg(long, short = 'C', help = "TLS certificate chain")]
    tls_cert: std::path::PathBuf,

    tarfile: std::path::PathBuf,
}

struct RecvSlot {
    storage: libc::sockaddr_storage,
    namelen: libc::socklen_t,
    iov: libc::iovec,
    hdr: libc::msghdr,
    buf: Vec<u8>,
}

impl RecvSlot {
    fn new() -> Box<Self> {
        let mut slot = Box::new(Self {
            storage: unsafe { std::mem::zeroed() },
            namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            iov: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            hdr: unsafe { std::mem::zeroed() },
            buf: vec![0; RECV_BUF_SIZE],
        });
        slot.refresh();
        slot
    }

    fn refresh(&mut self) {
        self.namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        self.iov = libc::iovec {
            iov_base: self.buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: self.buf.len(),
        };
        self.hdr = libc::msghdr {
            msg_name: std::ptr::from_mut::<libc::sockaddr_storage>(&mut self.storage).cast(),
            msg_namelen: self.namelen,
            msg_iov: std::ptr::from_mut::<libc::iovec>(&mut self.iov),
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
    }

    fn op(&mut self, fd: FixedFile) -> io_uring::squeue::Entry {
        self.refresh();
        io_uring::opcode::RecvMsg::new(fd, std::ptr::from_mut::<libc::msghdr>(&mut self.hdr))
            .build()
            .user_data(USER_DATA_RECV)
    }

    fn remote(&self) -> Result<SocketAddr> {
        sockaddr_to_addr(&self.storage, self.hdr.msg_namelen)
    }
}

struct SendOp {
    data: Vec<u8>,
    storage: libc::sockaddr_storage,
    namelen: libc::socklen_t,
}

impl SendOp {
    fn new(destination: SocketAddr, data: &[u8]) -> Self {
        let (storage, namelen) = sockaddr_from_addr(destination);
        Self {
            data: data.to_vec(),
            storage,
            namelen,
        }
    }

    fn op(&self, fd: FixedFile, user_data: u64) -> io_uring::squeue::Entry {
        io_uring::opcode::Send::new(fd, self.data.as_ptr(), self.data.len().try_into().unwrap())
            .dest_addr(std::ptr::from_ref::<libc::sockaddr_storage>(&self.storage).cast())
            .dest_addr_len(self.namelen)
            .build()
            .user_data(user_data)
    }
}

#[derive(Default)]
struct H3Connection {
    sent_control: bool,
    requests: HashMap<StreamId, RequestStream>,
}

#[derive(Default)]
struct RequestStream {
    recv: Vec<u8>,
    response: Option<PendingResponse>,
}

struct PendingResponse {
    bytes: Vec<u8>,
    written: usize,
    finished: bool,
}

struct ConnectionState {
    conn: Connection,
    h3: H3Connection,
}

struct Server {
    endpoint: Endpoint,
    connections: HashMap<ConnectionHandle, ConnectionState>,
    archive: Archive,
    socket_fd: FixedFile,
    pending_sends: HashMap<u64, Box<SendOp>>,
    next_send_id: u64,
}

impl Server {
    fn new(endpoint: Endpoint, archive: Archive, socket_fd: FixedFile) -> Self {
        Self {
            endpoint,
            connections: HashMap::new(),
            archive,
            socket_fd,
            pending_sends: HashMap::new(),
            next_send_id: USER_DATA_SEND_BASE,
        }
    }

    fn handle_datagram(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        data: BytesMut,
        ops: &mut Vec<io_uring::squeue::Entry>,
    ) {
        let mut scratch = Vec::new();
        match self
            .endpoint
            .handle(now, remote, None, None, data, &mut scratch)
        {
            Some(DatagramEvent::Response(transmit)) => {
                self.queue_transmit(transmit, &scratch, ops);
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                match self.endpoint.accept(incoming, now, &mut scratch, None) {
                    Ok((handle, conn)) => {
                        debug!("Accepted HTTP/3 connection {handle:?}");
                        self.connections.insert(
                            handle,
                            ConnectionState {
                                conn,
                                h3: H3Connection::default(),
                            },
                        );
                        self.drive_connection(handle, now, ops);
                    }
                    Err(e) => {
                        warn!("QUIC accept failed: {}", e.cause);
                        if let Some(transmit) = e.response {
                            self.queue_transmit(transmit, &scratch, ops);
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                if let Some(state) = self.connections.get_mut(&handle) {
                    state.conn.handle_event(event);
                    self.drive_connection(handle, now, ops);
                }
            }
            None => {}
        }
    }

    fn handle_timeouts(&mut self, now: Instant, ops: &mut Vec<io_uring::squeue::Entry>) {
        let handles: Vec<_> = self.connections.keys().copied().collect();
        for handle in handles {
            let Some(state) = self.connections.get_mut(&handle) else {
                continue;
            };
            if state
                .conn
                .poll_timeout()
                .is_some_and(|timeout| timeout <= now)
            {
                state.conn.handle_timeout(now);
                self.drive_connection(handle, now, ops);
            }
        }
    }

    fn drive_connection(
        &mut self,
        handle: ConnectionHandle,
        now: Instant,
        ops: &mut Vec<io_uring::squeue::Entry>,
    ) {
        let mut remove = false;
        let mut scratch = Vec::new();
        loop {
            let mut endpoint_events = Vec::new();
            let mut app_events = Vec::new();
            let mut transmits = Vec::new();
            {
                let Some(state) = self.connections.get_mut(&handle) else {
                    return;
                };
                while let Some(transmit) =
                    state
                        .conn
                        .poll_transmit(now, MAX_SEND_DATAGRAMS, &mut scratch)
                {
                    let size = transmit.size;
                    transmits.push((transmit, scratch[..size].to_vec()));
                    scratch.clear();
                }
                while let Some(event) = state.conn.poll_endpoint_events() {
                    endpoint_events.push(event);
                }
                while let Some(event) = state.conn.poll() {
                    app_events.push(event);
                }
            }

            for (transmit, bytes) in transmits {
                self.queue_transmit(transmit, &bytes, ops);
            }

            if endpoint_events.is_empty() && app_events.is_empty() {
                break;
            }

            for event in endpoint_events {
                remove |= event.is_drained();
                if let Some(conn_event) = self.endpoint.handle_event(handle, event)
                    && let Some(state) = self.connections.get_mut(&handle)
                {
                    state.conn.handle_event(conn_event);
                }
            }

            for event in app_events {
                if self.handle_app_event(handle, event) {
                    remove = true;
                }
            }
        }

        if remove {
            self.endpoint.handle_event(handle, EndpointEvent::drained());
            self.connections.remove(&handle);
        }
    }

    fn handle_app_event(&mut self, handle: ConnectionHandle, event: Event) -> bool {
        match event {
            Event::Connected => {
                if let Some(state) = self.connections.get_mut(&handle) {
                    send_h3_control_stream(&mut state.conn, &mut state.h3);
                }
            }
            Event::Stream(StreamEvent::Opened { dir }) => {
                let mut accepted = Vec::new();
                if let Some(state) = self.connections.get_mut(&handle) {
                    while let Some(id) = state.conn.streams().accept(dir) {
                        trace!("Accepted stream {id}");
                        if dir == Dir::Bi {
                            state.h3.requests.entry(id).or_default();
                        }
                        accepted.push(id);
                    }
                }
                for id in accepted {
                    self.read_stream(handle, id);
                }
            }
            Event::Stream(StreamEvent::Readable { id }) => {
                self.read_stream(handle, id);
            }
            Event::Stream(StreamEvent::Writable { id }) => {
                self.flush_response(handle, id);
            }
            Event::Stream(StreamEvent::Available { dir }) => {
                if dir == Dir::Uni
                    && let Some(state) = self.connections.get_mut(&handle)
                {
                    send_h3_control_stream(&mut state.conn, &mut state.h3);
                }
            }
            Event::Stream(StreamEvent::Finished { id })
            | Event::Stream(StreamEvent::Stopped { id, .. }) => {
                if let Some(state) = self.connections.get_mut(&handle) {
                    state.h3.requests.remove(&id);
                }
            }
            Event::ConnectionLost { reason } => {
                debug!("Connection {handle:?} lost: {reason}");
                return true;
            }
            Event::HandshakeDataReady | Event::DatagramReceived | Event::DatagramsUnblocked => {}
        }
        false
    }

    fn read_stream(&mut self, handle: ConnectionHandle, id: StreamId) {
        let Some(state) = self.connections.get_mut(&handle) else {
            return;
        };

        let mut finished = false;
        {
            let mut recv = state.conn.recv_stream(id);
            let mut chunks = match recv.read(true) {
                Ok(chunks) => chunks,
                Err(e) => {
                    debug!("read stream {id} failed: {e}");
                    return;
                }
            };
            loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => {
                        if id.dir() == Dir::Bi {
                            state
                                .h3
                                .requests
                                .entry(id)
                                .or_default()
                                .recv
                                .extend_from_slice(&chunk.bytes);
                        }
                    }
                    Ok(None) => {
                        finished = true;
                        break;
                    }
                    Err(ReadError::Blocked) => break,
                    Err(e) => {
                        debug!("stream {id} read error: {e}");
                        return;
                    }
                }
            }
        }

        if id.dir() == Dir::Bi && finished {
            let response = {
                let Some(req_stream) = state.h3.requests.get(&id) else {
                    return;
                };
                build_response(&req_stream.recv, &self.archive)
            };
            if let Some(req_stream) = state.h3.requests.get_mut(&id) {
                req_stream.response = Some(PendingResponse {
                    bytes: response,
                    written: 0,
                    finished: false,
                });
            }
            self.flush_response(handle, id);
        }
    }

    fn flush_response(&mut self, handle: ConnectionHandle, id: StreamId) {
        let Some(state) = self.connections.get_mut(&handle) else {
            return;
        };
        let Some(req_stream) = state.h3.requests.get_mut(&id) else {
            return;
        };
        let Some(response) = &mut req_stream.response else {
            return;
        };

        while response.written < response.bytes.len() {
            let mut send = state.conn.send_stream(id);
            match send.write(&response.bytes[response.written..]) {
                Ok(0) | Err(WriteError::Blocked) => return,
                Ok(n) => response.written += n,
                Err(e) => {
                    debug!("write stream {id} failed: {e}");
                    return;
                }
            }
        }

        if !response.finished {
            let mut send = state.conn.send_stream(id);
            if let Err(e) = send.finish() {
                debug!("finish stream {id} failed: {e}");
            }
            response.finished = true;
        }
    }

    fn queue_transmit(
        &mut self,
        transmit: Transmit,
        packet: &[u8],
        ops: &mut Vec<io_uring::squeue::Entry>,
    ) {
        if packet.len() < transmit.size {
            warn!("dropping malformed transmit with missing packet bytes");
            return;
        }
        if transmit.segment_size.is_some() {
            warn!("dropping segmented transmit; GSO is not enabled in this binary");
            return;
        }
        let id = self.next_send_id;
        self.next_send_id += 1;
        let send = Box::new(SendOp::new(transmit.destination, &packet[..transmit.size]));
        let op = send.op(self.socket_fd, id);
        self.pending_sends.insert(id, send);
        ops.push(op);
    }

    fn send_completed(&mut self, id: u64, result: i32) {
        self.pending_sends.remove(&id);
        if result < 0 {
            warn!(
                "send failed: {}",
                io::Error::from_raw_os_error(result.abs())
            );
        }
    }
}

fn send_h3_control_stream(conn: &mut Connection, h3: &mut H3Connection) {
    if h3.sent_control {
        return;
    }
    let Some(id) = conn.streams().open(Dir::Uni) else {
        return;
    };
    let mut bytes = Vec::new();
    encode_varint(H3_STREAM_CONTROL, &mut bytes);
    encode_frame(H3_FRAME_SETTINGS, &[], &mut bytes);
    let mut stream = conn.send_stream(id);
    if let Err(e) = stream.write(&bytes) {
        debug!("failed writing HTTP/3 control stream: {e}");
        return;
    }
    h3.sent_control = true;
}

fn build_response(request_stream: &[u8], archive: &Archive) -> Vec<u8> {
    let request = qpack::parse_request(request_stream);
    let is_head = request.method.as_deref() == Some("HEAD");
    let path = request.path.as_deref().unwrap_or("/");

    let (status, body) = match archive.entry(path) {
        Some(entry) => {
            let range = entry.plain();
            (200, archive.get_slice(range.pos, range.len))
        }
        None => (404, b"Not found\n".as_slice()),
    };
    let content_length = body.len();
    let body = if is_head { &[][..] } else { body };

    let mut headers = Vec::new();
    qpack::encode_response_headers(status, content_length, &mut headers);

    let mut out = Vec::new();
    encode_frame(H3_FRAME_HEADERS, &headers, &mut out);
    if !body.is_empty() {
        encode_frame(H3_FRAME_DATA, body, &mut out);
    }
    out
}

fn encode_frame(frame_type: u64, payload: &[u8], out: &mut Vec<u8>) {
    encode_varint(frame_type, out);
    encode_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn encode_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.push(((value >> 8) as u8) | 0x40);
        out.push(value as u8);
    } else if value < 1_073_741_824 {
        out.push(((value >> 24) as u8) | 0x80);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(((value >> 56) as u8) | 0xc0);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}

fn make_server_config(opt: &Opt) -> Result<ServerConfig> {
    let certs = tarweb::load_certs(&opt.tls_cert)?;
    let key = tarweb::load_private_key(&opt.tls_key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let mut transport = TransportConfig::default();
    transport.max_concurrent_uni_streams(16_u8.into());
    transport.max_concurrent_bidi_streams(256_u16.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

fn make_timeout(ts: &io_uring::types::Timespec) -> io_uring::squeue::Entry {
    io_uring::opcode::Timeout::new(std::ptr::from_ref(ts))
        .build()
        .user_data(USER_DATA_TIMEOUT)
}

fn parse_duration(src: &str) -> std::result::Result<Duration, String> {
    if let Some(ms) = src.strip_suffix("ms") {
        return Ok(Duration::from_millis(
            ms.parse().map_err(|_| "Invalid milliseconds")?,
        ));
    }
    if let Some(secs) = src.strip_suffix('s') {
        let secs = secs.parse::<f64>().map_err(|_| "Invalid seconds")?;
        let secs_whole = secs.trunc() as u64;
        let nanos = (secs.fract() * 1_000_000_000.0) as u32;
        return Ok(Duration::new(secs_whole, nanos));
    }
    Err("Invalid format. Use 'Xs' or 'Yms' (e.g., '1.5s', '500ms')".to_string())
}

fn sockaddr_from_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(addr) => {
            let sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(
                    std::ptr::from_mut::<libc::sockaddr_storage>(&mut storage).cast(),
                    sockaddr,
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            let sockaddr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                std::ptr::write(
                    std::ptr::from_mut::<libc::sockaddr_storage>(&mut storage).cast(),
                    sockaddr,
                );
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn sockaddr_to_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Result<SocketAddr> {
    match i32::from(storage.ss_family) {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let sockaddr: libc::sockaddr_in = unsafe {
                std::ptr::read(std::ptr::from_ref::<libc::sockaddr_storage>(storage).cast())
            };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(sockaddr.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(sockaddr.sin_port),
            ))
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let sockaddr: libc::sockaddr_in6 = unsafe {
                std::ptr::read(std::ptr::from_ref::<libc::sockaddr_storage>(storage).cast())
            };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)),
                u16::from_be(sockaddr.sin6_port),
            ))
        }
        family => Err(anyhow!("unsupported socket address family {family}")),
    }
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    tracing_subscriber::fmt()
        .with_env_filter(format!("tarweb={}", opt.verbose))
        .with_writer(std::io::stderr)
        .init();

    let archive = Archive::builder()
        .etags(opt.etags)
        .hugepages(opt.hugepages)
        .build(&opt.tarfile, &opt.prefix)
        .with_context(|| format!("Memory mapping file {:?}.", opt.tarfile.display()))?;

    let socket = std::net::UdpSocket::bind(opt.listen)
        .with_context(|| format!("binding UDP {}", opt.listen))?;
    socket.set_nonblocking(true)?;
    let socket_fd = socket.as_raw_fd();
    let local_addr = socket.local_addr()?;
    info!("HTTP/3 listening on {local_addr}");

    let endpoint_config = Arc::new(EndpointConfig::default());
    let server_config = Arc::new(make_server_config(&opt)?);
    let endpoint = Endpoint::new(endpoint_config, Some(server_config), false, None);

    let mut ring = io_uring::IoUring::new(opt.ring_size)?;
    ring.submitter().register_files(&[socket_fd])?;
    drop(socket);
    let mut recv = RecvSlot::new();
    let timeout: io_uring::types::Timespec = opt.periodic_wakeup.into();
    let mut server = Server::new(endpoint, archive, SOCKET_FIXED_FILE);

    unsafe {
        ring.submission().push(&recv.op(SOCKET_FIXED_FILE)).unwrap();
        ring.submission().push(&make_timeout(&timeout)).unwrap();
    }
    ring.submit()?;

    tarweb::privs::drop_privs(true)?;

    let mut ops = Vec::new();
    loop {
        let mut cq = ring.completion();
        cq.sync();
        if cq.is_empty() {
            drop(cq);
            ring.submit_and_wait(1)?;
            continue;
        }

        for cqe in cq {
            let user_data = cqe.user_data();
            let result = cqe.result();
            match user_data {
                USER_DATA_RECV => {
                    if result >= 0 {
                        let len: usize = result.try_into().unwrap();
                        match recv.remote() {
                            Ok(remote) => {
                                let data = BytesMut::from(&recv.buf[..len]);
                                server.handle_datagram(Instant::now(), remote, data, &mut ops);
                            }
                            Err(e) => warn!("recvmsg address error: {e}"),
                        }
                    } else if result != -libc::EAGAIN {
                        warn!(
                            "recvmsg failed: {}",
                            io::Error::from_raw_os_error(result.abs())
                        );
                    }
                    ops.push(recv.op(SOCKET_FIXED_FILE));
                }
                USER_DATA_TIMEOUT => {
                    server.handle_timeouts(Instant::now(), &mut ops);
                    ops.push(make_timeout(&timeout));
                }
                id if id >= USER_DATA_SEND_BASE => {
                    server.send_completed(id, result);
                }
                _ => warn!("unknown completion user_data={user_data} result={result}"),
            }
        }

        let mut sq = ring.submission();
        let to_push = std::cmp::min(sq.capacity() - sq.len(), ops.len());
        if to_push > 0 {
            unsafe {
                sq.push_multiple(&ops[..to_push])
                    .expect("submission queue had checked capacity");
            }
            ops.drain(..to_push);
            drop(sq);
            ring.submit()?;
        }
    }
}
