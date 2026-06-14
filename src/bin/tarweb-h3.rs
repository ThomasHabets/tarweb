//! LLM-coded HTTP/3 version of tarweb.
//!
//! Things to sort out:
//! * Do we really need custom hpack/qpack code?
//! * Add the allocation tripwire.
//! * Preallocate all buffers.
//! * Allow creating a separate outgoing socket, in case it's on a different
//!   address. E.g. listen to lo, but allow going out to anywhere.
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

#[path = "tarweb_h3/qpack.rs"]
mod qpack;

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    mpsc::{self, Receiver, Sender, TryRecvError},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use clap::Parser;
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig,
    EndpointEvent, Event, ReadError, ServerConfig, StreamEvent, StreamId, Transmit,
    TransportConfig, WriteError,
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

// Size of a single recvmsg buffer. This can't be bigger than a UDP packet,
// meaning (on the Internet) 1500 bytes. Adding 100 bytes just in case.
const RECV_BUF_SIZE: usize = 1600;
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

    #[arg(long, short, default_value = "[::1]:443", help = "UDP listen address.")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 1024, help = "io_uring ring size")]
    ring_size: u32,

    #[arg(long, default_value = "10ms", value_parser = parse_duration, help = "QUIC timer poll interval.")]
    periodic_wakeup: Duration,

    #[arg(
        long,
        help = "Number of connection worker threads. Defaults to available parallelism."
    )]
    threads: Option<usize>,

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

// The data storage for an outstanding recvmsg.
//
// TODO: should this not be pinned or something?
struct RecvSlot {
    storage: libc::sockaddr_storage,
    namelen: libc::socklen_t,
    iov: libc::iovec,
    hdr: libc::msghdr,
    buf: [u8; RECV_BUF_SIZE],
}

impl RecvSlot {
    // Allocate the reusable receive slot before the main loop starts.
    fn new() -> Box<Self> {
        // Some are dummy values we'll immediately overwrite in `refresh()`.
        let mut slot = Box::new(Self {
            storage: unsafe { std::mem::zeroed() },
            namelen: 0, // dummy
            iov: libc::iovec {
                iov_base: std::ptr::null_mut(), // dummy
                iov_len: 0,                     // dummy
            },
            hdr: unsafe { std::mem::zeroed() }, // dummy
            buf: [0; RECV_BUF_SIZE],
        });
        slot.refresh();
        slot
    }

    // Refresh the msghdr/iovec before each recvmsg submission.
    fn refresh(&mut self) {
        // TODO: should we zero out `storage`, to not reuse it between packets?
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

    // Build the io_uring recvmsg operation for the network thread.
    fn op(&mut self, fd: FixedFile) -> io_uring::squeue::Entry {
        self.refresh();
        io_uring::opcode::RecvMsg::new(fd, std::ptr::from_mut::<libc::msghdr>(&mut self.hdr))
            .build()
            .user_data(USER_DATA_RECV)
    }

    // Recover the sender address after recvmsg completes.
    fn remote(&self) -> Result<SocketAddr> {
        sockaddr_to_addr(&self.storage, self.hdr.msg_namelen)
    }
}

// A end operation send from the worker threads to the network thread owning the
// io_uring.
//
// TODO: should this be pinned?
//
// TODO: should we let each worker have its own socket for sending? This should
// speed things up by migrating both client-tarweb and tarweb-backend off of the
// network thread.
struct SendOp {
    data: Vec<u8>,
    storage: libc::sockaddr_storage,
    namelen: libc::socklen_t,
}

impl SendOp {
    // Snapshot a datagram and its destination so the network thread can send
    // it later from io_uring.
    fn new(destination: SocketAddr, data: impl Into<Vec<u8>>) -> Self {
        let (storage, namelen) = sockaddr_from_addr(destination);
        Self {
            data: data.into(),
            storage,
            namelen,
        }
    }

    // Build the io_uring send operation that will flush this datagram.
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

enum WorkerCommand {
    NewConnection {
        handle: ConnectionHandle,
        conn: Connection,
    },
    ConnectionEvent {
        handle: ConnectionHandle,
        event: ConnectionEvent,
    },
    Tick {
        now: Instant,
    },
}

enum NetworkCommand {
    Transmit {
        transmit: Transmit,
        packet: Vec<u8>,
    },
    EndpointEvent {
        handle: ConnectionHandle,
        event: EndpointEvent,
    },
    ConnectionClosed {
        handle: ConnectionHandle,
    },
}

struct NetworkServer {
    endpoint: Endpoint,
    socket_fd: FixedFile,
    pending_sends: HashMap<u64, Box<SendOp>>,
    next_send_id: u64,
    workers: Vec<Sender<WorkerCommand>>,
    worker_by_handle: HashMap<ConnectionHandle, usize>,
    network_rx: Receiver<NetworkCommand>,
    next_worker: usize,
}

impl NetworkServer {
    // Construct the network-side owner of the endpoint and UDP socket.
    fn new(
        endpoint: Endpoint,
        socket_fd: FixedFile,
        workers: Vec<Sender<WorkerCommand>>,
        network_rx: Receiver<NetworkCommand>,
    ) -> Self {
        Self {
            endpoint,
            socket_fd,
            pending_sends: HashMap::new(),
            next_send_id: USER_DATA_SEND_BASE,
            workers,
            worker_by_handle: HashMap::new(),
            network_rx,
            next_worker: 0,
        }
    }

    // Called from the network thread whenever a UDP datagram arrives.
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
                assert_eq!(
                    transmit.size,
                    scratch.len(),
                    "These should be equal. If not, truncate scratch?"
                );
                self.queue_transmit(transmit, &scratch, ops);
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                match self.endpoint.accept(incoming, now, &mut scratch, None) {
                    Ok((handle, conn)) => {
                        self.assign_connection(handle, conn);
                    }
                    Err(e) => {
                        warn!("QUIC accept failed: {}", e.cause);
                        if let Some(transmit) = e.response {
                            assert_eq!(
                                transmit.size,
                                scratch.len(),
                                "These should be equal. If not, truncate scratch?"
                            );
                            self.queue_transmit(transmit, &scratch, ops);
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                self.route_connection_event(handle, event);
            }
            None => {}
        }
    }

    // Assign a new QUIC connection to a worker thread.
    fn assign_connection(&mut self, handle: ConnectionHandle, conn: Connection) {
        let worker = self.next_worker % self.workers.len();
        self.next_worker = (self.next_worker + 1) % self.workers.len();
        debug!("Accepted HTTP/3 connection {handle:?} on worker {worker}");
        if let Err(e) = self.workers[worker].send(WorkerCommand::NewConnection { handle, conn }) {
            warn!("worker {worker} channel closed while accepting {handle:?}: {e}");
            self.endpoint.handle_event(handle, EndpointEvent::drained());
            return;
        }
        self.worker_by_handle.insert(handle, worker);
    }

    // Forward an endpoint event back to the worker that owns the connection.
    fn route_connection_event(&mut self, handle: ConnectionHandle, event: ConnectionEvent) {
        let Some(&worker) = self.worker_by_handle.get(&handle) else {
            warn!("dropping event for connection {handle:?} with no worker");
            return;
        };
        if let Err(e) = self.workers[worker].send(WorkerCommand::ConnectionEvent { handle, event })
        {
            warn!("worker {worker} channel closed for connection {handle:?}: {e}");
            self.worker_by_handle.remove(&handle);
            self.endpoint.handle_event(handle, EndpointEvent::drained());
        }
    }

    // Wake every worker so they can process QUIC timeouts.
    //
    // TODO: move this to another threads so that the network thread can sleep
    // more.
    fn handle_timeouts(&self, now: Instant) {
        for (worker, tx) in self.workers.iter().enumerate() {
            if let Err(e) = tx.send(WorkerCommand::Tick { now }) {
                warn!("worker {worker} channel closed during timeout tick: {e}");
            }
        }
    }

    // Drain commands emitted by workers and turn them into network-side work.
    fn handle_network_commands(&mut self, ops: &mut Vec<io_uring::squeue::Entry>) {
        loop {
            match self.network_rx.try_recv() {
                Ok(command) => self.handle_network_command(command, ops),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    // Apply one worker-to-network command.
    fn handle_network_command(
        &mut self,
        command: NetworkCommand,
        ops: &mut Vec<io_uring::squeue::Entry>,
    ) {
        match command {
            NetworkCommand::Transmit { transmit, packet } => {
                self.queue_transmit(transmit, &packet, ops);
            }
            NetworkCommand::EndpointEvent { handle, event } => {
                let drained = event.is_drained();
                if let Some(conn_event) = self.endpoint.handle_event(handle, event) {
                    self.route_connection_event(handle, conn_event);
                }
                if drained {
                    self.worker_by_handle.remove(&handle);
                }
            }
            NetworkCommand::ConnectionClosed { handle } => {
                self.worker_by_handle.remove(&handle);
                self.endpoint.handle_event(handle, EndpointEvent::drained());
            }
        }
    }

    // Queue an outbound UDP datagram on the fixed socket.
    //
    // TODO: instead of `packet` payload, take `impl Into<Vec<u8>>` to save a
    // copy?
    fn queue_transmit(
        &mut self,
        transmit: Transmit,
        packet: &[u8],
        ops: &mut Vec<io_uring::squeue::Entry>,
    ) {
        assert_eq!(
            transmit.size,
            packet.len(),
            "Temporary check to make sure they're always equal"
        );
        if packet.len() < transmit.size {
            warn!(
                "dropping malformed transmit with missing packet bytes. {} < {}",
                packet.len(),
                transmit.size
            );
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

    // Release the send completion bookkeeping once io_uring finishes.
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

struct WorkerState {
    id: usize,
    connections: HashMap<ConnectionHandle, ConnectionState>,
    archive: Arc<Archive>,
    network_tx: Sender<NetworkCommand>,
}

impl WorkerState {
    // Create a worker thread state with its own connection table.
    fn new(id: usize, archive: Arc<Archive>, network_tx: Sender<NetworkCommand>) -> Self {
        Self {
            id,
            connections: HashMap::new(),
            archive,
            network_tx,
        }
    }

    // Run the worker message loop until its command channel closes.
    fn run(mut self, rx: Receiver<WorkerCommand>) {
        while let Ok(command) = rx.recv() {
            self.handle_command(command);
        }
        debug!("HTTP/3 worker {} exiting", self.id);
    }

    // Handle a single command from the network thread.
    fn handle_command(&mut self, command: WorkerCommand) {
        match command {
            WorkerCommand::NewConnection { handle, conn } => {
                self.connections.insert(
                    handle,
                    ConnectionState {
                        conn,
                        h3: H3Connection::default(),
                    },
                );
                self.drive_connection(handle, Instant::now());
            }
            WorkerCommand::ConnectionEvent { handle, event } => {
                if let Some(state) = self.connections.get_mut(&handle) {
                    state.conn.handle_event(event);
                    self.drive_connection(handle, Instant::now());
                } else {
                    warn!(
                        "worker {} dropping event for unknown connection {handle:?}",
                        self.id
                    );
                }
            }
            WorkerCommand::Tick { now } => self.handle_timeouts(now),
        }
    }

    // Advance timeout-driven connection work on this worker.
    fn handle_timeouts(&mut self, now: Instant) {
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
                self.drive_connection(handle, now);
            }
        }
    }

    // Drain QUIC state for one connection and publish any resulting work.
    fn drive_connection(&mut self, handle: ConnectionHandle, now: Instant) {
        let mut remove = false;
        let mut sent_drained = false;
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

            for (transmit, packet) in transmits {
                self.send_network(NetworkCommand::Transmit { transmit, packet });
            }

            if endpoint_events.is_empty() && app_events.is_empty() {
                break;
            }

            for event in endpoint_events {
                sent_drained |= event.is_drained();
                remove |= event.is_drained();
                self.send_network(NetworkCommand::EndpointEvent { handle, event });
            }

            for event in app_events {
                if self.handle_app_event(handle, event) {
                    remove = true;
                }
            }
        }

        if remove {
            self.connections.remove(&handle);
            if !sent_drained {
                self.send_network(NetworkCommand::ConnectionClosed { handle });
            }
        }
    }

    // React to QUIC events that are not directly tied to a socket packet.
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
                debug!("worker {} connection {handle:?} lost: {reason}", self.id);
                return true;
            }
            Event::HandshakeDataReady | Event::DatagramReceived | Event::DatagramsUnblocked => {}
        }
        false
    }

    // Read request bytes from a bidirectional stream and build a response.
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
                build_response(&req_stream.recv, self.archive.as_ref())
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

    // Continue writing a queued HTTP response onto a QUIC stream.
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

    // Send a worker-produced command back to the network thread.
    fn send_network(&self, command: NetworkCommand) {
        if let Err(e) = self.network_tx.send(command) {
            warn!("network channel closed for worker {}: {e}", self.id);
        }
    }
}

// Open the HTTP/3 control stream and send SETTINGS once per connection.
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

// Turn a request body into a full HTTP/3 response frame sequence.
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

// Emit a length-prefixed HTTP/3 frame into the output buffer.
fn encode_frame(frame_type: u64, payload: &[u8], out: &mut Vec<u8>) {
    encode_varint(frame_type, out);
    encode_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

// Encode the QUIC-style variable-length integer used by HTTP/3 frames.
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

// Build the QUIC server configuration from the TLS key and certificate.
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

// Build the timeout SQE used to wake the main loop periodically.
fn make_timeout(ts: &io_uring::types::Timespec) -> io_uring::squeue::Entry {
    io_uring::opcode::Timeout::new(std::ptr::from_ref(ts))
        .build()
        .user_data(USER_DATA_TIMEOUT)
}

// Parse the human-friendly CLI duration syntax.
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

// Convert a SocketAddr into the sockaddr storage needed by io_uring.
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

// Convert the recorded sender sockaddr back into a Rust SocketAddr.
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

// Push as many queued SQEs as the ring can currently accept.
fn submit_ops(ring: &mut io_uring::IoUring, ops: &mut Vec<io_uring::squeue::Entry>) -> Result<()> {
    if ops.is_empty() {
        return Ok(());
    }
    let mut sq = ring.submission();
    let to_push = std::cmp::min(sq.capacity() - sq.len(), ops.len());
    if to_push == 0 {
        return Ok(());
    }
    unsafe {
        sq.push_multiple(&ops[..to_push])
            .expect("submission queue had checked capacity");
    }
    ops.drain(..to_push);
    drop(sq);
    ring.submit()?;
    Ok(())
}

// Wire up the archive, workers, endpoint, and io_uring loop.
fn main() -> Result<()> {
    println!(
        "tarweb-h3 {} ({}) built with {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("GIT_VERSION"),
        env!("RUSTC_VERSION"),
        env!("BUILD_PROFILE")
    );
    let opt = Opt::parse();
    tracing_subscriber::fmt()
        .with_env_filter(format!("tarweb={}", opt.verbose))
        .with_writer(std::io::stderr)
        .init();

    let archive = Arc::new(
        Archive::builder()
            .etags(opt.etags)
            .hugepages(opt.hugepages)
            .build(&opt.tarfile, &opt.prefix)
            .with_context(|| format!("Memory mapping file {:?}.", opt.tarfile.display()))?,
    );

    let worker_count = opt
        .threads
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .max(1);
    info!("Using {worker_count} HTTP/3 worker threads");

    // Spawn threads.
    let (network_tx, network_rx) = mpsc::channel();
    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut _worker_handles = Vec::with_capacity(worker_count);
    for id in 0..worker_count {
        let (worker_tx, worker_rx) = mpsc::channel();
        let worker = WorkerState::new(id, Arc::clone(&archive), network_tx.clone());
        let handle = std::thread::Builder::new()
            .name(format!("tarweb-h3-worker-{id}"))
            .spawn(move || worker.run(worker_rx))
            .with_context(|| format!("spawning HTTP/3 worker {id}"))?;
        worker_txs.push(worker_tx);
        _worker_handles.push(handle);
    }
    drop(network_tx);

    // Bind to listening socket.
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
    let mut server = NetworkServer::new(endpoint, SOCKET_FIXED_FILE, worker_txs, network_rx);

    unsafe {
        ring.submission().push(&recv.op(SOCKET_FIXED_FILE)).unwrap();
        ring.submission().push(&make_timeout(&timeout)).unwrap();
    }
    ring.submit()?;

    tarweb::privs::drop_privs(true)?;

    let mut ops = Vec::new();
    loop {
        server.handle_network_commands(&mut ops);
        submit_ops(&mut ring, &mut ops)?;

        let mut cq = ring.completion();
        cq.sync();
        if cq.is_empty() {
            drop(cq);
            if let Err(e) = ring.submit_and_wait(1) {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    debug!("Interrupted system call for submit_and_wait");
                } else {
                    warn!("io_uring submit_and_wait(): {e}");
                }
                continue;
            }
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
                    server.handle_timeouts(Instant::now());
                    ops.push(make_timeout(&timeout));
                }
                id if id >= USER_DATA_SEND_BASE => {
                    server.send_completed(id, result);
                }
                _ => warn!("unknown completion user_data={user_data} result={result}"),
            }
        }

        server.handle_network_commands(&mut ops);
        submit_ops(&mut ring, &mut ops)?;
    }
}
