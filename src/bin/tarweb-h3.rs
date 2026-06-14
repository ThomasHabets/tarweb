//! HTTP/3 version of tarweb.
//!
//! This is mostly written by LLM, but with manual oversight and fixes. I've not
//! really checked the H3 code carefully, as I hope to replace it with a
//! library.
//!
//! Things to sort out:
//! * Do we really need custom hpack/qpack code?
//! * Add the allocation tripwire.
//! * Preallocate all buffers.
//! * Allow each worker to have its own address and/or port, to offload the
//!   network thread.
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
    mpsc::{self, Receiver},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use clap::Parser;
use quinn_proto::crypto::rustls::QuicServerConfig;
use quinn_proto::{
    ConnectionId, DatagramEvent, Dir, EndpointConfig, EndpointEvent, Event, InvalidCid, ReadError,
    ServerConfig, StreamEvent, StreamId, Transmit, TransportConfig, WriteError,
};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use tarweb::archive::Archive;
use tracing::{debug, info, trace, warn};

// Max two bytes worth of workers because we map worker ID into the connection
// ID.
const MAX_WORKERS: usize = u16::MAX as usize;

// Minimum time to spent in each processing iteration loop waiting only for
// non-timer events.
const MINIMUM_TICK: std::time::Duration = std::time::Duration::from_millis(10);

// Maximum time to wait. This should only happen when there are no connections
// and no pending sends.
const MAXIMUM_TICK: std::time::Duration = std::time::Duration::from_mins(1);

// io-uring user data for operations.
const USER_DATA_RECV: u64 = 1;
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

// Arbitrary byte so that we can quickly know that this is not a connection ID
// we generated.
//
// A mismatch means it's a new connection, or garbage. If it's garbage, the
// assigned worker will take care of that.
const WORKER_CID_MARKER: u8 = 0xa7;
const WORKER_CID_LEN: usize = 16;

// Where in the CID we place our worker ID.
const WORKER_CID_WORKER_OFFSET: usize = 1;

// The nonce needs to be fairly big, because within a worker it's the unique
// identifier for a connection.
const WORKER_CID_NONCE_OFFSET: usize = 3;
const WORKER_CID_NONCE_LEN: usize = 8;

// The signature can be relatively short, because it's just the quick way to
// drop invalid packets. (invalid packets include ones from a previous
// run of the server).
const WORKER_CID_SIGNATURE_OFFSET: usize = WORKER_CID_NONCE_OFFSET + WORKER_CID_NONCE_LEN;
const WORKER_CID_SIGNATURE_LEN: usize = WORKER_CID_LEN - WORKER_CID_SIGNATURE_OFFSET;
const _: () = assert!(WORKER_CID_SIGNATURE_LEN == 5);

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

// An outbound UDP send operation owned by a worker io_uring.
//
// TODO: should this be pinned?
struct SendOp {
    data: Vec<u8>,
    storage: libc::sockaddr_storage,
    namelen: libc::socklen_t,
}

impl SendOp {
    // Snapshot a datagram and its destination so a worker can send it later
    // from io_uring.
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

// We need to generate connection IDs that include the worker ID.
struct WorkerConnectionIdGenerator {
    worker_id: u16,
    key: [u8; 32],
    next: u64,
}

impl WorkerConnectionIdGenerator {
    // Construct a worker-scoped CID generator. Generated CIDs carry the worker
    // id in a fixed prefix so the network thread can route packets without
    // invoking QUIC packet processing.
    fn new(worker_id: u16, key: [u8; 32]) -> Self {
        Self {
            worker_id,
            key,
            next: 0,
        }
    }
}

impl quinn_proto::ConnectionIdGenerator for WorkerConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0; WORKER_CID_LEN];
        bytes[0] = WORKER_CID_MARKER;
        bytes[WORKER_CID_WORKER_OFFSET..WORKER_CID_NONCE_OFFSET]
            .copy_from_slice(&self.worker_id.to_be_bytes());

        let mut nonce_hash = Sha3_256::new();
        nonce_hash.update(self.key);
        nonce_hash.update(b"tarweb-h3 cid nonce");
        nonce_hash.update(self.worker_id.to_be_bytes());
        nonce_hash.update(self.next.to_be_bytes());
        self.next = self.next.wrapping_add(1);
        let nonce = nonce_hash.finalize();
        bytes[WORKER_CID_NONCE_OFFSET..WORKER_CID_SIGNATURE_OFFSET]
            .copy_from_slice(&nonce[..WORKER_CID_NONCE_LEN]);

        let signature = worker_cid_signature(&self.key, &bytes[..WORKER_CID_SIGNATURE_OFFSET]);
        bytes[WORKER_CID_SIGNATURE_OFFSET..].copy_from_slice(&signature);
        ConnectionId::new(&bytes)
    }

    fn validate(&self, cid: &ConnectionId) -> std::result::Result<(), InvalidCid> {
        let cid = cid.as_ref();
        if cid.len() != WORKER_CID_LEN || cid[0] != WORKER_CID_MARKER {
            return Err(InvalidCid);
        }
        if u16::from_be_bytes([
            cid[WORKER_CID_WORKER_OFFSET],
            cid[WORKER_CID_WORKER_OFFSET + 1],
        ]) != self.worker_id
        {
            return Err(InvalidCid);
        }
        let expected = worker_cid_signature(&self.key, &cid[..WORKER_CID_SIGNATURE_OFFSET]);
        if cid[WORKER_CID_SIGNATURE_OFFSET..] != expected {
            return Err(InvalidCid);
        }
        Ok(())
    }

    fn cid_len(&self) -> usize {
        WORKER_CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

// Sign the routable CID prefix. This preserves cheap worker lookup while
// letting Quinn reject spoofed CIDs before it emits stateless resets.
fn worker_cid_signature(key: &[u8; 32], prefix: &[u8]) -> [u8; WORKER_CID_SIGNATURE_LEN] {
    let mut hash = Sha3_256::new();
    hash.update(key);
    hash.update(b"tarweb-h3 cid signature");
    hash.update(prefix);
    let digest = hash.finalize();
    let mut out = [0; WORKER_CID_SIGNATURE_LEN];
    out.copy_from_slice(&digest[..WORKER_CID_SIGNATURE_LEN]);
    out
}

// Pick the worker that should perform all QUIC processing for this datagram.
// Server-generated CIDs carry an explicit worker id; client-generated Initial
// CIDs fall back to a keyed hash so retransmits land on the same worker
// without letting the peer steer traffic by choosing the DCID.
//
// Packet will be dropped if this returns None, since it doesn't even have a
// destination CID.
fn worker_for_datagram(data: &[u8], key: &[u8; 32], worker_count: usize) -> Option<usize> {
    let cid = packet_destination_cid(data)?;
    if let Some(worker) = worker_from_server_cid(cid, worker_count) {
        return Some(worker);
    }
    Some(hash_connection_id(key, cid, worker_count))
}

// Extract only the QUIC destination connection ID from the invariant header.
// The network thread deliberately stops here; parsing/decryption stays on the
// selected worker.
//
// Packet will be dropped if this returns None, since it doesn't even have a
// destination CID.
fn packet_destination_cid(data: &[u8]) -> Option<&[u8]> {
    let first = *data.first()?;
    if first & 0x80 != 0 {
        let cid_len = *data.get(5)? as usize;
        if data.len() < 6 + cid_len {
            return None;
        }
        Some(&data[6..6 + cid_len])
    } else {
        if data.len() < 1 + WORKER_CID_LEN {
            return None;
        }
        Some(&data[1..1 + WORKER_CID_LEN])
    }
}

// Decode the worker prefix from CIDs generated by `WorkerConnectionIdGenerator`.
fn worker_from_server_cid(cid: &[u8], worker_count: usize) -> Option<usize> {
    if cid.len() != WORKER_CID_LEN || cid[0] != WORKER_CID_MARKER {
        return None;
    }
    let worker = u16::from_be_bytes([
        cid[WORKER_CID_WORKER_OFFSET],
        cid[WORKER_CID_WORKER_OFFSET + 1],
    ]) as usize;
    (worker < worker_count).then_some(worker)
}

// Hash client-generated Initial CIDs with a secret. This is the only routing
// path before the server has issued a worker-prefixed CID.
//
// Since the initial CID is client-controlled, we need to mix in our secret key
// before choosing a worker. Otherwise an attacker can target a specific worker.
fn hash_connection_id(key: &[u8; 32], cid: &[u8], worker_count: usize) -> usize {
    let digest = keyed_connection_id_digest(key, cid);
    let mut bytes = [0u8; std::mem::size_of::<usize>()];
    let len = bytes.len();
    bytes.copy_from_slice(&digest[..len]);
    usize::from_be_bytes(bytes) % worker_count
}

fn keyed_connection_id_digest(key: &[u8; 32], cid: &[u8]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(key);
    hash.update(b"tarweb-h3 worker shard");
    hash.update(cid);
    let digest = hash.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
    conn: quinn_proto::Connection,
    h3: H3Connection,
}

enum WorkerCommand {
    Datagram {
        now: Instant,
        remote: SocketAddr,
        data: BytesMut,
    },
}

/// A worker runs in its own thread, with its own io_uring used only for
/// sending.
///
/// The receive path comes from the network thread, since that's currently the
/// only way to route to the correct worker.
struct Worker {
    id: usize,

    // Endpoint is the main quinn API surface.
    endpoint: quinn_proto::Endpoint,

    // Active connections. They expire after a while.
    connections: HashMap<quinn_proto::ConnectionHandle, ConnectionState>,

    // Website contents.
    archive: Arc<Archive>,

    ring: io_uring::IoUring,

    // A pending send is set up in memory for use by io-uring. When a SendOp is
    // in this map, it is either about to be in flight (see `send_ops`) or
    // actually in flight.
    pending_sends: HashMap<u64, Box<SendOp>>,
    next_send_id: u64,

    // Temporary buffer of send ops about to be sent. The event loop builds this
    // up, and then submits them all at once to io_uring.
    send_ops: Vec<io_uring::squeue::Entry>,
}

impl Worker {
    // Create a worker thread state with its own connection table and send ring.
    //
    // Worker never read from the socket directly, since they share the socket.
    fn new(
        id: usize,
        archive: Arc<Archive>,
        endpoint: quinn_proto::Endpoint,
        socket: std::net::UdpSocket,
        ring_size: u32,
    ) -> Result<Self> {
        let ring = io_uring::IoUring::new(ring_size)?;
        ring.submitter().register_files(&[socket.as_raw_fd()])?;
        drop(socket);
        Ok(Self {
            id,
            endpoint,
            connections: HashMap::new(),
            archive,
            ring,
            pending_sends: HashMap::new(),
            next_send_id: USER_DATA_SEND_BASE,
            send_ops: Vec::new(),
        })
    }

    // Run the worker message loop until its command channel closes.
    fn run(mut self, rx: Receiver<WorkerCommand>) {
        loop {
            let now = Instant::now();
            let wait = if self.pending_sends.is_empty() {
                self.connections
                    .values_mut()
                    .filter_map(|v| {
                        v.conn
                            .poll_timeout()
                            .map(|t| t.saturating_duration_since(now))
                    })
                    //.inspect(|v| trace!("Connection min: {v:?}"))
                    .min()
                    .unwrap_or(MAXIMUM_TICK)
                    .max(MINIMUM_TICK)
                    .min(MAXIMUM_TICK)
            } else {
                MINIMUM_TICK
            };
            trace!("Worker {} next timeout: {:?}", self.id, wait);
            let next_tick = now + wait;

            // Wait for next event.
            match rx.recv_timeout(wait) {
                Ok(WorkerCommand::Datagram { now, remote, data }) => {
                    self.handle_datagram(now, remote, data)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            // Run timers. May be nothing to run, and this is just an empty tick
            // (because received message, or just waiting for send completions),
            // but it's harmless.
            if Instant::now() >= next_tick {
                trace!("Worker {} running timers", self.id);
                self.handle_timeouts(now);
            }

            // Cleanup.
            self.reap_send_completions();

            // If anything above created more ops, give them to io_uring.
            if let Err(e) = submit_ops(&mut self.ring, &mut self.send_ops) {
                warn!("worker {} failed to submit send ops: {e}", self.id);
            }
        }
        debug!("HTTP/3 worker {} exiting", self.id);
    }

    // Run QUIC endpoint processing for a datagram already assigned to this
    // worker. This is where Initial handling, accept, and connection routing
    // happen, so the network thread never performs that work.
    fn handle_datagram(&mut self, now: Instant, remote: SocketAddr, data: BytesMut) {
        let mut scratch = Vec::new();
        match self.endpoint.handle(
            now,
            remote,
            /* local ip */ None,
            /* ECN */ None,
            data,
            &mut scratch,
        ) {
            Some(DatagramEvent::Response(transmit)) => {
                assert_eq!(
                    transmit.size,
                    scratch.len(),
                    "These should be equal. If not, truncate scratch?"
                );
                self.queue_transmit(transmit, scratch);
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                match self.endpoint.accept(incoming, now, &mut scratch, None) {
                    Ok((handle, conn)) => self.assign_connection(handle, conn, now),
                    Err(e) => {
                        warn!("worker {} QUIC accept failed: {}", self.id, e.cause);
                        if let Some(transmit) = e.response {
                            assert_eq!(
                                transmit.size,
                                scratch.len(),
                                "These should be equal. If not, truncate scratch?"
                            );
                            self.queue_transmit(transmit, scratch);
                        }
                    }
                }
            }
            Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                self.handle_connection_event(handle, event, now);
            }
            None => {}
        }
    }

    // Register a newly accepted QUIC connection on this worker and immediately
    // drain any handshake/application work it made available.
    fn assign_connection(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        conn: quinn_proto::Connection,
        now: Instant,
    ) {
        debug!(
            "Accepted HTTP/3 connection {handle:?} on worker {}",
            self.id
        );
        self.connections.insert(
            handle,
            ConnectionState {
                conn,
                h3: H3Connection::default(),
            },
        );
        self.drive_connection(handle, now);
    }

    // Deliver an endpoint-produced connection event to a local connection.
    fn handle_connection_event(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        event: quinn_proto::ConnectionEvent,
        now: Instant,
    ) {
        if let Some(state) = self.connections.get_mut(&handle) {
            state.conn.handle_event(event);
            self.drive_connection(handle, now);
        } else {
            warn!(
                "worker {} dropping event for unknown connection {handle:?}",
                self.id
            );
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
    fn drive_connection(&mut self, handle: quinn_proto::ConnectionHandle, now: Instant) {
        let mut remove = false;
        let mut sent_drained = false;
        let mut scratch = Vec::new();
        loop {
            let mut endpoint_events = Vec::new();
            let mut app_events = Vec::new();

            // Packets to transmit. TODO: This is ripe for a bump allocator.
            let mut transmits = Vec::new();

            // Collect what we need to do. We have to do it this way first
            // because the loop holds mutable borrow.
            {
                let Some(state) = self.connections.get_mut(&handle) else {
                    return;
                };

                // TODO: Get multiple segments and send them using `SendBundle`.
                while let Some(transmit) =
                    state
                        .conn
                        .poll_transmit(now, /* max segments */ 1, &mut scratch)
                {
                    let size = transmit.size;
                    // The copying and keeping in memory here is not too bad. We
                    // We need it copied into memory until the sendmsg op
                    // completes anyway.
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

            // Send packets.
            for (transmit, packet) in transmits {
                self.queue_transmit(transmit, packet);
            }

            if endpoint_events.is_empty() && app_events.is_empty() {
                break;
            }

            let mut returned_conn_events = Vec::new();
            for event in endpoint_events {
                sent_drained |= event.is_drained();
                remove |= event.is_drained();
                if let Some(conn_event) = self.endpoint.handle_event(handle, event) {
                    returned_conn_events.push(conn_event);
                }
            }

            // Handle endpoint events, and forward them to the endpoint.
            if let Some(state) = self.connections.get_mut(&handle) {
                for event in returned_conn_events {
                    state.conn.handle_event(event);
                }
            }

            // Handle app events like "connected" and "I have some data".
            for event in app_events {
                if self.handle_app_event(handle, event) {
                    remove = true;
                }
            }
        }

        if remove {
            self.connections.remove(&handle);
            if !sent_drained {
                self.endpoint.handle_event(handle, EndpointEvent::drained());
            }
        }
    }

    // React to QUIC events that are not directly tied to a socket packet.
    fn handle_app_event(&mut self, handle: quinn_proto::ConnectionHandle, event: Event) -> bool {
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
    fn read_stream(&mut self, handle: quinn_proto::ConnectionHandle, id: StreamId) {
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
    fn flush_response(&mut self, handle: quinn_proto::ConnectionHandle, id: StreamId) {
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

    // Queue an outbound UDP datagram on this worker's fixed socket.
    fn queue_transmit(&mut self, transmit: Transmit, packet: Vec<u8>) {
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
        if let Some(n) = transmit.segment_size {
            warn!(
                "dropping segmented ({n} of {}) transmit; GSO is not enabled in this binary",
                transmit.size
            );
            return;
        }
        let id = self.next_send_id;
        self.next_send_id += 1;
        let send = Box::new(SendOp::new(transmit.destination, packet));
        let op = send.op(SOCKET_FIXED_FILE, id);
        self.pending_sends.insert(id, send);
        self.send_ops.push(op);
    }

    // Release send buffers once this worker's ring completes sends.
    fn reap_send_completions(&mut self) {
        let mut cq = self.ring.completion();
        cq.sync();
        let completions: Vec<_> = cq.map(|cqe| (cqe.user_data(), cqe.result())).collect();
        for (id, result) in completions {
            if id < USER_DATA_SEND_BASE {
                warn!("worker {} unknown completion user_data={id}", self.id);
                continue;
            }
            self.pending_sends.remove(&id);
            if result < 0 {
                warn!(
                    "worker {} send failed: {}",
                    self.id,
                    io::Error::from_raw_os_error(result.abs())
                );
            }
        }
    }
}

// Open the HTTP/3 control stream and send SETTINGS once per connection.
fn send_h3_control_stream(conn: &mut quinn_proto::Connection, h3: &mut H3Connection) {
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
        .max(1)
        .min(MAX_WORKERS);
    info!("Using {worker_count} HTTP/3 worker threads");

    let server_config = Arc::new(make_server_config(&opt)?);

    // Bind to listening socket.
    let socket = std::net::UdpSocket::bind(opt.listen)
        .with_context(|| format!("binding UDP {}", opt.listen))?;
    socket.set_nonblocking(true)?;
    info!("HTTP/3 listening on {}", socket.local_addr()?);

    let mut cid_key = [0; 32];
    rand::rng().fill_bytes(&mut cid_key);

    // Start workers.
    let mut worker_txs = Vec::with_capacity(worker_count);
    let mut _worker_handles = Vec::with_capacity(worker_count);
    {
        let (worker_init_tx, worker_init_rx) = mpsc::channel();
        for id in 0..worker_count {
            let (worker_tx, worker_rx) = mpsc::channel();
            let worker_id = u16::try_from(id).expect("worker_count was checked above");
            let mut endpoint_config = EndpointConfig::default();
            endpoint_config.cid_generator(move || {
                Box::new(WorkerConnectionIdGenerator::new(worker_id, cid_key))
            });
            // TODO: set reset key.
            let endpoint = quinn_proto::Endpoint::new(
                Arc::new(endpoint_config),
                Some(Arc::clone(&server_config)),
                false,
                None,
            );
            let worker_socket = socket.try_clone()?;
            let worker_archive = Arc::clone(&archive);
            let init_tx = worker_init_tx.clone();
            let ring_size = opt.ring_size;
            let handle = std::thread::Builder::new()
                .name(format!("tarweb-h3-worker-{id}"))
                .spawn(move || {
                    match Worker::new(id, worker_archive, endpoint, worker_socket, ring_size) {
                        Ok(worker) => {
                            let _ = init_tx.send(Ok(id));
                            worker.run(worker_rx);
                        }
                        Err(e) => {
                            let _ =
                                init_tx.send(Err(format!("HTTP/3 worker {id} init failed: {e}")));
                        }
                    }
                })
                .with_context(|| format!("spawning HTTP/3 worker {id}"))?;
            worker_txs.push(worker_tx);
            _worker_handles.push(handle);
        }
        drop(worker_init_tx);
        for _ in 0..worker_count {
            match worker_init_rx
                .recv()
                .context("waiting for HTTP/3 worker init")?
            {
                Ok(id) => debug!("HTTP/3 worker {id} initialized"),
                Err(e) => return Err(anyhow!(e)),
            }
        }
    }

    let mut ring = io_uring::IoUring::new(opt.ring_size)?;
    ring.submitter().register_files(&[socket.as_raw_fd()])?;
    drop(socket);

    // This `recv` object MUST live longer than any outstanding
    // reception.
    let mut recv = RecvSlot::new();

    unsafe {
        ring.submission().push(&recv.op(SOCKET_FIXED_FILE)).unwrap();
    }
    ring.submit()?;

    tarweb::privs::drop_privs(true)?;

    let mut ops = Vec::new();
    loop {
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
                                let packet = &recv.buf[..len];
                                if let Some(worker) =
                                    worker_for_datagram(packet, &cid_key, worker_txs.len())
                                {
                                    let data = BytesMut::from(packet);
                                    if let Err(e) =
                                        worker_txs[worker].send(WorkerCommand::Datagram {
                                            now: Instant::now(),
                                            remote,
                                            data,
                                        })
                                    {
                                        warn!(
                                            "worker {worker} channel closed while forwarding datagram: {e}"
                                        );
                                    }
                                } else {
                                    trace!("dropping datagram without a routable QUIC CID");
                                }
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
                _ => warn!("unknown completion user_data={user_data} result={result}"),
            }
        }

        submit_ops(&mut ring, &mut ops)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::ConnectionIdGenerator;

    #[test]
    fn worker_cid_routes_to_issuing_worker() {
        let key = [0x5a; 32];
        let mut generator = WorkerConnectionIdGenerator::new(42, key);
        let cid = generator.generate_cid();

        assert_eq!(worker_from_server_cid(cid.as_ref(), 64), Some(42));
        assert!(generator.validate(&cid).is_ok());

        let mut short_packet = Vec::with_capacity(1 + WORKER_CID_LEN);
        short_packet.push(0x40);
        short_packet.extend_from_slice(cid.as_ref());
        assert_eq!(worker_for_datagram(&short_packet, &key, 64), Some(42));
    }

    #[test]
    fn tampered_worker_cid_fails_endpoint_validation() {
        let key = [0x5a; 32];
        let mut generator = WorkerConnectionIdGenerator::new(7, key);
        let mut cid = generator.generate_cid().as_ref().to_vec();
        cid[WORKER_CID_SIGNATURE_OFFSET] ^= 0x01;

        assert!(generator.validate(&ConnectionId::new(&cid)).is_err());
        assert_eq!(worker_from_server_cid(&cid, 16), Some(7));
    }

    #[test]
    fn client_initial_cid_hashes_consistently() {
        let key = [0x6b; 32];
        let mut long_packet = Vec::new();
        long_packet.push(0xc0);
        long_packet.extend_from_slice(&1u32.to_be_bytes());
        long_packet.push(4);
        long_packet.extend_from_slice(&[1, 2, 3, 4]);
        long_packet.push(0);

        let first = worker_for_datagram(&long_packet, &key, 8);
        let second = worker_for_datagram(&long_packet, &key, 8);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    #[test]
    fn client_initial_cid_digest_changes_with_key() {
        let mut long_packet = Vec::new();
        long_packet.push(0xc0);
        long_packet.extend_from_slice(&1u32.to_be_bytes());
        long_packet.push(4);
        long_packet.extend_from_slice(&[1, 2, 3, 4]);
        long_packet.push(0);

        let cid = packet_destination_cid(&long_packet).unwrap();
        let a = keyed_connection_id_digest(&[0x11; 32], cid);
        let b = keyed_connection_id_digest(&[0x22; 32], cid);
        assert_ne!(a, b);
    }
}
