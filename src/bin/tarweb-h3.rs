//! LLM-coded HTTP/3 version of tarweb.
//!
//! Things to sort out:
//! * Do we really need all this hpack/qpack code?
//! * Add the allocation tripwire.
//! * Preallocate all buffers.
//! * Landlock.
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use clap::Parser;
use io_uring::types::Fd;
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

    fn op(&mut self, fd: i32) -> io_uring::squeue::Entry {
        self.refresh();
        io_uring::opcode::RecvMsg::new(Fd(fd), std::ptr::from_mut::<libc::msghdr>(&mut self.hdr))
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

    fn op(&self, fd: i32, user_data: u64) -> io_uring::squeue::Entry {
        io_uring::opcode::Send::new(
            Fd(fd),
            self.data.as_ptr(),
            self.data.len().try_into().unwrap(),
        )
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
    socket_fd: i32,
    pending_sends: HashMap<u64, Box<SendOp>>,
    next_send_id: u64,
}

impl Server {
    fn new(endpoint: Endpoint, archive: Archive, socket_fd: i32) -> Self {
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
    let request = parse_h3_request(request_stream);
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
    encode_response_headers(status, content_length, &mut headers);

    let mut out = Vec::new();
    encode_frame(H3_FRAME_HEADERS, &headers, &mut out);
    if !body.is_empty() {
        encode_frame(H3_FRAME_DATA, body, &mut out);
    }
    out
}

#[derive(Default)]
struct H3Request {
    method: Option<String>,
    path: Option<String>,
}

fn parse_h3_request(stream: &[u8]) -> H3Request {
    let mut pos = 0;
    while pos < stream.len() {
        let Some(frame_type) = decode_varint(stream, &mut pos) else {
            break;
        };
        let Some(len) = decode_varint(stream, &mut pos).and_then(|n| usize::try_from(n).ok())
        else {
            break;
        };
        let Some(end) = pos.checked_add(len).filter(|end| *end <= stream.len()) else {
            break;
        };
        if frame_type == H3_FRAME_HEADERS {
            return decode_qpack_headers(&stream[pos..end]);
        }
        pos = end;
    }
    H3Request {
        method: None,
        path: Some("/".to_string()),
    }
}

fn decode_qpack_headers(mut payload: &[u8]) -> H3Request {
    let mut request = H3Request::default();
    let mut pos = 0;
    let _ = decode_varint(payload, &mut pos);
    let _ = decode_varint(payload, &mut pos);
    payload = &payload[pos..];
    pos = 0;

    while pos < payload.len() {
        let first = payload[pos];
        pos += 1;
        if first & 0x80 != 0 {
            let is_static = first & 0x40 != 0;
            let Some(index) = decode_prefixed_int(first & 0x3f, 6, payload, &mut pos) else {
                break;
            };
            if is_static && let Some((name, value)) = qpack_static(index) {
                apply_header(&mut request, name, value);
            }
        } else if first & 0x40 != 0 {
            let is_static = first & 0x10 != 0;
            let Some(name_index) = decode_prefixed_int(first & 0x0f, 4, payload, &mut pos) else {
                break;
            };
            let Some(value) = decode_qpack_string(payload, &mut pos) else {
                continue;
            };
            if is_static && let Some((name, _)) = qpack_static(name_index) {
                apply_header(&mut request, name, &value);
            }
        } else if first & 0x20 != 0 {
            let Some(name_len) = decode_prefixed_int(first & 0x07, 3, payload, &mut pos) else {
                break;
            };
            let Some(name) = decode_raw_string(first & 0x08 != 0, name_len, payload, &mut pos)
            else {
                continue;
            };
            let Some(value) = decode_qpack_string(payload, &mut pos) else {
                continue;
            };
            apply_header(&mut request, &name, &value);
        } else {
            break;
        }
    }

    if request.path.is_none() {
        request.path = Some("/".to_string());
    }
    request
}

fn apply_header(request: &mut H3Request, name: &str, value: &str) {
    match name {
        ":method" => request.method = Some(value.to_string()),
        ":path" => request.path = Some(value.to_string()),
        _ => {}
    }
}

fn qpack_static(index: u64) -> Option<(&'static str, &'static str)> {
    Some(match index {
        0 => (":authority", ""),
        1 => (":path", "/"),
        4 => ("content-length", "0"),
        15 => (":method", "CONNECT"),
        16 => (":method", "DELETE"),
        17 => (":method", "GET"),
        18 => (":method", "HEAD"),
        19 => (":method", "OPTIONS"),
        20 => (":method", "POST"),
        21 => (":method", "PUT"),
        22 => (":scheme", "http"),
        23 => (":scheme", "https"),
        25 => (":status", "200"),
        27 => (":status", "404"),
        52 => ("content-type", "text/html; charset=utf-8"),
        53 => ("content-type", "text/plain"),
        _ => return None,
    })
}

fn encode_response_headers(status: u16, content_length: usize, out: &mut Vec<u8>) {
    encode_varint(0, out);
    encode_varint(0, out);
    let status_index = match status {
        200 => 25,
        404 => 27,
        _ => 25,
    };
    encode_qpack_static_indexed(status_index, out);
    encode_qpack_literal_static_name(4, &content_length.to_string(), out);
    encode_qpack_static_indexed(53, out);
}

fn encode_qpack_static_indexed(index: u8, out: &mut Vec<u8>) {
    debug_assert!(index < 64);
    out.push(0b1100_0000 | index);
}

fn encode_qpack_literal_static_name(name_index: u8, value: &str, out: &mut Vec<u8>) {
    debug_assert!(name_index < 16);
    out.push(0b0101_0000 | name_index);
    encode_qpack_string(value.as_bytes(), out);
}

fn encode_qpack_string(bytes: &[u8], out: &mut Vec<u8>) {
    encode_prefixed_int(bytes.len() as u64, 7, 0, out);
    out.extend_from_slice(bytes);
}

fn decode_qpack_string(data: &[u8], pos: &mut usize) -> Option<String> {
    let first = *data.get(*pos)?;
    *pos += 1;
    let huffman = first & 0x80 != 0;
    let len = decode_prefixed_int(first & 0x7f, 7, data, pos)?;
    decode_raw_string(huffman, len, data, pos)
}

fn decode_raw_string(huffman: bool, len: u64, data: &[u8], pos: &mut usize) -> Option<String> {
    let len = usize::try_from(len).ok()?;
    let end = pos.checked_add(len)?;
    let bytes = data.get(*pos..end)?;
    *pos = end;
    if huffman {
        return String::from_utf8(decode_hpack_huffman(bytes)?).ok();
    }
    std::str::from_utf8(bytes).ok().map(ToOwned::to_owned)
}

fn decode_hpack_huffman(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code = 0_u64;
    let mut code_len = 0_usize;

    for byte in data {
        for bit_index in (0..8).rev() {
            code = (code << 1) | u64::from((byte >> bit_index) & 1);
            code_len += 1;

            if let Some(symbol) = HPACK_HUFFMAN[..256]
                .iter()
                .position(|&(bits, candidate)| bits == code_len && candidate == code)
            {
                out.push(symbol.try_into().ok()?);
                code = 0;
                code_len = 0;
            } else if code_len > 30 {
                return None;
            }
        }
    }

    if code_len == 0 {
        return Some(out);
    }
    if code_len <= 7 && code == (1_u64 << code_len) - 1 {
        Some(out)
    } else {
        None
    }
}

// QPACK uses the HPACK static Huffman code.
const HPACK_HUFFMAN: [(usize, u64); 257] = [
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff),
];

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

fn decode_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *data.get(*pos)?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    *pos += 1;
    for _ in 1..len {
        value = (value << 8) | u64::from(*data.get(*pos)?);
        *pos += 1;
    }
    Some(value)
}

fn encode_prefixed_int(mut value: u64, prefix_bits: u8, high_bits: u8, out: &mut Vec<u8>) {
    let prefix_max = (1u64 << prefix_bits) - 1;
    if value < prefix_max {
        out.push(high_bits | value as u8);
        return;
    }
    out.push(high_bits | prefix_max as u8);
    value -= prefix_max;
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_prefixed_int(
    first_value: u8,
    prefix_bits: u8,
    data: &[u8],
    pos: &mut usize,
) -> Option<u64> {
    let prefix_max = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first_value);
    if value < prefix_max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        value = value.checked_add(u64::from(byte & 0x7f) << shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
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
    info!("HTTP/3 listening on {}", socket.local_addr()?);

    let endpoint_config = Arc::new(EndpointConfig::default());
    let server_config = Arc::new(make_server_config(&opt)?);
    let endpoint = Endpoint::new(endpoint_config, Some(server_config), false, None);

    let mut ring = io_uring::IoUring::new(opt.ring_size)?;
    let mut recv = RecvSlot::new();
    let timeout: io_uring::types::Timespec = opt.periodic_wakeup.into();
    let mut server = Server::new(endpoint, archive, socket_fd);

    unsafe {
        ring.submission().push(&recv.op(socket_fd)).unwrap();
        ring.submission().push(&make_timeout(&timeout)).unwrap();
    }
    ring.submit()?;

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
                    ops.push(recv.op(socket_fd));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_hpack_huffman(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut bits = 0_u64;
        let mut bits_left = 40_usize;

        for &byte in data {
            let (nbits, code) = HPACK_HUFFMAN[usize::from(byte)];
            bits |= code << (bits_left - nbits);
            bits_left -= nbits;

            while bits_left <= 32 {
                out.push((bits >> 32) as u8);
                bits <<= 8;
                bits_left += 8;
            }
        }

        if bits_left != 40 {
            bits |= (1 << bits_left) - 1;
            out.push((bits >> 32) as u8);
        }

        out
    }

    #[test]
    fn parses_static_get_root_headers() {
        let mut headers = vec![0, 0];
        encode_qpack_static_indexed(17, &mut headers);
        encode_qpack_static_indexed(1, &mut headers);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_h3_request(&stream);
        assert_eq!(request.method.as_deref(), Some("GET"));
        assert_eq!(request.path.as_deref(), Some("/"));
    }

    #[test]
    fn parses_literal_static_path_headers() {
        let mut headers = vec![0, 0];
        encode_qpack_static_indexed(18, &mut headers);
        encode_qpack_literal_static_name(1, "/assets/app.css", &mut headers);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_h3_request(&stream);
        assert_eq!(request.method.as_deref(), Some("HEAD"));
        assert_eq!(request.path.as_deref(), Some("/assets/app.css"));
    }

    #[test]
    fn decodes_hpack_huffman_strings() {
        assert_eq!(decode_hpack_huffman(&[0b0011_1111]).unwrap(), b"o");
        assert_eq!(decode_hpack_huffman(&[7]).unwrap(), b"0");
        assert_eq!(decode_hpack_huffman(&[(0x21 << 2) + 3]).unwrap(), b"A");
        assert_eq!(
            decode_hpack_huffman(&encode_hpack_huffman(b"/README.md")).unwrap(),
            b"/README.md"
        );
    }

    #[test]
    fn parses_huffman_literal_static_path_headers() {
        let mut headers = vec![0, 0];
        encode_qpack_static_indexed(17, &mut headers);
        headers.push(0b0101_0001);
        let encoded_path = encode_hpack_huffman(b"/README.md");
        encode_prefixed_int(encoded_path.len() as u64, 7, 0x80, &mut headers);
        headers.extend_from_slice(&encoded_path);

        let mut stream = Vec::new();
        encode_frame(H3_FRAME_HEADERS, &headers, &mut stream);

        let request = parse_h3_request(&stream);
        assert_eq!(request.method.as_deref(), Some("GET"));
        assert_eq!(request.path.as_deref(), Some("/README.md"));
    }
}
