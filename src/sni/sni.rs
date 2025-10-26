//! TCP terminating server that snoops on TLS SNI, and then passes the FD on to
//! another server, like tarweb.
//!
//! This file is like 75% AI coded, but seems to work despite that. Improving it
//! is on the backlog because it does seem to work.
//!
//! The idea here is to actually make different routing decisions based on SNI,
//! and depending on the match, either pass the FD, or do TCP level proxying.
//!
//! TODO:
//! * Add max connection idle time.
use std::os::unix::io::AsRawFd;

use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio::net::UnixDatagram;
use tracing::{debug, info, trace, warn};

use tarweb::sock;

// How much capacity to prepare for ClientHello and stuff.
const BUF_CAPACITY: usize = 2048;

#[derive(clap::Parser)]
struct Opt {
    #[arg(
        long,
        short,
        help = "Verbosity level. Can be error, warn info, debug, or trace.",
        default_value = "info"
    )]
    verbose: String,

    #[arg(long)]
    sock: std::path::PathBuf,
}

/// Read enough bytes from `stream` to cover the entire TLS ClientHello handshake
/// (which may span multiple records). Returns the handshake (type+len+body).
///
/// TLS record format:
///   - 5B header: content_type(1)=22, legacy_version(2), length(2)
///   - payload: one or more handshake messages
///
/// Handshake header:
///   - msg_type(1)=1(ClientHello)
///   - length(3) = body_len
///
/// Return all bytes read, and clienthello bytes.
async fn read_tls_clienthello(stream: &mut tokio::net::TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    const REC_HDR_LEN: usize = 5;
    let mut hello = Vec::with_capacity(BUF_CAPACITY);
    let mut bytes = Vec::with_capacity(BUF_CAPACITY);

    // We need at least first record to see handshake header (type + 3-byte len).
    // Loop records until we have full ClientHello bytes (4 + body_len).
    let mut needed: Option<usize> = None;

    while !needed.map(|n| hello.len() >= n).unwrap_or_default() {
        // Read record header.
        let mut rec_hdr = [0u8; REC_HDR_LEN];
        stream
            .read_exact(&mut rec_hdr)
            .await
            .context("read TLS record header")?;
        bytes.extend(rec_hdr);

        // Parse header.
        let content_type = rec_hdr[0];
        let _legacy_ver = u16::from_be_bytes([rec_hdr[1], rec_hdr[2]]);
        let rec_len = u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]) as usize;

        // Confirm it's Handshake.
        if content_type != 22 {
            return Err(anyhow!(
                "unexpected TLS content_type {}, want 22 (handshake)",
                content_type
            ));
        }
        if rec_len == 0 {
            return Err(anyhow!("zero-length TLS record"));
        }

        // Read whole record.
        let mut rec_payload = vec![0u8; rec_len];
        stream
            .read_exact(&mut rec_payload)
            .await
            .context("read TLS record payload")?;

        // Append to handshake buffer (could contain partial or full ClientHello).
        hello.extend(&rec_payload);
        bytes.extend(&rec_payload);

        // If we haven't established how many bytes we need, try now.
        if needed.is_none() {
            if hello.len() < 4 {
                // Not enough to read handshake header yet; continue.
                continue;
            }
            let msg_type = hello[0];
            if msg_type != 1 {
                return Err(anyhow!(
                    "first handshake msg is type {}, expected 1 (ClientHello)",
                    msg_type
                ));
            }
            let body_len =
                ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | (hello[3] as usize);
            needed = Some(4 + body_len);
        }
    }

    // Truncate to exactly the ClientHello (in case next record started).
    // TODO: that's impossible, right?
    let n = needed.unwrap();
    if hello.len() > n {
        hello.truncate(n);
    }
    Ok((bytes, hello))
}

/// Sends `fd` and handshake data using SCM_RIGHTS on a Unix datagram.
async fn pass_fd_over_uds(
    fd: std::os::unix::io::RawFd,
    sock: UnixDatagram,
    bytes: Vec<u8>,
) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let iov = [std::io::IoSlice::new(&bytes)];
    let cmsg = [ControlMessage::ScmRights(&[fd])];

    // Async wait until it *should* be fine to write.
    sock.writable().await?;

    // Send sync, but per above *should* be fine to write. Also with
    // `MSG_DONTWAIT` it shouldn't block.
    let sent = sendmsg::<()>(
        sock.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT,
        None,
    )
    .context("sendmsg SCM_RIGHTS")?;
    if sent != bytes.len() {
        return Err(anyhow!(
            "sendmsg: expected to send {} bytes, sent {sent}",
            bytes.len()
        ));
    }
    Ok(())
}

/// Extract SNI host_name from a TLS ClientHello (handshake header + body).
/// Returns Ok(Some(host)) if found, Ok(None) if no SNI extension exists.
///
/// Entirely jippitycoded.
fn extract_sni(clienthello: &[u8]) -> Result<Option<String>> {
    // Handshake header: type(1)=1, len(3)
    if clienthello.len() < 4 {
        bail!("ClientHello too short for handshake header");
    }
    if clienthello[0] != 1 {
        bail!("not a ClientHello (handshake type {})", clienthello[0]);
    }
    let body_len = ((clienthello[1] as usize) << 16)
        | ((clienthello[2] as usize) << 8)
        | (clienthello[3] as usize);
    if clienthello.len() < 4 + body_len {
        bail!("truncated ClientHello body");
    }
    let body = &clienthello[4..4 + body_len];

    let mut i = 0usize;
    // legacy_version(2) + random(32) + session_id_len(1)
    if body.len() < 35 {
        bail!("ClientHello body too short");
    }
    i += 2 + 32;
    let sid_len = body[i] as usize;
    i += 1;
    if body.len() < i + sid_len {
        bail!("truncated session_id");
    }
    i += sid_len;

    // cipher_suites: len(2) + entries (each 2 bytes)
    if body.len() < i + 2 {
        bail!("missing cipher_suites length");
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len || !cs_len.is_multiple_of(2) {
        bail!("invalid cipher_suites vector");
    }
    i += cs_len;

    // compression_methods: len(1) + values
    if body.len() < i + 1 {
        bail!("missing compression_methods length");
    }
    let cm_len = body[i] as usize;
    i += 1;
    if body.len() < i + cm_len {
        bail!("invalid compression_methods vector");
    }
    i += cm_len;

    // optional extensions: len(2) + vector
    if i == body.len() {
        return Ok(None); // no extensions -> no SNI
    }
    if body.len() < i + 2 {
        bail!("missing extensions length");
    }
    let ext_total = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_total {
        bail!("truncated extensions block");
    }

    let mut j = i;
    while j + 4 <= i + ext_total {
        let etype = u16::from_be_bytes([body[j], body[j + 1]]);
        let elen = u16::from_be_bytes([body[j + 2], body[j + 3]]) as usize;
        j += 4;
        if j + elen > i + ext_total {
            bail!("truncated extension body");
        }
        if etype == 0x0000 {
            // server_name ext
            let ext = &body[j..j + elen];
            if ext.len() < 2 {
                bail!("server_name: missing list length");
            }
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            if ext.len() < 2 + list_len {
                bail!("server_name: truncated list");
            }
            let mut k = 2usize;
            while k + 3 <= 2 + list_len {
                let name_type = ext[k];
                let host_len = u16::from_be_bytes([ext[k + 1], ext[k + 2]]) as usize;
                k += 3;
                if k + host_len > 2 + list_len {
                    bail!("server_name: truncated host entry");
                }
                if name_type == 0 {
                    let host_bytes = &ext[k..k + host_len];
                    // RFC 6066: ASCII, no trailing dot, no NULs. We’ll do a lossy UTF-8 just in case.
                    let host = String::from_utf8_lossy(host_bytes).to_string();
                    return Ok(Some(host));
                }
                k += host_len;
            }
            // SNI ext present but no host_name item
            return Ok(None);
        }
        j += elen;
    }

    Ok(None)
}

#[derive(Debug)]
enum Backend {
    Null,
    Pass(std::path::PathBuf),
    Proxy(String),
}

#[derive(Debug)]
struct Rule {
    re: regex::Regex,
    backend: Backend,
}

/// A backend has been selected. Deal with the stream and its backend as
/// appropriate.
async fn handle_conn_backend(
    id: usize,
    mut stream: tokio::net::TcpStream,
    bytes: Vec<u8>,
    backend: &Backend,
) -> Result<()> {
    match backend {
        Backend::Null => {
            trace!("id={id} Null backend. Closing");
            Ok(())
        }
        Backend::Pass(path) => {
            let sock = tokio::net::UnixDatagram::unbound().context("create UnixDatagram")?;
            sock.connect(path)
                .with_context(|| format!("connect to {:?}", path.display()))?;
            pass_fd_over_uds(stream.as_raw_fd(), sock, bytes).await
        }
        Backend::Proxy(addr) => {
            use std::net::ToSocketAddrs;
            use tokio::io::AsyncWriteExt;

            let addrs = addr.to_socket_addrs()?;
            let mut conn = None;
            for addr in addrs {
                match tokio::net::TcpStream::connect(addr).await {
                    Ok(ok) => {
                        trace!("id={id} Connected to backend {addr}");
                        conn = Some(ok);
                        break;
                    }
                    Err(e) => {
                        debug!("id={id} Failed to connect to backend {addr:?}: {e}");
                    }
                }
            }
            let Some(mut conn) = conn else {
                return Err(anyhow!("failed to connect to all backends"));
            };
            let (mut up_r, mut up_w) = conn.split();
            let (mut down_r, mut down_w) = stream.split();
            let upstream = async {
                up_w.write_all(&bytes).await?;
                tokio::io::copy(&mut down_r, &mut up_w).await?;
                up_w.shutdown().await?;
                trace!("id={id} Upstream write completed");
                Ok::<_, anyhow::Error>(())
            };
            let downstream = async {
                tokio::io::copy(&mut up_r, &mut down_w).await?;
                down_w.shutdown().await?;
                trace!("id={id} Downstream write completed");
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(upstream, downstream)?;
            Ok(())
        }
    }
}

async fn handle_conn(
    id: usize,
    mut stream: tokio::net::TcpStream,
    uds_path: &std::path::Path,
) -> Result<()> {
    // Config.
    let rules = [
        Rule {
            re: regex::Regex::new("foo")?,
            backend: Backend::Null,
        },
        Rule {
            re: regex::Regex::new("bar")?,
            backend: Backend::Proxy("localhost:8080".to_string()),
        },
    ];
    let default_backend = Backend::Pass(uds_path.to_path_buf());

    // Read and validate a full TLS ClientHello.
    let (bytes, clienthello) = read_tls_clienthello(&mut stream).await?;
    debug!("id={id} ClientHello len={} bytes", clienthello.len());
    let Some(sni) = extract_sni(&clienthello)? else {
        warn!("Failed to extract SNI");
        return Ok(());
    };
    debug!("id={id} SNI: {sni:?}");

    for rule in rules.iter() {
        if rule.re.is_match(&sni) {
            trace!("id={id} SNI {sni} matched rule {rule:?}");
            return handle_conn_backend(id, stream, bytes, &rule.backend).await;
        }
    }
    handle_conn_backend(id, stream, bytes, &default_backend).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    tracing_subscriber::fmt()
        //.with_env_filter(format!("sni_router={}", opt.verbose))
        .with_env_filter(opt.verbose)
        .with_writer(std::io::stderr)
        .init();
    info!("SNI Router");
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 4433)).await?;
    sock::set_nodelay(listener.as_raw_fd())?;
    let mut id = 0;
    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("id={id} fd={} Accepted {}", stream.as_raw_fd(), peer);

        let uds_path = opt.sock.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(id, stream, &uds_path).await {
                warn!("id={id} Handling connection: {e:#}");
            }
            debug!("id={id} Done");
        });
        id += 1;
    }
}
