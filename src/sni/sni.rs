//! TCP terminating server that snoops on TLS SNI, and then passes the FD on to
//! another server, like tarweb.
//!
//! The idea here is to actually make different routing decisions based on SNI,
//! and depending on the match, either pass the FD, or do TCP level proxying.
//!
//! ## Notable
//!
//! * Under extremely heavy fd passing, `net.unix.max_dgram_qlen` could possibly
//!   become a factor.
//!
//! ## TODO
//!
//! * Add max connection idle time.
//! * Think more about how to best degrade if `sendmsg()` passing the FD fails
//!   with `EMSGSIZE`. Queue? Drop?
//! * Maybe leave the unix socket connected, and only try to reconnect on error?
//! * Add a bunch of tests.
//! * Backup backends. E.g. if unix socket fails, maybe route to a "sorry
//!   server".
#![allow(clippy::similar_names)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::net::ToSocketAddrs;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
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

    /// Address to listen to.
    #[arg(long, short, default_value = "[::]:443")]
    listen: std::net::SocketAddr,

    #[arg(long)]
    cert_file: Option<std::path::PathBuf>,

    #[arg(long)]
    key_file: Option<std::path::PathBuf>,

    #[arg(long)]
    sock: std::path::PathBuf,
}

/// Read enough bytes from `stream` to cover the entire TLS `ClientHello` handshake
/// (which may span multiple records). Returns the handshake (type+len+body).
///
/// TLS record format:
///   - 5B header: `content_type(1)=22`, `legacy_version(2)`, length(2)
///   - payload: one or more handshake messages
///
/// Handshake header:
///   - `msg_type(1)=1(ClientHello)`
///   - length(3) = `body_len`
///
/// Return all bytes read, and clienthello bytes.
///
/// This function is mostly AI coded. Seems to work, and reviewing it it seems
/// safe.
async fn read_tls_clienthello(stream: &mut tokio::net::TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    const REC_HDR_LEN: usize = 5;
    let mut hello = Vec::with_capacity(BUF_CAPACITY);
    let mut bytes = Vec::with_capacity(BUF_CAPACITY);

    // We need at least first record to see handshake header (type + 3-byte len).
    // Loop records until we have full ClientHello bytes (4 + body_len).
    let mut needed: Option<usize> = None;

    while needed.is_none_or(|n| hello.len() < n) {
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
                "unexpected TLS content_type {content_type}, want 22 (handshake)"
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
                    "first handshake msg is type {msg_type}, expected 1 (ClientHello)"
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

/// Sends file descriptor and handshake data using `SCM_RIGHTS` on a Unix datagram.
async fn pass_fd_over_uds(
    stream: tokio::net::TcpStream,
    sock: UnixDatagram,
    bytes: Vec<u8>,
) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let fd = stream.as_raw_fd();
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

/// Extract SNI `host_name` from a TLS `ClientHello` (handshake header + body).
/// Returns Ok(Some(host)) if found, Ok(None) if no SNI extension exists.
///
/// This function is mostly jipptycoded. Seems to work, and reviewing it it seems
/// safe.
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
    let cmethod_len = body[i] as usize;
    i += 1;
    if body.len() < i + cmethod_len {
        bail!("invalid compression_methods vector");
    }
    i += cmethod_len;

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
struct TlsConfig {
    cert_file: std::path::PathBuf,
    key_file: std::path::PathBuf,
}

#[derive(Debug)]
enum Backend {
    // Just close the connection.
    Null,

    // Connect to a unix socket and pass in bytes read so far, and the file
    // descriptor to continue.
    Pass {
        path: std::path::PathBuf,
        tls: Option<TlsConfig>,
    },

    // Proxy string. DNS resolved on every new connection.
    //
    // If a TlsConfig is provided then the handshake and kTLS setup is done by
    // the SNI router.
    Proxy {
        addr: String,
        tls: Option<TlsConfig>,
    },
}

#[derive(Debug)]
struct Rule {
    re: regex::Regex,
    backend: Backend,
}

// TODO: this should probably become a protobuf.
#[derive(Debug)]
struct Config {
    rules: Vec<Rule>,
    default_backend: Backend,
}

/// Perform TLS handshake and setsockopt with kTLS.
///
/// Returns the new stream and the new initial bytes.
async fn tls_handshake(
    mut stream: tokio::net::TcpStream,
    mut bytes: Vec<u8>,
    config: &TlsConfig,
) -> Result<(tokio::net::TcpStream, Vec<u8>)> {
    use std::io::Read;
    use tokio::io::AsyncWriteExt;

    let certs = tarweb::load_certs(&config.cert_file)?;
    let key = tarweb::load_private_key(&config.key_file)?;

    debug!(
        "Handshaking with {:?}/{:?}",
        config.cert_file, config.key_file
    );
    let cfg = Arc::new({
        let mut cfg =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
        cfg.enable_secret_extraction = true;
        cfg
    });

    let mut tls = rustls::ServerConnection::new(cfg)?;
    loop {
        // Give bytes we have to rustls.
        {
            let mut cur = std::io::Cursor::new(&bytes);
            let n = tls.read_tls(&mut cur)?;
            bytes.drain(0..n);
        }
        let io = tls.process_new_packets()?;

        // Send rustls bytes to the peer.
        let bytes_to_write = io.tls_bytes_to_write();
        if bytes_to_write > 0 {
            let mut buf = vec![0u8; bytes_to_write];
            let mut cur = std::io::Cursor::new(&mut buf);
            let n = tls.write_tls(&mut cur)?;
            // TODO: can we assume remote side will not be overwhelmed?
            // If it is, and insists on writing, then we deadlock (time out).
            stream.write_all(&buf[..n]).await?;
        }
        let still_handshaking = tls.is_handshaking();
        if !still_handshaking {
            let plain_n = io.plaintext_bytes_to_read();
            let mut buf = vec![0u8; plain_n];
            let n = tls.reader().read(&mut buf[..plain_n])?;
            assert_eq!(plain_n, n);

            // Enable initial TLS option.
            let ulp_name = b"tls\0";
            let rc = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_TCP,
                    libc::TCP_ULP,
                    ulp_name.as_ptr().cast(),
                    ulp_name.len().try_into()?,
                )
            };
            if rc < 0 {
                return Err(anyhow!(
                    "setsockopt()=>{rc}: {}",
                    std::io::Error::from_raw_os_error(rc.abs())
                ));
            }

            // Hand over keys.
            let suite = tls.negotiated_cipher_suite().ok_or(anyhow!("bleh"))?;
            let keys = tls.dangerous_extract_secrets()?;
            let tls_rx = ktls::CryptoInfo::from_rustls(suite, keys.rx)?;
            let tls_tx = ktls::CryptoInfo::from_rustls(suite, keys.tx)?;
            for (name, s) in [(libc::TLS_RX, tls_rx), (libc::TLS_TX, tls_tx)] {
                let rc = unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_TLS,
                        name,
                        s.as_ptr(),
                        s.size().try_into()?,
                    )
                };
                if rc < 0 {
                    return Err(anyhow!(
                        "setsockopt()=>{rc}: {}",
                        std::io::Error::from_raw_os_error(rc.abs())
                    ));
                }
            }
            return Ok((stream, buf));
        }

        // Handshake still going.
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        bytes.extend(&buf[..n]);

        // TODO: what should this magic value be?
        if bytes.len() > 8192 {
            return Err(anyhow!("max TLS outstanding size exceeded"));
        }
    }
}

/// A backend has been selected. Deal with the stream and its backend as
/// appropriate.
async fn handle_conn_backend(
    id: usize,
    stream: tokio::net::TcpStream,
    bytes: Vec<u8>,
    backend: &Backend,
) -> Result<()> {
    match backend {
        Backend::Null => {
            trace!("id={id} Null backend. Closing");
            Ok(())
        }
        Backend::Pass { path, tls } => {
            // Connecting to a UnixDatagram should be cheap, and not at all be
            // visible to the backend. It's only when we SendMsg that it can
            // cause any load. So we first do this connect, so that we don't
            // needlessly do a handshake only to then never connect to anything.
            let sock = tokio::net::UnixDatagram::unbound().context("create UnixDatagram")?;
            sock.connect(path)
                .with_context(|| format!("connect to {:?}", path.display()))?;
            // This doesn't work, because we're using DGRAM. Maybe it works with
            // SEQPACKET?
            if false {
                let ucred = nix::sys::socket::getsockopt(
                    &sock,
                    nix::sys::socket::sockopt::PeerCredentials,
                )?;
                debug!(
                    "id={id} peer pid={} uid={} gid={}",
                    ucred.pid(),
                    ucred.uid(),
                    ucred.gid()
                );
            }
            let (stream, bytes) = if let Some(tls) = tls {
                tls_handshake(stream, bytes, tls).await?
            } else {
                (stream, bytes)
            };
            pass_fd_over_uds(stream, sock, bytes).await
        }
        Backend::Proxy { addr, tls } => {
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
            let (mut stream, bytes) = if let Some(tls) = tls {
                tls_handshake(stream, bytes, tls).await?
            } else {
                (stream, bytes)
            };
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

fn is_full_match(re: &regex::Regex, text: &str) -> bool {
    match re.find(text) {
        Some(m) => m.start() == 0 && m.end() == text.len(),
        None => false,
    }
}

async fn handle_conn(id: usize, mut stream: tokio::net::TcpStream, config: &Config) -> Result<()> {
    // Read and validate a full TLS ClientHello.
    let (bytes, clienthello) = read_tls_clienthello(&mut stream).await?;
    debug!("id={id} ClientHello len={} bytes", clienthello.len());
    let Some(sni) = extract_sni(&clienthello)? else {
        warn!("Failed to extract SNI");
        return Ok(());
    };
    debug!("id={id} SNI: {sni:?}");

    for rule in &config.rules {
        if is_full_match(&rule.re, &sni) {
            trace!("id={id} SNI {sni} matched rule {rule:?}");
            return handle_conn_backend(id, stream, bytes, &rule.backend).await;
        }
    }
    handle_conn_backend(id, stream, bytes, &config.default_backend).await
}

async fn mainloop(config: Arc<Config>, listener: tokio::net::TcpListener) -> Result<()> {
    let mut id = 0;
    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("id={id} fd={} Accepted {}", stream.as_raw_fd(), peer);

        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(id, stream, &config).await {
                warn!("id={id} Handling connection: {e:#}");
            }
            debug!("id={id} Done");
        });
        id += 1;
    }
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
    let listener = tokio::net::TcpListener::bind(&opt.listen)
        .await
        .context(format!("listening to {}", opt.listen))?;
    sock::set_nodelay(listener.as_raw_fd())?;
    // Config.
    let mut config = Config {
        rules: vec![
            Rule {
                re: regex::Regex::new("foo")?,
                backend: Backend::Null,
            },
            Rule {
                re: regex::Regex::new("bar")?,
                backend: Backend::Proxy {
                    addr: "localhost:8080".to_string(),
                    tls: None,
                },
            },
        ],
        default_backend: Backend::Pass {
            path: opt.sock.clone(),
            tls: None,
        },
    };
    if let (Some(cf), Some(kf)) = (opt.cert_file, opt.key_file) {
        config.rules.push(Rule {
            re: regex::Regex::new("baz")?,
            backend: Backend::Pass {
                path: opt.sock.clone(),
                tls: Some(TlsConfig {
                    cert_file: cf.clone(),
                    key_file: kf.clone(),
                }),
            },
        });
    }
    mainloop(Arc::new(config), listener).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn default_client() -> Result<()> {
        if false {
            tracing_subscriber::fmt()
                .with_env_filter("trace")
                .with_writer(std::io::stderr)
                .init();
        }
        for curl_opt in ["--tlsv1", "--tlsv1.1", "--tls1.2", "--tls1.3"] {
            for sni in ["foo", "bar", "bar2", "socket"] {
                info!("TESTING: sni={sni} opt={curl_opt}");

                let tmp_dir = tempfile::TempDir::new()?;
                let hit_something = std::sync::atomic::AtomicBool::new(false);
                let listener =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let listener_port = listener.local_addr()?.port();

                // Backends.
                let backend_bar =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let backend_bar_port = backend_bar.local_addr()?.port();
                let backend_baz =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let backend_baz_port = backend_baz.local_addr()?.port();

                let sockfile = tmp_dir.path().join("tarweb-testing.sock");
                let backend_sock = tokio::net::UnixDatagram::bind(&sockfile)?;

                // Test config.
                #[allow(clippy::regex_creation_in_loops)]
                let config = Config {
                    rules: vec![
                        Rule {
                            re: regex::Regex::new("foo")?,
                            backend: Backend::Null,
                        },
                        Rule {
                            re: regex::Regex::new("socket")?,
                            backend: Backend::Pass {
                                path: sockfile.clone(),
                                tls: None,
                            },
                        },
                        Rule {
                            re: regex::Regex::new("bar")?,
                            backend: Backend::Proxy {
                                addr: format!("[::1]:{backend_bar_port}"),
                                tls: None,
                            },
                        },
                    ],
                    default_backend: Backend::Proxy {
                        addr: format!("[::1]:{backend_baz_port}"),
                        tls: None,
                    },
                };
                let _main =
                    tokio::task::spawn(async move { mainloop(Arc::new(config), listener).await });

                let (done_tx1, mut done_rx_bar) = tokio::sync::mpsc::channel::<()>(1);
                let (done_tx2, mut done_rx_baz) = tokio::sync::mpsc::channel::<()>(1);
                let (done_tx3, mut done_rx_sock) = tokio::sync::mpsc::channel::<()>(1);
                let client = async {
                    // Expect failure because our backend immediately disconnects.
                    let _status = tokio::process::Command::new("curl")
                        .arg("-S")
                        .arg("--no-progress-meter")
                        .arg("--connect-to")
                        .arg(format!("foo:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("bar:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("socket:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("bar2:443:[::1]:{listener_port}"))
                        .arg(format!("https://{sni}/"))
                        .spawn()?
                        .wait()
                        .await?;
                    drop(done_tx1);
                    drop(done_tx2);
                    drop(done_tx3);
                    Ok::<(), anyhow::Error>(())
                };
                let backend_bar = async {
                    if sni == "bar" {
                        info!("COVERED: bar");
                        hit_something.store(true, Ordering::Relaxed);
                        tokio::select! {
                            _ = backend_bar.accept() => Ok(()),
                            _ = done_rx_bar.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                let backend_baz = async {
                    if sni == "bar2" {
                        info!("COVERED: default");
                        hit_something.store(true, Ordering::Relaxed);
                        tokio::select! {
                            _ = backend_baz.accept() => Ok(()),
                            _ = done_rx_baz.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                let backend_sock = async {
                    if sni == "socket" {
                        info!("COVERED: socket");
                        hit_something.store(true, Ordering::Relaxed);
                        let mut buf = [0u8; 2048];
                        tokio::select! {
                            _ = backend_sock.recv(&mut buf) => Ok(()),
                            _ = done_rx_sock.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                if sni == "foo" {
                    // Connected to nothing.
                    hit_something.store(true, Ordering::Relaxed);
                }
                tokio::time::timeout(tokio::time::Duration::from_secs(5), async {
                    tokio::try_join!(client, backend_bar, backend_baz, backend_sock,)
                })
                .await??;
                assert!(
                    hit_something.load(Ordering::Relaxed),
                    "SNI {sni:?} and opts {curl_opt:?} did not do anything"
                );
            }
        }
        Ok(())
    }
}
