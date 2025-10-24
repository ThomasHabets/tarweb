use std::os::unix::io::AsRawFd;

use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::net::UnixDatagram;

#[derive(clap::Parser)]
struct Opt {
    #[arg(long)]
    sock: std::path::PathBuf,
}

/// Reads enough bytes from `stream` to cover the entire TLS ClientHello handshake
/// (which may span multiple records). Returns the handshake (type+len+body).
///
/// TLS record format:
///   - 5B header: content_type(1)=22, legacy_version(2), length(2)
///   - payload: one or more handshake messages
///
/// Handshake header:
///   - msg_type(1)=1(ClientHello)
///   - length(3) = body_len
async fn read_tls_clienthello(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut hs = Vec::new();

    // We need at least first record to see handshake header (type + 3-byte len).
    // Loop records until we have full ClientHello bytes (4 + body_len).
    let mut needed: Option<usize> = None;

    while needed.map(|n| hs.len() >= n).unwrap_or(false) == false {
        let mut rec_hdr = [0u8; 5];
        stream
            .read_exact(&mut rec_hdr)
            .await
            .context("read TLS record header")?;

        let content_type = rec_hdr[0];
        let _legacy_ver = u16::from_be_bytes([rec_hdr[1], rec_hdr[2]]);
        let rec_len = u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]) as usize;

        if content_type != 22 {
            return Err(anyhow!(
                "unexpected TLS content_type {}, want 22 (handshake)",
                content_type
            ));
        }
        if rec_len == 0 {
            return Err(anyhow!("zero-length TLS record"));
        }

        let mut rec_payload = vec![0u8; rec_len];
        stream
            .read_exact(&mut rec_payload)
            .await
            .context("read TLS record payload")?;

        // Append to handshake buffer (could contain partial or full ClientHello).
        hs.extend(&rec_payload);

        // If we haven't established how many bytes we need, try now.
        if needed.is_none() {
            if hs.len() < 4 {
                // Not enough to read handshake header yet; continue.
                continue;
            }
            let msg_type = hs[0];
            if msg_type != 1 {
                return Err(anyhow!(
                    "first handshake msg is type {}, expected 1 (ClientHello)",
                    msg_type
                ));
            }
            let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
            needed = Some(4 + body_len);
        }
    }

    // Truncate to exactly the ClientHello (in case next record started).
    let n = needed.unwrap();
    if hs.len() > n {
        hs.truncate(n);
    }

    Ok(hs.to_vec())
}

/// Sends `fd` to a receiver bound at `uds_path` via SCM_RIGHTS on a Unix datagram.
///
/// Notes:
/// - The receiver gets a *new* fd number in its process.
/// - We send a 1-byte payload because some kernels reject empty datagrams with ancillary data.
fn pass_fd_over_uds(fd: std::os::unix::io::RawFd, sock: &UnixDatagram, hello: &[u8]) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let iov = [std::io::IoSlice::new(hello)]; // minimal payload
    let cmsg = [ControlMessage::ScmRights(&[fd])];

    // Safety: using raw fd for sendmsg via nix on our StdUnixDatagram.
    let raw = sock.as_raw_fd();
    let sent =
        sendmsg::<()>(raw, &iov, &cmsg, MsgFlags::empty(), None).context("sendmsg SCM_RIGHTS")?;
    if sent != 1 {
        return Err(anyhow!("sendmsg: expected to send 1 byte, sent {}", sent));
    }
    Ok(())
}

/// Extract SNI host_name from a TLS ClientHello (handshake header + body).
/// Returns Ok(Some(host)) if found, Ok(None) if no SNI extension exists.
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
    if body.len() < i + cs_len || cs_len % 2 != 0 {
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

async fn handle_conn(stream: &mut tokio::net::TcpStream, uds_path: &std::path::Path) -> Result<()> {
    // Read and validate a full TLS ClientHello.
    let clienthello = read_tls_clienthello(stream).await?;
    println!("ClientHello len={} bytes", clienthello.len());
    let Some(sni) = extract_sni(&clienthello)? else {
        println!("Failed to extract SNI");
        return Ok(());
    };
    println!("SNI: {sni:?}");

    let sock = tokio::net::UnixDatagram::unbound().context("create UnixDatagram")?;
    sock.connect(uds_path)
        .with_context(|| format!("connect to {}", uds_path.display()))?;
    pass_fd_over_uds(stream.as_raw_fd(), &sock, &clienthello)?;

    // Optionally, keep the TCP open for the receiver a short grace period
    // if needed; here we just drop immediately.
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("SNI");
    let opt = Opt::parse();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 4433)).await?;
    loop {
        let (mut stream, peer) = listener.accept().await?;
        println!("accepted {}", peer);

        let uds_path = opt.sock.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(&mut stream, &uds_path).await {
                eprintln!("{}: error: {:#}", peer, e);
            }
        });
    }
    Ok(())
}
