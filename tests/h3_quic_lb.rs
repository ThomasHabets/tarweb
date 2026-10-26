//! Cross-repository test. Run after building both binaries:
//! SNI_ROUTER_H3_BIN=../sni-router/target/debug/sni-router-h3 \
//!   cargo test --test h3_quic_lb -- --ignored --nocapture

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use bytes::BytesMut;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{ClientConfig, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ReadError};

struct Server {
    child: Child,
    log: tempfile::NamedTempFile,
}

impl Server {
    fn start(command: &mut Command) -> Result<Self> {
        let log = tempfile::NamedTempFile::new()?;
        let child = command
            .stdout(Stdio::from(log.as_file().try_clone()?))
            .stderr(Stdio::from(log.as_file().try_clone()?))
            .spawn()?;
        Ok(Self { child, log })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "{}",
                std::fs::read_to_string(self.log.path()).unwrap_or_default()
            );
        }
    }
}

struct Client {
    endpoint: Endpoint,
    conn: quinn_proto::Connection,
    handle: quinn_proto::ConnectionHandle,
    socket: UdpSocket,
    connected: usize,
    last_cid: Vec<u8>,
    cid_len: usize,
}

impl Client {
    fn new(
        remote: SocketAddr,
        cert: rustls::pki_types::CertificateDer<'static>,
        cid_len: usize,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);
        let (handle, conn) = endpoint.connect(Instant::now(), config, remote, "localhost")?;
        Ok(Self {
            endpoint,
            conn,
            handle,
            socket: Self::socket()?,
            connected: 0,
            last_cid: Vec::new(),
            cid_len,
        })
    }

    fn socket() -> Result<UdpSocket> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(5)))?;
        Ok(socket)
    }

    fn step(&mut self) -> Result<()> {
        let now = Instant::now();
        if self
            .conn
            .poll_timeout()
            .is_some_and(|deadline| now >= deadline)
        {
            self.conn.handle_timeout(now);
        }
        while let Some(event) = self.conn.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(self.handle, event) {
                self.conn.handle_event(event);
            }
        }
        while let Some(event) = self.conn.poll() {
            match event {
                Event::Connected => self.connected += 1,
                Event::ConnectionLost { reason } => bail!("QUIC connection lost: {reason}"),
                _ => {}
            }
        }
        let mut packet = Vec::new();
        while let Some(transmit) = self.conn.poll_transmit(now, 1, &mut packet) {
            if packet.first().is_some_and(|first| first & 0x80 == 0) {
                self.last_cid = packet[1..1 + self.cid_len].to_vec();
            }
            self.socket
                .send_to(&packet[..transmit.size], transmit.destination)?;
            packet.clear();
        }
        let mut buf = [0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                let mut response = Vec::new();
                match self.endpoint.handle(
                    Instant::now(),
                    peer,
                    None,
                    None,
                    BytesMut::from(&buf[..len]),
                    &mut response,
                ) {
                    Some(DatagramEvent::ConnectionEvent(handle, event)) => {
                        ensure!(handle == self.handle, "unexpected QUIC connection");
                        self.conn.handle_event(event);
                    }
                    Some(DatagramEvent::Response(transmit)) => {
                        self.socket
                            .send_to(&response[..transmit.size], transmit.destination)?;
                    }
                    _ => {}
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn until(&mut self, ready: impl Fn(&Self) -> bool) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready(self) {
            ensure!(
                Instant::now() < deadline,
                "QUIC test timed out: {:?}",
                self.conn.stats()
            );
            self.step()?;
        }
        Ok(())
    }

    fn fetch(&mut self, expected: &[u8]) -> Result<()> {
        let id = self
            .conn
            .streams()
            .open(Dir::Bi)
            .context("opening request stream")?;
        // HEADERS: zero dynamic table references, GET, https, path '/'.
        let request = [1, 5, 0, 0, 0xd1, 0xd7, 0xc1];
        ensure!(self.conn.send_stream(id).write(&request)? == request.len());
        self.conn.send_stream(id).finish()?;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            ensure!(Instant::now() < deadline, "HTTP/3 response timed out");
            self.step()?;
            let mut stream = self.conn.recv_stream(id);
            let mut chunks = stream.read(true)?;
            let finished = loop {
                match chunks.next(usize::MAX) {
                    Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                    Ok(None) => break true,
                    Err(ReadError::Blocked) => break false,
                    Err(e) => return Err(e.into()),
                }
            };
            let _ = chunks.finalize();
            if finished {
                break;
            }
        }
        ensure!(
            received
                .windows(expected.len())
                .any(|bytes| bytes == expected),
            "unexpected HTTP/3 response: {received:?}"
        );
        Ok(())
    }
}

fn free_addr() -> Result<SocketAddr> {
    Ok(UdpSocket::bind("127.0.0.1:0")?.local_addr()?)
}

fn run(router: &Path, quic_lb: bool) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.path().join("cert.pem");
    let tls_key = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&tls_key, cert.signing_key.serialize_pem())?;
    let lb_key = dir.path().join("lb.key");
    std::fs::write(&lb_key, "8f95f09245765f80256934e50c66207f\n")?;
    let archive_path = dir.path().join("site.tar");
    let content = b"QUIC-LB rotation and migration work\n";
    let mut archive = tar::Builder::new(std::fs::File::create(&archive_path)?);
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, "index.html", content.as_slice())?;
    archive.finish()?;
    let backend = free_addr()?;
    let frontend = free_addr()?;
    let mut backend_command = Command::new(env!("CARGO_BIN_EXE_tarweb-h3"));
    backend_command
        .args([
            "--listen",
            &backend.to_string(),
            "--threads",
            "2",
            "--verbose",
            "debug",
        ])
        .arg("--tls-cert")
        .arg(&cert_path)
        .arg("--tls-key")
        .arg(&tls_key)
        .arg(&archive_path);
    if quic_lb {
        backend_command
            .arg("--quic-lb-key-file")
            .arg(&lb_key)
            .args(["--quic-lb-server-id", "123"]);
    }
    let backend_server = Server::start(&mut backend_command)?;
    let config = dir.path().join("h3.conf");
    let lb_config = if quic_lb {
        format!(
            "quic_lb: < key_file: \"{}\" servers: < server_id: 123 addr: \"{backend}\" > >",
            lb_key.display()
        )
    } else {
        String::new()
    };
    std::fs::write(
        &config,
        format!(
            "{lb_config}\n\
         rules: < regex: \"localhost\" backend: < proxy: < addr: \"{backend}\" > > >\n\
         default: < backend: < null: <> > >\n"
        ),
    )?;
    let mut router_command = Command::new(router);
    router_command
        .args(["--listen", &frontend.to_string(), "--verbose", "debug"])
        .arg("--config")
        .arg(&config);
    let router_server = Server::start(&mut router_command)?;
    let result = (|| -> Result<()> {
        let cid_len = if quic_lb { 17 } else { 16 };
        let mut client = Client::new(frontend, cert.cert.der().clone(), cid_len)?;
        client.until(|c| c.connected == 1 && c.conn.stats().frame_rx.new_connection_id >= 2)?;
        let control = client
            .conn
            .streams()
            .open(Dir::Uni)
            .context("opening control stream")?;
        client.conn.send_stream(control).write(&[0, 4, 0])?;
        client.fetch(content)?;
        let original_cid = client.last_cid.clone();
        ensure!(original_cid.len() == cid_len);
        if !quic_lb {
            ensure!(original_cid[0] == 0xa7);
        }
        client.conn.local_address_changed();
        client.fetch(content)?;
        ensure!(client.last_cid != original_cid, "CID did not rotate");
        if !quic_lb {
            return Ok(());
        }
        let rotated_cid = client.last_cid.clone();
        let old_port = client.socket.local_addr()?;
        client.socket = Client::socket()?;
        ensure!(client.socket.local_addr()? != old_port);
        client.conn.local_address_changed();
        client.fetch(content)?;
        ensure!(
            client.last_cid != rotated_cid,
            "migration did not use a new CID"
        );
        client.until(|c| c.conn.stats().frame_rx.path_challenge > 0)?;
        client.until(|c| c.conn.stats().frame_tx.path_response > 0)?;
        client.fetch(content)?;
        ensure!(client.connected == 1, "migration opened another connection");
        Ok(())
    })();
    if result.is_err() {
        eprintln!(
            "tarweb-h3:\n{}",
            std::fs::read_to_string(backend_server.log.path())?
        );
        eprintln!(
            "sni-router-h3:\n{}",
            std::fs::read_to_string(router_server.log.path())?
        );
    }
    result
}

#[test]
#[ignore = "requires a built sni-router-h3; set SNI_ROUTER_H3_BIN"]
fn legacy_rotation_and_quic_lb_migration() -> Result<()> {
    let router = std::env::var_os("SNI_ROUTER_H3_BIN")
        .context("set SNI_ROUTER_H3_BIN to the built router binary")?;
    run(Path::new(&router), false)?;
    run(Path::new(&router), true)
}
