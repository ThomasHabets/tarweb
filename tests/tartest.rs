// TODO test:
// * Through SNI router
// * With PROXY
// * Without proxy
// * Proxy pass
// * Inline proxying.
// * Print server error log if assert fails.
use std::io::{Read, Write};
use std::process::Command;

use anyhow::Result;

// const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
struct Child {
    process: Option<std::process::Child>,
    thread: Option<std::thread::JoinHandle<Result<Vec<u8>>>>,
}

impl Child {
    fn new(process: std::process::Child, thread: std::thread::JoinHandle<Result<Vec<u8>>>) -> Self {
        Self {
            process: Some(process),
            thread: Some(thread),
        }
    }
    fn is_done(&mut self) -> Result<bool> {
        Ok(self.process.as_mut().unwrap().try_wait()?.is_some())
    }
    fn into(mut self) -> Result<(std::process::Child, Result<Vec<u8>>)> {
        self.stop();
        let mut child = self.process.take().unwrap();
        let _ = child.wait();
        let stderr = self
            .thread
            .take()
            .unwrap()
            .join()
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok((child, stderr))
    }
    fn stop(&mut self) {
        if let Some(w) = &mut self.process {
            let _ = w.kill();
            let _ = w.wait();
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.stop();
    }
}

fn gzip(bs: &[u8]) -> Result<Vec<u8>> {
    let mut child = std::process::Command::new("gzip")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut out = Vec::new();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(bs)?;
        stdin.flush()?;
    }
    if !child.wait()?.success() {
        return Err(anyhow::anyhow!("failed to gzip"));
    }
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut out)?;
    }
    Ok(out)
}

fn gunzip(bs: &[u8]) -> Result<Vec<u8>> {
    let mut child = std::process::Command::new("gunzip")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut out = Vec::new();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(bs)?;
        stdin.flush()?;
    }
    if !child.wait()?.success() {
        return Err(anyhow::anyhow!("failed to gzip"));
    }
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut out)?;
    }
    Ok(out)
}

fn make_tarfile(dir: &std::path::Path) -> Result<()> {
    let file = std::fs::File::create(dir.join("site.tar"))?;
    let mut tar = tar::Builder::new(file);

    // Index file.
    {
        let data = b"hello world";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "index.html", &data[..])
            .expect("failed to add file");
    }

    // Some other.
    {
        let data = b"the big brown etcetera";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "something.txt", &data[..])
            .expect("failed to add file");
    }

    // Compressed, plain.
    {
        let data = b"what's updog?";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "compressed.txt", &data[..])
            .expect("failed to add file");
    }

    // Compressed, gzipped.
    {
        let data = gzip(b"what's updog?")?;
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "compressed.txt.gz", &data[..])
            .expect("failed to add file");
    }

    tar.finish().expect("failed to finalize");
    Ok(())
}

// Probe_tcp keeps trying to connect until it succeeds. If child process is
// exited, then that's an error.
fn probe_tcp(child: &mut Child, addr: std::net::SocketAddr) -> Result<()> {
    while std::net::TcpStream::connect(addr).is_err() {
        if child.is_done()? {
            return Err(anyhow::anyhow!("server has exited"));
        }
    }
    Ok(())
}

fn probe_pass(child: &mut Child, addr: &std::path::Path) -> Result<()> {
    loop {
        let sock = std::os::unix::net::UnixDatagram::unbound()?;
        if sock.connect(addr).is_ok() {
            break;
        }
        if child.is_done()? {
            return Err(anyhow::anyhow!("server has exited"));
        }
    }
    Ok(())
}

fn start_server_pass(dir: &std::path::Path, with_tls: bool) -> Result<(Child, std::path::PathBuf)> {
    make_tarfile(dir)?;
    let addr = dir.join("pass.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tarweb"));
    child.args(["-v", "trace", "--passfd", addr.to_str().unwrap()]);
    if with_tls {
        child.args([
            "--tls-cert",
            dir.join("cert.crt").to_str().unwrap(),
            "--tls-key",
            dir.join("key.pem").to_str().unwrap(),
        ]);
    }
    let mut child = child
        .args([dir.join("site.tar").to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        //.stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stdout.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });
    let mut ch = Child::new(child, thread);
    probe_pass(&mut ch, &addr)?;
    Ok((ch, addr))
}

fn start_server(dir: &std::path::Path, with_tls: bool) -> Result<(Child, std::net::SocketAddr)> {
    make_tarfile(dir)?;

    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    let addr = format!("[::1]:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tarweb"));
    child.args(["-v", "trace", "-l", &addr]);
    if with_tls {
        child.args([
            "--tls-cert",
            dir.join("cert.crt").to_str().unwrap(),
            "--tls-key",
            dir.join("key.pem").to_str().unwrap(),
        ]);
    }
    let mut child = child
        .args([dir.join("site.tar").to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        //.stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stdout.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });
    let mut ch = Child::new(child, thread);
    let addr = addr.parse()?;
    probe_tcp(&mut ch, addr)?;
    Ok((ch, addr))
}

fn start_router(config: &std::path::Path) -> Result<(Child, std::net::SocketAddr)> {
    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    // TODO: depends on this port being free. Find a free port instead.
    let addr = format!("[::1]:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sni_router"))
        .args(["-v", "trace", "-l", &addr, "-c", config.to_str().unwrap()])
        .stdout(std::process::Stdio::piped())
        //.stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stdout.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });
    let mut ch = Child::new(child, thread);
    let addr = addr.parse()?;
    if let Err(e) = probe_tcp(&mut ch, addr) {
        let ch = ch.into()?.0.wait_with_output()?;
        println!("out:\n{}", String::from_utf8_lossy(&ch.stdout));
        println!("err:\n{}", String::from_utf8_lossy(&ch.stderr));
        return Err(e);
    }
    Ok((ch, addr))
}

#[test]
fn curl_http() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(dir.path(), false)?;

    for compressed in [false, true] {
        for (path, content) in [
            ("non-existing", "Not found\n"),
            ("", "hello world"),
            ("index.html", "hello world"),
            ("something.txt", "the big brown etcetera"),
            ("compressed.txt", "what's updog?"),
        ] {
            let mut curl = Command::new("curl");
            curl.args(["-sS"]);
            if compressed {
                curl.args(["--compressed"]);
            }
            let curl = curl.args([&format!("http://{addr}/{path}")]).output()?;

            let stdout = String::from_utf8(curl.stdout)?;
            let stderr = String::from_utf8(curl.stderr)?;
            assert!(
                curl.status.success(),
                "curl failed. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
            );
            assert_eq!(stdout, content);
        }
    }
    let child = child_dropper.into()?.0.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}

#[test]
fn range_nocompress() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child, addr) = start_server(dir.path(), false)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // First byte only.
    for (start, end, want) in [
        // Good ranges at start.
        (0, 0, "h"),
        (0, 1, "he"),
        (0, 2, "hel"),
        (0, 9, "hello worl"),
        (0, 10, "hello world"),
        // Good ranges from mid.
        (1, 1, "e"),
        (2, 4, "llo"),
        (6, 6, "w"),
        (10, 10, "d"),
        (8, 9, "rl"),
        (8, 10, "rld"),
        // Bad ranges.
        (0, 11, "hello world"),  // One out of bounds.
        (0, 100, "hello world"), // Many out of bounds.
        (1, 0, "hello world"),   // Bad order.
        (8, 11, "hello world"),  // Out of range.
    ] {
        let resp = client
            .get(format!("http://{addr}/"))
            .header("range", &format!("bytes={start}-{end}"))
            .send()?;
        let hs = resp.headers();
        assert_eq!(
            hs.get("content-length").unwrap(),
            &want.len().to_string(),
            "Bad content length for {start},{end}"
        );
        if end > 10 || end < start {
            assert!(
                hs.get("content-range").is_none(),
                "Failed for {start},{end}"
            );
        } else {
            assert_eq!(
                hs.get("content-range").unwrap(),
                &format!("bytes {start}-{end}/11"),
                "Failed for {start},{end}"
            );
        }
        assert_eq!(resp.text()?, want, "Bad output for {start},{end}");
    }
    let (child, stderr) = child.into()?;
    let child = child.wait_with_output()?;
    println!(
        "tarweb out:\n{}\nerr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&stderr?)
    );
    Ok(())
}

#[test]
fn range_compress() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child, addr) = start_server(dir.path(), false)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_gzip()
        .build()?;
    let bytes_re = regex::Regex::new(r"(?i)^bytes (\d+)-(\d+)/(\d+)$").unwrap();

    let mut full = Vec::new();
    let total_len: usize;

    // First byte only.
    {
        let resp = client
            .get(format!("http://{addr}/compressed.txt"))
            .header("accept-encoding", "gzip")
            .header("range", "bytes=0-0")
            .send()?;
        let hs = resp.headers();
        assert_eq!(hs.get("content-length").unwrap(), "1");
        let m = bytes_re
            .captures(hs.get("content-range").unwrap().to_str()?)
            .unwrap();
        assert_eq!(&m[1], "0");
        assert_eq!(&m[2], "0");
        total_len = m[3].parse()?;
        full.extend(resp.bytes()?);
    }

    // Half of rest.
    {
        let resp = client
            .get(format!("http://{addr}/compressed.txt"))
            .header("accept-encoding", "gzip")
            .header("range", &format!("bytes=1-{}", total_len / 2))
            .send()?;
        let hs = resp.headers();
        assert_eq!(
            hs.get("content-length").unwrap(),
            &(total_len / 2).to_string()
        );
        let m = bytes_re
            .captures(hs.get("content-range").unwrap().to_str()?)
            .unwrap();
        assert_eq!(&m[1], "1");
        assert_eq!(&m[2], (total_len / 2).to_string());
        assert_eq!(&m[3], total_len.to_string());
        full.extend(resp.bytes()?);
    }

    // Second half.
    {
        let resp = client
            .get(format!("http://{addr}/compressed.txt"))
            .header("accept-encoding", "gzip")
            .header(
                "range",
                &format!("bytes={}-{}", total_len / 2 + 1, total_len - 1),
            )
            .send()?;
        let hs = resp.headers();
        assert_eq!(
            hs.get("content-length").unwrap(),
            &(total_len - total_len / 2 - 1).to_string()
        );
        let m = bytes_re
            .captures(hs.get("content-range").unwrap().to_str()?)
            .unwrap();
        assert_eq!(&m[1], (total_len / 2 + 1).to_string());
        assert_eq!(&m[2], (total_len - 1).to_string());
        assert_eq!(&m[3], total_len.to_string());
        full.extend(resp.bytes()?);
    }

    let plain = gunzip(&full)?;
    assert_eq!(
        String::from_utf8(plain)?,
        "what's updog?",
        "{} bytes compressed wrong",
        full.len()
    );

    let (child, stderr) = child.into()?;
    let child = child.wait_with_output()?;
    println!(
        "tarweb out:\n{}\nerr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&stderr?)
    );
    Ok(())
}

#[test]
fn some_requests() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(dir.path(), false)?;

    for compressed in [false, true] {
        for auto_decompress in [false, true] {
            for (path, code, content, has_compressed) in [
                ("non-existing", 404, "Not found\n", false),
                ("", 200, "hello world", false),
                ("index.html", 200, "hello world", false),
                ("something.txt", 200, "the big brown etcetera", false),
                ("compressed.txt", 200, "what's updog?", true),
            ] {
                eprintln!("-------- compressed={compressed}/{auto_decompress} {path:?} -----");
                let mut client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10));
                if !auto_decompress || !compressed {
                    // It seems reqwest will automatically request gzip if
                    // the feature is enabled? I thought it only would be if I
                    // add the header?
                    client = client.no_gzip();
                }
                let client = client.build()?;
                let mut req = client.get(format!("http://{addr}/{path}"));
                if compressed {
                    req = req.header("accept-encoding", "gzip");
                }
                let resp = req.send()?;

                // Check response.
                assert_eq!(resp.status(), code);
                eprintln!("{:?}", resp.headers());
                for (k, v) in [
                    ("server", "tarweb/0.1.0"),
                    ("cache-control", "public, max-age=300"),
                    ("connection", "keep-alive"),
                    ("vary", "accept-encoding"),
                    ("content-length", &content.len().to_string()),
                ] {
                    if k == "content-length" && has_compressed && compressed {
                        if auto_decompress {
                            // Auto decompress does not provide a content-length.
                            continue;
                        }
                        // Else the header just has to exist, because we don't
                        // keep track of how long the payload is.
                        //
                        // Pedantic clippy is being idiotic here.
                        #[allow(clippy::expect_fun_call)]
                        {
                            assert_ne!(
                                resp.headers().get(k).expect(&format!("no {k:?} header")),
                                ""
                            );
                        }
                        continue;
                    }

                    #[allow(clippy::expect_fun_call)]
                    {
                        assert_eq!(resp.headers().get(k).expect(&format!("no {k:?} header")), v);
                    }
                }
                if compressed && !auto_decompress && has_compressed {
                    assert_eq!(
                        resp.headers()
                            .get(reqwest::header::CONTENT_ENCODING)
                            .unwrap(),
                        "gzip"
                    );
                }
                if !compressed || auto_decompress {
                    assert_eq!(resp.text()?, content);
                }
            }
        }
    }
    let (child, _stderr) = child_dropper.into()?;
    let child = child.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}

#[allow(clippy::too_many_lines)]
#[test]
fn e2e() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let dir = tempfile::TempDir::new()?;

    // create certs.
    {
        let subject_alt_names = vec!["foo".to_string(), "localhost".to_string()];
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_der = cert.pem();
        let key_der = signing_key.serialize_pem();
        let mut f = std::fs::File::create(dir.path().join("cert.crt"))?;
        f.write_all(cert_der.as_bytes())?;
        f.sync_all()?;
        let mut f = std::fs::File::create(dir.path().join("key.pem"))?;
        f.write_all(key_der.as_bytes())?;
        f.sync_all()?;
    }

    // Start tarweb.
    //let (plain_tarweb, plain_addr) = start_server(dir.path())?;
    let (_tls_tarweb, tls_addr) = start_server_pass(dir.path(), true)?;

    // Set up config.
    {
        println!("Writing {:?}", dir.path().join("config.cfg"));
        let mut f = std::fs::File::create(dir.path().join("config.cfg"))?;
        f.write_all(
            format!(
                r#"
rules: <
        regex: "foo"
        backend: <
                null: <>
        >
>
default_backend: <
        # For localhost SNI, let tarweb deal with the handshaking.
        pass: <
                path: "{}"
        >
>
max_lifetime_ms: 10000
"#,
                tls_addr.display()
            )
            .as_bytes(),
        )?;
        f.sync_all()?;
    }
    let (_router, router_addr) = start_router(&dir.path().join("config.cfg"))?;
    for (path, content) in [
        ("", "hello world"),
        ("index.html", "hello world"),
        ("something.txt", "the big brown etcetera"),
        ("compressed.txt", "what's updog?"),
    ] {
        eprintln!("-------- {path:?} -----");
        let mut curl = Command::new("curl");
        curl.args([
            "-sS",
            "--cacert",
            dir.path().join("cert.crt").to_str().unwrap(),
            "--connect-to",
            &format!("localhost:443:{router_addr}"),
        ]);
        let curl = curl.args([&format!("https://localhost/{path}")]).output()?;

        let stdout = String::from_utf8(curl.stdout)?;
        let stderr = String::from_utf8(curl.stderr)?;
        assert!(
            curl.status.success(),
            "curl failed. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
        );
        assert_eq!(stdout, content);
    }
    /*
    let (child, _stderr) = child_dropper.into()?;
    let child = child.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    */
    drop(dir);
    Ok(())
}
