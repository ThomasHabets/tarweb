// TODO test:
// * Compressed range get.
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

fn probe_tcp(child: &mut Child, addr: std::net::SocketAddr) -> Result<()> {
    while std::net::TcpStream::connect(addr).is_err() {
        if child.is_done()? {
            return Err(anyhow::anyhow!("server has exited"));
        }
    }
    Ok(())
}

fn start_server(dir: &std::path::Path) -> Result<(Child, std::net::SocketAddr)> {
    make_tarfile(dir)?;

    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    // TODO: depends on this port being free. Find a free port instead.
    let addr = format!("[::1]:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tarweb"))
        .args([
            "-v",
            "trace",
            "-l",
            &addr,
            dir.join("site.tar").to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().unwrap();
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

#[test]
fn curl_http() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(dir.path())?;

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
    let (child, addr) = start_server(dir.path())?;
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
fn some_requests() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(dir.path())?;

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
