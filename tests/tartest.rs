use std::io::{Read, Write};
use std::process::Command;

use anyhow::Result;

// const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
struct KillOnDrop(Option<std::process::Child>);

impl KillOnDrop {
    fn is_done(&mut self) -> Result<bool> {
        Ok(self.0.as_mut().unwrap().try_wait()?.is_some())
    }
    fn into(mut self) -> std::process::Child {
        self.stop();
        self.0.take().unwrap()
    }
    fn stop(&mut self) {
        if let Some(w) = &mut self.0 {
            let _ = w.kill();
            let _ = w.wait();
        }
    }
}

impl Drop for KillOnDrop {
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

fn probe_tcp(child: &mut KillOnDrop, addr: std::net::SocketAddr) -> Result<()> {
    while std::net::TcpStream::connect(addr).is_err() {
        if child.is_done()? {
            return Err(anyhow::anyhow!("server has exited"));
        }
    }
    Ok(())
}

fn start_server(dir: &std::path::Path) -> Result<(KillOnDrop, std::net::SocketAddr)> {
    make_tarfile(dir)?;

    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    // TODO: depends on this port being free. Find a free port instead.
    let addr = format!("[::1]:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_tarweb"))
        .args([
            "-v",
            "trace",
            "-l",
            &addr,
            dir.join("site.tar").to_str().unwrap(),
        ])
        //.stderr(std::process::Stdio::piped())
        //.stderr(std::process::Stdio::null())
        .spawn()?;
    let mut ch = KillOnDrop(Some(child));
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
    let child = child_dropper.into().wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}

#[test]
fn some_requests() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(dir.path())?;

    for compressed in [false, true] {
        for auto_decompress in [false, true] {
            for (path, code, content, has_compressed) in [
                /*
                ("non-existing", 404, "Not found\n", false),
                ("", 200, "hello world", false),
                ("index.html", 200, "hello world", false),
                ("something.txt", 200, "the big brown etcetera", false),
                */
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
    let child = child_dropper.into();
    let child = child.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}
