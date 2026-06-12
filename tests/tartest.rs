// ## TODO
// * Print server error log if assert fails.
use std::io::{Read, Write};
use std::process::Command;

use anyhow::{Context, Result};

// Dump stderr from all processes on Drop unless success is set.
struct LogDump {
    success: bool,
    processes: Vec<Child>,
}

impl LogDump {
    fn new() -> Self {
        Self {
            success: false,
            processes: Vec::new(),
        }
    }
    fn add(&mut self, child: Child) {
        self.processes.push(child);
    }
    fn set_success(&mut self) {
        self.success = true;
    }
}

impl Drop for LogDump {
    fn drop(&mut self) {
        if !self.success {
            eprintln!("============ Dropping child process data");
            let v = std::mem::take(&mut self.processes);
            for proc in v {
                eprintln!("============ Process: {}", proc.name);
                match proc.shutdown() {
                    Ok((ch, err)) => {
                        eprintln!("process ended with {:?}", ch.wait_with_output().unwrap());
                        eprintln!("{}", String::from_utf8_lossy(&err.unwrap()));
                    }
                    Err(e) => {
                        panic!("Failed to stop process: {e}");
                    }
                }
            }
        }
    }
}

// const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
struct Child {
    name: String,
    process: Option<std::process::Child>,
    thread: Option<std::thread::JoinHandle<Result<Vec<u8>>>>,
}

impl Child {
    fn new(
        name: String,
        process: std::process::Child,
        thread: std::thread::JoinHandle<Result<Vec<u8>>>,
    ) -> Self {
        Self {
            name,
            process: Some(process),
            thread: Some(thread),
        }
    }
    fn is_done(&mut self) -> Result<bool> {
        Ok(self.process.as_mut().unwrap().try_wait()?.is_some())
    }
    fn shutdown(mut self) -> Result<(std::process::Child, Result<Vec<u8>>)> {
        self.stop();
        let mut child = self.process.take().unwrap();
        let _ = child.wait();
        let stderr = self
            .thread
            .take()
            .unwrap()
            .join()
            .inspect(|s| {
                eprintln!(
                    "Child stderr got {} bytes",
                    s.as_ref().map(|s| s.len()).unwrap_or(1)
                );
            })
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

fn start_server_pass<S: Into<String>>(
    name: S,
    dir: &std::path::Path,
    with_tls: bool,
    with_proxyline: bool,
) -> Result<(Child, std::path::PathBuf)> {
    let name = name.into();
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
    if with_proxyline {
        child.args(["--proxy-protocol"]);
    }
    let mut child = child
        .args([dir.join("site.tar").to_str().unwrap()])
        //.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        eprintln!("Child captured {} bytes", v.len());
        Ok(v)
    });
    let mut ch = Child::new(name, child, thread);
    probe_pass(&mut ch, &addr)?;
    Ok((ch, addr))
}

fn start_server<S: Into<String>>(
    name: S,
    dir: &std::path::Path,
    with_tls: bool,
    with_proxyline: bool,
    extra_args: &[&str],
) -> Result<(Child, std::net::SocketAddr)> {
    let name = name.into();
    make_tarfile(dir)?;

    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    let addr = format!("[::1]:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tarweb"));
    child.args(["-v", "trace", "-l", &addr]);
    child.args(extra_args);
    if with_tls {
        child.args([
            "--tls-cert",
            dir.join("cert.crt").to_str().unwrap(),
            "--tls-key",
            dir.join("key.pem").to_str().unwrap(),
        ]);
    }
    if with_proxyline {
        child.args(["--proxy-protocol"]);
    }
    let mut child = child
        .args([dir.join("site.tar").to_str().unwrap()])
        //.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stderr = child.stderr.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });
    let mut ch = Child::new(name, child, thread);
    let addr = addr.parse()?;
    probe_tcp(&mut ch, addr)?;
    Ok((ch, addr))
}

fn start_router<S: Into<String>>(
    name: S,
    config: &std::path::Path,
) -> Result<(Child, std::net::SocketAddr)> {
    let name = name.into();
    // Bind to a port to pick a port number.
    let l = std::net::TcpListener::bind("[::]:0")?;
    let port = l.local_addr()?.port();
    drop(l);

    // TODO: depends on this port being free. Find a free port instead.
    let addr = format!("[::1]:{port}");
    let mut child = Command::new("sni-router")
        .args(["-v", "trace", "-l", &addr, "-c", config.to_str().unwrap()])
        //.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning sni-router")?;
    let mut stderr = child.stderr.take().unwrap();
    let thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        stderr.read_to_end(&mut v)?;
        Ok(v)
    });
    let mut ch = Child::new(name, child, thread);
    let addr = addr.parse()?;
    if let Err(e) = probe_tcp(&mut ch, addr) {
        let ch = ch.shutdown()?.0.wait_with_output()?;
        println!("out:\n{}", String::from_utf8_lossy(&ch.stdout));
        println!("err:\n{}", String::from_utf8_lossy(&ch.stderr));
        return Err(e);
    }
    Ok((ch, addr))
}

#[test]
fn curl_http() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server("tarweb", dir.path(), false, false, &[])?;

    run_test(child_dropper, || {
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
        Ok(())
    })
}

#[test]
fn request_headers_too_large_returns_431_and_closes() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server("tarweb", dir.path(), false, false, &[])?;

    run_test(child_dropper, || {
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        let cookie = "x".repeat(1200);
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\n\r\n"
        )?;
        stream.flush()?;

        let response = {
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            response
        };
        let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let headers = std::str::from_utf8(&response[..header_end])?;
        let body = std::str::from_utf8(&response[header_end..]).unwrap();

        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .ok_or_else(|| anyhow::anyhow!("missing content-length in {headers:?}"))?;

        assert!(
            headers.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
            "bad response: {response:?}"
        );
        assert!(
            headers.contains("\r\nConnection: close\r\n"),
            "missing close header: {response:?}"
        );
        assert_eq!(
            body, "Request Header Fields Too Large\n",
            "bad response body: {body:?}"
        );
        assert_eq!(body.len(), content_length);

        Ok(())
    })
}

#[test]
fn request_body_headers_close_after_response() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) =
        start_server("tarweb body header close", dir.path(), false, false, &[])?;
    run_test(child_dropper, || {
        for extra in [
            "Content-Length: 4\r\n\r\nbody",
            "Content-Length: nope\r\n\r\n",
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            let mut stream = std::net::TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            write!(stream, "GET / HTTP/1.1\r\nHost: {addr}\r\n{extra}")?;
            stream.flush()?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            let header_end = response
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| {
                    anyhow::anyhow!("missing response header terminator: {response:?}")
                })?
                + 4;
            let headers = std::str::from_utf8(&response[..header_end])?;
            let body = std::str::from_utf8(&response[header_end..])?;

            assert!(
                headers.starts_with("HTTP/1.1 200 OK\r\n"),
                "bad response for {extra:?}: {response:?}"
            );
            assert_response_header(headers, "Connection", "close");
            assert_eq!(body, "hello world");
        }

        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        write!(
            stream,
            "GET / HTTP/1.1\r\nHost: {addr}\r\nContent-Length:0\r\n\r\n"
        )?;
        stream.flush()?;
        let body = read_one_http_body(&mut stream)?;
        assert_eq!(body, "hello world");

        write!(
            stream,
            "GET /something.txt HTTP/1.1\r\nHost: {addr}\r\n\r\n"
        )?;
        stream.flush()?;
        let body = read_one_http_body(&mut stream)?;
        assert_eq!(body, "the big brown etcetera");

        Ok(())
    })
}

#[test]
fn accept_oneshot_stops_accepting_when_pool_is_exhausted() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(
        "tarweb accept multi exhausted",
        dir.as_ref(),
        false,
        false,
        &["--max-connections", "1"],
    )?;
    run_test(child_dropper, || {
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Server will be busy with this first request.
        let mut holder = std::net::TcpStream::connect(addr)?;
        holder.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        write!(
            holder,
            "GET / HTTP/1.1\r\nX-Test: 1\r\nHost: {addr}\r\n\r\n"
        )?;
        holder.flush()?;

        // This request is blocked by the first request.
        let mut queued = std::net::TcpStream::connect(addr)?;
        queued.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
        write!(
            queued,
            "GET / HTTP/1.1\r\nConnection: close\r\nX-Test: 2\r\nHost: {addr}\r\n\r\n"
        )?;
        queued.flush()?;

        // Await a reply on the second request.
        let mut probe = [0u8; 1];
        match queued.peek(&mut probe) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Ok(0) => {
                return Err(anyhow::anyhow!(
                    "queued connection closed before pool freed"
                ));
            }
            Ok(n) => {
                return Err(anyhow::anyhow!(
                    "queued connection received {n} bytes while pool was exhausted"
                ));
            }
            Err(e) => return Err(e.into()),
        }

        // Finish the first request. We need to drop the holder because by default
        // in HTTP/1.1 we keep-alive.
        assert_eq!(read_one_http_body(&mut holder)?, "hello world");
        drop(holder);

        queued.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        assert_eq!(read_one_http_body(&mut queued)?, "hello world");
        // Not dropping queued because it uses `Connection: close`.

        // Do a third request to confirm `queued` closed.
        let mut third = std::net::TcpStream::connect(addr)?;
        third.set_read_timeout(Some(std::time::Duration::from_millis(500)))?;
        write!(third, "GET / HTTP/1.1\r\nX-Test: 3\r\nHost: {addr}\r\n\r\n")?;
        third.flush()?;
        assert_eq!(read_one_http_body(&mut third)?, "hello world");

        Ok(())
    })
}

fn run_test(
    child_dropper: Child,
    f: impl FnOnce() -> Result<()> + std::panic::UnwindSafe,
) -> Result<()> {
    let res = std::panic::catch_unwind(f);

    let (child, stderr) = child_dropper.shutdown()?;
    let child = child.wait_with_output()?;
    let stderr = stderr?;
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            eprintln!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
            eprintln!("tarweb err:\n{}", String::from_utf8_lossy(&stderr));
            Err(e)
        }
        Err(e) => {
            eprintln!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
            eprintln!("tarweb err:\n{}", String::from_utf8_lossy(&stderr));
            std::panic::resume_unwind(e);
        }
    }
}

#[test]
fn accept_oneshot_serves_multiple_connections() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server("tarweb accept multi", dir.path(), false, false, &[])?;
    run_test(child_dropper, || wrapped_a_few_simple_requests(&addr))
}

#[test]
fn accept_multi_serves_multiple_connections() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server(
        "tarweb accept multi",
        dir.path(),
        false,
        false,
        &["--accept-multi"],
    )?;
    run_test(child_dropper, || wrapped_a_few_simple_requests(&addr))
}

fn wrapped_a_few_simple_requests(addr: &std::net::SocketAddr) -> Result<()> {
    let mut streams = Vec::new();
    for _ in 0..8 {
        let stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        streams.push(stream);
    }

    for (n, stream) in streams.iter_mut().enumerate() {
        let path = if n % 2 == 0 { "/" } else { "/something.txt" };
        write!(stream, "GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
        stream.flush()?;
    }

    for (n, stream) in streams.iter_mut().enumerate() {
        let want = if n % 2 == 0 {
            "hello world"
        } else {
            "the big brown etcetera"
        };
        assert_eq!(read_one_http_body(stream)?, want);
    }

    Ok(())
}

#[test]
fn accept_encoding_q_zero_rejects_compressed_variant() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server("tarweb q zero", dir.path(), false, false, &[])?;
    run_test(child_dropper, || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .no_gzip()
            .build()?;

        for header in ["gzip;q=0", "gzip; q=0.000", "br;q=0, gzip;q=0"] {
            let resp = client
                .get(format!("http://{addr}/compressed.txt"))
                .header("accept-encoding", header)
                .send()?;
            assert_eq!(resp.status(), 200);
            assert!(
                resp.headers()
                    .get(reqwest::header::CONTENT_ENCODING)
                    .is_none(),
                "unexpected compressed response for {header:?}: {:?}",
                resp.headers()
            );
            assert_eq!(resp.text()?, "what's updog?");
        }

        let resp = client
            .get(format!("http://{addr}/compressed.txt"))
            .header("accept-encoding", "gzip;q=0.001")
            .send()?;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .unwrap(),
            "gzip"
        );
        Ok(())
    })
}

#[test]
fn head_requests_send_headers_without_body() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) = start_server("tarweb head", dir.path(), false, false, &[])?;

    run_test(child_dropper, || {
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut reader = BufferedHttpReader::default();

        write!(stream, "HEAD / HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, false)?;
        assert!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "bad HEAD response: {headers:?}"
        );
        assert_response_header(&headers, "Content-Length", "11");
        assert!(body.is_empty(), "HEAD response included a body: {body:?}");

        write!(
            stream,
            "GET /something.txt HTTP/1.1\r\nHost: {addr}\r\n\r\n"
        )?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, true)?;
        assert!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "bad response after HEAD: {headers:?}"
        );
        assert_eq!(std::str::from_utf8(&body)?, "the big brown etcetera");

        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut reader = BufferedHttpReader::default();
        write!(
            stream,
            "HEAD /does-not-exist HTTP/1.1\r\nHost: {addr}\r\n\r\n"
        )?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, false)?;
        assert!(
            headers.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "bad HEAD 404 response: {headers:?}"
        );
        assert_response_header(&headers, "Content-Length", "10");
        assert!(
            body.is_empty(),
            "HEAD 404 response included a body: {body:?}"
        );
        write!(stream, "GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, true)?;
        assert!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "bad response after HEAD 404: {headers:?}"
        );
        assert_eq!(std::str::from_utf8(&body)?, "hello world");

        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut reader = BufferedHttpReader::default();
        write!(
            stream,
            "HEAD / HTTP/1.1\r\nHost: {addr}\r\nRange: bytes=0-1\r\n\r\n"
        )?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, false)?;
        assert!(
            headers.starts_with("HTTP/1.1 206 Partial Content\r\n"),
            "bad HEAD range response: {headers:?}"
        );
        assert_response_header(&headers, "Content-Length", "2");
        assert_response_header(&headers, "Content-Range", "bytes 0-1/11");
        assert!(
            body.is_empty(),
            "HEAD range response included a body: {body:?}"
        );
        write!(stream, "GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
        stream.flush()?;
        let (headers, body) = reader.read_response(&mut stream, true)?;
        assert!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "bad response after HEAD range: {headers:?}"
        );
        assert_eq!(std::str::from_utf8(&body)?, "hello world");

        Ok(())
    })
}

fn read_one_http_body(stream: &mut std::net::TcpStream) -> Result<String> {
    let mut response = Vec::new();
    let header_end = loop {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).context("read_one_http_body() read")?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "connection closed before response headers: {response:?}"
            ));
        }
        response.extend_from_slice(&buf[..n]);
        if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&response[..header_end])?.to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length: ")
                .and_then(|v| v.parse::<usize>().ok())
        })
        .ok_or_else(|| anyhow::anyhow!("missing content-length in {headers:?}"))?;
    while response.len() - header_end < content_length {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "connection closed before response body: {response:?}"
            ));
        }
        response.extend_from_slice(&buf[..n]);
    }
    Ok(std::str::from_utf8(&response[header_end..header_end + content_length])?.to_string())
}

#[derive(Default)]
struct BufferedHttpReader {
    buf: Vec<u8>,
}

impl BufferedHttpReader {
    fn read_response(
        &mut self,
        stream: &mut std::net::TcpStream,
        read_body: bool,
    ) -> Result<(String, Vec<u8>)> {
        let header_end = loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            self.read_more(stream, "response headers")?;
        };
        let headers = std::str::from_utf8(&self.buf[..header_end])?.to_string();
        let content_length = response_header(&headers, "Content-Length")
            .and_then(|v| v.parse::<usize>().ok())
            .ok_or_else(|| anyhow::anyhow!("missing content-length in {headers:?}"))?;
        let body_len = if read_body { content_length } else { 0 };
        while self.buf.len() - header_end < body_len {
            self.read_more(stream, "response body")?;
        }
        let body = self.buf[header_end..header_end + body_len].to_vec();
        self.buf.drain(..header_end + body_len);
        Ok((headers, body))
    }

    fn read_more(&mut self, stream: &mut std::net::TcpStream, part: &str) -> Result<()> {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "connection closed before reading {part}: {:?}",
                self.buf
            ));
        }
        self.buf.extend_from_slice(&buf[..n]);
        Ok(())
    }
}

fn response_header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(": ")?;
        k.eq_ignore_ascii_case(name).then_some(v)
    })
}

fn assert_response_header(headers: &str, name: &str, want: &str) {
    assert_eq!(
        response_header(headers, name),
        Some(want),
        "bad {name} header in {headers:?}"
    );
}

#[test]
fn proxy_protocol_line_can_arrive_in_chunks() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child_dropper, addr) =
        start_server("tarweb proxy protocol", dir.path(), false, true, &[])?;

    run_test(child_dropper, || {
        let mut stream = std::net::TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        for chunk in ["PROXY TCP4 ", "192.0.2.10 198.51.100.20 ", "12345 80\r\n"] {
            stream.write_all(chunk.as_bytes())?;
            stream.flush()?;
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        write!(stream, "GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
        stream.flush()?;

        let mut response = Vec::new();
        let header_end = loop {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(anyhow::anyhow!(
                    "connection closed before response headers: {response:?}"
                ));
            }
            response.extend_from_slice(&buf[..n]);
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = std::str::from_utf8(&response[..header_end])?.to_string();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .ok_or_else(|| anyhow::anyhow!("missing content-length in {headers:?}"))?;
        while response.len() - header_end < content_length {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(anyhow::anyhow!(
                    "connection closed before response body: {response:?}"
                ));
            }
            response.extend_from_slice(&buf[..n]);
        }
        let body = std::str::from_utf8(&response[header_end..header_end + content_length])?;

        assert!(
            headers.starts_with("HTTP/1.1 200 OK\r\n"),
            "bad response: {response:?}"
        );
        assert_eq!(body, "hello world");

        Ok(())
    })
}

#[test]
fn range_nocompress() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let (child, addr) = start_server("tarweb", dir.path(), false, false, &[])?;
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
    let (child, stderr) = child.shutdown()?;
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
    let (child, addr) = start_server("tarweb", dir.path(), false, false, &[])?;
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

    let (child, stderr) = child.shutdown()?;
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
    let (child_dropper, addr) = start_server("tarweb", dir.path(), false, false, &[])?;

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
                    ("server", r"tarweb/\d+[.]\d+[.]\d+"),
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

                    let val_re = regex::Regex::new(&("^".to_owned() + v + "$"))?;
                    #[allow(clippy::expect_fun_call)]
                    {
                        assert!(
                            val_re.is_match(str::from_utf8(
                                resp.headers()
                                    .get(k)
                                    .expect(&format!("no {k:?} header"))
                                    .as_bytes()
                            )?)
                        );
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
    let (child, _stderr) = child_dropper.shutdown()?;
    let child = child.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}

#[test]
fn e2e_proxy() -> Result<()> {
    e2e("proxy")
}
#[test]
fn e2e_proxy_frontend_tls() -> Result<()> {
    e2e("proxy-frontend")
}
#[test]
fn e2e_proxy_proxyline() -> Result<()> {
    e2e("proxy-proxy")
}
#[test]
fn e2e_proxy_frontend_tls_proxyline() -> Result<()> {
    e2e("proxy-frontend-proxy")
}
#[test]
fn e2e_pass() -> Result<()> {
    e2e("localhost")
}

#[allow(clippy::too_many_lines)]
fn e2e(sni: &str) -> Result<()> {
    let mut logdump = LogDump::new();
    let dir = tempfile::TempDir::new()?;

    // create certs.
    {
        let subject_alt_names = vec![
            // Null.
            "foo".to_string(),
            // Pass FD.
            "localhost".to_string(),
            // Frontend TLS.
            "proxy-frontend".to_string(),
            // Frontend TLS and proxy protocol.
            "proxy-frontend-proxy".to_string(),
            // Proxy protocol.
            "proxy-proxy".to_string(),
            // Proxy.
            "proxy".to_string(),
        ];
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
    let (plain_tarweb, plain_addr) = start_server("tarweb plain", dir.path(), false, false, &[])?;
    logdump.add(plain_tarweb);
    let (plainline_tarweb, plainline_addr) =
        start_server("tarweb plain proxy line", dir.path(), false, true, &[])?;
    logdump.add(plainline_tarweb);
    let (tls_tarweb, tls_addr) = start_server_pass("tarweb TLS pass", dir.path(), true, false)?;
    logdump.add(tls_tarweb);
    let (tlsline_tarweb, tlsline_addr) =
        start_server("tarweb TLS proxy line", dir.path(), true, true, &[])?;
    logdump.add(tlsline_tarweb);

    // Set up config.
    {
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
rules: <
        regex: "proxy-frontend"
        backend: <
                proxy: <
                    addr: "{plain_addr}"
                >
                frontend_tls: <
                    cert_file: "{cert}"
                    key_file: "{key}"
                >
        >
>
rules: <
        regex: "proxy-frontend-proxy"
        backend: <
                proxy: <
                    addr: "{plainline_addr}"
                    proxy_header: true,
                >
                frontend_tls: <
                    cert_file: "{cert}"
                    key_file: "{key}"
                >
        >
>
rules: <
        regex: "proxy-proxy"
        backend: <
                proxy: <
                    addr: "{tlsline_addr}"
                    proxy_header: true,
                >
        >
>
default: <
        backend: <
                # For localhost SNI, let tarweb deal with the handshaking.
                pass: <
                        path: "{tls_addr}"
                >
        >
>
max_lifetime_ms: 10000
"#,
                cert = dir.path().join("cert.crt").display(),
                key = dir.path().join("key.pem").display(),
                tls_addr = tls_addr.display(),
            )
            .as_bytes(),
        )?;
        f.sync_all()?;
    }
    let (_router, router_addr) = start_router("sni", &dir.path().join("config.cfg"))?;

    // Ensure `foo` SNI fails.
    {
        let curl = Command::new("curl")
            .args([
                "-sS",
                "--cacert",
                dir.path().join("cert.crt").to_str().unwrap(),
                "--connect-to",
                &format!("foo:443:{router_addr}"),
                "https://foo/",
            ])
            .output()?;
        let stdout = String::from_utf8(curl.stdout)?;
        let stderr = String::from_utf8(curl.stderr)?;
        assert!(
            !curl.status.success(),
            "curl succeeded, shouldn't. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
        );
    }

    // Try a few URLs on what should work.
    for (path, content) in [
        ("", "hello world"),
        ("index.html", "hello world"),
        ("something.txt", "the big brown etcetera"),
        ("compressed.txt", "what's updog?"),
    ] {
        eprintln!("-------- Path with SNI {sni:?}: {path:?} -----");
        let mut curl = Command::new("curl");
        let curl = curl
            .args([
                "-sS",
                "--cacert",
                dir.path().join("cert.crt").to_str().unwrap(),
                "--connect-to",
                &format!("{sni}:443:{router_addr}"),
                &format!("https://{sni}/{path}"),
            ])
            .output()?;

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
    logdump.set_success();
    Ok(())
}

#[test]
fn oha_2s() -> Result<()> {
    oha(2)
}

#[test]
#[ignore = "too heavy to run on every commit"]
fn oha_10s() -> Result<()> {
    oha(10)
}

fn oha(secs: u32) -> Result<()> {
    let mut logdump = LogDump::new();
    let dir = tempfile::TempDir::new()?;

    // create certs.
    {
        let subject_alt_names = vec![
            // Pass FD.
            "localhost".to_string(),
            // Proxy.
            "proxy".to_string(),
        ];
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
    let (plain_tarweb, plain_addr) = start_server("tarweb plain", dir.path(), false, false, &[])?;
    logdump.add(plain_tarweb);
    let (tls_tarweb, tls_addr) = start_server_pass("tarweb TLS pass", dir.path(), true, false)?;
    logdump.add(tls_tarweb);

    // Set up config.
    {
        let mut f = std::fs::File::create(dir.path().join("config.cfg"))?;
        f.write_all(
            format!(
                r#"
rules: <
        regex: "proxy-proxy"
        backend: <
                proxy: <
                    addr: "{plain_addr}"
                >
                frontend_tls: <
                    cert_file: "{cert}"
                    key_file: "{key}"
                >
        >
>
default: <
        backend: <
                pass: <
                        path: "{tls_addr}"
                >
        >
>
max_lifetime_ms: 10000
"#,
                cert = dir.path().join("cert.crt").display(),
                key = dir.path().join("key.pem").display(),
                tls_addr = tls_addr.display(),
            )
            .as_bytes(),
        )?;
        f.sync_all()?;
    }
    let (router, router_addr) = start_router("sni", &dir.path().join("config.cfg"))?;
    logdump.add(router);

    let mut oha = Command::new("oha");
    let oha = oha
        .args([
            "--insecure",
            "--no-tui",
            "-z",
            &format!("{secs}s"),
            &format!("https://{router_addr}/"),
        ])
        .output()?;

    let stdout = String::from_utf8(oha.stdout)?;
    let stderr = String::from_utf8(oha.stderr)?;
    assert!(
        oha.status.success(),
        "curl failed. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
    );
    logdump.set_success();
    Ok(())
}

#[test]
fn e2e_no_clienthello_proxy() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let mut logdump = LogDump::new();
    let (proxy_tarweb, addr) = start_server("tarweb plain proxy", dir.path(), false, false, &[])?;
    logdump.add(proxy_tarweb);
    let config = format!(
        r#"
default: <
        backend: <
                proxy: <
                        addr: "{addr}"
                >
        >
>
max_lifetime_ms: 10000
"#
    );
    e2e_plain_no_clienthello(dir.path(), &mut logdump, &config)?;
    logdump.set_success();
    Ok(())
}

#[test]
fn e2e_no_clienthello_pass() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let mut logdump = LogDump::new();
    let (proxy_tarweb, path) = start_server_pass("tarweb plain proxy", dir.path(), false, false)?;
    logdump.add(proxy_tarweb);
    let config = format!(
        r#"
default: <
        backend: <
                pass: <
                        path: "{}"
                >
        >
>
max_lifetime_ms: 10000
"#,
        path.display()
    );
    e2e_plain_no_clienthello(dir.path(), &mut logdump, &config)?;
    logdump.set_success();
    Ok(())
}

#[test]
fn e2e_no_clienthello_proxy_line() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    let mut logdump = LogDump::new();
    let (proxy_tarweb, addr) = start_server("tarweb plain proxy", dir.path(), false, true, &[])?;
    logdump.add(proxy_tarweb);
    let config = format!(
        r#"
default: <
        backend: <
                proxy: <
                        addr: "{addr}"
                        proxy_header: true
                >
        >
>
max_lifetime_ms: 10000
"#
    );
    e2e_plain_no_clienthello(dir.path(), &mut logdump, &config)?;
    logdump.set_success();
    Ok(())
}

// If there's no ClientHello, then only default can be used.
fn e2e_plain_no_clienthello(
    dir: &std::path::Path,
    logdump: &mut LogDump,
    config: &str,
) -> Result<()> {
    // Set up config.
    {
        let mut f = std::fs::File::create(dir.join("config.cfg"))?;
        f.write_all(config.as_bytes())?;
        f.sync_all()?;
    }
    let (router, router_addr) = start_router("sni", &dir.join("config.cfg"))?;
    logdump.add(router);

    // Try a few URLs on what should work.
    for (path, content) in [
        ("", "hello world"),
        ("index.html", "hello world"),
        ("something.txt", "the big brown etcetera"),
        ("compressed.txt", "what's updog?"),
    ] {
        eprintln!("-------- Path {path:?} -----");
        let url = format!("http://{router_addr}/{path}");
        let mut curl = Command::new("curl");
        let curl = curl.args(["-sS", "-m5", &url]).output()?;

        let stdout = String::from_utf8(curl.stdout)?;
        let stderr = String::from_utf8(curl.stderr)?;
        assert!(
            curl.status.success(),
            "curl to {url:?} failed. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
        );
        assert_eq!(stdout, content);
    }
    Ok(())
}
