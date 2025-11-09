use std::process::Command;

use anyhow::Result;

// const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
struct KillOnDrop<'a>(&'a mut std::process::Child);

impl KillOnDrop<'_> {
    fn is_done(&mut self) -> Result<bool> {
        Ok(self.0.try_wait()?.is_some())
    }
}

impl Drop for KillOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

#[test]
fn curl_http_404() -> Result<()> {
    let dir = tempfile::TempDir::new()?;
    make_tarfile(dir.path())?;

    // TODO: depends on this port being free. Find a free port instead.
    let port = 8080;
    let addr = format!("[::1]:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tarweb"))
        .args([
            "-v",
            "trace",
            "-l",
            &addr,
            dir.path().join("site.tar").to_str().unwrap(),
        ])
        .spawn()?;
    let mut child_dropper = KillOnDrop(&mut child);

    probe_tcp(&mut child_dropper, addr.parse()?)?;

    for (path, content) in [("non-existing", "Not found\n"), ("", "hello world")] {
        let curl = Command::new("curl")
            .args(["-sS", &format!("http://localhost:{port}/{path}")])
            .output()?;

        let stdout = String::from_utf8(curl.stdout)?;
        let stderr = String::from_utf8(curl.stderr)?;
        assert!(
            curl.status.success(),
            "curl failed. Stdout: \n{stdout:?}\nStderr:\n{stderr}"
        );
        assert_eq!(stdout, content);
    }
    drop(child_dropper);
    let child = child.wait_with_output()?;
    println!("tarweb out:\n{}", String::from_utf8_lossy(&child.stdout));
    Ok(())
}
