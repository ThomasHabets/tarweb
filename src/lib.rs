use anyhow::{Result, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub mod sock;

/// Load certificate chain from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
pub fn load_certs<P: AsRef<std::path::Path>>(
    filename: P,
) -> std::io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).collect()
}

/// Load private key from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
pub fn load_private_key<P: AsRef<std::path::Path>>(filename: P) -> Result<PrivateKeyDer<'static>> {
    let keyfile = std::fs::File::open(filename)?;
    let mut reader = std::io::BufReader::new(keyfile);
    rustls_pemfile::private_key(&mut reader)?.ok_or(anyhow!("no private key in file"))
}
