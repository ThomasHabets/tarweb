use anyhow::Context;
use anyhow::Result;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub mod privs;
pub mod sock;

/// Load certificate chain from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
pub fn load_certs<P: AsRef<std::path::Path>>(filename: P) -> Result<Vec<CertificateDer<'static>>> {
    let filename = filename.as_ref();
    let pem = CertificateDer::pem_file_iter(filename)
        .context(format!("Loading certs from {}", filename.display()))?;
    let r: Result<_, rustls::pki_types::pem::Error> = pem.collect();
    Ok(r?)
}

/// Load private key from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
pub fn load_private_key<P: AsRef<std::path::Path>>(filename: P) -> Result<PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    PrivateKeyDer::from_pem_file(filename)
        .context(format!("Loading private key from {}", filename.display()))
}
