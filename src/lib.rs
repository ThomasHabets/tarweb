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
pub fn load_certs<P: AsRef<std::path::Path>>(
    filename: P,
) -> Result<Vec<CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    CertificateDer::pem_file_iter(filename)?.collect()
}

/// Load private key from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
pub fn load_private_key<P: AsRef<std::path::Path>>(
    filename: P,
) -> Result<PrivateKeyDer<'static>, rustls::pki_types::pem::Error> {
    PrivateKeyDer::from_pem_file(filename)
}
