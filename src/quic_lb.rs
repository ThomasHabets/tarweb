//! QUIC-LB draft-ietf-quic-load-balancers-22, single-pass AES encoding.
//!
//! This intentionally small codec is also implemented by sni-router/tarweb.
//! Keep the interoperability vectors in both repositories in sync.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use anyhow::{Context, Result, ensure};

pub const CID_LEN: usize = 17;

#[derive(Clone)]
pub struct Codec {
    config_id: u8,
    cipher: Aes128,
}

impl std::fmt::Debug for Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Codec")
            .field("config_id", &self.config_id)
            .finish_non_exhaustive()
    }
}

impl Codec {
    pub fn new(config_id: u8, key: &[u8; 16]) -> Result<Self> {
        ensure!(config_id < 7, "QUIC-LB configuration ID must be 0..6");
        Ok(Self {
            config_id,
            cipher: Aes128::new(key.into()),
        })
    }

    pub fn from_key_file(config_id: u8, path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("reading QUIC-LB key file")?;
        let text = text.trim();
        ensure!(
            text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "QUIC-LB key must contain 32 hexadecimal characters"
        );
        let mut key = [0u8; 16];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .context("QUIC-LB key must contain 32 hexadecimal characters")?;
        }
        Self::new(config_id, &key)
    }

    // The server ID occupies the start of plaintext; the rest is the nonce.
    pub fn encrypt(&self, plaintext: [u8; 16]) -> [u8; CID_LEN] {
        let mut block = plaintext.into();
        self.cipher.encrypt_block(&mut block);
        let mut cid = [0u8; CID_LEN];
        cid[0] = (self.config_id << 5) | 16;
        cid[1..].copy_from_slice(&block);
        cid
    }

    pub fn decrypt(&self, cid: &[u8]) -> Option<[u8; 16]> {
        if cid.len() != CID_LEN || cid[0] >> 5 != self.config_id {
            return None;
        }
        // The low five bits may carry a length or random bits (section 3.3).
        let mut block = <[u8; 16]>::try_from(&cid[1..]).ok()?.into();
        self.cipher.decrypt_block(&mut block);
        Some(block.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_single_pass_vector() -> Result<()> {
        // Appendix B.2: an eight-byte SID and eight-byte nonce.
        let codec = Codec::new(
            2,
            &[
                0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80, 0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66,
                0x20, 0x7f,
            ],
        )?;
        let plaintext = [
            0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f, 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0,
            0xd1, 0xe5,
        ];
        let cid = [
            0x50, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e,
            0xcf, 0x8c, 0xc3,
        ];
        assert_eq!(codec.encrypt(plaintext), cid);
        assert_eq!(codec.decrypt(&cid), Some(plaintext));
        assert!(codec.decrypt(&cid[..16]).is_none());
        let mut unknown = cid;
        unknown[0] = 0xf0;
        assert!(codec.decrypt(&unknown).is_none());
        let mut random_length_bits = cid;
        random_length_bits[0] = 0x41;
        assert_eq!(codec.decrypt(&random_length_bits), Some(plaintext));
        assert!(Codec::new(7, &[0; 16]).is_err());
        Ok(())
    }

    #[test]
    fn project_vector() -> Result<()> {
        // Four-byte backend ID, followed by opaque server nonce bytes.
        let codec = Codec::new(0, &[0; 16])?;
        let plaintext = [0u8; 16];
        let cid = [
            0x10, 0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca,
            0x34, 0x2b, 0x2e,
        ];
        assert_eq!(codec.encrypt(plaintext), cid);
        assert_eq!(codec.decrypt(&cid), Some(plaintext));
        Ok(())
    }

    #[test]
    fn validates_key_files_without_disclosing_keys() -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), " 00000000000000000000000000000000\n")?;
        Codec::from_key_file(0, file.path())?;
        for invalid in [
            "",
            "0",
            "+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0",
            "gg000000000000000000000000000000",
            "é000000000000000000000000000000",
        ] {
            std::fs::write(file.path(), invalid)?;
            assert!(Codec::from_key_file(0, file.path()).is_err());
        }
        Ok(())
    }
}
