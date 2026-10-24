//! формат файлу .byz
//!
//! цей модуль нічого не стискає і не шифрує, він тільки знає,
//! де в файлі щось лежить і перевіряє що данні схожі на правду

/*  відкритий хедер, 33 байта

офсет | розмір | поле
---------------------------------
 0     | 4      | MAGIC (BYZ\x01)
 4     | 1      | VERSION
 5     | 16     | SALT
 21    | 12     | NONCE

*/

use crate::error::{ByzError, Result};

/// маркер формату. ASCII "BYZ" + 0x01
pub const MAGIC: [u8; 4] = [0x42, 0x59, 0x5A, 0x01];

/// версія формату. v1 = argon2id (64 MiB, t=3, p=1)
pub const FORMAT_VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

// офсети полів в заголовці
// виписані константами щоб уникнути незрозумілих чисел в коді і не налажать
const VERSION_POS: usize = MAGIC.len(); // 4
const SALT_START: usize = VERSION_POS + 1; // 5
const SALT_END: usize = SALT_START + SALT_LEN; // 21
const NONCE_END: usize = SALT_END + NONCE_LEN; // 33

/// повний размір відкритого хедера в байтах.
pub const HEADER_LEN: usize = NONCE_END;

/// відкритий хедер архіва
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn new(salt: [u8; SALT_LEN], nonce: [u8; NONCE_LEN]) -> Self {
        Header {
            version: FORMAT_VERSION,
            salt,
            nonce,
        }
    }

    /// конвертує хедер в 33 байта
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..MAGIC.len()].copy_from_slice(&MAGIC);
        out[VERSION_POS] = self.version;
        out[SALT_START..SALT_END].copy_from_slice(&self.salt);
        out[SALT_END..NONCE_END].copy_from_slice(&self.nonce);

        out
    }

    /// читає заголовок з початку `data`.
    /// все що йде після перших 33 байт ігнорується, бо його зріже код який викликає цей метод
    pub fn from_bytes(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_LEN {
            return Err(ByzError::BadFormat(format!(
                "file too short: {} bytes, header needs {}",
                data.len(),
                HEADER_LEN,
            )));
        }

        if data[..MAGIC.len()] != MAGIC {
            return Err(ByzError::BadFormat("not a .byz file".into()));
        }

        let version = data[VERSION_POS];
        if version != FORMAT_VERSION {
            return Err(ByzError::BadFormat(format!(
                "unsupported format version {version}",
            )));
        }

        let salt = data[SALT_START..SALT_END]
            .try_into()
            .expect("slice length is fixed by SALT_START..SALT_END");
        let nonce = data[SALT_END..NONCE_END]
            .try_into()
            .expect("slice length is fixed by SALT_END..NONCE_END");

        Ok(Header {
            version,
            salt,
            nonce,
        })
    }
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        let salt: [u8; SALT_LEN] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; NONCE_LEN] = core::array::from_fn(|i| 100 + i as u8);
        Header::new(salt, nonce)
    }

    #[test]
    fn header_len_is_33() {
        assert_eq!(HEADER_LEN, 33);
    }

    #[test]
    fn header_layout_is_exact() {
        let bytes = sample_header().to_bytes();
        assert_eq!(&bytes[0..4], b"BYZ\x01");
        assert_eq!(bytes[4], FORMAT_VERSION);
        assert_eq!(bytes[5], 0);
        assert_eq!(bytes[20], 15);
        assert_eq!(bytes[21], 100);
        assert_eq!(bytes[32], 111);
    }

    #[test]
    fn header_roundtrip() {
        let h = sample_header();
        let parsed = Header::from_bytes(&h.to_bytes()).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn trailing_data_is_ignored() {
        let h = sample_header();
        let mut file = h.to_bytes().to_vec();
        file.extend_from_slice(b"ciphertext goes here");
        assert_eq!(Header::from_bytes(&file).unwrap(), h);
    }

    #[test]
    fn truncated_header_is_rejected_at_every_length() {
        let bytes = sample_header().to_bytes();
        for len in 0..HEADER_LEN {
            let err = Header::from_bytes(&bytes[..len]).unwrap_err();
            assert!(matches!(err, ByzError::BadFormat(_)), "len = {len}");
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = sample_header().to_bytes();
        bytes[0] = b'X';
        let err = Header::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut bytes = sample_header().to_bytes();
        bytes[VERSION_POS] = 99;
        let err = Header::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("unsupported format version 99"));
    }
}
