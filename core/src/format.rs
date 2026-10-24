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

// офсети полів в хедері
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

    /// читає хедер з початку `data`.
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

/*  метадані. лежать всередині зашифрованої частини, усі числа little-endian

file_count: u32
далі file_count записів, кожен такий:

поле          | тип
------------------------
 path_len     | u16
 path         | UTF-8, path_len байт
 original_len | u64
 stored_len   | u64
 flags        | u8

*/

/// біт 0 у flags: дані стиснуті Гаффманом.
/// якщо біт не встановлений, дані збережені як є (STORED)
pub const FLAG_COMPRESSED: u8 = 0b0000_0001;

// усі прапорці які знає версія 1. будь-який інший біт означає що файл зіпсований або чужий
const KNOWN_FLAGS: u8 = FLAG_COMPRESSED;

// мінімальний розмір одного запису (шлях може бути порожнім):
// path_len (2) + original_len (8) + stored_len (8) + flags (1)
const ENTRY_FIXED_LEN: usize = 2 + 8 + 8 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub original_len: u64,
    pub stored_len: u64,
    pub flags: u8,
}

impl FileEntry {
    pub fn new(path: String, original_len: u64, stored_len: u64, compressed: bool) -> Self {
        let flags = if compressed { FLAG_COMPRESSED } else { 0 };
        FileEntry {
            path,
            original_len,
            stored_len,
            flags,
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    /// дописує в кінець out
    fn write_to(&self, out: &mut Vec<u8>) -> Result<()> {
        // довжина шляху рахується в байтах а не в символах, кирилична літера займає 2 байти.
        // u16::try_from замість as u16, бо as мовчки відрізав би зайве
        let path_len = u16::try_from(self.path.len()).map_err(|_| {
            ByzError::BadArgs(format!(
                "path is too long: {} bytes (max {})",
                self.path.len(),
                u16::MAX,
            ))
        })?;

        out.extend_from_slice(&path_len.to_le_bytes());
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(&self.original_len.to_le_bytes());
        out.extend_from_slice(&self.stored_len.to_le_bytes());
        out.push(self.flags);

        Ok(())
    }

    /// читає один запис з поточної позиції `reader`
    fn read_from(reader: &mut Reader<'_>) -> Result<FileEntry> {
        let path_len = reader.read_u16()? as usize;
        // take() перевіряє що стільки байт справді є, ще до того як ми щось виділимо
        let path_bytes = reader.take(path_len)?;
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| ByzError::BadFormat("path is not valid utf-8".into()))?
            .to_owned();

        let original_len = reader.read_u64()?;
        let stored_len = reader.read_u64()?;
        let flags = reader.read_u8()?;

        // `!KNOWN_FLAGS` вмикає всі біти крім відомих
        // тож результат != 0 означає що встановлений якийсь невідомий біт
        if flags & !KNOWN_FLAGS != 0 {
            return Err(ByzError::BadFormat(format!(
                "unknown file flags: {flags:#04x}"
            )));
        }

        let entry = FileEntry {
            path,
            original_len,
            stored_len,
            flags,
        };

        // без стиснення дані лежать як є, тож розміри мусять збігатися
        if !entry.is_compressed() && entry.stored_len != entry.original_len {
            return Err(ByzError::BadFormat(format!(
                "stored file has different sizes: original {}, stored {}",
                entry.original_len, entry.stored_len,
            )));
        }

        Ok(entry)
    }
}

/// метадані всього архіву, список файлів у порядку їх блоків
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub files: Vec<FileEntry>,
}

impl Metadata {
    /// конвертує метадані в байти
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let count = u32::try_from(self.files.len())
            .map_err(|_| ByzError::BadArgs(format!("too many files: {}", self.files.len())))?;

        let mut out = Vec::new();
        out.extend_from_slice(&count.to_le_bytes());
        for file in &self.files {
            file.write_to(&mut out)?;
        }

        Ok(out)
    }

    /// читає метадані з початку `data`.
    /// повертає метадані і скільки байт вони зайняли: після них у `data`
    /// починаються блоки файлів, їх обробляє код який викликає цей метод
    pub fn from_bytes(data: &[u8]) -> Result<(Metadata, usize)> {
        let mut reader = Reader::new(data);

        let count = reader.read_u32()? as usize;

        // захист від підробленого file_count: кожен запис займає мінімум
        // ENTRY_FIXED_LEN байт, тож записів не може бути більше ніж влізе в дані.
        // без цієї перевірки file_count = 4 мільярди змусив би нас виділити гігабайти
        let min_needed = count
            .checked_mul(ENTRY_FIXED_LEN)
            .ok_or_else(|| ByzError::BadFormat("file count is too large".into()))?;
        if min_needed > reader.remaining() {
            return Err(ByzError::BadFormat(format!(
                "metadata declares {count} files but is too short to hold them"
            )));
        }

        // тут виділення вже безпечне: count обмежений реальним розміром даних
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            files.push(FileEntry::read_from(&mut reader)?);
        }

        Ok((Metadata { files }, reader.position()))
    }

    /// сума stored_len усіх файлів, тобто скільки байт мають займати блоки.
    /// None якщо сума не влізла в u64
    pub fn total_stored_len(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for file in &self.files {
            total = total.checked_add(file.stored_len)?;
        }

        Some(total)
    }
}

/// допоміжний рідер, йде по байтах зліва направо і запам'ятовує позицію.
/// `'a` означає що рідер не може пережити дані на які дивиться. він нічого не копіює
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }

    /// скільки байт ще не прочитано. pos ніколи не перевищує data.len(), тож віднімання безпечне
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// бере наступні `n` байт і зсуває позицію. помилка якщо стільки байт немає
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(ByzError::BadFormat("metadata is truncated".into()));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;

        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?.try_into().expect("take(2) returns 2 bytes");
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?.try_into().expect("take(4) returns 4 bytes");
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?.try_into().expect("take(8) returns 8 bytes");
        Ok(u64::from_le_bytes(bytes))
    }
}

// юніт тести
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

    // допоміжні функції для метаданих

    fn sample_metadata() -> Metadata {
        Metadata {
            files: vec![
                FileEntry::new("docs/readme.txt".into(), 1000, 400, true),
                FileEntry::new("photo.png".into(), 5000, 5000, false),
                FileEntry::new("порожній.txt".into(), 0, 0, false),
            ],
        }
    }

    /// збирає запис вручну, щоб можна було зробити навмисно зіпсований
    fn raw_entry(path: &[u8], original_len: u64, stored_len: u64, flags: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(path);
        out.extend_from_slice(&original_len.to_le_bytes());
        out.extend_from_slice(&stored_len.to_le_bytes());
        out.push(flags);
        out
    }

    /// метадані з одного сирого запису
    fn raw_metadata(entry: &[u8]) -> Vec<u8> {
        let mut out = 1u32.to_le_bytes().to_vec();
        out.extend_from_slice(entry);
        out
    }

    #[test]
    fn metadata_layout_is_exact_little_endian() {
        let meta = Metadata {
            files: vec![FileEntry::new("a".into(), 0x0102, 0x0102, false)],
        };
        let bytes = meta.to_bytes().unwrap();

        let expected: Vec<u8> = vec![
            1, 0, 0, 0, // file_count = 1
            1, 0,    // path_len = 1
            b'a', // path
            0x02, 0x01, 0, 0, 0, 0, 0, 0, // original_len = 0x0102
            0x02, 0x01, 0, 0, 0, 0, 0, 0, // stored_len = 0x0102
            0, // flags
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn metadata_roundtrip() {
        let meta = sample_metadata();
        let bytes = meta.to_bytes().unwrap();
        let (parsed, used) = Metadata::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, meta);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn empty_metadata_roundtrip() {
        let meta = Metadata { files: vec![] };
        let bytes = meta.to_bytes().unwrap();
        assert_eq!(bytes, vec![0, 0, 0, 0]);

        let (parsed, used) = Metadata::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, meta);
        assert_eq!(used, 4);
    }

    #[test]
    fn path_length_is_counted_in_bytes_not_chars() {
        let path = "тест";
        let meta = Metadata {
            files: vec![FileEntry::new(path.into(), 0, 0, false)],
        };
        let bytes = meta.to_bytes().unwrap();

        // 4 символи, але 8 байт
        assert_eq!(path.chars().count(), 4);
        assert_eq!(&bytes[4..6], &8u16.to_le_bytes());
    }

    #[test]
    fn trailing_data_after_metadata_is_left_alone() {
        let meta = sample_metadata();
        let mut data = meta.to_bytes().unwrap();
        let meta_len = data.len();
        data.extend_from_slice(b"file blobs go here");

        let (parsed, used) = Metadata::from_bytes(&data).unwrap();
        assert_eq!(parsed, meta);
        assert_eq!(used, meta_len);
    }

    #[test]
    fn truncated_metadata_is_rejected_at_every_length() {
        let bytes = sample_metadata().to_bytes().unwrap();
        for len in 0..bytes.len() {
            let err = Metadata::from_bytes(&bytes[..len]).unwrap_err();
            assert!(matches!(err, ByzError::BadFormat(_)), "len = {len}");
        }
    }

    #[test]
    fn huge_file_count_is_rejected_without_allocating() {
        let bytes = u32::MAX.to_le_bytes();
        let err = Metadata::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn path_len_beyond_data_is_rejected() {
        // кажемо що шлях 65535 байт, а даних немає
        let mut data = 1u32.to_le_bytes().to_vec();
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        let err = Metadata::from_bytes(&data).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn invalid_utf8_path_is_rejected() {
        let data = raw_metadata(&raw_entry(&[0xFF, 0xFE], 0, 0, 0));
        let err = Metadata::from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("utf-8"));
    }

    #[test]
    fn unknown_flags_are_rejected() {
        let data = raw_metadata(&raw_entry(b"a", 0, 0, 0b0000_0010));
        let err = Metadata::from_bytes(&data).unwrap_err();
        assert!(err.to_string().contains("unknown file flags"));
    }

    #[test]
    fn stored_file_with_different_sizes_is_rejected() {
        let data = raw_metadata(&raw_entry(b"a", 10, 11, 0));
        let err = Metadata::from_bytes(&data).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn compressed_file_may_have_different_sizes() {
        let data = raw_metadata(&raw_entry(b"a", 10, 3, FLAG_COMPRESSED));
        let (meta, _) = Metadata::from_bytes(&data).unwrap();
        assert!(meta.files[0].is_compressed());
    }

    #[test]
    fn too_long_path_is_rejected_on_write() {
        let meta = Metadata {
            files: vec![FileEntry::new("a".repeat(70_000), 0, 0, false)],
        };
        let err = meta.to_bytes().unwrap_err();
        assert!(matches!(err, ByzError::BadArgs(_)));
    }

    #[test]
    fn total_stored_len_sums_and_detects_overflow() {
        assert_eq!(sample_metadata().total_stored_len(), Some(400 + 5000));

        let overflow = Metadata {
            files: vec![
                FileEntry::new("a".into(), 0, u64::MAX, true),
                FileEntry::new("b".into(), 0, 1, true),
            ],
        };
        assert_eq!(overflow.total_stored_len(), None);
    }
}
