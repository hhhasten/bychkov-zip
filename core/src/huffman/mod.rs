//! стиснення Хаффмана
//!
//! модуль складається з кроків, кожен у своєму файлі:
//!   - lengths: частоти байтів і довжини кодів
//!   - canonical: канонічні коди за довжинами
//!   - bitio: запис і читання окремих бітів
//!   - decoder: відновлення байтів з потоку бітів
//!
//! назовні виставлено лише дві функції: `compress` і `decompress`.
//! підмодулі приватні, решта ядра про них не знає
//!
//! формат стиснених даних:
//!
//! ```text
//! [256 байт: довжина коду кожного байта, 0 = байта немає][потік бітів]
//! ```
//!
//! останній байт потоку добитий нулями. скільки байтів відновлювати,
//! розпаковувальнику повідомляє `original_len` (він зберігається в метаданих архіву)
//!

mod bitio;
mod canonical;
mod decoder;
mod lengths;

use crate::error::{ByzError, Result};
use bitio::{BitReader, BitWriter};
use canonical::canonical_codes;
use decoder::Decoder;
use lengths::{ALPHABET_SIZE, code_lengths, count_frequencies};

/// стискає дані Гаффманом.
///
/// помилка можлива лише якщо дерево вийшло глибшим за `MAX_CODE_LEN`,
/// а при ліміті архіватора 500 МБ цього не станеться
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let freqs = count_frequencies(data);
    let lengths = code_lengths(&freqs);
    let codes = canonical_codes(&lengths)?;

    // спочатку таблиця довжин, потім біти
    let mut out = lengths.to_vec();

    let mut writer = BitWriter::new();
    for &byte in data {
        let code = codes[byte as usize];
        writer.write_bits(code.bits, code.len);
    }
    out.extend_from_slice(&writer.finish());

    Ok(out)
}

pub fn decompress(data: &[u8], original_len: u64) -> Result<Vec<u8>> {
    if data.len() < ALPHABET_SIZE {
        return Err(ByzError::BadFormat(
            "huffman data is shorter than its length table".into(),
        ));
    }
    let (table, bit_data) = data.split_at(ALPHABET_SIZE);

    let lengths: [u8; ALPHABET_SIZE] = table
        .try_into()
        .expect("split_at gives exactly ALPHABET_SIZE bytes");

    let decoder = Decoder::new(&lengths)?;

    // кожен байт займає щонайменше один біт, тож більше ніж є бітів відновити не вийде.
    // ця перевірка заодно захищає від підробленого original_len:
    // без неї Vec::with_capacity спробував би виділити гігабайти
    let available_bits = bit_data.len() as u64 * 8;
    if original_len > available_bits {
        return Err(ByzError::BadFormat(
            "huffman data is too short for the declared size".into(),
        ));
    }

    let mut out = Vec::with_capacity(original_len as usize);
    let mut reader = BitReader::new(bit_data);

    for _ in 0..original_len {
        out.push(decoder.decode(&mut reader)?);
    }

    Ok(out)
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// стискає і розпаковує, перевіряє що вийшло те саме
    fn assert_roundtrip(data: &[u8]) {
        let packed = compress(data).unwrap();
        let unpacked = decompress(&packed, data.len() as u64).unwrap();
        assert_eq!(unpacked, data);
    }

    #[test]
    fn roundtrip_empty() {
        assert_roundtrip(&[]);
    }

    #[test]
    fn roundtrip_single_byte() {
        assert_roundtrip(&[42]);
    }

    #[test]
    fn roundtrip_single_repeated_byte() {
        assert_roundtrip(&[7u8; 10_000]);
    }

    #[test]
    fn roundtrip_two_distinct_bytes() {
        assert_roundtrip(b"abababababbbbbbaaaa");
    }

    #[test]
    fn roundtrip_all_256_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_roundtrip(&data);
    }

    #[test]
    fn roundtrip_text() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(100);
        assert_roundtrip(text.as_bytes());
    }

    #[test]
    fn roundtrip_random_bytes() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut data = vec![0u8; 100_000];
        rng.fill_bytes(&mut data);
        assert_roundtrip(&data);
    }

    #[test]
    fn roundtrip_many_small_inputs_with_different_alphabets() {
        // різна довжина і різна кількість унікальних байтів
        let mut rng = StdRng::seed_from_u64(2);
        for round in 0..300usize {
            let len = round % 200;
            let alphabet = (round % 255) as u8 + 1;
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            for byte in &mut data {
                *byte %= alphabet;
            }
            assert_roundtrip(&data);
        }
    }

    #[test]
    fn text_gets_smaller() {
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(100);
        let packed = compress(text.as_bytes()).unwrap();
        assert!(packed.len() < text.len());
    }

    #[test]
    fn random_bytes_do_not_get_smaller() {
        // нестисливі дані: Гаффман не допоможе, а таблиця довжин додає 256 байт.
        // саме тому архіватор порівнює розмір і за потреби зберігає дані як є (STORED)
        let mut rng = StdRng::seed_from_u64(3);
        let mut data = vec![0u8; 10_000];
        rng.fill_bytes(&mut data);

        let packed = compress(&data).unwrap();
        assert!(packed.len() >= data.len());
    }

    #[test]
    fn compression_is_deterministic() {
        let text = "abracadabra".repeat(50);
        assert_eq!(
            compress(text.as_bytes()).unwrap(),
            compress(text.as_bytes()).unwrap()
        );
    }

    #[test]
    fn original_len_cuts_off_the_padding_bits() {
        // 11 байтів стають кількома бітами, останній байт добитий нулями.
        // розпаковувальник зупиняється по original_len і не вигадує зайвого
        let packed = compress(b"abracadabra").unwrap();
        assert_eq!(decompress(&packed, 11).unwrap(), b"abracadabra");
        assert_eq!(decompress(&packed, 5).unwrap(), b"abrac");
    }

    #[test]
    fn too_short_data_is_rejected() {
        let err = decompress(&[0u8; 100], 0).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn declared_size_larger_than_data_is_rejected() {
        let packed = compress(b"abracadabra").unwrap();
        let err = decompress(&packed, u64::MAX).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn corrupted_length_table_is_rejected() {
        let mut packed = compress(b"abracadabra").unwrap();
        // три байти з довжиною 1: такого дерева не існує
        packed[0] = 1;
        packed[1] = 1;
        packed[2] = 1;
        let err = decompress(&packed, 1).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn invalid_code_in_stream_is_rejected() {
        // у таблиці єдиний байт з довжиною 1 (тобто код `0`), а в потоці біт `1`
        let mut data = vec![0u8; ALPHABET_SIZE];
        data[9] = 1;
        data.push(0b1000_0000);
        let err = decompress(&data, 1).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }
}
