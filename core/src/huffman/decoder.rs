//! з потоку бітів декодер відновлює байти за канонічними кодами
//!
//! ключова властивість канонічних кодів:
//! усі коди однакової довжини ідуть підряд як числа,
//! тобто лежать у проміжку [перший код, перший код + скільки їх).
//! тому читаємо біт за бітом і на кожній довжині перевіряємо чи не потрапили
//! ми в такий проміжок. дерево будувати не треба
//!

use super::bitio::BitReader;
use super::canonical::{MAX_CODE_LEN, canonical_codes};
use super::lengths::ALPHABET_SIZE;
use crate::error::{ByzError, Result};

pub struct Decoder {
    symbols: Vec<u8>,
    count: [usize; MAX_CODE_LEN + 1],
    first_code: [u64; MAX_CODE_LEN + 1],
    first_index: [usize; MAX_CODE_LEN + 1],
    max_len: usize,
}

impl Decoder {
    /// будує декодер за довжинами кодів. довжини перевіряє `canonical_codes`
    pub fn new(lengths: &[u8; ALPHABET_SIZE]) -> Result<Decoder> {
        let codes = canonical_codes(lengths)?;

        let mut symbols: Vec<u8> = (0..=255u8)
            .filter(|&symbol| lengths[symbol as usize] > 0)
            .collect();
        symbols.sort_by_key(|&symbol| (lengths[symbol as usize], symbol));

        let mut count = [0usize; MAX_CODE_LEN + 1];
        let mut first_code = [0u64; MAX_CODE_LEN + 1];
        let mut first_index = [0usize; MAX_CODE_LEN + 1];

        for (index, &symbol) in symbols.iter().enumerate() {
            let len = lengths[symbol as usize] as usize;
            // перший байт нової довжини має найменший код цієї довжини
            if count[len] == 0 {
                first_code[len] = codes[symbol as usize].bits;
                first_index[len] = index;
            }
            count[len] += 1;
        }

        let max_len = symbols
            .last()
            .map_or(0, |&symbol| lengths[symbol as usize] as usize);

        Ok(Decoder {
            symbols,
            count,
            first_code,
            first_index,
            max_len,
        })
    }

    /// читає з `reader` біти одного коду і повертає байт
    pub fn decode(&self, reader: &mut BitReader<'_>) -> Result<u8> {
        let mut code: u64 = 0;

        for len in 1..=self.max_len {
            let bit = reader
                .read_bit()
                .ok_or_else(|| ByzError::BadFormat("huffman stream is truncated".into()))?;
            code = (code << 1) | bit as u64;

            // чи лежить прочитаний код у проміжку кодів цієї довжини
            if self.count[len] > 0 && code >= self.first_code[len] {
                let offset = code - self.first_code[len];
                if offset < self.count[len] as u64 {
                    return Ok(self.symbols[self.first_index[len] + offset as usize]);
                }
            }
        }

        // дійшли до найбільшої довжини і жоден код не підійшов
        Err(ByzError::BadFormat("invalid huffman code".into()))
    }
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::super::bitio::BitWriter;
    use super::*;

    /// довжини з прикладу RFC 1951: байти 0..=7 мають довжини 3, 3, 3, 3, 3, 2, 4, 4
    fn rfc_lengths() -> [u8; ALPHABET_SIZE] {
        let mut lengths = [0u8; ALPHABET_SIZE];
        lengths[..8].copy_from_slice(&[3, 3, 3, 3, 3, 2, 4, 4]);
        lengths
    }

    #[test]
    fn decodes_what_the_encoder_wrote() {
        let lengths = rfc_lengths();
        let codes = canonical_codes(&lengths).unwrap();
        let decoder = Decoder::new(&lengths).unwrap();

        let message = [5u8, 0, 6, 7, 3, 5, 5, 1, 2, 4];
        let mut writer = BitWriter::new();
        for &symbol in &message {
            let code = codes[symbol as usize];
            writer.write_bits(code.bits, code.len);
        }
        let bytes = writer.finish();

        let mut reader = BitReader::new(&bytes);
        for &expected in &message {
            assert_eq!(decoder.decode(&mut reader).unwrap(), expected);
        }
    }

    #[test]
    fn unassigned_bit_pattern_is_rejected() {
        // один байт з довжиною 1: код `0` існує, а `1` ні
        let mut lengths = [0u8; ALPHABET_SIZE];
        lengths[9] = 1;
        let decoder = Decoder::new(&lengths).unwrap();

        let mut reader = BitReader::new(&[0b1000_0000]);
        let err = decoder.decode(&mut reader).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn truncated_stream_is_rejected() {
        let decoder = Decoder::new(&rfc_lengths()).unwrap();
        let mut reader = BitReader::new(&[]);
        let err = decoder.decode(&mut reader).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn empty_alphabet_cannot_decode_anything() {
        let decoder = Decoder::new(&[0u8; ALPHABET_SIZE]).unwrap();
        let mut reader = BitReader::new(&[0xFF]);
        assert!(decoder.decode(&mut reader).is_err());
    }

    #[test]
    fn invalid_lengths_are_rejected_by_constructor() {
        let mut lengths = [0u8; ALPHABET_SIZE];
        lengths[..3].copy_from_slice(&[1, 1, 1]);
        assert!(Decoder::new(&lengths).is_err());
    }
}
