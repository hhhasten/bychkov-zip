//! запис і читання окремих бітів
//!
//! біти йдуть від старшого до молодшого: перший біт потоку це старший біт
//! першого байта, другий біт це другий за старшинством і так далі
//!

/// накопичує біти і складає їх у байти
#[derive(Debug, Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    filled: u8,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | bit as u8;
        self.filled += 1;

        if self.filled == 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.filled = 0;
        }
    }

    pub fn write_bits(&mut self, bits: u64, len: u8) {
        for i in (0..len).rev() {
            self.write_bit((bits >> i) & 1 == 1);
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.filled > 0 {
            self.current <<= 8 - self.filled;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

/// читає біти зі шматка байтів зліва направо
#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0 }
    }

    pub fn read_bit(&mut self) -> Option<bool> {
        let byte = *self.data.get(self.pos / 8)?;
        let bit = (byte >> (7 - self.pos % 8)) & 1 == 1;
        self.pos += 1;

        Some(bit)
    }
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_packed_from_the_high_end() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b101, 3);
        writer.write_bits(0b01, 2);

        // 101 01 і три нулі добивки
        assert_eq!(writer.finish(), vec![0b1010_1000]);
    }

    #[test]
    fn full_byte_needs_no_padding() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xAB, 8);
        assert_eq!(writer.finish(), vec![0xAB]);
    }

    #[test]
    fn ninth_bit_starts_a_new_byte() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xFF, 8);
        writer.write_bit(true);
        assert_eq!(writer.finish(), vec![0xFF, 0b1000_0000]);
    }

    #[test]
    fn empty_writer_produces_no_bytes() {
        assert_eq!(BitWriter::new().finish(), Vec::<u8>::new());
    }

    #[test]
    fn reader_reads_from_the_high_end_and_stops_at_the_end() {
        let mut reader = BitReader::new(&[0b1010_0000]);
        let bits: Vec<bool> = (0..8).map(|_| reader.read_bit().unwrap()).collect();

        assert_eq!(
            bits,
            vec![true, false, true, false, false, false, false, false]
        );
        assert_eq!(reader.read_bit(), None);
    }

    #[test]
    fn reader_on_empty_data_returns_none() {
        assert_eq!(BitReader::new(&[]).read_bit(), None);
    }

    #[test]
    fn write_then_read_gives_the_same_bits() {
        // записуємо коди різної довжини і читаємо їх назад біт за бітом
        let items: Vec<(u64, u8)> = vec![
            (0b1, 1),
            (0b0, 1),
            (0b110, 3),
            (0, 5),
            (0x1234_5678_9ABC, 48),
            (0b11, 2),
        ];

        let mut writer = BitWriter::new();
        for &(bits, len) in &items {
            writer.write_bits(bits, len);
        }
        let bytes = writer.finish();

        let mut reader = BitReader::new(&bytes);
        for &(bits, len) in &items {
            for i in (0..len).rev() {
                assert_eq!(reader.read_bit(), Some((bits >> i) & 1 == 1));
            }
        }
    }
}
