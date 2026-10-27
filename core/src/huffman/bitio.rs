//! запис і читання окремих бітів
//!
//! біти йдуть від старшого до молодшого: перший біт потоку це старший біт
//! першого байта, другий біт це другий за старшинством і так далі
//!

#[derive(Debug, Default)]
pub struct BitWritter {
    bytes: Vec<u8>,
    current: u8,
    filled: u8,
}

impl BitWritter {
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
        for i in (0..len) {
            self.write_bit((bits >> i) & 1 == 1);
        }
    }
}
