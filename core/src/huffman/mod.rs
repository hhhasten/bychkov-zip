//! стиснення Хаффмана
//!
//! модуль складається з кроків, кожен у своєму файлі:
//!   - lengths: частоти байтів і довжини кодів
//!

mod lengths;

pub use lengths::{ALPHABET_SIZE, code_lengths, count_frequencies};
