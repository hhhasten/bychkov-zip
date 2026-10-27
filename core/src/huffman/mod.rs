//! стиснення Хаффмана
//!
//! модуль складається з кроків, кожен у своєму файлі:
//!   - lengths: частоти байтів і довжини кодів
//!   - canonical: канонічні коди за довжинами
//!   - bitio: запис і читання окремих бітів
//!

mod bitio;
mod canonical;
mod lengths;

pub use canonical::{Code, MAX_CODE_LEN, canonical_codes};
pub use lengths::{ALPHABET_SIZE, code_lengths, count_frequencies};
