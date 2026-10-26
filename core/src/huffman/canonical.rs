//! канонічні коди Гаффмана
//!
//! навіщо це потрібно:
//! в архіві ми зберігаємо лише довжини кодів до 256 байт, а не саме дерево
//! щоб розпаковувальник отримав ті самі коди що й стискальник, коди мають однозначно випливати з довжин
//! для цього діє правило:
//!   - коротші коди йдуть раніше за довші
//!   - серед кодів однакової довжини раніше йде менший байт
//!   - кожен наступний код це попередній + 1 (з дописаними нулями, якщо довжина зросла)
//!
//! біти кожного коду записуються від старшого до молодшого

use super::lengths::ALPHABET_SIZE;
use crate::error::{ByzError, Result};

/// найбільша довжина коду
pub const MAX_CODE_LEN: usize = 48;

/// один код = `n` молодших бітів числа `bits`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Code {
    pub bits: u64,
    /// довжина в бітах, 0 означає що в цього байта коду немає
    pub len: u8,
}

/// будує канонічні коди за довжинами
pub fn canonical_codes(lengths: &[u8; ALPHABET_SIZE]) -> Result<[Code; ALPHABET_SIZE]> {
    // крок 1: рахуємо скільки кодів кожної довжини і перевіряємо довжини
    // сума 2^(-довжина) по всіх кодах не може перевищувати 1
    // інакше коди неминуче були б префіксами один одного,
    // щоб обійтися без дробів, множимо на 2^MAX_CODE_LEN
    let mut count_per_len = [0u64; MAX_CODE_LEN + 1];
    let mut kraft_sum: u64 = 0;

    for &len in lengths {
        let len = len as usize;
        if len == 0 {
            continue;
        }
        if len > MAX_CODE_LEN {
            return Err(ByzError::BadFormat(format!(
                "huffman code length {len} is too long (max {MAX_CODE_LEN})"
            )));
        }
        count_per_len[len] += 1;
        kraft_sum += 1u64 << (MAX_CODE_LEN - len);
    }

    if kraft_sum > 1u64 << MAX_CODE_LEN {
        return Err(ByzError::BadFormat(
            "huffman code lengths do not form a valid tree".into(),
        ));
    }

    // крок 2: перший код кожної довжини
    // він іде одразу після останнього коду попередньої довжини, плюс зсув вліво на один біт
    let mut next_code = [0u64; MAX_CODE_LEN + 1];
    let mut code: u64 = 0;
    for len in 1..=MAX_CODE_LEN {
        code = (code + count_per_len[len - 1]) << 1;
        next_code[len] = code;
    }

    // крок 3: роздаємо коди байтам за зростанням значення байта,
    // тому серед однакових довжин менший байт отримує менший код
    let mut codes = [Code::default(); ALPHABET_SIZE];
    for (symbol, &len) in lengths.iter().enumerate() {
        if len > 0 {
            codes[symbol] = Code {
                bits: next_code[len as usize],
                len,
            };
            next_code[len as usize] += 1;
        }
    }

    Ok(codes)
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::super::lengths::{code_lengths, count_frequencies};
    use super::*;

    /// масив довжин з пар (байт, довжина)
    fn lengths_of(pairs: &[(u8, u8)]) -> [u8; ALPHABET_SIZE] {
        let mut lengths = [0u8; ALPHABET_SIZE];
        for &(byte, len) in pairs {
            lengths[byte as usize] = len;
        }
        lengths
    }

    fn code(bits: u64, len: u8) -> Code {
        Code { bits, len }
    }

    #[test]
    fn empty_lengths_give_no_codes() {
        let codes = canonical_codes(&[0u8; ALPHABET_SIZE]).unwrap();
        assert!(codes.iter().all(|c| *c == Code::default()));
    }

    #[test]
    fn single_symbol_gets_code_zero() {
        let codes = canonical_codes(&lengths_of(&[(42, 1)])).unwrap();
        assert_eq!(codes[42], code(0b0, 1));
    }

    #[test]
    fn rfc1951_example() {
        // приклад з опису формату Deflate (RFC 1951, розділ 3.2.2):
        // байти 0..=7 мають довжини 3, 3, 3, 3, 3, 2, 4, 4
        let lengths = lengths_of(&[
            (0, 3),
            (1, 3),
            (2, 3),
            (3, 3),
            (4, 3),
            (5, 2),
            (6, 4),
            (7, 4),
        ]);
        let codes = canonical_codes(&lengths).unwrap();

        assert_eq!(codes[0], code(0b010, 3));
        assert_eq!(codes[1], code(0b011, 3));
        assert_eq!(codes[2], code(0b100, 3));
        assert_eq!(codes[3], code(0b101, 3));
        assert_eq!(codes[4], code(0b110, 3));
        assert_eq!(codes[5], code(0b00, 2));
        assert_eq!(codes[6], code(0b1110, 4));
        assert_eq!(codes[7], code(0b1111, 4));
    }

    #[test]
    fn textbook_example_from_previous_step() {
        // довжини з тесту в lengths.rs: a=1, b=3, c=3, d=3, e=4, f=4
        let lengths = lengths_of(&[
            (b'a', 1),
            (b'b', 3),
            (b'c', 3),
            (b'd', 3),
            (b'e', 4),
            (b'f', 4),
        ]);
        let codes = canonical_codes(&lengths).unwrap();

        assert_eq!(codes[b'a' as usize], code(0b0, 1));
        assert_eq!(codes[b'b' as usize], code(0b100, 3));
        assert_eq!(codes[b'c' as usize], code(0b101, 3));
        assert_eq!(codes[b'd' as usize], code(0b110, 3));
        assert_eq!(codes[b'e' as usize], code(0b1110, 4));
        assert_eq!(codes[b'f' as usize], code(0b1111, 4));
    }

    #[test]
    fn codes_are_prefix_free_for_real_data() {
        // жоден код не може бути початком іншого, інакше розпакувати однозначно не вийде
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(50);
        let lengths = code_lengths(&count_frequencies(text.as_bytes()));
        let codes = canonical_codes(&lengths).unwrap();

        let used: Vec<Code> = codes.iter().copied().filter(|c| c.len > 0).collect();
        for (i, a) in used.iter().enumerate() {
            for (j, b) in used.iter().enumerate() {
                if i == j || a.len > b.len {
                    continue;
                }
                // беремо в довшого коду стільки старших бітів, скільки має коротший
                let b_prefix = b.bits >> (b.len - a.len);
                assert_ne!(b_prefix, a.bits, "{a:?} is a prefix of {b:?}");
            }
        }
    }

    #[test]
    fn codes_keep_lengths_and_fit_in_their_length() {
        let text = "abracadabra alakazam".repeat(20);
        let lengths = code_lengths(&count_frequencies(text.as_bytes()));
        let codes = canonical_codes(&lengths).unwrap();

        for symbol in 0..ALPHABET_SIZE {
            assert_eq!(codes[symbol].len, lengths[symbol]);
            if codes[symbol].len > 0 {
                assert!(codes[symbol].bits < 1u64 << codes[symbol].len);
            }
        }
    }

    #[test]
    fn oversubscribed_lengths_are_rejected() {
        // три коди довжини 1 не існують: місць лише два (0 і 1)
        let err = canonical_codes(&lengths_of(&[(0, 1), (1, 1), (2, 1)])).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn too_long_length_is_rejected() {
        let too_long = (MAX_CODE_LEN + 1) as u8;
        let err = canonical_codes(&lengths_of(&[(0, too_long)])).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));

        let err = canonical_codes(&lengths_of(&[(0, 255)])).unwrap_err();
        assert!(matches!(err, ByzError::BadFormat(_)));
    }

    #[test]
    fn incomplete_tree_is_accepted() {
        // коди не обов'язково заповнюють усе дерево (так буває при одному байті),
        // тож розпаковувальник пізніше сам відхилить невикористані біти
        let codes = canonical_codes(&lengths_of(&[(0, 2), (1, 2)])).unwrap();
        assert_eq!(codes[0], code(0b00, 2));
        assert_eq!(codes[1], code(0b01, 2));
    }
}
