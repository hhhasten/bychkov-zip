/*
    ентропія Шеннона:
        H = -Σ p(i) * log2(p(i)), де p(i) - доля байта i в даних.

    результат лежить в діапазоні від 0.0 до 8.0 біт на байт:
        0.0 -> всі байти однакові, стискається ідеально
        8.0 -> всі 256 значений рівновірогідні, тобто стиснути не можна

*/

/// значення вище цього порогу свідчить що файл не стискається
pub const INCOMPRESSIBLE_THRESHOLD: f64 = 7.5;

/// обчислює ентропію нулевого порядку в бітах на байт
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // скільки разів зустрівся кожен байт
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    // сумуємо вклад кожного байту який зустрівся
    let total = data.len() as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0) // log2(0) не визначений тому нулеві каунти пропускаємо
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum();

    // з p = 1 виходить -0.0 тому приводимо до звичаного нуля
    if h > 0.0 { h } else { 0.0 }
}

pub fn is_incompressible(data: &[u8]) -> bool {
    shannon_entropy(data) >= INCOMPRESSIBLE_THRESHOLD
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn single_symbol_is_zero() {
        assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
    }

    #[test]
    fn two_equal_symbols_is_one_bit() {
        let data: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        assert!((shannon_entropy(&data) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn uniform_256_is_eight_bits() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn english_text_is_compressible() {
        let text = "today's weather is beautiful. ".repeat(200);
        let h = shannon_entropy(text.as_bytes());
        assert!(h > 3.0 && h < 5.0, "h = {h}");
        assert!(!is_incompressible(text.as_bytes()));
    }

    #[test]
    fn cyrillic_text_is_compressible() {
        let text = "вован золєвський привєт я говорящий тест вітаю тебе з хелоувіном. ".repeat(228);
        let h = shannon_entropy(text.as_bytes());
        assert!(h > 3.0 && h < 5.0, "h = {h}");
        assert!(!is_incompressible(text.as_bytes()));
    }

    #[test]
    fn random_data_is_incompressible() {
        let data = random_bytes(1 << 20);
        assert!(shannon_entropy(&data) > 7.99);
        assert!(is_incompressible(&data));
    }

    #[test]
    fn tiny_inputs_are_never_flagged() {
        // ентропія не може бути більше log2(n), адже для 16 байт це максимум 4 біта.
        // тому is_incompressible() на мілких файлах безсильна.
        let data = random_bytes(16);
        assert!(!is_incompressible(&data));
    }
}
