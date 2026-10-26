//! частоти байтів і довжини кодів Хаффмана
//!
//! часті байти кодуємо короткими бітовими кодами, рідкісні довгими.
//!
//! для цього будуємо бінарне дерево:
//!   - кожен байт який зустрівся це лист, вага листа = скільки разів він зустрівся
//!   - беремо два найлегші вузли і об'єднуємо під новим вузлом, вага = сума
//!   - повторюємо поки не залишиться один вузол - корінь
//!   - глибина листа в дереві = довжина коду цього байта
//!
//! самі коди тут не будуються, лише їх довжини

use std::{cmp::Reverse, collections::BinaryHeap};

/// скільки різних значень може мати байт
pub const ALPHABET_SIZE: usize = 256;

/// скільки раз зустрівся кожен байт
pub fn count_frequencies(data: &[u8]) -> [u64; ALPHABET_SIZE] {
    let mut freqs = [0u64; ALPHABET_SIZE];
    for &byte in data {
        freqs[byte as usize] += 1;
    }

    freqs
}

/// вузол дерева, усе дерево лежить в одному Vec
/// а вузли посилаються на одне одного по індексу
enum Node {
    Leaf(u8),
    Internal(usize, usize), // індекси лівої і правої дитини у векторі вузлів
}

/// довжини кодів для кожного байта за частотами, 0 -> байт не зустрівся і коду нема
pub fn code_lengths(freqs: &[u64; ALPHABET_SIZE]) -> [u8; ALPHABET_SIZE] {
    let mut lengths = [0u8; ALPHABET_SIZE];

    let mut nodes: Vec<Node> = Vec::new();

    // BinaryHeap віддає найбільший елемент
    // але оскільки нам треба найменший ми юзаємо Reverse

    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = BinaryHeap::new();

    for (symbol, &freq) in freqs.iter().enumerate() {
        if freq > 0 {
            nodes.push(Node::Leaf(symbol as u8));
            heap.push(Reverse((freq, nodes.len() - 1)));
        }
    }

    match nodes.len() {
        0 => return lengths,
        1 => {
            // у дереві з одного листа глибина 0, а код довжини 0 неможливий
            // адже тоді нема з чого читати біти. даємо єдиному байту код з 1 біта
            if let Node::Leaf(symbol) = nodes[0] {
                lengths[symbol as usize] = 1;
            }
            return lengths;
        }
        _ => {}
    }

    // основний цикл де ми зливаємо два найлегші вузли в один
    while heap.len() > 1 {
        let Reverse((weight_a, index_a)) = heap.pop().expect("heap has at least two nodes");
        let Reverse((weight_b, index_b)) = heap.pop().expect("heap has at least two nodes");

        nodes.push(Node::Internal(index_a, index_b));

        // сума ваг не переповниться, усі ваги разом дорівнюють довжині даних
        heap.push(Reverse((weight_a + weight_b, nodes.len() - 1)));
    }

    let Reverse((_, root)) = heap.pop().expect("heap has the root");

    // обходимо дерево від кореня, глибина листа і є довжина коду.
    // замість рекурсії явний стек - пари (індекс вузла, глибина)
    let mut stack: Vec<(usize, u8)> = vec![(root, 0)];
    while let Some((index, depth)) = stack.pop() {
        match nodes[index] {
            Node::Leaf(symbol) => lengths[symbol as usize] = depth,
            Node::Internal(left, right) => {
                stack.push((left, depth + 1));
                stack.push((right, depth + 1));
            }
        }
    }
    lengths
}

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::shannon_entropy;

    /// частоти з пар (байт, скільки разів)
    fn freqs_of(pairs: &[(u8, u64)]) -> [u64; ALPHABET_SIZE] {
        let mut freqs = [0u64; ALPHABET_SIZE];
        for &(byte, count) in pairs {
            freqs[byte as usize] = count;
        }
        freqs
    }

    #[test]
    fn counts_frequencies() {
        let freqs = count_frequencies(b"abracadabra");
        assert_eq!(freqs[b'a' as usize], 5);
        assert_eq!(freqs[b'b' as usize], 2);
        assert_eq!(freqs[b'r' as usize], 2);
        assert_eq!(freqs[b'c' as usize], 1);
        assert_eq!(freqs[b'd' as usize], 1);
        assert_eq!(freqs.iter().sum::<u64>(), 11);
    }

    #[test]
    fn empty_input_has_no_codes() {
        let lengths = code_lengths(&count_frequencies(&[]));
        assert_eq!(lengths, [0u8; ALPHABET_SIZE]);
    }

    #[test]
    fn single_symbol_gets_one_bit() {
        let lengths = code_lengths(&count_frequencies(&[7u8; 1000]));
        assert_eq!(lengths[7], 1);
        assert_eq!(lengths.iter().filter(|&&l| l > 0).count(), 1);
    }

    #[test]
    fn two_symbols_get_one_bit_each() {
        let lengths = code_lengths(&freqs_of(&[(10, 5), (200, 1)]));
        assert_eq!(lengths[10], 1);
        assert_eq!(lengths[200], 1);
    }

    #[test]
    fn textbook_example() {
        let freqs = freqs_of(&[
            (b'a', 45),
            (b'b', 13),
            (b'c', 12),
            (b'd', 16),
            (b'e', 9),
            (b'f', 5),
        ]);
        let lengths = code_lengths(&freqs);

        assert_eq!(lengths[b'a' as usize], 1);
        assert_eq!(lengths[b'b' as usize], 3);
        assert_eq!(lengths[b'c' as usize], 3);
        assert_eq!(lengths[b'd' as usize], 3);
        assert_eq!(lengths[b'e' as usize], 4);
        assert_eq!(lengths[b'f' as usize], 4);
    }

    #[test]
    fn ties_are_broken_deterministically() {
        // три байти з однаковою вагою: першими зливаються найменші байти,
        // а найбільший залишається ближче до кореня
        let lengths = code_lengths(&freqs_of(&[(0, 1), (1, 1), (2, 1)]));
        assert_eq!(lengths[0], 2);
        assert_eq!(lengths[1], 2);
        assert_eq!(lengths[2], 1);
    }

    #[test]
    fn same_frequencies_give_same_lengths_regardless_of_order() {
        let a = code_lengths(&count_frequencies(b"aabbbcccc"));
        let b = code_lengths(&count_frequencies(b"cbcbcacab"));
        assert_eq!(a, b);
    }

    #[test]
    fn equal_frequencies_of_all_256_bytes_give_8_bits() {
        let data: Vec<u8> = (0..=255u8).collect();
        let lengths = code_lengths(&count_frequencies(&data));
        assert!(lengths.iter().all(|&l| l == 8));
    }

    #[test]
    fn code_lengths_satisfy_kraft_equality() {
        // повне бінарне дерево: сума 2^(-довжина) по всіх листах дорівнює 1.
        // щоб не рахувати з дробами, множимо на 2^max
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(50);
        let lengths = code_lengths(&count_frequencies(text.as_bytes()));

        let max = *lengths.iter().max().unwrap() as u32;
        let sum: u64 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1u64 << (max - l as u32))
            .sum();
        assert_eq!(sum, 1u64 << max);
    }

    #[test]
    fn average_code_length_is_close_to_entropy() {
        // теорема Шеннона для кодів Гаффмана: H <= середня довжина < H + 1
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(50);
        let data = text.as_bytes();
        let freqs = count_frequencies(data);
        let lengths = code_lengths(&freqs);

        let total_bits: u64 = (0..ALPHABET_SIZE)
            .map(|i| freqs[i] * lengths[i] as u64)
            .sum();
        let avg = total_bits as f64 / data.len() as f64;
        let h = shannon_entropy(data);

        assert!(avg >= h, "avg = {avg}, h = {h}");
        assert!(avg < h + 1.0, "avg = {avg}, h = {h}");
    }

    #[test]
    fn fibonacci_frequencies_make_the_deepest_tree() {
        // частоти 1, 1, 2, 3, 5, 8, ... дають "драбину": кожне злиття
        // додає один рівень. для n байтів глибина n - 1
        let mut pairs = Vec::new();
        let (mut a, mut b) = (1u64, 1u64);
        for symbol in 0..20u8 {
            pairs.push((symbol, a));
            (a, b) = (b, a + b);
        }
        let lengths = code_lengths(&freqs_of(&pairs));

        assert_eq!(*lengths.iter().max().unwrap(), 19);
    }
}
