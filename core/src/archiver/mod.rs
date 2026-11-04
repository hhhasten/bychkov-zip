//! оркестратор: збирає архів .byz з файлів і розбирає його назад
//!
//! сам нічого не рахує, лише викликає інші модулі в потрібному порядку.
//! упаковка:
//!   файли -> entropy -> huffman -> format (метадані) -> crypto -> запис .byz
//! розпаковка:
//!   читання .byz -> crypto -> format -> перевірка шляхів -> huffman -> запис файлів
//!
//! про прогрес архіватор нічого не друкує: він викликає функцію `on_event`,
//! яку йому передали. що з цими подіями робити (вивести в stdout, показати
//! в тестах) вирішує той, хто викликає
//!

pub const MAX_INPUT_BYTES: u64 = 500 * 1024 * 1024;

// найбільший архів який ми читаємо: ліміт на вміст плюс запас
// на заголовок, тег і метадані (імена файлів)
pub const MAX_ARCHIVE_BYTES: u64 = MAX_INPUT_BYTES + 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    // упаковка
    Analyzing,
    Compressing,
    Encrypting,
    // розпаковка
    Decrypting,
    Extracting,
    Complete,
}

impl Stage {
    /// текст для рядка `byz-status:текст` з контракту cli (префікс додає сам cli)
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Analyzing => "analyzing",
            Stage::Compressing => "compressing",
            Stage::Encrypting => "encrypting",
            Stage::Decrypting => "decrypting",
            Stage::Extracting => "extracting",
            Stage::Complete => "complete",
        }
    }
}

/// подія для того, хто стежить за процесом
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Status(Stage),
    /// відсотки 0..=100
    Progress(u8),
}

// скільки відсотків прогресу займає читання і стиснення файлів.
// шифрування і запис це по одному великому кроку тому їх ми окремо не міряємо
const COMPRESS_PROGRESS_END: u8 = 90;
const ENCRYPT_PROGRESS_END: u8 = 95;

// розпаковка: розшифрування це один крок (0..10), далі розпаковка файлів за байтами (10..90),
// останні відсотки це запис файлів на диск
const DECRYPT_PROGRESS_END: u8 = 10;
const EXTRACT_PROGRESS_END: u8 = 90;

/// відсотки в межах етапу: від `start` до `end` пропорційно до опрацьованих байтів
fn scaled_percent(processed: u64, total: u64, start: u8, end: u8) -> u8 {
    if total == 0 {
        return end;
    }
    let span = (end - start) as u64;
    start + (processed * span / total) as u8
}

mod create;
mod extract;

pub use create::create_archive;
pub use extract::extract_archive;

#[cfg(test)]
mod tests;
