//! Archive creation.

use super::{
    COMPRESS_PROGRESS_END, ENCRYPT_PROGRESS_END, Event, MAX_INPUT_BYTES, Stage, scaled_percent,
};
use crate::crypto::{derive_key, encrypt, random_nonce, random_salt};
use crate::entropy::is_incompressible;
use crate::error::{ByzError, Result, io_error_with_path};
use crate::format::{FileEntry, HEADER_LEN, Header, Metadata};
use crate::huffman;
use crate::input::collect_inputs;
use std::fs;
use std::path::{Path, PathBuf};

/// створює архів `output` з файлів і папок `inputs`, захищений паролем.
///
/// `on_event` отримує статуси і прогрес. прогрес під час стиснення рахується
/// за реально опрацьованими байтами
pub fn create_archive(
    inputs: &[PathBuf],
    output: &Path,
    password: &[u8],
    on_event: &mut dyn FnMut(Event),
) -> Result<()> {
    if password.is_empty() {
        return Err(ByzError::BadArgs("password must not be empty".into()));
    }

    on_event(Event::Status(Stage::Analyzing));
    let files = collect_inputs(inputs, MAX_INPUT_BYTES)?;
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();

    on_event(Event::Status(Stage::Compressing));
    on_event(Event::Progress(0));

    let mut entries = Vec::with_capacity(files.len());
    let mut blobs: Vec<u8> = Vec::new();
    let mut processed_bytes: u64 = 0;

    for input in files {
        let data = fs::read(&input.path).map_err(|e| io_error_with_path(e, &input.path))?;

        // файл міг вирости між перевіркою розміру і читанням,
        // тому ліміт перевіряємо ще раз за реально прочитаним
        processed_bytes += data.len() as u64;
        if processed_bytes > MAX_INPUT_BYTES {
            return Err(ByzError::TooLarge {
                size: processed_bytes,
                limit: MAX_INPUT_BYTES,
            });
        }

        let (entry, blob) = pack_file(input.archive_path, data)?;
        entries.push(entry);
        blobs.extend_from_slice(&blob);

        on_event(Event::Progress(scaled_percent(
            processed_bytes,
            total_bytes,
            0,
            COMPRESS_PROGRESS_END,
        )));
    }

    on_event(Event::Status(Stage::Encrypting));

    let mut plaintext = Metadata { files: entries }.to_bytes()?;
    plaintext.extend_from_slice(&blobs);

    let archive = seal(&plaintext, password)?;
    on_event(Event::Progress(ENCRYPT_PROGRESS_END));

    write_file(output, &archive)?;

    on_event(Event::Progress(100));
    on_event(Event::Status(Stage::Complete));

    Ok(())
}

/// шифрує відкритий текст і повертає готові байти архіву: заголовок + шифротекст
pub(super) fn seal(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let salt = random_salt()?;
    let nonce = random_nonce()?;
    let header = Header::new(salt, nonce);
    let header_bytes = header.to_bytes();

    let key = derive_key(password, &salt, header.version)?;
    // відкритий заголовок іде як AAD: підмінити його не вийде
    let ciphertext = encrypt(plaintext, &key, &nonce, &header_bytes)?;

    let mut archive = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    archive.extend_from_slice(&header_bytes);
    archive.extend_from_slice(&ciphertext);

    Ok(archive)
}

/// вирішує як зберегти один файл: стиснутим чи як є.
/// повертає запис для метаданих і блок байтів для архіву
fn pack_file(archive_path: String, data: Vec<u8>) -> Result<(FileEntry, Vec<u8>)> {
    let original_len = data.len() as u64;

    // ентропія. якщо дані схожі на випадкові, навіть не пробуємо
    if !is_incompressible(&data) {
        let packed = huffman::compress(&data)?;

        // порівнюємо реальний результат.
        // таблиця довжин додає 256 байт, на малих файлах стиснення програє
        if packed.len() < data.len() {
            let entry = FileEntry::new(archive_path, original_len, packed.len() as u64, true);
            return Ok((entry, packed));
        }
    }

    let entry = FileEntry::new(archive_path, original_len, original_len, false);
    Ok((entry, data))
}

/// пише файл через тимчасовий: якщо щось піде не так посередині,
/// на місці архіву не залишиться обірваний файл
fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);

    if let Err(e) = fs::write(&tmp_path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_error_with_path(e, path));
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(io_error_with_path(e, path));
    }

    Ok(())
}
