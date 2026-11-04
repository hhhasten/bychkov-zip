//! Archive extraction.

use super::{
    DECRYPT_PROGRESS_END, EXTRACT_PROGRESS_END, Event, MAX_ARCHIVE_BYTES, MAX_INPUT_BYTES, Stage,
    scaled_percent,
};
use crate::crypto::{decrypt, derive_key};
use crate::error::{ByzError, Result, io_error_with_path};
use crate::format::{HEADER_LEN, Header, Metadata};
use crate::huffman;
use crate::path::validate_archive_path;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// зворотній бік `seal`: перевіряє заголовок, виводить ключ і розшифровує.
/// неправильний пароль чи зіпсований файл це `AuthFailed`
fn open_sealed(archive: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let header = Header::from_bytes(archive)?;
    // довжину вже перевірив from_bytes, тож split_at не панікує
    let (header_bytes, ciphertext) = archive.split_at(HEADER_LEN);

    let key = derive_key(password, &header.salt, header.version)?;
    decrypt(ciphertext, &key, &header.nonce, header_bytes)
}

/// розпаковує архів `archive_path` у папку `output_dir`.
///
/// порядок важливий: спочатку розшифрування і перевірка всього (метадані, розміри,
/// шляхи, дублі), потім розпаковка в пам'ять, і лише після цього перший запис на диск.
/// тому неправильний пароль, зіпсований архів чи небезпечний шлях не залишають
/// на диску нічого
pub fn extract_archive(
    archive_path: &Path,
    output_dir: &Path,
    password: &[u8],
    on_event: &mut dyn FnMut(Event),
) -> Result<()> {
    if password.is_empty() {
        return Err(ByzError::BadArgs("password must not be empty".into()));
    }

    on_event(Event::Status(Stage::Decrypting));
    on_event(Event::Progress(0));

    // розмір дивимось до читання, щоб гігантський файл не з'їв пам'ять
    let size = fs::metadata(archive_path)
        .map_err(|e| io_error_with_path(e, archive_path))?
        .len();
    if size > MAX_ARCHIVE_BYTES {
        return Err(ByzError::TooLarge {
            size,
            limit: MAX_ARCHIVE_BYTES,
        });
    }
    let archive = fs::read(archive_path).map_err(|e| io_error_with_path(e, archive_path))?;

    let plaintext = open_sealed(&archive, password)?;
    drop(archive);

    let (meta, meta_len) = Metadata::from_bytes(&plaintext)?;
    let blobs = &plaintext[meta_len..];

    // блоки мають займати рівно стільки, скільки сказано в метаданих
    if meta.total_stored_len() != Some(blobs.len() as u64) {
        return Err(ByzError::BadFormat(
            "file data size does not match the metadata".into(),
        ));
    }

    // захист від "бомби": розпаковане не може перевищувати ліміт, з яким архіви створюються
    let total_original = meta
        .files
        .iter()
        .fold(0u64, |sum, file| sum.saturating_add(file.original_len));
    if total_original > MAX_INPUT_BYTES {
        return Err(ByzError::TooLarge {
            size: total_original,
            limit: MAX_INPUT_BYTES,
        });
    }

    // усі шляхи перевіряються до того, як щось записано на диск
    let relative_paths = validate_entries(&meta)?;

    on_event(Event::Progress(DECRYPT_PROGRESS_END));
    on_event(Event::Status(Stage::Extracting));

    // розпаковуємо все в пам'ять: якщо якийсь блок зіпсований, дізнаємось про це
    // до запису першого файлу
    let total_stored = blobs.len() as u64;
    let mut restored: Vec<Vec<u8>> = Vec::with_capacity(meta.files.len());
    let mut offset: usize = 0;
    let mut processed: u64 = 0;

    for entry in &meta.files {
        let stored_len = usize::try_from(entry.stored_len)
            .map_err(|_| ByzError::BadFormat("file block is too large".into()))?;
        let blob = offset
            .checked_add(stored_len)
            .and_then(|end| blobs.get(offset..end))
            .ok_or_else(|| ByzError::BadFormat("file block is out of range".into()))?;
        offset += stored_len;

        let content = if entry.is_compressed() {
            huffman::decompress(blob, entry.original_len)?
        } else {
            blob.to_vec()
        };
        restored.push(content);

        processed += entry.stored_len;
        on_event(Event::Progress(scaled_percent(
            processed,
            total_stored,
            DECRYPT_PROGRESS_END,
            EXTRACT_PROGRESS_END,
        )));
    }

    write_files(output_dir, &relative_paths, &restored)?;

    on_event(Event::Progress(100));
    on_event(Event::Status(Stage::Complete));

    Ok(())
}

/// Validates all paths and rejects duplicates (case-insensitive).
fn validate_entries(meta: &Metadata) -> Result<Vec<PathBuf>> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut paths = Vec::with_capacity(meta.files.len());

    for entry in &meta.files {
        let relative = validate_archive_path(&entry.path)?;

        if !seen.insert(entry.path.to_lowercase()) {
            return Err(ByzError::BadFormat(format!(
                "archive contains the same path twice: {:?}",
                entry.path
            )));
        }
        paths.push(relative);
    }

    Ok(paths)
}

/// записує розпаковані файли в `output_dir`
fn write_files(output_dir: &Path, relative_paths: &[PathBuf], contents: &[Vec<u8>]) -> Result<()> {
    fs::create_dir_all(output_dir).map_err(|e| io_error_with_path(e, output_dir))?;
    // канонічний шлях: усі символічні посилання розкриті, з ним порівнюємо кожну ціль
    let root = fs::canonicalize(output_dir).map_err(|e| io_error_with_path(e, output_dir))?;

    // спочатку перевіряємо що жоден файл не існує, щоб не перезаписати чуже
    // і не писати половину файлів, якщо третій вже зайнятий
    let targets: Vec<PathBuf> = relative_paths.iter().map(|rel| root.join(rel)).collect();
    for target in &targets {
        if fs::symlink_metadata(target).is_ok() {
            return Err(ByzError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} already exists", target.display()),
            )));
        }
    }

    for (target, content) in targets.iter().zip(contents) {
        let parent = target
            .parent()
            .expect("target is inside root, so it always has a parent");
        fs::create_dir_all(parent).map_err(|e| io_error_with_path(e, parent))?;

        // друга лінія захисту: якщо проміжна папка виявилась символічним посиланням
        // назовні, справжній шлях батька вийде за межі root
        let real_parent = fs::canonicalize(parent).map_err(|e| io_error_with_path(e, parent))?;
        if !real_parent.starts_with(&root) {
            return Err(ByzError::UnsafePath(format!(
                "{:?} (resolves outside of the output folder)",
                target
            )));
        }

        // create_new відмовляється відкривати файл що вже існує
        // (і не йде за символічним посиланням)
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .map_err(|e| io_error_with_path(e, target))?;
        file.write_all(content)
            .map_err(|e| io_error_with_path(e, target))?;
    }

    Ok(())
}
