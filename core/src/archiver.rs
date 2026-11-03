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

use crate::crypto::{decrypt, derive_key, encrypt, random_nonce, random_salt};
use crate::entropy::is_incompressible;
use crate::error::{ByzError, Result, io_error_with_path};
use crate::format::{FileEntry, HEADER_LEN, Header, Metadata};
use crate::huffman;
use crate::input::collect_inputs;
use crate::path::validate_archive_path;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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

/// відсотки в межах етапу: від `start` до `end` пропорційно до опрацьованих байтів
fn scaled_percent(processed: u64, total: u64, start: u8, end: u8) -> u8 {
    if total == 0 {
        return end;
    }
    let span = (end - start) as u64;
    // u64 вистачає: processed не більше ~500 МБ, множимо щонайбільше на 100
    start + (processed * span / total) as u8
}

/// шифрує відкритий текст і повертає готові байти архіву: заголовок + шифротекст
fn seal(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>> {
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

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt;
    use crate::format::FLAG_COMPRESSED;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use tempfile::TempDir;

    const PASSWORD: &[u8] = b"test password";

    /// створює файл у тимчасовій папці і повертає шлях
    fn make_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(42);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }

    fn text_bytes() -> Vec<u8> {
        "the quick brown fox jumps over the lazy dog. "
            .repeat(200)
            .into_bytes()
    }

    /// створює архів і повертає його вміст та зібрані події
    fn build(inputs: &[PathBuf], dir: &TempDir) -> (Vec<u8>, Vec<Event>) {
        let output = dir.path().join("out.byz");
        let mut events = Vec::new();
        create_archive(inputs, &output, PASSWORD, &mut |e| events.push(e)).unwrap();
        (fs::read(&output).unwrap(), events)
    }

    /// розкриває архів вручну через format і crypto:
    /// повертає метадані і байти блоків усіх файлів підряд
    fn open_archive(archive: &[u8], password: &[u8]) -> Result<(Metadata, Vec<u8>)> {
        let header = Header::from_bytes(archive)?;
        let key = derive_key(password, &header.salt, header.version)?;
        let plaintext = decrypt(
            &archive[HEADER_LEN..],
            &key,
            &header.nonce,
            &archive[..HEADER_LEN],
        )?;
        let (meta, used) = Metadata::from_bytes(&plaintext)?;
        Ok((meta, plaintext[used..].to_vec()))
    }

    #[test]
    fn text_file_is_stored_compressed() {
        let dir = TempDir::new().unwrap();
        let text = text_bytes();
        let file = make_file(&dir, "notes.txt", &text);

        let (archive, _) = build(&[file], &dir);
        let (meta, blobs) = open_archive(&archive, PASSWORD).unwrap();

        let entry = &meta.files[0];
        assert_eq!(entry.path, "notes.txt");
        assert_eq!(entry.original_len, text.len() as u64);
        assert!(entry.is_compressed());
        assert!(entry.stored_len < entry.original_len);
        // блок справді розпаковується назад у вихідний файл
        assert_eq!(
            huffman::decompress(&blobs, entry.original_len).unwrap(),
            text
        );
    }

    #[test]
    fn random_file_is_stored_as_is() {
        let dir = TempDir::new().unwrap();
        let data = random_bytes(20_000);
        let file = make_file(&dir, "photo.jpg", &data);

        let (archive, _) = build(&[file], &dir);
        let (meta, blobs) = open_archive(&archive, PASSWORD).unwrap();

        assert!(!meta.files[0].is_compressed());
        assert_eq!(meta.files[0].stored_len, data.len() as u64);
        assert_eq!(blobs, data);
    }

    #[test]
    fn tiny_file_is_stored_because_huffman_would_make_it_bigger() {
        // ентропія маленького файлу низька, але таблиця довжин (256 байт)
        // робить стиснений варіант більшим. спрацьовує друга лінія захисту
        let dir = TempDir::new().unwrap();
        let file = make_file(&dir, "tiny.txt", b"hello hello hello");

        let (archive, _) = build(&[file], &dir);
        let (meta, blobs) = open_archive(&archive, PASSWORD).unwrap();

        assert!(!meta.files[0].is_compressed());
        assert_eq!(blobs, b"hello hello hello");
    }

    #[test]
    fn empty_file_is_stored() {
        let dir = TempDir::new().unwrap();
        let file = make_file(&dir, "empty.txt", b"");

        let (archive, _) = build(&[file], &dir);
        let (meta, blobs) = open_archive(&archive, PASSWORD).unwrap();

        assert_eq!(meta.files[0].original_len, 0);
        assert_eq!(meta.files[0].stored_len, 0);
        assert!(blobs.is_empty());
    }

    #[test]
    fn several_files_keep_order_and_blob_boundaries() {
        let dir = TempDir::new().unwrap();
        let text = text_bytes();
        let random = random_bytes(5_000);
        let inputs = vec![
            make_file(&dir, "a.txt", &text),
            make_file(&dir, "b.bin", &random),
            make_file(&dir, "c.txt", b"short"),
        ];

        let (archive, _) = build(&inputs, &dir);
        let (meta, blobs) = open_archive(&archive, PASSWORD).unwrap();

        let names: Vec<&str> = meta.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.bin", "c.txt"]);

        // суми розмірів з метаданих збігаються з довжиною області блоків
        assert_eq!(meta.total_stored_len(), Some(blobs.len() as u64));

        // розрізаємо блоки за stored_len і перевіряємо кожен файл
        let mut offset = 0usize;
        let expected: [&[u8]; 3] = [&text, &random, b"short"];
        for (entry, original) in meta.files.iter().zip(expected) {
            let end = offset + entry.stored_len as usize;
            let blob = &blobs[offset..end];
            offset = end;

            let restored = if entry.flags & FLAG_COMPRESSED != 0 {
                huffman::decompress(blob, entry.original_len).unwrap()
            } else {
                blob.to_vec()
            };
            assert_eq!(restored, original, "file {}", entry.path);
        }
    }

    #[test]
    fn archive_starts_with_the_open_header_and_opens_only_with_the_right_password() {
        let dir = TempDir::new().unwrap();
        let file = make_file(&dir, "a.txt", &text_bytes());

        let (archive, _) = build(&[file], &dir);
        assert_eq!(&archive[..4], b"BYZ\x01");

        let err = open_archive(&archive, b"wrong password").unwrap_err();
        assert!(matches!(err, ByzError::AuthFailed));
    }

    #[test]
    fn same_input_gives_different_archives() {
        // сіль і nonce щоразу нові, тож навіть однакові дані дають різні файли
        let dir = TempDir::new().unwrap();
        let file = make_file(&dir, "a.txt", &text_bytes());

        let (first, _) = build(std::slice::from_ref(&file), &dir);
        let (second, _) = build(&[file], &dir);
        assert_ne!(first, second);
    }

    #[test]
    fn events_arrive_in_order_and_progress_never_goes_back() {
        let dir = TempDir::new().unwrap();
        let inputs = vec![
            make_file(&dir, "a.txt", &text_bytes()),
            make_file(&dir, "b.bin", &random_bytes(10_000)),
        ];

        let (_, events) = build(&inputs, &dir);

        let statuses: Vec<Stage> = events
            .iter()
            .filter_map(|e| match e {
                Event::Status(stage) => Some(*stage),
                _ => None,
            })
            .collect();
        assert_eq!(
            statuses,
            vec![
                Stage::Analyzing,
                Stage::Compressing,
                Stage::Encrypting,
                Stage::Complete
            ]
        );

        let progress: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                Event::Progress(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert!(progress.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(progress.first(), Some(&0));
        assert_eq!(progress.last(), Some(&100));
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = TempDir::new().unwrap();
        let file = make_file(&dir, "a.txt", b"data");
        build(&[file], &dir);

        assert!(dir.path().join("out.byz").exists());
        assert!(!dir.path().join("out.byz.tmp").exists());
    }

    #[test]
    fn missing_file_error_names_the_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.txt");
        let output = dir.path().join("out.byz");

        let err = create_archive(&[missing], &output, PASSWORD, &mut |_| {}).unwrap_err();
        assert!(matches!(err, ByzError::Io(_)));
        assert!(err.to_string().contains("nope.txt"));
        assert!(!output.exists());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("one")).unwrap();
        fs::create_dir(dir.path().join("two")).unwrap();
        let a = dir.path().join("one").join("same.txt");
        let b = dir.path().join("two").join("same.txt");
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();

        let err = collect_inputs(&[a, b], MAX_INPUT_BYTES).err().unwrap();
        assert!(matches!(err, ByzError::BadArgs(_)));
    }

    #[test]
    fn no_inputs_and_empty_password_are_rejected() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("out.byz");

        let err = create_archive(&[], &output, PASSWORD, &mut |_| {}).unwrap_err();
        assert!(matches!(err, ByzError::BadArgs(_)));

        let file = make_file(&dir, "a.txt", b"data");
        let err = create_archive(&[file], &output, b"", &mut |_| {}).unwrap_err();
        assert!(matches!(err, ByzError::BadArgs(_)));
    }

    #[test]
    fn total_size_limit_is_enforced_before_reading() {
        let dir = TempDir::new().unwrap();
        let a = make_file(&dir, "a.bin", &[0u8; 600]);
        let b = make_file(&dir, "b.bin", &[0u8; 600]);

        // кожен файл окремо влазить в ліміт 1000, а разом ні
        assert!(collect_inputs(std::slice::from_ref(&a), 1000).is_ok());
        let err = collect_inputs(&[a, b], 1000).err().unwrap();
        assert!(matches!(
            err,
            ByzError::TooLarge {
                size: 1200,
                limit: 1000
            }
        ));
    }

    #[test]
    fn percent_is_proportional_to_processed_bytes() {
        assert_eq!(scaled_percent(0, 100, 0, 90), 0);
        assert_eq!(scaled_percent(50, 100, 0, 90), 45);
        assert_eq!(scaled_percent(100, 100, 0, 90), 90);
        // розпаковка: діапазон 10..90
        assert_eq!(scaled_percent(0, 100, 10, 90), 10);
        assert_eq!(scaled_percent(50, 100, 10, 90), 50);
        assert_eq!(scaled_percent(100, 100, 10, 90), 90);
        // нема що обробляти: етап вважаємо завершеним
        assert_eq!(scaled_percent(0, 0, 0, 90), 90);
    }

    // розпаковка

    /// розпаковує архів у `out` і повертає результат разом з подіями
    fn extract(archive: &Path, out: &Path, password: &[u8]) -> (Result<()>, Vec<Event>) {
        let mut events = Vec::new();
        let result = extract_archive(archive, out, password, &mut |e| events.push(e));
        (result, events)
    }

    /// збирає справжній зашифрований архів з довільними записами (навіть небезпечними),
    /// так, як це міг би зробити зловмисник який знає пароль
    fn forge_archive(path: &Path, files: &[(&str, &[u8])]) {
        let entries = files
            .iter()
            .map(|(name, data)| {
                FileEntry::new(
                    name.to_string(),
                    data.len() as u64,
                    data.len() as u64,
                    false,
                )
            })
            .collect();
        let mut plaintext = Metadata { files: entries }.to_bytes().unwrap();
        for (_, data) in files {
            plaintext.extend_from_slice(data);
        }
        fs::write(path, seal(&plaintext, PASSWORD).unwrap()).unwrap();
    }

    /// те саме, але з готових метаданих і блоків (для зіпсованих варіантів)
    fn forge_raw(path: &Path, metadata: Metadata, blobs: &[u8]) {
        let mut plaintext = metadata.to_bytes().unwrap();
        plaintext.extend_from_slice(blobs);
        fs::write(path, seal(&plaintext, PASSWORD).unwrap()).unwrap();
    }

    #[test]
    fn create_then_extract_restores_every_file() {
        let dir = TempDir::new().unwrap();
        let text = text_bytes();
        let random = random_bytes(8_000);
        let inputs = vec![
            make_file(&dir, "notes.txt", &text),
            make_file(&dir, "photo.jpg", &random),
            make_file(&dir, "tiny.txt", b"hi"),
            make_file(&dir, "empty.txt", b""),
        ];
        let archive = dir.path().join("all.byz");
        create_archive(&inputs, &archive, PASSWORD, &mut |_| {}).unwrap();

        let out = dir.path().join("restored");
        let (result, _) = extract(&archive, &out, PASSWORD);
        result.unwrap();

        assert_eq!(fs::read(out.join("notes.txt")).unwrap(), text);
        assert_eq!(fs::read(out.join("photo.jpg")).unwrap(), random);
        assert_eq!(fs::read(out.join("tiny.txt")).unwrap(), b"hi");
        assert_eq!(fs::read(out.join("empty.txt")).unwrap(), b"");
    }

    #[test]
    fn extract_events_arrive_in_order() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        create_archive(
            &[make_file(&dir, "a.txt", &text_bytes())],
            &archive,
            PASSWORD,
            &mut |_| {},
        )
        .unwrap();

        let (result, events) = extract(&archive, &dir.path().join("out"), PASSWORD);
        result.unwrap();

        let statuses: Vec<Stage> = events
            .iter()
            .filter_map(|e| match e {
                Event::Status(stage) => Some(*stage),
                _ => None,
            })
            .collect();
        assert_eq!(
            statuses,
            vec![Stage::Decrypting, Stage::Extracting, Stage::Complete]
        );

        let progress: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                Event::Progress(p) => Some(*p),
                _ => None,
            })
            .collect();
        assert!(progress.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(progress.first(), Some(&0));
        assert_eq!(progress.last(), Some(&100));
    }

    #[test]
    fn wrong_password_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        create_archive(
            &[make_file(&dir, "a.txt", b"secret")],
            &archive,
            PASSWORD,
            &mut |_| {},
        )
        .unwrap();

        let out = dir.path().join("out");
        let (result, _) = extract(&archive, &out, b"wrong password");
        assert!(matches!(result.unwrap_err(), ByzError::AuthFailed));
        assert!(!out.exists());
    }

    #[test]
    fn extract_rejects_empty_password() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        create_archive(
            &[make_file(&dir, "a.txt", b"x")],
            &archive,
            PASSWORD,
            &mut |_| {},
        )
        .unwrap();

        let (result, _) = extract(&archive, &dir.path().join("out"), b"");
        assert!(matches!(result.unwrap_err(), ByzError::BadArgs(_)));
    }

    #[test]
    fn tampered_archive_is_rejected_and_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        create_archive(
            &[make_file(&dir, "a.txt", &text_bytes())],
            &archive,
            PASSWORD,
            &mut |_| {},
        )
        .unwrap();
        let original = fs::read(&archive).unwrap();

        // змінюємо по одному байту: у nonce (відкритий заголовок), у шифротексті, у тезі
        for position in [20, HEADER_LEN + 3, original.len() - 1] {
            let mut tampered = original.clone();
            tampered[position] ^= 1;
            fs::write(&archive, &tampered).unwrap();

            let out = dir.path().join(format!("out{position}"));
            let (result, _) = extract(&archive, &out, PASSWORD);
            assert!(
                matches!(result.unwrap_err(), ByzError::AuthFailed),
                "position = {position}"
            );
            assert!(!out.exists());
        }
    }

    #[test]
    fn truncated_and_foreign_files_are_rejected() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        create_archive(
            &[make_file(&dir, "a.txt", &text_bytes())],
            &archive,
            PASSWORD,
            &mut |_| {},
        )
        .unwrap();
        let original = fs::read(&archive).unwrap();

        // обрізаний посередині: тег не сходиться
        fs::write(&archive, &original[..original.len() / 2]).unwrap();
        let (result, _) = extract(&archive, &dir.path().join("o1"), PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::AuthFailed));

        // коротший за заголовок
        fs::write(&archive, &original[..10]).unwrap();
        let (result, _) = extract(&archive, &dir.path().join("o2"), PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::BadFormat(_)));

        // взагалі не .byz
        fs::write(&archive, random_bytes(500)).unwrap();
        let (result, _) = extract(&archive, &dir.path().join("o3"), PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::BadFormat(_)));

        // файлу немає
        let (result, _) = extract(
            &dir.path().join("nope.byz"),
            &dir.path().join("o4"),
            PASSWORD,
        );
        assert!(matches!(result.unwrap_err(), ByzError::Io(_)));
    }

    #[test]
    fn zip_slip_entries_are_rejected_and_nothing_is_written() {
        let bad_paths = [
            "../evil.txt",
            "a/../../evil.txt",
            "/etc/evil.txt",
            "C:\\evil.txt",
            "C:evil.txt",
            "..\\evil.txt",
            "a//b.txt",
            "./a.txt",
            "",
            "dir/",
            "CON",
            "nul.txt",
            "name.",
            "name ",
            "bad\0name.txt",
        ];

        for bad in bad_paths {
            let dir = TempDir::new().unwrap();
            let archive = dir.path().join("evil.byz");
            // перший запис нормальний: він теж не має потрапити на диск
            forge_archive(&archive, &[("good.txt", b"good"), (bad, b"evil")]);

            let out = dir.path().join("out");
            let (result, _) = extract(&archive, &out, PASSWORD);
            assert!(
                matches!(result, Err(ByzError::UnsafePath(_))),
                "path {bad:?} was not rejected: {result:?}"
            );
            assert!(!out.exists(), "path {bad:?}: output folder was created");
            assert!(!dir.path().join("evil.txt").exists());
        }
    }

    #[test]
    fn path_validation_accepts_normal_names() {
        for good in [
            "a.txt",
            "dir/a.txt",
            "папка/файл.txt",
            "console.txt",
            "a.b.c",
            "COM10.txt",
        ] {
            assert!(validate_archive_path(good).is_ok(), "{good}");
        }
        assert_eq!(
            validate_archive_path("dir/sub/a.txt").unwrap(),
            PathBuf::from("dir").join("sub").join("a.txt")
        );
    }

    #[test]
    fn windows_device_names_are_rejected() {
        for bad in [
            "CON", "con", "Con.txt", "PRN", "AUX.log", "NUL", "COM1", "com9.txt", "LPT3",
        ] {
            assert!(validate_archive_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn subfolders_from_archive_are_created() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        forge_archive(&archive, &[("docs/inner/readme.txt", b"hello")]);

        let out = dir.path().join("out");
        extract(&archive, &out, PASSWORD).0.unwrap();
        assert_eq!(
            fs::read(out.join("docs").join("inner").join("readme.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn existing_files_are_never_overwritten() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        forge_archive(
            &archive,
            &[("new.txt", b"new"), ("taken.txt", b"from archive")],
        );

        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("taken.txt"), b"mine").unwrap();

        let (result, _) = extract(&archive, &out, PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::Io(_)));
        // чужий файл цілий, і new.txt теж не записаний
        assert_eq!(fs::read(out.join("taken.txt")).unwrap(), b"mine");
        assert!(!out.join("new.txt").exists());
    }

    #[test]
    fn duplicate_paths_in_archive_are_rejected() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        forge_archive(&archive, &[("a.txt", b"1"), ("A.TXT", b"2")]);

        let out = dir.path().join("out");
        let (result, _) = extract(&archive, &out, PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::BadFormat(_)));
        assert!(!out.exists());
    }

    #[test]
    fn blocks_size_must_match_metadata() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        let meta = Metadata {
            files: vec![FileEntry::new("a.txt".into(), 10, 10, false)],
        };
        // у метаданих 10 байт, у блоках 5
        forge_raw(&archive, meta, b"short");

        let (result, _) = extract(&archive, &dir.path().join("out"), PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::BadFormat(_)));
    }

    #[test]
    fn declared_size_above_limit_is_rejected_before_unpacking() {
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        // стиснений запис що обіцяє розпакуватися в більше ніж дозволено
        let meta = Metadata {
            files: vec![FileEntry::new(
                "bomb.bin".into(),
                MAX_INPUT_BYTES + 1,
                0,
                true,
            )],
        };
        forge_raw(&archive, meta, b"");

        let out = dir.path().join("out");
        let (result, _) = extract(&archive, &out, PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::TooLarge { .. }));
        assert!(!out.exists());
    }

    #[test]
    fn corrupted_compressed_block_writes_nothing() {
        // правильна автентифікація, але всередині сміття замість Хаффмана:
        // помилка має виникнути до запису першого файлу
        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("a.byz");
        let meta = Metadata {
            files: vec![
                FileEntry::new("first.txt".into(), 5, 5, false),
                FileEntry::new("second.txt".into(), 100, 10, true),
            ],
        };
        forge_raw(&archive, meta, b"helloGARBAGE!!");

        let out = dir.path().join("out");
        let (result, _) = extract(&archive, &out, PASSWORD);
        assert!(matches!(result.unwrap_err(), ByzError::BadFormat(_)));
        assert!(!out.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_output_cannot_redirect_writes_outside() {
        let dir = TempDir::new().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();

        let out = dir.path().join("out");
        fs::create_dir(&out).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("link")).unwrap();

        let archive = dir.path().join("a.byz");
        forge_archive(&archive, &[("link/stolen.txt", b"data")]);

        let (result, _) = extract(&archive, &out, PASSWORD);
        assert!(matches!(result, Err(ByzError::UnsafePath(_))), "{result:?}");
        assert!(!outside.join("stolen.txt").exists());
    }
}
