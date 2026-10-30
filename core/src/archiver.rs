//! оркестратор: збирає архів .byz з файлів (а пізніше і розбирає назад)
//!
//! сам нічого не рахує, лише викликає інші модулі в потрібному порядку:
//!   файли -> entropy -> huffman -> format (метадані) -> crypto -> запис .byz
//!
//! про прогрес архіватор нічого не друкує: він викликає функцію `on_event`,
//! яку йому передали. що з цими подіями робити (вивести в stdout, показати
//! в тестах) вирішує той, хто викликає
//!

use crate::crypto::{derive_key, encrypt, random_nonce, random_salt};
use crate::entropy::is_incompressible;
use crate::error::{ByzError, Result};
use crate::format::{FileEntry, HEADER_LEN, Header, Metadata};
use crate::huffman;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const MAX_INPUT_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Analyzing,
    Compressing,
    Encrypting,
    Complete,
}

impl Stage {
    /// текст для рядка `status:текст` з контракту cli
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Analyzing => "analyzing",
            Stage::Compressing => "compressing",
            Stage::Encrypting => "encrypting",
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

struct Input {
    path: PathBuf,
    archive_path: String,
    size: u64,
}

/// створює архів `output` з файлів `inputs`, захищений паролем.
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

        on_event(Event::Progress(percent(processed_bytes, total_bytes)));
    }

    on_event(Event::Status(Stage::Encrypting));

    let mut plaintext = Metadata { files: entries }.to_bytes()?;
    plaintext.extend_from_slice(&blobs);

    let salt = random_salt()?;
    let nonce = random_nonce()?;
    let header = Header::new(salt, nonce);
    let header_bytes = header.to_bytes();

    let key = derive_key(password, &salt, header.version)?;

    let ciphertext = encrypt(&plaintext, &key, &nonce, &header_bytes)?;
    on_event(Event::Progress(ENCRYPT_PROGRESS_END));

    let mut archive = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    archive.extend_from_slice(&header_bytes);
    archive.extend_from_slice(&ciphertext);
    write_file(output, &archive)?;

    on_event(Event::Progress(100));
    on_event(Event::Status(Stage::Complete));

    Ok(())
}

/// відсотки в межах етапу стиснення (0..=COMPRESS_PROGRESS_END)
fn percent(processed: u64, total: u64) -> u8 {
    if total == 0 {
        return COMPRESS_PROGRESS_END;
    }
    // u64 вистачає: processed не більше 500 МБ, множимо на 90
    (processed * COMPRESS_PROGRESS_END as u64 / total) as u8
}

/// перевіряє вхідні шляхи і збирає про них все потрібне.
/// `limit` це ліміт сумарного розміру
fn collect_inputs(paths: &[PathBuf], limit: u64) -> Result<Vec<Input>> {
    if paths.is_empty() {
        return Err(ByzError::BadArgs("no input files".into()));
    }

    let mut files = Vec::with_capacity(paths.len());
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;

    for path in paths {
        let meta = fs::metadata(path).map_err(|e| io_error_with_path(e, path))?;

        if meta.is_dir() {
            return Err(ByzError::BadArgs(format!(
                "{} is a folder, only files are supported",
                path.display()
            )));
        }
        if !meta.is_file() {
            return Err(ByzError::BadArgs(format!(
                "{} is not a regular file",
                path.display()
            )));
        }

        let archive_path = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                ByzError::BadArgs(format!(
                    "file name of {} is not valid utf-8",
                    path.display()
                ))
            })?
            .to_owned();

        // у архіві зберігаються лише імена, тож два файли з однаковим іменем
        // з різних папок при розпакуванні перезаписали б один одного
        if !seen_names.insert(archive_path.clone()) {
            return Err(ByzError::BadArgs(format!(
                "two input files have the same name: {archive_path}"
            )));
        }

        total = total.saturating_add(meta.len());
        if total > limit {
            return Err(ByzError::TooLarge { size: total, limit });
        }

        files.push(Input {
            path: path.clone(),
            archive_path,
            size: meta.len(),
        });
    }

    Ok(files)
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

/// додає до помилки вводу-виводу шлях, інакше з "file not found" незрозуміло якого саме
fn io_error_with_path(error: io::Error, path: &Path) -> ByzError {
    ByzError::Io(io::Error::new(
        error.kind(),
        format!("{}: {error}", path.display()),
    ))
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
    fn folder_input_is_rejected() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("out.byz");

        let err = create_archive(&[dir.path().to_path_buf()], &output, PASSWORD, &mut |_| {})
            .unwrap_err();
        assert!(matches!(err, ByzError::BadArgs(_)));
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
        assert_eq!(percent(0, 100), 0);
        assert_eq!(percent(50, 100), 45);
        assert_eq!(percent(100, 100), COMPRESS_PROGRESS_END);
        // нема що обробляти: стиснення вважаємо завершеним
        assert_eq!(percent(0, 0), COMPRESS_PROGRESS_END);
    }
}
