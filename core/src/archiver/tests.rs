//! Unit tests for archive creation and extraction.

use super::create::seal;
use super::*;
use crate::crypto::{decrypt, derive_key};
use crate::error::{ByzError, Result};
use crate::format::{FLAG_COMPRESSED, FileEntry, HEADER_LEN, Header, Metadata};
use crate::huffman;
use std::fs;
use std::path::{Path, PathBuf};

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
