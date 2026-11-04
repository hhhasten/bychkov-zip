use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn run(dir: &Path, args: &[&str], password: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_byz"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    if let Some(password) = password {
        // The CLI may reject the arguments and exit before it reads the
        // password, so a broken pipe here is expected and not a test failure.
        if let Err(err) = writeln!(stdin, "{password}") {
            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe, "{err}");
        }
    }
    drop(stdin);

    child.wait_with_output().unwrap()
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn create_and_extract_round_trip() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let archive = dir.path().join("out.byz");
    let unpacked = dir.path().join("unpacked");

    let created = run(
        dir.path(),
        &["create", path(&archive), "a.txt"],
        Some("secret"),
    );
    assert!(created.status.success());

    let extracted = run(
        dir.path(),
        &["extract", path(&archive), "-o", path(&unpacked)],
        Some("secret"),
    );
    assert!(extracted.status.success());
    assert_eq!(fs::read(unpacked.join("a.txt")).unwrap(), b"hello");
}

#[test]
fn dot_archives_the_current_folder_under_its_name() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"hello").unwrap();

    let created = run(dir.path(), &["create", "out.byz", "."], Some("secret"));
    assert!(created.status.success(), "{created:?}");

    let extracted = run(
        dir.path(),
        &["extract", "out.byz", "-o", "unpacked"],
        Some("secret"),
    );
    assert!(extracted.status.success(), "{extracted:?}");

    let folder = dir.path().file_name().unwrap().to_str().unwrap();
    assert_eq!(
        fs::read(dir.path().join("unpacked").join(folder).join("a.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn folder_contents_are_archived() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("docs/sub")).unwrap();
    fs::write(dir.path().join("docs/a.txt"), b"a").unwrap();
    fs::write(dir.path().join("docs/sub/b.txt"), b"b").unwrap();
    let archive = dir.path().join("out.byz");
    let unpacked = dir.path().join("unpacked");

    assert!(
        run(
            dir.path(),
            &["create", path(&archive), "docs"],
            Some("secret")
        )
        .status
        .success()
    );
    assert!(
        run(
            dir.path(),
            &["extract", path(&archive), "-o", path(&unpacked)],
            Some("secret"),
        )
        .status
        .success()
    );

    assert_eq!(fs::read(unpacked.join("docs/sub/b.txt")).unwrap(), b"b");
}

#[test]
fn rejects_wrong_and_empty_passwords() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let archive = dir.path().join("out.byz");

    assert!(
        run(
            dir.path(),
            &["create", path(&archive), "a.txt"],
            Some("secret")
        )
        .status
        .success()
    );

    let wrong = run(
        dir.path(),
        &["extract", path(&archive), "-o", "out"],
        Some("wrong"),
    );
    assert_eq!(wrong.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("byz-error:AUTH_FAILED"));

    let empty = run(
        dir.path(),
        &["create", path(&archive), "a.txt", "--force"],
        Some(""),
    );
    assert_eq!(empty.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&empty.stderr).contains("byz-error:BAD_ARGS"));
}

#[test]
fn existing_archive_requires_force() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let archive = dir.path().join("out.byz");

    for (args, expected) in [
        (vec!["create", path(&archive), "a.txt"], 0),
        (vec!["create", path(&archive), "a.txt"], 2),
        (vec!["create", path(&archive), "a.txt", "--force"], 0),
    ] {
        let result = run(dir.path(), &args, Some("secret"));
        assert_eq!(result.status.code(), Some(expected));
    }
}

#[test]
fn reports_statuses_and_progress_on_stdout() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let archive = dir.path().join("out.byz");

    let result = run(
        dir.path(),
        &["create", path(&archive), "a.txt"],
        Some("secret"),
    );
    assert!(result.status.success());

    let stdout = String::from_utf8(result.stdout).unwrap();
    let mut statuses = Vec::new();
    let mut progress = Vec::new();

    for line in stdout.lines() {
        if let Some(stage) = line.strip_prefix("byz-status:") {
            statuses.push(stage);
        } else if let Some(percent) = line.strip_prefix("byz-progress:") {
            progress.push(percent.parse::<u8>().unwrap());
        } else {
            panic!("unexpected stdout line: {line:?}");
        }
    }

    assert_eq!(statuses.first(), Some(&"analyzing"));
    assert_eq!(statuses.last(), Some(&"complete"));
    assert!(progress.windows(2).all(|pair| pair[0] <= pair[1]));
    assert_eq!(progress.last(), Some(&100));
}

#[test]
fn help_and_version_do_not_read_a_password() {
    let dir = TempDir::new().unwrap();

    let help = run(dir.path(), &["--help"], None);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));

    let version = run(dir.path(), &["--version"], None);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("byz"));
}
