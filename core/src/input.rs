//! Collects files and directories for archive creation.

use crate::error::{ByzError, Result, io_error_with_path};
use crate::path::validate_archive_path;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Input {
    pub(crate) path: PathBuf,
    pub(crate) archive_path: String,
    pub(crate) size: u64,
}

pub(crate) fn collect_inputs(paths: &[PathBuf], limit: u64) -> Result<Vec<Input>> {
    if paths.is_empty() {
        return Err(ByzError::BadArgs("no input files".into()));
    }

    let mut collector = Collector::new(limit);
    for path in paths {
        collector.add_input(path)?;
    }
    collector.finish()
}

struct Collector {
    files: Vec<Input>,
    files_seen: HashSet<String>,
    dirs_seen: HashSet<String>,
    total: u64,
    limit: u64,
}

impl Collector {
    fn new(limit: u64) -> Self {
        Self {
            files: Vec::new(),
            files_seen: HashSet::new(),
            dirs_seen: HashSet::new(),
            total: 0,
            limit,
        }
    }

    fn add_input(&mut self, path: &Path) -> Result<()> {
        let meta = fs::symlink_metadata(path).map_err(|e| io_error_with_path(e, path))?;

        if meta.file_type().is_symlink() {
            return Err(ByzError::BadArgs(format!(
                "symlinks are not supported: {}",
                path.display()
            )));
        }

        if meta.is_dir() {
            let prefix = dir_name(path)?;
            self.walk_dir(path, &prefix)
        } else if meta.is_file() {
            self.push(path.to_path_buf(), file_name(path)?.to_owned(), meta.len())
        } else {
            Err(ByzError::BadArgs(format!(
                "{} is not a regular file or directory",
                path.display()
            )))
        }
    }

    fn walk_dir(&mut self, root: &Path, prefix: &str) -> Result<()> {
        let mut stack = vec![(root.to_path_buf(), prefix.to_owned())];

        while let Some((dir, prefix)) = stack.pop() {
            let mut entries = fs::read_dir(&dir)
                .map_err(|e| io_error_with_path(e, &dir))?
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|e| io_error_with_path(e, &dir))?;
            entries.sort_by_key(|entry| entry.file_name());

            for entry in entries {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| {
                    ByzError::BadArgs(format!("file name is not valid UTF-8: {name:?}"))
                })?;
                let archive_path = format!("{prefix}/{name}");

                let file_type = entry
                    .file_type()
                    .map_err(|e| io_error_with_path(e, &path))?;

                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    stack.push((path, archive_path));
                } else if file_type.is_file() {
                    let size = entry
                        .metadata()
                        .map_err(|e| io_error_with_path(e, &path))?
                        .len();
                    self.push(path, archive_path, size)?;
                }
            }
        }

        Ok(())
    }

    fn push(&mut self, path: PathBuf, archive_path: String, size: u64) -> Result<()> {
        validate_archive_path(&archive_path)?;

        if archive_path.len() > usize::from(u16::MAX) {
            return Err(ByzError::BadArgs(format!(
                "path is too long: {archive_path}"
            )));
        }

        let key = archive_path.to_lowercase();
        if self.files_seen.contains(&key) {
            return Err(ByzError::BadArgs(format!(
                "duplicate archive path: {archive_path}"
            )));
        }
        if self.dirs_seen.contains(&key) {
            return Err(ByzError::BadArgs(format!(
                "file conflicts with a folder: {archive_path}"
            )));
        }

        let mut prefix = key.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if self.files_seen.contains(parent) {
                return Err(ByzError::BadArgs(format!(
                    "folder conflicts with a file: {parent}"
                )));
            }
            self.dirs_seen.insert(parent.to_owned());
            prefix = parent;
        }

        self.total = self.total.saturating_add(size);
        if self.total > self.limit {
            return Err(ByzError::TooLarge {
                size: self.total,
                limit: self.limit,
            });
        }

        self.files_seen.insert(key);
        self.files.push(Input {
            path,
            archive_path,
            size,
        });

        Ok(())
    }

    fn finish(self) -> Result<Vec<Input>> {
        if self.files.is_empty() {
            return Err(ByzError::BadArgs(
                "no files found in the input paths".into(),
            ));
        }
        Ok(self.files)
    }
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ByzError::BadArgs(format!("path has no UTF-8 file name: {}", path.display()))
        })
}

/// Archive prefix for a directory input.
/// `.` and `..` have no file name of their own, so use the real folder name.
fn dir_name(path: &Path) -> Result<String> {
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        return Ok(name.to_owned());
    }

    fs::canonicalize(path)
        .map_err(|e| io_error_with_path(e, path))?
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            ByzError::BadArgs(format!(
                "cannot derive a folder name for {}",
                path.display()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(path: &Path, data: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    #[test]
    fn collects_files_and_nested_directories() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("docs/readme.txt"), b"hello");
        write(&dir.path().join("docs/sub/note.txt"), b"note");
        write(&dir.path().join("photo.jpg"), b"img");
        fs::create_dir_all(dir.path().join("docs/empty")).unwrap();

        let inputs = collect_inputs(
            &[dir.path().join("docs"), dir.path().join("photo.jpg")],
            u64::MAX,
        )
        .unwrap();

        let paths: Vec<_> = inputs.iter().map(|i| i.archive_path.as_str()).collect();
        assert_eq!(paths, ["docs/readme.txt", "docs/sub/note.txt", "photo.jpg"]);

        let sizes: Vec<_> = inputs.iter().map(|i| i.size).collect();
        assert_eq!(sizes, [5, 4, 3]);
    }

    #[test]
    fn dot_and_dotdot_get_the_real_folder_name() {
        let cwd = std::env::current_dir().unwrap();
        let expected = cwd.file_name().unwrap().to_str().unwrap();

        assert_eq!(dir_name(Path::new(".")).unwrap(), expected);
        assert!(!dir_name(Path::new("..")).unwrap().is_empty());
    }

    #[test]
    fn rejects_duplicate_paths() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("one/same.txt"), b"a");
        write(&dir.path().join("two/same.txt"), b"b");

        let err = collect_inputs(
            &[
                dir.path().join("one/same.txt"),
                dir.path().join("two/same.txt"),
            ],
            u64::MAX,
        )
        .unwrap_err();

        assert!(matches!(err, ByzError::BadArgs(_)));
    }

    #[test]
    fn rejects_file_folder_conflict() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("docs/a.txt"), b"a");
        write(&dir.path().join("other/docs"), b"file");

        let err = collect_inputs(
            &[dir.path().join("docs"), dir.path().join("other/docs")],
            u64::MAX,
        )
        .unwrap_err();

        assert!(matches!(err, ByzError::BadArgs(_)));
    }

    #[test]
    fn enforces_total_size_limit() {
        let dir = TempDir::new().unwrap();
        write(&dir.path().join("a.bin"), &[0; 600]);
        write(&dir.path().join("b.bin"), &[0; 600]);

        let err = collect_inputs(&[dir.path().join("a.bin"), dir.path().join("b.bin")], 1000)
            .unwrap_err();

        assert!(matches!(
            err,
            ByzError::TooLarge {
                size: 1200,
                limit: 1000
            }
        ));
    }
}
