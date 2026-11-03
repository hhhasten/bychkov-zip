//! Collects files and directories for archive creation.

use crate::error::{ByzError, Result, io_error_with_path};
use crate::path::validate_archive_path;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

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
            let prefix = file_name(path)?;
            self.walk_dir(path, prefix)
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
