//! Archive path validation shared by creation and extraction.

use crate::error::{ByzError, Result};
use std::path::PathBuf;

/// Validates an archive-relative path and converts it to a filesystem path.
pub(crate) fn validate_archive_path(path: &str) -> Result<PathBuf> {
    let unsafe_path = |reason: &str| ByzError::UnsafePath(format!("{path:?} ({reason})"));

    if path.is_empty() {
        return Err(unsafe_path("empty path"));
    }
    if path.starts_with('/') {
        return Err(unsafe_path("absolute path"));
    }

    let mut relative = PathBuf::new();
    for part in path.split('/') {
        if part.is_empty() {
            return Err(unsafe_path("empty path component"));
        }
        if part == "." || part == ".." {
            return Err(unsafe_path("'.' or '..' component"));
        }
        if part.contains(['\\', ':']) || part.chars().any(|c| c.is_control()) {
            return Err(unsafe_path("forbidden character"));
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(unsafe_path("name ends with a dot or a space"));
        }
        if is_windows_reserved_name(part) {
            return Err(unsafe_path("reserved device name"));
        }
        relative.push(part);
    }

    Ok(relative)
}

fn is_windows_reserved_name(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();

    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }

    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(bytes[3], b'1'..=b'9')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_paths() {
        for path in [
            "a.txt",
            "dir/a.txt",
            "папка/файл.txt",
            "console.txt",
            "COM10.txt",
        ] {
            assert!(validate_archive_path(path).is_ok(), "{path}");
        }

        assert_eq!(
            validate_archive_path("dir/sub/a.txt").unwrap(),
            PathBuf::from("dir").join("sub").join("a.txt")
        );
    }

    #[test]
    fn rejects_unsafe_paths() {
        for path in [
            "",
            "../evil.txt",
            "a/../../evil.txt",
            "/etc/evil.txt",
            "C:\\evil.txt",
            "..\\evil.txt",
            "a//b.txt",
            "./a.txt",
            "dir/",
            "name.",
            "name ",
            "bad\0name.txt",
        ] {
            assert!(
                matches!(validate_archive_path(path), Err(ByzError::UnsafePath(_))),
                "{path:?}"
            );
        }
    }

    #[test]
    fn rejects_windows_device_names() {
        for path in [
            "CON", "con", "Con.txt", "PRN", "AUX.log", "NUL", "COM1", "com9.txt", "LPT3",
        ] {
            assert!(validate_archive_path(path).is_err(), "{path}");
        }
    }
}
