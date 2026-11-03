//! CLI command implementations.

use super::args::Command;
use super::password;
use bychkov_zip::archiver::{create_archive, extract_archive};
use bychkov_zip::error::{ByzError, Result};
use std::path::{Path, PathBuf};

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Create {
            output,
            inputs,
            force,
        } => create(&output, &inputs, force),
        Command::Extract { archive, output } => extract(&archive, output.as_deref()),
    }
}

fn create(output: &Path, inputs: &[PathBuf], force: bool) -> Result<()> {
    if !force && output.exists() {
        return Err(ByzError::BadArgs(format!(
            "{} already exists (use --force)",
            output.display()
        )));
    }

    let password = password::read(true)?;
    create_archive(inputs, output, &password, &mut |_| {})
}

fn extract(archive: &Path, output: Option<&Path>) -> Result<()> {
    let password = password::read(false)?;
    extract_archive(
        archive,
        output.unwrap_or(Path::new(".")),
        &password,
        &mut |_| {},
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = TempDir::new().unwrap();
        let output = dir.path().join("out.byz");
        std::fs::write(&output, b"old").unwrap();

        let err = create(&output, &[], false).unwrap_err();
        assert!(matches!(err, ByzError::BadArgs(_)));
        assert_eq!(std::fs::read(output).unwrap(), b"old");
    }
}
