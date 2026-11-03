//! Command-line arguments.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "byz", version, about = "Encrypted archiver")]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an archive
    #[command(alias = "c")]
    Create {
        /// Output archive
        output: PathBuf,

        /// Files and directories to add
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Overwrite the output archive if it exists
        #[arg(long)]
        force: bool,
    },

    /// Extract an archive
    #[command(alias = "x")]
    Extract {
        /// Archive to extract
        archive: PathBuf,

        /// Output directory (defaults to the current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

pub fn parse() -> Args {
    Args::parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from([&["byz"], args].concat()).unwrap()
    }

    #[test]
    fn parses_create_with_alias_and_force() {
        let args = parse(&["c", "out.byz", "a.txt", "docs", "--force"]);
        let Command::Create {
            output,
            inputs,
            force,
        } = args.command
        else {
            panic!("expected create");
        };
        assert_eq!(output, PathBuf::from("out.byz"));
        assert_eq!(inputs, [PathBuf::from("a.txt"), PathBuf::from("docs")]);
        assert!(force);
    }

    #[test]
    fn parses_extract_with_output() {
        let args = parse(&["x", "in.byz", "-o", "out"]);
        let Command::Extract { archive, output } = args.command else {
            panic!("expected extract");
        };
        assert_eq!(archive, PathBuf::from("in.byz"));
        assert_eq!(output, Some(PathBuf::from("out")));
    }

    #[test]
    fn create_requires_at_least_one_input() {
        assert!(Args::try_parse_from(["byz", "create", "out.byz"]).is_err());
    }
}
