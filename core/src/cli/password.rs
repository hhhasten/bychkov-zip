//! Password input from a terminal or from stdin.

use bychkov_zip::error::{ByzError, Result};
use std::io::{self, BufRead, IsTerminal, Write};
use zeroize::Zeroizing;

pub fn read(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if io::stdin().is_terminal() {
        let password = terminal("Password: ")?;
        if confirm {
            let repeated = terminal("Confirm password: ")?;
            ensure_match(&password, &repeated)?;
        }
        Ok(password)
    } else {
        stdin_password(io::stdin().lock())
    }
}

fn terminal(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(ByzError::Io)?;

    let text = Zeroizing::new(rpassword::read_password().map_err(ByzError::Io)?);
    Ok(Zeroizing::new(text.as_bytes().to_vec()))
}

fn stdin_password(mut reader: impl BufRead) -> Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(String::new());
    if reader.read_line(&mut line).map_err(ByzError::Io)? == 0 {
        return Err(ByzError::BadArgs("password is required on stdin".into()));
    }

    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    if line.is_empty() {
        return Err(ByzError::BadArgs("password must not be empty".into()));
    }

    Ok(Zeroizing::new(line.as_bytes().to_vec()))
}

fn ensure_match(password: &[u8], repeated: &[u8]) -> Result<()> {
    if password == repeated {
        Ok(())
    } else {
        Err(ByzError::BadArgs("passwords do not match".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_password_line() {
        let password = stdin_password(&b"secret\n"[..]).unwrap();
        assert_eq!(password.as_slice(), b"secret");
    }

    #[test]
    fn keeps_spaces_and_strips_line_ending() {
        let password = stdin_password(&b" pass phrase \r\n"[..]).unwrap();
        assert_eq!(password.as_slice(), b" pass phrase ");
    }

    #[test]
    fn rejects_empty_password_and_eof() {
        for input in [&b"\n"[..], &b"\r\n"[..], &b""[..]] {
            let err = stdin_password(input).unwrap_err();
            assert!(matches!(err, ByzError::BadArgs(_)), "{input:?}");
        }
    }

    #[test]
    fn checks_confirmation() {
        assert!(ensure_match(b"secret", b"secret").is_ok());
        assert!(matches!(
            ensure_match(b"secret", b"other"),
            Err(ByzError::BadArgs(_))
        ));
    }
}
