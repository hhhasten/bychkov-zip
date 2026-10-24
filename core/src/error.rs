use thiserror::Error;

/// єдиний тип помилки для усього ядра
#[derive(Error, Debug)]
pub enum ByzError {
    #[error("internal error: {0}")]
    Internal(String),

    #[error("bad arguments: {0}")]
    BadArgs(String),

    #[error("wrong password or corrupted archive")]
    AuthFailed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsafe path in archive: {0}")]
    UnsafePath(String),

    #[error("input too large: {size} bytes (limit: {limit})")]
    TooLarge { size: u64, limit: u64 },

    #[error("Unsupported archive format: {0}")]
    BadFormat(String),
}
impl ByzError {
    /// код виходу з процесу
    pub fn exit_code(&self) -> i32 {
        match self {
            ByzError::Internal(_) => 1,
            ByzError::BadArgs(_) => 2,
            ByzError::AuthFailed => 3,
            ByzError::Io(_) => 4,
            ByzError::UnsafePath(_) => 5,
            ByzError::TooLarge { .. } => 6,
            ByzError::BadFormat(_) => 7,
        }
    }

    /// символьне представлення коду виходу
    pub fn code_name(&self) -> &'static str {
        match self {
            ByzError::Internal(_) => "INTERNAL",
            ByzError::BadArgs(_) => "BAD_ARGS",
            ByzError::AuthFailed => "AUTH_FAILED",
            ByzError::Io(_) => "IO",
            ByzError::UnsafePath(_) => "UNSAFE_PATH",
            ByzError::TooLarge { .. } => "TOO_LARGE",
            ByzError::BadFormat(_) => "BAD_FORMAT",
        }
    }
}

/// аліас щоб писати Result<T> а не Result<T, ByzError>.
pub type Result<T> = std::result::Result<T, ByzError>;

// юніт тести
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec() {
        assert_eq!(ByzError::AuthFailed.exit_code(), 3);
        assert_eq!(ByzError::UnsafePath("../x".into()).exit_code(), 5);
        assert_eq!(ByzError::BadFormat("x".into()).code_name(), "BAD_FORMAT");
    }
}
