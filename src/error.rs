use std::fmt;

#[derive(Debug)]
pub enum Error {
    Sql(String),
    Io(String),
    Json(String),
    InvalidManifest(String),
    NotFound(String),
    AlreadyExists(String),
    BelowThreshold(usize, usize),
    LengthMismatch { expected: usize, actual: usize },
    Decode(String),
    DigestMismatch { shard: usize, expected: String, actual: String },
    InjectedFailure(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Sql(e) => write!(f, "sqlite error: {e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Json(e) => write!(f, "json error: {e}"),
            Error::InvalidManifest(e) => write!(f, "invalid manifest: {e}"),
            Error::NotFound(e) => write!(f, "not found: {e}"),
            Error::AlreadyExists(e) => write!(f, "already exists: {e}"),
            Error::BelowThreshold(have, need) => {
                write!(f, "only {have} usable shards, recovery needs {need}")
            }
            Error::LengthMismatch { expected, actual } => {
                write!(f, "shard length mismatch: expected {expected}, got {actual}")
            }
            Error::Decode(e) => write!(f, "decode failed: {e}"),
            Error::DigestMismatch { shard, expected, actual } => write!(
                f,
                "digest mismatch for shard {shard}: expected {expected}, got {actual}"
            ),
            Error::InjectedFailure(op) => write!(f, "injected disk failure during {op}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sql(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
