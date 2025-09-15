use thiserror::Error;

#[derive(Error, Debug)]
pub enum CpkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid CPK signature")]
    InvalidSignature,

    #[error("Invalid UTF signature")]
    InvalidUtfSignature,

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid archive format: {0}")]
    InvalidFormat(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, CpkError>;
