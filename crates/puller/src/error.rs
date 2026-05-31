use thiserror::Error;

pub type PullerResult<T> = Result<T, PullerError>;

#[derive(Debug, Error)]
pub enum PullerError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("HTTP {status} from {url}: {body}")]
    Http {
        url: String,
        status: u16,
        body: String,
    },
    #[error("manifest validation failed: {0}")]
    Validation(String),
    #[error(
        "blob hash mismatch: expected {} but got {}",
        hex::encode(.expected),
        hex::encode(.actual)
    )]
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("blob size mismatch: expected {expected} bytes but got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("io error: {0}")]
    Io(String),
}
