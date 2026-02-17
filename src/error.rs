//! Error types for the slient_layer library

use thiserror::Error;

/// Result type alias for slient_layer operations
pub type Result<T> = std::result::Result<T, SlientError>;

/// Error types that can occur during steganography operations
#[derive(Error, Debug)]
pub enum SlientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Image error: {0}")]
    Image(#[from] image::ImageError),

    #[error("Audio error: {0}")]
    Audio(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Insufficient capacity: need {needed} bytes, but only {available} bytes available")]
    InsufficientCapacity { needed: usize, available: usize },

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Verification failed: data integrity check failed")]
    VerificationFailed,

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decoding error: {0}")]
    Decoding(String),
}

impl From<aes_gcm::Error> for SlientError {
    fn from(err: aes_gcm::Error) -> Self {
        SlientError::Encryption(err.to_string())
    }
}
