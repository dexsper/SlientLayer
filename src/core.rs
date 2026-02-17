//! Core traits and structures for steganography operations

use crate::error::{Result, SlientError};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};

/// Main trait for steganography operations
pub trait Steganography {
    /// Embed data into a carrier
    fn embed(&self, carrier: &[u8], data: &[u8], options: &EmbedOptions) -> Result<Vec<u8>>;

    /// Extract data from a carrier
    fn extract(&self, carrier: &[u8], options: &ExtractOptions) -> Result<Vec<u8>>;

    /// Calculate the maximum capacity for data embedding in bytes
    fn capacity(&self, carrier: &[u8]) -> Result<usize>;

    /// Verify if carrier contains embedded data
    fn verify(&self, carrier: &[u8], options: &ExtractOptions) -> Result<bool>;
}

/// Options for embedding data
#[derive(Debug, Clone)]
pub struct EmbedOptions {
    /// Optional password for encryption
    pub password: Option<String>,
    
    /// Strength of embedding (higher = more robust but lower capacity)
    /// Range: 1-10, default: 5
    pub strength: u8,
    
    /// Whether to use error correction codes
    pub use_ecc: bool,
    
    /// Custom seed for pseudo-random embedding pattern
    pub seed: Option<u64>,
}

impl Default for EmbedOptions {
    fn default() -> Self {
        Self {
            password: None,
            strength: 5,
            use_ecc: true,
            seed: None,
        }
    }
}

/// Options for extracting data
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Optional password for decryption
    pub password: Option<String>,
    
    /// Custom seed (must match embedding seed)
    pub seed: Option<u64>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            password: None,
            seed: None,
        }
    }
}

/// Header stored with embedded data for integrity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataHeader {
    /// Magic number for identification
    pub magic: u32,
    
    /// Version of the steganography format
    pub version: u16,
    
    /// Length of the payload in bytes
    pub payload_len: u32,
    
    /// Checksum of the payload (SHA-256 hash)
    pub checksum: [u8; 32],
    
    /// Whether the payload is encrypted
    pub encrypted: bool,
    
    /// Strength parameter used for embedding
    pub strength: u8,
}

impl DataHeader {
    /// Magic number: "SLNT" in ASCII
    pub const MAGIC: u32 = 0x534C4E54;
    
    /// Current format version
    pub const VERSION: u16 = 1;
    
    pub fn new(payload_len: usize, checksum: [u8; 32], encrypted: bool, strength: u8) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::VERSION,
            payload_len: payload_len as u32,
            checksum,
            encrypted,
            strength,
        }
    }
    
    pub fn validate(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }

    /// Fixed size of the binary header (4+2+4+32+1+1 bytes). Format-stable.
    pub const BYTE_SIZE: usize = 4 + 2 + 4 + 32 + 1 + 1;

    /// Serialize header to exactly BYTE_SIZE bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut buf = [0u8; Self::BYTE_SIZE];
        let mut cursor = Cursor::new(&mut buf[..]);
        cursor.write_u32::<LittleEndian>(self.magic).unwrap();
        cursor.write_u16::<LittleEndian>(self.version).unwrap();
        cursor.write_u32::<LittleEndian>(self.payload_len).unwrap();
        cursor.write_all(&self.checksum).unwrap();
        cursor.write_u8(if self.encrypted { 1 } else { 0 }).unwrap();
        cursor.write_u8(self.strength).unwrap();
        buf
    }

    /// Deserialize header from exactly BYTE_SIZE bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::BYTE_SIZE {
            return Err(SlientError::InvalidData(
                "Header buffer too short".to_string(),
            ));
        }
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.read_u32::<LittleEndian>().map_err(|e| SlientError::Decoding(e.to_string()))?;
        let version = cursor.read_u16::<LittleEndian>().map_err(|e| SlientError::Decoding(e.to_string()))?;
        let payload_len = cursor.read_u32::<LittleEndian>().map_err(|e| SlientError::Decoding(e.to_string()))?;
        let mut checksum = [0u8; 32];
        cursor.read_exact(&mut checksum).map_err(|e| SlientError::Decoding(e.to_string()))?;
        let encrypted = cursor.read_u8().map_err(|e| SlientError::Decoding(e.to_string()))? != 0;
        let strength = cursor.read_u8().map_err(|e| SlientError::Decoding(e.to_string()))?;
        Ok(Self { magic, version, payload_len, checksum, encrypted, strength })
    }
}

/// Calculate SHA-256 checksum of data
pub fn calculate_checksum(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Encrypt data using AES-GCM
pub fn encrypt_data(data: &[u8], password: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        Aes256Gcm, Nonce,
    };
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| crate::error::SlientError::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| crate::error::SlientError::Encryption(e.to_string()))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using AES-GCM
pub fn decrypt_data(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use sha2::{Sha256, Digest};

    if encrypted.len() < 12 {
        return Err(crate::error::SlientError::InvalidData(
            "Encrypted data too short".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| crate::error::SlientError::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| crate::error::SlientError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_header_validation() {
        let checksum = [0u8; 32];
        let header = DataHeader::new(100, checksum, true, 5);
        assert!(header.validate());
    }

    #[test]
    fn test_checksum() {
        let data = b"Hello, World!";
        let checksum1 = calculate_checksum(data);
        let checksum2 = calculate_checksum(data);
        assert_eq!(checksum1, checksum2);
    }

    #[test]
    fn test_encryption_decryption() {
        let data = b"Secret message";
        let password = "test_password";

        let encrypted = encrypt_data(data, password).unwrap();
        assert_ne!(encrypted, data);

        let decrypted = decrypt_data(&encrypted, password).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Secret message";
        let password = "test_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt_data(data, password).unwrap();
        let result = decrypt_data(&encrypted, wrong_password);
        assert!(result.is_err());
    }
}
