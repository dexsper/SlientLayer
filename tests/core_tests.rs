//! Integration tests for core functionality

use slient_layer::core::{
    calculate_checksum, decrypt_data, encrypt_data, DataHeader, EmbedOptions, ExtractOptions,
};

#[test]
fn test_checksum_consistency() {
    let data1 = b"Test data for checksum";
    let data2 = b"Test data for checksum";
    let data3 = b"Different data";

    let checksum1 = calculate_checksum(data1);
    let checksum2 = calculate_checksum(data2);
    let checksum3 = calculate_checksum(data3);

    assert_eq!(checksum1, checksum2);
    assert_ne!(checksum1, checksum3);
}

#[test]
fn test_encryption_decryption() {
    let original_data = b"This is a secret message that needs encryption";
    let password = "super_secret_password";

    let encrypted = encrypt_data(original_data, password).unwrap();
    
    assert_ne!(encrypted, original_data);
    
    let decrypted = decrypt_data(&encrypted, password).unwrap();
    assert_eq!(decrypted, original_data);
}

#[test]
fn test_encryption_wrong_password() {
    let original_data = b"Secret message";
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    let encrypted = encrypt_data(original_data, correct_password).unwrap();
    
    let result = decrypt_data(&encrypted, wrong_password);
    assert!(result.is_err());
}

#[test]
fn test_encryption_different_results() {
    let data = b"Test data";
    let password = "password";

    let encrypted1 = encrypt_data(data, password).unwrap();
    let encrypted2 = encrypt_data(data, password).unwrap();

    assert_ne!(encrypted1, encrypted2);

    let decrypted1 = decrypt_data(&encrypted1, password).unwrap();
    let decrypted2 = decrypt_data(&encrypted2, password).unwrap();
    assert_eq!(decrypted1, data);
    assert_eq!(decrypted2, data);
}

#[test]
fn test_data_header_validation() {
    let checksum = [0u8; 32];
    let header = DataHeader::new(1024, checksum, true, 5);

    assert_eq!(header.magic, DataHeader::MAGIC);
    assert_eq!(header.version, DataHeader::VERSION);
    assert_eq!(header.payload_len, 1024);
    assert_eq!(header.encrypted, true);
    assert_eq!(header.strength, 5);
    assert!(header.validate());
}

#[test]
fn test_data_header_invalid() {
    let checksum = [0u8; 32];
    let mut header = DataHeader::new(1024, checksum, false, 5);

    header.magic = 0x12345678;
    assert!(!header.validate());
}

#[test]
fn test_embed_options_defaults() {
    let options = EmbedOptions::default();

    assert!(options.password.is_none());
    assert_eq!(options.strength, 5);
    assert_eq!(options.use_ecc, true);
    assert!(options.seed.is_none());
}

#[test]
fn test_extract_options_defaults() {
    let options = ExtractOptions::default();

    assert!(options.password.is_none());
    assert!(options.seed.is_none());
}

#[test]
fn test_embed_options_custom() {
    let options = EmbedOptions {
        password: Some("test_password".to_string()),
        strength: 8,
        use_ecc: false,
        seed: Some(12345),
    };

    assert_eq!(options.password, Some("test_password".to_string()));
    assert_eq!(options.strength, 8);
    assert_eq!(options.use_ecc, false);
    assert_eq!(options.seed, Some(12345));
}

#[test]
fn test_large_data_encryption() {
    let large_data = vec![42u8; 1024 * 1024];
    let password = "password_for_large_data";

    let encrypted = encrypt_data(&large_data, password).unwrap();
    let decrypted = decrypt_data(&encrypted, password).unwrap();

    assert_eq!(decrypted, large_data);
}

#[test]
fn test_empty_data_encryption() {
    let empty_data = b"";
    let password = "password";

    let encrypted = encrypt_data(empty_data, password).unwrap();
    let decrypted = decrypt_data(&encrypted, password).unwrap();

    assert_eq!(decrypted, empty_data);
}

#[test]
fn test_unicode_password() {
    let data = b"Test data";
    let password = "パスワード123";

    let encrypted = encrypt_data(data, password).unwrap();
    let decrypted = decrypt_data(&encrypted, password).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn test_header_serialization() {
    let checksum = calculate_checksum(b"test data");
    let header = DataHeader::new(12345, checksum, true, 7);

    let serialized = header.to_bytes();
    let deserialized = DataHeader::from_bytes(&serialized).unwrap();

    assert_eq!(header.magic, deserialized.magic);
    assert_eq!(header.version, deserialized.version);
    assert_eq!(header.payload_len, deserialized.payload_len);
    assert_eq!(header.checksum, deserialized.checksum);
    assert_eq!(header.encrypted, deserialized.encrypted);
    assert_eq!(header.strength, deserialized.strength);
}
