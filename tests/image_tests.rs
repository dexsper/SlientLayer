//! Integration tests for image steganography

use slient_layer::{embed_image, extract_image, ImageSteganography, Steganography, EmbedOptions, ExtractOptions};
use tempfile::NamedTempFile;
use image::{ImageBuffer, Rgb};
use std::io::Write;

fn create_test_image(width: u32, height: u32) -> Vec<u8> {
    let img = ImageBuffer::from_fn(width, height, |x, y| {
        let r = (x % 256) as u8;
        let g = (y % 256) as u8;
        let b = ((x + y) % 256) as u8;
        Rgb([r, g, b])
    });

    let mut buffer = std::io::Cursor::new(Vec::new());
    img.write_to(&mut buffer, image::ImageFormat::Png).unwrap();
    buffer.into_inner()
}

#[test]
fn test_basic_embed_extract() {
    let carrier = create_test_image(512, 512);
    let secret = b"Hello, World! This is a secret message.";

    let steg = ImageSteganography::new();
    let options = EmbedOptions::default();

    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

    assert_eq!(secret.as_slice(), extracted.as_slice());
}

#[test]
fn test_with_encryption() {
    let carrier = create_test_image(512, 512);
    let secret = b"Encrypted secret message";
    let password = "test_password_123";

    let steg = ImageSteganography::new();
    let embed_opts = EmbedOptions {
        password: Some(password.to_string()),
        ..Default::default()
    };

    let embedded = steg.embed(&carrier, secret, &embed_opts).unwrap();

    let extract_opts = ExtractOptions {
        password: Some(password.to_string()),
        ..Default::default()
    };

    let extracted = steg.extract(&embedded, &extract_opts).unwrap();
    assert_eq!(secret.as_slice(), extracted.as_slice());
}

#[test]
fn test_wrong_password() {
    let carrier = create_test_image(512, 512);
    let secret = b"Secret message";
    let password = "correct_password";

    let steg = ImageSteganography::new();
    let embed_opts = EmbedOptions {
        password: Some(password.to_string()),
        ..Default::default()
    };

    let embedded = steg.embed(&carrier, secret, &embed_opts).unwrap();

    let extract_opts = ExtractOptions {
        password: Some("wrong_password".to_string()),
        ..Default::default()
    };

    let result = steg.extract(&embedded, &extract_opts);
    assert!(result.is_err());
}

#[test]
fn test_capacity() {
    let carrier = create_test_image(512, 512);
    let steg = ImageSteganography::new();

    let capacity = steg.capacity(&carrier).unwrap();
    assert!(capacity > 1000, "Capacity should be reasonable");

    let data = vec![42u8; capacity / 2];
    let options = EmbedOptions::default();
    let result = steg.embed(&carrier, &data, &options);
    assert!(result.is_ok());
}

#[test]
fn test_insufficient_capacity() {
    let carrier = create_test_image(64, 64);
    let steg = ImageSteganography::new();

    let capacity = steg.capacity(&carrier).unwrap();
    let data = vec![42u8; capacity + 1000];

    let options = EmbedOptions::default();
    let result = steg.embed(&carrier, &data, &options);
    assert!(result.is_err());
}

#[test]
fn test_different_strengths() {
    let carrier = create_test_image(512, 512);
    let secret = b"Testing different strengths";

    let steg = ImageSteganography::new();

    for strength in 1..=10 {
        let options = EmbedOptions {
            strength,
            ..Default::default()
        };

        let embedded = steg.embed(&carrier, secret, &options).unwrap();
        let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

        assert_eq!(secret.as_slice(), extracted.as_slice(), "Failed at strength {}", strength);
    }
}

#[test]
fn test_file_api() {
    let carrier = create_test_image(512, 512);
    let secret = b"Testing file API";

    let mut input_file = NamedTempFile::new().unwrap();
    let output_file = NamedTempFile::new().unwrap();

    input_file.write_all(&carrier).unwrap();
    input_file.flush().unwrap();

    embed_image(
        input_file.path(),
        output_file.path(),
        secret,
        Some("password"),
    )
    .unwrap();

    let extracted = extract_image(output_file.path(), Some("password")).unwrap();
    assert_eq!(secret.as_slice(), extracted.as_slice());
}

#[test]
fn test_large_data() {
    let carrier = create_test_image(1024, 1024);
    let steg = ImageSteganography::new();

    let capacity = steg.capacity(&carrier).unwrap();
    let large_data = vec![0x42u8; capacity.min(10000)];

    let options = EmbedOptions::default();
    let embedded = steg.embed(&carrier, &large_data, &options).unwrap();
    let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

    assert_eq!(large_data, extracted);
}

#[test]
fn test_unicode_data() {
    let carrier = create_test_image(512, 512);
    let secret = "Привет, мир! 你好世界! 🌍🚀".as_bytes();

    let steg = ImageSteganography::new();
    let options = EmbedOptions::default();

    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

    assert_eq!(secret, extracted.as_slice());
    assert_eq!(
        "Привет, мир! 你好世界! 🌍🚀",
        String::from_utf8(extracted).unwrap()
    );
}

#[test]
fn test_verify() {
    let carrier = create_test_image(512, 512);
    let secret = b"Verification test";

    let steg = ImageSteganography::new();
    let options = EmbedOptions::default();

    assert!(!steg.verify(&carrier, &ExtractOptions::default()).unwrap());

    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    assert!(steg.verify(&embedded, &ExtractOptions::default()).unwrap());
}
