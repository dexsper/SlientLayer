//! Integration tests for audio steganography

use slient_layer::{embed_audio, extract_audio, AudioSteganography, Steganography, EmbedOptions, ExtractOptions};
use tempfile::NamedTempFile;
use std::io::Write;

fn create_test_wav(duration_secs: u32, sample_rate: u32) -> Vec<u8> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };

    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut cursor, spec).unwrap();

    let samples = (duration_secs.max(30)) * sample_rate;
    for t in 0..samples {
        let freq = 440.0;
        let sample = (t as f32 * freq * 2.0 * std::f32::consts::PI / sample_rate as f32).sin();
        writer.write_sample((sample * i16::MAX as f32) as i16).unwrap();
    }

    writer.finalize().unwrap();
    cursor.into_inner()
}

#[test]
fn test_basic_embed_extract() {
    let carrier = create_test_wav(2, 44100);
    let secret = b"Hello, Audio World!";

    let steg = AudioSteganography::new();
    let options = EmbedOptions::default();

    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

    assert_eq!(secret.as_slice(), extracted.as_slice());
}

#[test]
fn test_with_encryption() {
    let carrier = create_test_wav(2, 44100);
    let secret = b"Encrypted audio message";
    let password = "audio_password_123";

    let steg = AudioSteganography::new();
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
fn test_capacity() {
    let carrier = create_test_wav(30, 44100);
    let steg = AudioSteganography::new();

    let capacity = steg.capacity(&carrier).unwrap();
    assert!(capacity >= 50, "Capacity should be at least 50 bytes, got {}", capacity);

    if capacity > 0 {
        let data = vec![42u8; (capacity / 2).max(1)];
        let options = EmbedOptions::default();
        let result = steg.embed(&carrier, &data, &options);
        assert!(result.is_ok());
    }
}

#[test]
fn test_insufficient_capacity() {
    let carrier = create_test_wav(1, 44100);
    let steg = AudioSteganography::new();

    let capacity = steg.capacity(&carrier).unwrap();
    let data = vec![42u8; capacity + 100];

    let options = EmbedOptions::default();
    let result = steg.embed(&carrier, &data, &options);
    assert!(result.is_err());
}

#[test]
fn test_different_sample_rates() {
    let secret = b"Testing sample rates";
    let steg = AudioSteganography::new();
    let options = EmbedOptions::default();

    for &sample_rate in &[8000, 16000, 22050, 44100, 48000] {
        let carrier = create_test_wav(2, sample_rate);
        
        let embedded = steg.embed(&carrier, secret, &options).unwrap();
        let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

        assert_eq!(
            secret.as_slice(),
            extracted.as_slice(),
            "Failed at sample rate {}",
            sample_rate
        );
    }
}

#[test]
fn test_file_api() {
    let carrier = create_test_wav(2, 44100);
    let secret = b"Testing audio file API";

    // Create temporary files
    let mut input_file = NamedTempFile::new().unwrap();
    let output_file = NamedTempFile::new().unwrap();

    input_file.write_all(&carrier).unwrap();
    input_file.flush().unwrap();

    // Embed
    embed_audio(
        input_file.path(),
        output_file.path(),
        secret,
        Some("password"),
    )
    .unwrap();

    // Extract
    let extracted = extract_audio(output_file.path(), Some("password")).unwrap();
    assert_eq!(secret.as_slice(), extracted.as_slice());
}

#[test]
fn test_verify() {
    let carrier = create_test_wav(2, 44100);
    let secret = b"Audio verification test";

    let steg = AudioSteganography::new();
    let options = EmbedOptions::default();

    // Audio without embedded data
    assert!(!steg.verify(&carrier, &ExtractOptions::default()).unwrap());

    // Audio with embedded data
    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    assert!(steg.verify(&embedded, &ExtractOptions::default()).unwrap());
}

#[test]
fn test_different_strengths() {
    let carrier = create_test_wav(3, 44100);
    let secret = b"Testing audio strengths";

    let steg = AudioSteganography::new();

    for strength in [1, 3, 5, 7, 10] {
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
fn test_unicode_audio_data() {
    let carrier = create_test_wav(2, 44100);
    let secret = "Audio: Привет! 你好! 🎵".as_bytes();

    let steg = AudioSteganography::new();
    let options = EmbedOptions::default();

    let embedded = steg.embed(&carrier, secret, &options).unwrap();
    let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

    assert_eq!(secret, extracted.as_slice());
    assert_eq!(
        "Audio: Привет! 你好! 🎵",
        String::from_utf8(extracted).unwrap()
    );
}
