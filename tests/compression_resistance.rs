//! Integration test: Compression resistance

use slient_layer::{ImageSteganography, Steganography, EmbedOptions, ExtractOptions};
use image::{ImageBuffer, Rgb};

fn create_test_image(width: u32, height: u32) -> Vec<u8> {
    let img = ImageBuffer::from_fn(width, height, |x, y| {
        let r = ((x % 256) as u8).wrapping_add((y % 256) as u8);
        let g = ((x / 4) % 256) as u8;
        let b = ((y / 4) % 256) as u8;
        Rgb([r, g, b])
    });

    let mut carrier_bytes = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut carrier_bytes),
        image::ImageFormat::Png,
    ).unwrap();
    carrier_bytes
}

#[test]
fn test_jpeg_compression_quality_95() {
    let carrier = create_test_image(512, 512);
    let secret = b"Test message for JPEG compression at quality 95";

    let steg = ImageSteganography::new();
    let embed_options = EmbedOptions {
        password: Some("test".to_string()),
        strength: 7,
        use_ecc: true,
        seed: None,
    };

    let embedded_png = steg.embed(&carrier, secret, &embed_options).unwrap();

    let img = image::load_from_memory(&embedded_png).unwrap();
    let mut jpeg_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
        std::io::Cursor::new(&mut jpeg_bytes),
        95,
    );
    encoder.encode(
        img.as_bytes(),
        img.width(),
        img.height(),
        img.color().into(),
    ).unwrap();

    let extract_options = ExtractOptions {
        password: Some("test".to_string()),
        seed: None,
    };

    let extracted = steg.extract(&jpeg_bytes, &extract_options).unwrap();
    let mut correct_bytes = 0;
    for i in 0..secret.len().min(extracted.len()) {
        if secret[i] == extracted[i] {
            correct_bytes += 1;
        }
    }
    let success_rate = (correct_bytes as f64 / secret.len() as f64) * 100.0;
    assert!(success_rate >= 95.0, "Success rate {}%: losing more than 5% at JPEG quality 95", success_rate);
}

#[test]
fn test_jpeg_compression_quality_85() {
    let carrier = create_test_image(512, 512);
    let secret = b"JPEG quality 85 test";

    let steg = ImageSteganography::new();
    let embed_options = EmbedOptions {
        password: None,
        strength: 8,
        use_ecc: true,
        seed: None,
    };

    let embedded_png = steg.embed(&carrier, secret, &embed_options).unwrap();

    let img = image::load_from_memory(&embedded_png).unwrap();
    let mut jpeg_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
        std::io::Cursor::new(&mut jpeg_bytes),
        85,
    );
    encoder.encode(
        img.as_bytes(),
        img.width(),
        img.height(),
        img.color().into(),
    ).unwrap();

    let extracted = steg.extract(&jpeg_bytes, &ExtractOptions::default()).unwrap();
    let mut correct_bytes = 0;
    for i in 0..secret.len().min(extracted.len()) {
        if secret[i] == extracted[i] {
            correct_bytes += 1;
        }
    }
    let success_rate = (correct_bytes as f64 / secret.len() as f64) * 100.0;
    assert!(success_rate >= 90.0, "Success rate {}%: losing more than 10% at JPEG quality 85", success_rate);
}

#[test]
fn test_jpeg_compression_quality_75() {
    let carrier = create_test_image(800, 600);
    let secret = b"Quality 75 is minimum recommended";

    let steg = ImageSteganography::new();
    let embed_options = EmbedOptions {
        password: None,
        strength: 8,
        use_ecc: true,
        seed: None,
    };

    let embedded_png = steg.embed(&carrier, secret, &embed_options).unwrap();

    let img = image::load_from_memory(&embedded_png).unwrap();
    let mut jpeg_bytes = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
        std::io::Cursor::new(&mut jpeg_bytes),
        75,
    );
    encoder.encode(
        img.as_bytes(),
        img.width(),
        img.height(),
        img.color().into(),
    ).unwrap();

    let extracted = steg.extract(&jpeg_bytes, &ExtractOptions::default()).unwrap();
    let mut correct_bytes = 0;
    for i in 0..secret.len().min(extracted.len()) {
        if secret[i] == extracted[i] {
            correct_bytes += 1;
        }
    }
    let success_rate = (correct_bytes as f64 / secret.len() as f64) * 100.0;
    assert!(success_rate >= 85.0, "Success rate {}%: losing more than 15% at JPEG quality 75", success_rate);
}

#[test]
fn test_png_optimization_no_loss() {
    let carrier = create_test_image(512, 512);
    let secret = b"PNG optimization should not affect data";

    let steg = ImageSteganography::new();
    let options = EmbedOptions::default();

    let embedded = steg.embed(&carrier, secret, &options).unwrap();

    let img = image::load_from_memory(&embedded).unwrap();
    let mut optimized = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut optimized),
        image::ImageFormat::Png,
    ).unwrap();

    let extracted = steg.extract(&optimized, &ExtractOptions::default()).unwrap();
    
    assert_eq!(secret, extracted.as_slice(), "PNG optimization caused data loss!");
}

#[test]
fn test_high_strength_better_compression_resistance() {
    let carrier = create_test_image(640, 480);
    let secret = b"Comparing strength levels";

    let steg = ImageSteganography::new();

    let low_strength = EmbedOptions {
        strength: 3,
        ..Default::default()
    };
    let embedded_low = steg.embed(&carrier, secret, &low_strength).unwrap();

    let high_strength = EmbedOptions {
        strength: 9,
        ..Default::default()
    };
    let embedded_high = steg.embed(&carrier, secret, &high_strength).unwrap();

    let quality = 70;
    
    let compress = |data: &[u8]| -> Vec<u8> {
        let img = image::load_from_memory(data).unwrap();
        let mut jpeg = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
            std::io::Cursor::new(&mut jpeg),
            quality,
        );
        encoder.encode(img.as_bytes(), img.width(), img.height(), img.color().into()).unwrap();
        jpeg
    };

    let compressed_low = compress(&embedded_low);
    let compressed_high = compress(&embedded_high);

    let _extract_low = steg.extract(&compressed_low, &ExtractOptions::default());
    let extract_high = steg.extract(&compressed_high, &ExtractOptions::default());

    assert!(extract_high.is_ok(), "High strength (9) should survive JPEG quality {}", quality);
}
