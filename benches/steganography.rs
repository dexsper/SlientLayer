use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use image::{ImageBuffer, Rgb};
use slient_layer::{
    AudioSteganography, EmbedOptions, ExtractOptions, ImageSteganography, Steganography,
};
use std::hint::black_box;

fn create_test_image(size: u32) -> Vec<u8> {
    let img = ImageBuffer::from_fn(size, size, |x, y| {
        Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
    });
    let mut buffer = std::io::Cursor::new(Vec::new());
    img.write_to(&mut buffer, image::ImageFormat::Png).unwrap();
    buffer.into_inner()
}

fn create_test_wav(duration_secs: u32) -> Vec<u8> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut cursor, spec).unwrap();
    for t in 0..(duration_secs * 44100) {
        let sample = (t as f32 * 440.0 * 2.0 * std::f32::consts::PI / 44100.0).sin();
        writer
            .write_sample((sample * i16::MAX as f32) as i16)
            .unwrap();
    }
    writer.finalize().unwrap();
    cursor.into_inner()
}

fn bench_image_embed(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_embed");

    for size in [256, 512, 1024].iter() {
        let carrier = create_test_image(*size);
        let data = vec![42u8; 100];
        let steg = ImageSteganography::new();
        let options = EmbedOptions::default();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                steg.embed(black_box(&carrier), black_box(&data), black_box(&options))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_image_extract(c: &mut Criterion) {
    let mut group = c.benchmark_group("image_extract");

    for size in [256, 512, 1024].iter() {
        let carrier = create_test_image(*size);
        let data = vec![42u8; 100];
        let steg = ImageSteganography::new();
        let options = EmbedOptions::default();
        let embedded = steg.embed(&carrier, &data, &options).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                steg.extract(black_box(&embedded), black_box(&ExtractOptions::default()))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_audio_embed(c: &mut Criterion) {
    let mut group = c.benchmark_group("audio_embed");

    for duration in [1, 2, 3].iter() {
        let carrier = create_test_wav(*duration);
        let data = vec![42u8; 50];
        let steg = AudioSteganography::new();
        let options = EmbedOptions::default();

        group.bench_with_input(BenchmarkId::from_parameter(duration), duration, |b, _| {
            b.iter(|| {
                steg.embed(black_box(&carrier), black_box(&data), black_box(&options))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_audio_extract(c: &mut Criterion) {
    let mut group = c.benchmark_group("audio_extract");

    for duration in [1, 2, 3].iter() {
        let carrier = create_test_wav(*duration);
        let data = vec![42u8; 50];
        let steg = AudioSteganography::new();
        let options = EmbedOptions::default();
        let embedded = steg.embed(&carrier, &data, &options).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(duration), duration, |b, _| {
            b.iter(|| {
                steg.extract(black_box(&embedded), black_box(&ExtractOptions::default()))
                    .unwrap()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_image_embed,
    bench_image_extract,
    bench_audio_embed,
    bench_audio_extract
);
criterion_main!(benches);
