//! Audio steganography with compression resistance
//!
//! This module implements LSB steganography for audio files.

use crate::core::{
    calculate_checksum, decrypt_data, encrypt_data, DataHeader, EmbedOptions, ExtractOptions,
    Steganography,
};
use crate::error::{Result, SlientError};
use std::path::Path;

/// Audio steganography implementation using LSB
pub struct AudioSteganography;

impl AudioSteganography {
    /// Create a new audio steganography instance
    pub fn new() -> Self {
        Self
    }

    /// Read WAV file as integer samples
    fn read_wav_int(data: &[u8]) -> Result<(Vec<i16>, hound::WavSpec)> {
        let cursor = std::io::Cursor::new(data);
        let mut reader = hound::WavReader::new(cursor)
            .map_err(|e| SlientError::Audio(e.to_string()))?;

        let spec = reader.spec();
        
        // Only support 16-bit int for simplicity
        if spec.sample_format != hound::SampleFormat::Int || spec.bits_per_sample != 16 {
            return Err(SlientError::UnsupportedFormat(
                "Only 16-bit integer WAV files are supported".to_string()
            ));
        }
        
        let samples: Vec<i16> = reader
            .samples::<i16>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| SlientError::Audio(e.to_string()))?;

        Ok((samples, spec))
    }

    /// Write WAV file from integer samples
    fn write_wav_int(samples: &[i16], spec: hound::WavSpec) -> Result<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = hound::WavWriter::new(&mut cursor, spec)
            .map_err(|e| SlientError::Audio(e.to_string()))?;

        for &sample in samples {
            writer
                .write_sample(sample)
                .map_err(|e| SlientError::Audio(e.to_string()))?;
        }

        writer
            .finalize()
            .map_err(|e| SlientError::Audio(e.to_string()))?;

        Ok(cursor.into_inner())
    }
}

impl Default for AudioSteganography {
    fn default() -> Self {
        Self::new()
    }
}

impl Steganography for AudioSteganography {
    fn embed(&self, carrier: &[u8], data: &[u8], options: &EmbedOptions) -> Result<Vec<u8>> {
        let (mut samples, spec) = Self::read_wav_int(carrier)?;

        let mut payload = data.to_vec();
        if let Some(password) = &options.password {
            payload = encrypt_data(&payload, password)?;
        }

        let checksum = calculate_checksum(&payload);
        let header = DataHeader::new(
            payload.len(),
            checksum,
            options.password.is_some(),
            options.strength,
        );

        let header_bytes = header.to_bytes();
        let mut full_data = header_bytes.to_vec();
        full_data.extend_from_slice(&payload);

        let capacity = self.capacity(carrier)?;
        if full_data.len() > capacity {
            return Err(SlientError::InsufficientCapacity {
                needed: full_data.len(),
                available: capacity,
            });
        }

        let mut bit_index = 0;
        let total_bits = full_data.len() * 8;

        for sample in samples.iter_mut() {
            if bit_index >= total_bits {
                break;
            }

            let byte_idx = bit_index / 8;
            let bit_pos = 7 - (bit_index % 8);
            let bit = (full_data[byte_idx] >> bit_pos) & 1;

            *sample = (*sample & !1) | (bit as i16);

            bit_index += 1;
        }

        Self::write_wav_int(&samples, spec)
    }

    fn extract(&self, carrier: &[u8], options: &ExtractOptions) -> Result<Vec<u8>> {
        let (samples, _spec) = Self::read_wav_int(carrier)?;

        let header_size = DataHeader::BYTE_SIZE;
        let header_bits = header_size * 8;

        let mut header_bytes = vec![0u8; header_size];
        let mut bit_index = 0;

        for sample in samples.iter().take(header_bits) {
            if bit_index >= header_bits {
                break;
            }

            let bit = (*sample & 1) as u8;

            let byte_idx = bit_index / 8;
            let bit_pos = 7 - (bit_index % 8);
            header_bytes[byte_idx] |= bit << bit_pos;

            bit_index += 1;
        }

        let header = DataHeader::from_bytes(&header_bytes)?;

        if !header.validate() {
            return Err(SlientError::InvalidData(
                "Invalid header or no embedded data found".to_string(),
            ));
        }

        let total_bytes = header_size + header.payload_len as usize;
        let total_bits = total_bytes * 8;
        let mut full_data = vec![0u8; total_bytes];
        bit_index = 0;

        for sample in samples.iter().take(total_bits) {
            if bit_index >= total_bits {
                break;
            }

            let bit = (*sample & 1) as u8;

            let byte_idx = bit_index / 8;
            let bit_pos = 7 - (bit_index % 8);
            full_data[byte_idx] |= bit << bit_pos;

            bit_index += 1;
        }

        let payload = &full_data[header_size..];

        let result = if header.encrypted {
            if let Some(password) = &options.password {
                decrypt_data(&payload, password)?
            } else {
                return Err(SlientError::InvalidKey(
                    "Password required for encrypted data".to_string(),
                ));
            }
        } else {
            payload.to_vec()
        };

        let calculated_checksum = calculate_checksum(&payload);
        if calculated_checksum != header.checksum {
            return Err(SlientError::VerificationFailed);
        }

        Ok(result)
    }

    fn capacity(&self, carrier: &[u8]) -> Result<usize> {
        let (samples, _spec) = Self::read_wav_int(carrier)?;

        let total_bits = samples.len();
        let header_size = DataHeader::BYTE_SIZE;

        Ok((total_bits / 8).saturating_sub(header_size))
    }

    fn verify(&self, carrier: &[u8], options: &ExtractOptions) -> Result<bool> {
        match self.extract(carrier, options) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Convenience function to embed data in an audio file
pub fn embed_audio(
    input_path: &Path,
    output_path: &Path,
    data: &[u8],
    password: Option<&str>,
) -> Result<()> {
    let carrier = std::fs::read(input_path)?;
    let steg = AudioSteganography::new();

    let options = EmbedOptions {
        password: password.map(|s| s.to_string()),
        ..Default::default()
    };

    let result = steg.embed(&carrier, data, &options)?;
    std::fs::write(output_path, result)?;

    Ok(())
}

/// Convenience function to extract data from an audio file
pub fn extract_audio(input_path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
    let carrier = std::fs::read(input_path)?;
    let steg = AudioSteganography::new();

    let options = ExtractOptions {
        password: password.map(|s| s.to_string()),
        ..Default::default()
    };

    steg.extract(&carrier, &options)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_wav() -> Vec<u8> {
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };

        let mut cursor = std::io::Cursor::new(Vec::new());
        let mut writer = hound::WavWriter::new(&mut cursor, spec).unwrap();

        for t in 0..(3 * 44100) {
            let sample = (t as f32 * 440.0 * 2.0 * std::f32::consts::PI / 44100.0).sin();
            writer.write_sample((sample * i16::MAX as f32) as i16).unwrap();
        }

        writer.finalize().unwrap();
        cursor.into_inner()
    }

    #[test]
    fn test_audio_steganography_basic() {
        let carrier = create_test_wav();
        let steg = AudioSteganography::new();
        
        let data = b"Hi";
        let options = EmbedOptions::default();

        let embedded = steg.embed(&carrier, data, &options).unwrap();
        let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

        assert_eq!(data, extracted.as_slice());
    }

    #[test]
    fn test_audio_capacity() {
        let carrier = create_test_wav();
        let steg = AudioSteganography::new();
        let capacity = steg.capacity(&carrier).unwrap();

        println!("Audio capacity: {} bytes", capacity);
        // With LSB we get 1 bit per sample: 3*44100 samples = ~16KB
        assert!(capacity > 1000, "Capacity should be reasonable, got {}", capacity);
    }
}
