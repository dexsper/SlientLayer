//! Image steganography with compression resistance
//!
//! This module implements DCT-based steganography for images, which is resistant
//! to JPEG compression. The technique embeds data in the middle-frequency DCT
//! coefficients, which are less affected by compression.

use crate::core::{
    DataHeader, EmbedOptions, ExtractOptions, Steganography, calculate_checksum, decrypt_data,
    encrypt_data,
};
use crate::error::{Result, SlientError};
use image::{GenericImageView, ImageBuffer, Rgb};
use rustdct::DctPlanner;
use std::path::Path;

const BLOCK_SIZE: usize = 8;
const DCT_MID_INDICES: [usize; 6] = [9, 2, 10, 17, 3, 11];

/// Image steganography implementation
pub struct ImageSteganography;

impl ImageSteganography {
    pub fn new() -> Self {
        Self
    }

    fn split_into_blocks(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> Vec<Vec<f64>> {
        let (width, height) = img.dimensions();
        let mut blocks = Vec::new();

        for y in (0..height).step_by(BLOCK_SIZE) {
            for x in (0..width).step_by(BLOCK_SIZE) {
                let mut block = Vec::with_capacity(BLOCK_SIZE * BLOCK_SIZE);

                for dy in 0..BLOCK_SIZE {
                    for dx in 0..BLOCK_SIZE {
                        let px = (x + dx as u32).min(width - 1);
                        let py = (y + dy as u32).min(height - 1);
                        let pixel = img.get_pixel(px, py);
                        let luminance = 0.299 * pixel[0] as f64
                            + 0.587 * pixel[1] as f64
                            + 0.114 * pixel[2] as f64;
                        block.push(luminance);
                    }
                }

                blocks.push(block);
            }
        }

        blocks
    }

    fn apply_dct(blocks: &[Vec<f64>]) -> Vec<Vec<f64>> {
        let mut planner = DctPlanner::new();
        let dct_forward = planner.plan_dct2(BLOCK_SIZE);
        let mut out: Vec<Vec<f64>> = blocks.iter().map(|b| b.clone()).collect();
        let mut row_buf = vec![0.0f64; BLOCK_SIZE];
        let mut col_buf = vec![0.0f64; BLOCK_SIZE];
        for block in out.iter_mut() {
            for row in 0..BLOCK_SIZE {
                row_buf.copy_from_slice(&block[row * BLOCK_SIZE..(row + 1) * BLOCK_SIZE]);
                dct_forward.process_dct2(&mut row_buf);
                block[row * BLOCK_SIZE..(row + 1) * BLOCK_SIZE].copy_from_slice(&row_buf);
            }
            for col in 0..BLOCK_SIZE {
                for row in 0..BLOCK_SIZE {
                    col_buf[row] = block[row * BLOCK_SIZE + col];
                }
                dct_forward.process_dct2(&mut col_buf);
                for row in 0..BLOCK_SIZE {
                    block[row * BLOCK_SIZE + col] = col_buf[row];
                }
            }
        }
        out
    }

    fn apply_idct(blocks: &[Vec<f64>]) -> Vec<Vec<f64>> {
        let mut planner = DctPlanner::new();
        let dct_inverse = planner.plan_dct3(BLOCK_SIZE);
        let mut out: Vec<Vec<f64>> = blocks.iter().map(|b| b.clone()).collect();
        let mut row_buf = vec![0.0f64; BLOCK_SIZE];
        let mut col_buf = vec![0.0f64; BLOCK_SIZE];
        for block in out.iter_mut() {
            for col in 0..BLOCK_SIZE {
                for row in 0..BLOCK_SIZE {
                    col_buf[row] = block[row * BLOCK_SIZE + col];
                }
                dct_inverse.process_dct3(&mut col_buf);
                for row in 0..BLOCK_SIZE {
                    block[row * BLOCK_SIZE + col] = col_buf[row];
                }
            }
            for row in 0..BLOCK_SIZE {
                row_buf.copy_from_slice(&block[row * BLOCK_SIZE..(row + 1) * BLOCK_SIZE]);
                dct_inverse.process_dct3(&mut row_buf);
                block[row * BLOCK_SIZE..(row + 1) * BLOCK_SIZE].copy_from_slice(&row_buf);
            }
        }
        out
    }

    fn embed_bits_in_dct(dct_blocks: &mut [Vec<f64>], data: &[u8], strength: u8) -> Result<()> {
        let delta = (strength as f64).max(1.0) * 15.0;
        let total_bits = data.len() * 8;
        let num_blocks = dct_blocks.len();

        let mut block_order: Vec<usize> = (0..num_blocks).collect();
        let mut state = 12345u64;
        for i in (1..num_blocks).rev() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            let j = (state as usize) % (i + 1);
            block_order.swap(i, j);
        }

        let mut bit_index = 0;
        for &block_idx in &block_order {
            if bit_index >= total_bits {
                break;
            }
            let block = &mut dct_blocks[block_idx];

            for &idx in &DCT_MID_INDICES {
                if bit_index >= total_bits {
                    break;
                }
                let byte_idx = bit_index / 8;
                let bit_pos = 7 - (bit_index % 8);
                let bit = (data[byte_idx] >> bit_pos) & 1;
                let coef = block[idx];
                if bit == 1 {
                    block[idx] = coef.abs() + delta;
                } else {
                    block[idx] = -(coef.abs() + delta * 0.5);
                }
                bit_index += 1;
            }
        }
        Ok(())
    }

    fn extract_bits_from_dct(dct_blocks: &[Vec<f64>], num_bytes: usize, _strength: u8) -> Vec<u8> {
        const SIGN_THRESHOLD: f64 = 0.5;

        let mut data = vec![0u8; num_bytes];
        let total_bits = num_bytes * 8;
        let num_blocks = dct_blocks.len();

        let mut block_order: Vec<usize> = (0..num_blocks).collect();
        let mut state = 12345u64;
        for i in (1..num_blocks).rev() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            let j = (state as usize) % (i + 1);
            block_order.swap(i, j);
        }

        let mut bit_index = 0;
        for &block_idx in &block_order {
            if bit_index >= total_bits {
                break;
            }

            let block = &dct_blocks[block_idx];
            for &idx in &DCT_MID_INDICES {
                if bit_index >= total_bits {
                    break;
                }
                let coef = block[idx];
                let bit = if coef > SIGN_THRESHOLD { 1u8 } else { 0u8 };
                let byte_idx = bit_index / 8;
                let bit_pos = 7 - (bit_index % 8);
                data[byte_idx] |= bit << bit_pos;
                bit_index += 1;
            }
        }
        data
    }

    fn reconstruct_image(
        blocks: &[Vec<f64>],
        width: u32,
        height: u32,
        original: &ImageBuffer<Rgb<u8>, Vec<u8>>,
    ) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
        let blocks_per_row = ((width + BLOCK_SIZE as u32 - 1) / BLOCK_SIZE as u32) as usize;

        // One global scale so the image doesn't get blocky
        let (min_val, max_val) =
            blocks
                .iter()
                .fold((f64::INFINITY, f64::NEG_INFINITY), |(mn, mx), block| {
                    let b_min = block.iter().cloned().fold(f64::INFINITY, f64::min);
                    let b_max = block.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                    (mn.min(b_min), mx.max(b_max))
                });
        let scale = if max_val > min_val {
            255.0 / (max_val - min_val)
        } else {
            1.0
        };
        let offset = min_val;

        let mut img = ImageBuffer::new(width, height);
        for (block_idx, block) in blocks.iter().enumerate() {
            let block_x = (block_idx % blocks_per_row) * BLOCK_SIZE;
            let block_y = (block_idx / blocks_per_row) * BLOCK_SIZE;

            for dy in 0..BLOCK_SIZE {
                for dx in 0..BLOCK_SIZE {
                    let x = block_x + dx;
                    let y = block_y + dy;
                    if x >= width as usize || y >= height as usize {
                        continue;
                    }
                    let new_y = ((block[dy * BLOCK_SIZE + dx] - offset) * scale)
                        .round()
                        .clamp(0.0, 255.0);
                    let new_lum_u8 = new_y as u8;
                    let orig_px = original.get_pixel(x as u32, y as u32);
                    let orig_lum = 0.299 * orig_px[0] as f64
                        + 0.587 * orig_px[1] as f64
                        + 0.114 * orig_px[2] as f64;
                    // Keep color tint but ensure stored luminance is exactly new_lum_u8 (for correct extraction)
                    let (r, g, b) = if orig_lum >= 1.0 {
                        let k = new_lum_u8 as f64 / orig_lum;
                        let r_ = (orig_px[0] as f64 * k).round().clamp(0.0, 255.0) as u8;
                        let g_ = (orig_px[1] as f64 * k).round().clamp(0.0, 255.0) as u8;
                        let b_ = (orig_px[2] as f64 * k).round().clamp(0.0, 255.0) as u8;
                        let got_lum = (0.299 * r_ as f64 + 0.587 * g_ as f64 + 0.114 * b_ as f64)
                            .round() as u8;
                        if got_lum == new_lum_u8 {
                            (r_, g_, b_)
                        } else {
                            (new_lum_u8, new_lum_u8, new_lum_u8)
                        }
                    } else {
                        (new_lum_u8, new_lum_u8, new_lum_u8)
                    };
                    img.put_pixel(x as u32, y as u32, Rgb([r, g, b]));
                }
            }
        }
        img
    }
}

impl Default for ImageSteganography {
    fn default() -> Self {
        Self::new()
    }
}

impl Steganography for ImageSteganography {
    fn embed(&self, carrier: &[u8], data: &[u8], options: &EmbedOptions) -> Result<Vec<u8>> {
        let img = image::load_from_memory(carrier)?;
        let rgb_img = img.to_rgb8();
        let (width, height) = rgb_img.dimensions();

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

        let blocks = Self::split_into_blocks(&rgb_img);
        let mut dct_blocks = Self::apply_dct(&blocks);

        Self::embed_bits_in_dct(&mut dct_blocks, &full_data, options.strength)?;

        let idct_blocks = Self::apply_idct(&dct_blocks);

        let result_img = Self::reconstruct_image(&idct_blocks, width, height, &rgb_img);

        let mut output = Vec::new();
        result_img.write_to(
            &mut std::io::Cursor::new(&mut output),
            image::ImageFormat::Png,
        )?;

        Ok(output)
    }

    fn extract(&self, carrier: &[u8], options: &ExtractOptions) -> Result<Vec<u8>> {
        let img = image::load_from_memory(carrier)?;
        let rgb_img = img.to_rgb8();

        let blocks = Self::split_into_blocks(&rgb_img);
        let dct_blocks = Self::apply_dct(&blocks);

        let header_size = DataHeader::BYTE_SIZE;
        let header_bytes = Self::extract_bits_from_dct(&dct_blocks, header_size, 5);
        let header = DataHeader::from_bytes(&header_bytes)?;

        if !header.validate() {
            return Err(SlientError::InvalidData(
                "Invalid header or no embedded data found".to_string(),
            ));
        }

        let total_bytes = header_size + header.payload_len as usize;
        let full_data = Self::extract_bits_from_dct(&dct_blocks, total_bytes, header.strength);
        let payload = &full_data[header_size..];

        let mut result = payload.to_vec();
        if header.encrypted {
            if let Some(password) = &options.password {
                result = decrypt_data(&result, password)?;
            } else {
                return Err(SlientError::InvalidKey(
                    "Password required for encrypted data".to_string(),
                ));
            }
        }

        let calculated_checksum = calculate_checksum(&payload);
        if calculated_checksum != header.checksum {
            return Err(SlientError::VerificationFailed);
        }

        Ok(result)
    }

    fn capacity(&self, carrier: &[u8]) -> Result<usize> {
        let img = image::load_from_memory(carrier)?;
        let (width, height) = img.dimensions();

        let num_blocks = ((width + BLOCK_SIZE as u32 - 1) / BLOCK_SIZE as u32)
            * ((height + BLOCK_SIZE as u32 - 1) / BLOCK_SIZE as u32);

        let bits_per_block = DCT_MID_INDICES.len();
        let total_bits = (num_blocks as usize) * bits_per_block;

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

pub fn embed_image(
    input_path: &Path,
    output_path: &Path,
    data: &[u8],
    password: Option<&str>,
) -> Result<()> {
    let carrier = std::fs::read(input_path)?;
    let steg = ImageSteganography::new();

    let options = EmbedOptions {
        password: password.map(|s| s.to_string()),
        ..Default::default()
    };

    let result = steg.embed(&carrier, data, &options)?;
    std::fs::write(output_path, result)?;

    Ok(())
}

pub fn extract_image(input_path: &Path, password: Option<&str>) -> Result<Vec<u8>> {
    let carrier = std::fs::read(input_path)?;
    let steg = ImageSteganography::new();

    let options = ExtractOptions {
        password: password.map(|s| s.to_string()),
        ..Default::default()
    };

    steg.extract(&carrier, &options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_steganography_basic() {
        let img = ImageBuffer::from_fn(256, 256, |x, y| {
            let val = ((x + y) % 256) as u8;
            Rgb([val, val, val])
        });

        let mut carrier = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut carrier),
            image::ImageFormat::Png,
        )
        .unwrap();

        let steg = ImageSteganography::new();
        let data = b"Hello, World!";
        let options = EmbedOptions::default();

        let embedded = steg.embed(&carrier, data, &options).unwrap();
        let extracted = steg.extract(&embedded, &ExtractOptions::default()).unwrap();

        assert_eq!(data, extracted.as_slice());
    }

    #[test]
    fn test_capacity() {
        let img = ImageBuffer::from_fn(256, 256, |_, _| Rgb([128u8, 128, 128]));

        let mut carrier = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut carrier),
            image::ImageFormat::Png,
        )
        .unwrap();

        let steg = ImageSteganography::new();
        let capacity = steg.capacity(&carrier).unwrap();

        assert!(capacity > 100);
    }
}
