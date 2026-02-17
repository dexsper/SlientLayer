//! # Slient Layer - Compression-Resistant Steganography Library
//!
//! A Rust library for hiding data in images and audio files with resistance to compression.
//! Uses DCT-based and spread spectrum techniques to survive JPEG compression and lossy audio encoding.
//!
//! ## Features
//!
//! - **Image steganography**: Hide data in PNG/JPEG images with DCT-based embedding
//! - **Audio steganography**: Hide data in WAV files using spread spectrum
//! - **Compression resistance**: Data survives JPEG compression and MP3 encoding with <5% loss
//! - **CLI tool**: Command-line interface for easy usage
//! - **FFI support**: C-compatible API for use in other languages
//! - **Extensible**: Easy to add support for video formats
//!
//! ## Usage
//!
//! ```rust,no_run
//! use slient_layer::{ImageSteganography, embed_image, extract_image};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Hide data in an image
//! let secret = b"Hello, World!";
//! embed_image(
//!     Path::new("input.png"),
//!     Path::new("output.png"),
//!     secret,
//!     Some("password")
//! )?;
//!
//! // Extract data from an image
//! let extracted = extract_image(
//!     Path::new("output.png"),
//!     Some("password")
//! )?;
//! assert_eq!(extracted, secret);
//! # Ok(())
//! # }
//! ```

pub mod core;
pub mod error;
pub mod image_steg;
pub mod audio_steg;
pub mod cli;
pub mod ffi;

pub use crate::core::{Steganography, EmbedOptions, ExtractOptions};
pub use crate::error::{Result, SlientError};
pub use crate::image_steg::{ImageSteganography, embed_image, extract_image};
pub use crate::audio_steg::{AudioSteganography, embed_audio, extract_audio};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
