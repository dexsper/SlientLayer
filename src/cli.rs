//! CLI interface for slient_layer

use crate::audio_steg::{embed_audio, extract_audio};
use crate::core::{ExtractOptions, Steganography};
use crate::error::Result;
use crate::image_steg::{embed_image, extract_image};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "slient")]
#[command(author, version, about = "Compression-resistant steganography tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed data into an image or audio file
    Embed {
        /// Input carrier file (image or audio)
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output file with embedded data
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Data to embed (text message)
        #[arg(short = 'm', long, value_name = "TEXT", group = "data")]
        message: Option<String>,

        /// File containing data to embed
        #[arg(short = 'f', long, value_name = "FILE", group = "data")]
        file: Option<PathBuf>,

        /// Password for encryption (optional)
        #[arg(short, long)]
        password: Option<String>,

        /// Embedding strength (1-10, default: 5)
        #[arg(short, long, default_value_t = 5)]
        strength: u8,

        /// Disable error correction codes
        #[arg(long)]
        no_ecc: bool,

        /// Custom seed for pseudo-random embedding
        #[arg(long)]
        seed: Option<u64>,

        /// Media type (image or audio, auto-detected if not specified)
        #[arg(short = 't', long)]
        media_type: Option<MediaType>,
    },

    /// Extract data from an image or audio file
    Extract {
        /// Input file with embedded data
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output file for extracted data (optional, prints to stdout if not specified)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Password for decryption (if data was encrypted)
        #[arg(short, long)]
        password: Option<String>,

        /// Custom seed (must match embedding seed)
        #[arg(long)]
        seed: Option<u64>,

        /// Media type (image or audio, auto-detected if not specified)
        #[arg(short = 't', long)]
        media_type: Option<MediaType>,

        /// Try to interpret extracted data as UTF-8 text
        #[arg(long)]
        as_text: bool,
    },

    /// Get capacity information for a carrier file
    Capacity {
        /// Input carrier file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Media type (image or audio, auto-detected if not specified)
        #[arg(short = 't', long)]
        media_type: Option<MediaType>,
    },

    /// Verify if a file contains embedded data
    Verify {
        /// Input file to verify
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Password for decryption (if data was encrypted)
        #[arg(short, long)]
        password: Option<String>,

        /// Custom seed (must match embedding seed)
        #[arg(long)]
        seed: Option<u64>,

        /// Media type (image or audio, auto-detected if not specified)
        #[arg(short = 't', long)]
        media_type: Option<MediaType>,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum MediaType {
    Image,
    Audio,
}

impl MediaType {
    fn from_extension(path: &PathBuf) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext.to_lowercase().as_str() {
                "png" | "jpg" | "jpeg" | "bmp" | "gif" | "webp" => Some(MediaType::Image),
                "wav" | "wave" => Some(MediaType::Audio),
                _ => None,
            })
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Embed {
            input,
            output,
            message,
            file,
            password,
            strength,
            no_ecc: _,
            seed: _,
            media_type,
        } => {
            // Validate input file exists
            if !input.exists() {
                return Err(crate::error::SlientError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Input file not found: {}", input.display())
                    )
                ));
            }

            // Get data to embed
            let data = if let Some(msg) = message {
                msg.into_bytes()
            } else if let Some(file_path) = file {
                if !file_path.exists() {
                    return Err(crate::error::SlientError::Io(
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Data file not found: {}", file_path.display())
                        )
                    ));
                }
                std::fs::read(&file_path)?
            } else {
                return Err(crate::error::SlientError::InvalidData(
                    "Either --message or --file must be specified".to_string(),
                ));
            };

            // Validate data is not empty
            if data.is_empty() {
                return Err(crate::error::SlientError::InvalidData(
                    "Cannot embed empty data".to_string(),
                ));
            }

            // Validate strength
            if !(1..=10).contains(&strength) {
                return Err(crate::error::SlientError::InvalidData(
                    "Strength must be between 1 and 10".to_string(),
                ));
            }

            // Determine media type
            let media = media_type
                .or_else(|| MediaType::from_extension(&input))
                .ok_or_else(|| {
                    crate::error::SlientError::UnsupportedFormat(
                        "Could not determine media type. Please specify --media-type".to_string(),
                    )
                })?;

            // Check capacity BEFORE embedding
            let carrier = std::fs::read(&input)?;
            let capacity = match media {
                MediaType::Image => {
                    let steg = crate::image_steg::ImageSteganography::new();
                    steg.capacity(&carrier)?
                }
                MediaType::Audio => {
                    let steg = crate::audio_steg::AudioSteganography::new();
                    steg.capacity(&carrier)?
                }
            };

            println!("Carrier capacity: {} bytes ({:.1} KB)", capacity, capacity as f64 / 1024.0);
            println!("Data to embed: {} bytes ({:.1} KB)", data.len(), data.len() as f64 / 1024.0);

            // Check if data fits
            let header_size = std::mem::size_of::<crate::core::DataHeader>();
            let encrypted_overhead = if password.is_some() { 28 } else { 0 }; // AES-GCM overhead
            let total_needed = data.len() + header_size + encrypted_overhead;

            if total_needed > capacity {
                return Err(crate::error::SlientError::InsufficientCapacity {
                    needed: total_needed,
                    available: capacity,
                });
            }

            let utilization = (total_needed as f64 / capacity as f64) * 100.0;
            println!("Capacity utilization: {:.1}%", utilization);

            if utilization > 80.0 {
                println!("Warning: High capacity utilization (>80%) - consider using a larger carrier");
            }

            println!("\nEmbedding data...");

            match media {
                MediaType::Image => {
                    embed_image(&input, &output, &data, password.as_deref())?;
                }
                MediaType::Audio => {
                    embed_audio(&input, &output, &data, password.as_deref())?;
                }
            }

            println!("Saved to {}", output.display());
        }

        Commands::Extract {
            input,
            output,
            password,
            seed: _,
            media_type,
            as_text,
        } => {
            // Validate input file exists
            if !input.exists() {
                return Err(crate::error::SlientError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Input file not found: {}", input.display())
                    )
                ));
            }

            // Determine media type
            let media = media_type
                .or_else(|| MediaType::from_extension(&input))
                .ok_or_else(|| {
                    crate::error::SlientError::UnsupportedFormat(
                        "Could not determine media type. Please specify --media-type".to_string(),
                    )
                })?;

            println!("Extracting data from {}...", input.display());

            let data = match media {
                MediaType::Image => extract_image(&input, password.as_deref())?,
                MediaType::Audio => extract_audio(&input, password.as_deref())?,
            };

            println!("Extracted {} bytes", data.len());

            if let Some(output_path) = output {
                std::fs::write(&output_path, &data)?;
                println!("Saved to {}", output_path.display());
            } else if as_text {
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        if text.is_empty() {
                            println!("\n(Empty message)");
                        } else {
                            println!("\nExtracted message:\n{}", text);
                        }
                    }
                    Err(_) => {
                        return Err(crate::error::SlientError::InvalidData(
                            format!("Data is not valid UTF-8 text (size: {} bytes). Use without --as-text or specify --output to save binary data.", data.len()),
                        ))
                    }
                }
            } else {
                std::io::Write::write_all(&mut std::io::stdout(), &data)?;
            }
        }

        Commands::Capacity { input, media_type } => {
            // Validate input file exists
            if !input.exists() {
                return Err(crate::error::SlientError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Input file not found: {}", input.display())
                    )
                ));
            }

            let media = media_type
                .or_else(|| MediaType::from_extension(&input))
                .ok_or_else(|| {
                    crate::error::SlientError::UnsupportedFormat(
                        "Could not determine media type. Please specify --media-type".to_string(),
                    )
                })?;

            let carrier = std::fs::read(&input)?;
            let capacity = match media {
                MediaType::Image => {
                    let steg = crate::image_steg::ImageSteganography::new();
                    steg.capacity(&carrier)?
                }
                MediaType::Audio => {
                    let steg = crate::audio_steg::AudioSteganography::new();
                    steg.capacity(&carrier)?
                }
            };

            let file_size = carrier.len();
            let capacity_ratio = (capacity as f64 / file_size as f64) * 100.0;

            println!("File: {}", input.display());
            println!("File size: {} bytes ({:.1} KB)", file_size, file_size as f64 / 1024.0);
            println!("Capacity: {} bytes ({:.1} KB)", capacity, capacity as f64 / 1024.0);
            println!("Capacity ratio: {:.1}%", capacity_ratio);
        }

        Commands::Verify {
            input,
            password,
            seed,
            media_type,
        } => {
            // Validate input file exists
            if !input.exists() {
                return Err(crate::error::SlientError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Input file not found: {}", input.display())
                    )
                ));
            }

            let media = media_type
                .or_else(|| MediaType::from_extension(&input))
                .ok_or_else(|| {
                    crate::error::SlientError::UnsupportedFormat(
                        "Could not determine media type. Please specify --media-type".to_string(),
                    )
                })?;

            let options = ExtractOptions {
                password: password.clone(),
                seed,
            };

            println!("Verifying {}...", input.display());

            let carrier = std::fs::read(&input)?;
            let has_data = match media {
                MediaType::Image => {
                    let steg = crate::image_steg::ImageSteganography::new();
                    steg.verify(&carrier, &options)?
                }
                MediaType::Audio => {
                    let steg = crate::audio_steg::AudioSteganography::new();
                    steg.verify(&carrier, &options)?
                }
            };

            if has_data {
                println!("File contains embedded data");
            } else {
                println!("No embedded data found or verification failed");
                if password.is_none() {
                    println!("  Hint: If data was encrypted, provide --password");
                }
            }
        }
    }

    Ok(())
}
