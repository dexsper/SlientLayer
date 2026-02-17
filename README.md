# Slient Layer

[![Crates.io](https://img.shields.io/crates/v/slient_layer.svg)](https://crates.io/crates/slient_layer)
[![Documentation](https://docs.rs/slient_layer/badge.svg)](https://docs.rs/slient_layer)
[![License](https://img.shields.io/crates/l/slient_layer.svg)](LICENSE)

A high-performance, compression-resistant steganography library for Rust with support for images and audio files.

## 🔗 Navigation

- [Features](#features)  
- [Installation](#installation)  
- [Quick Start](#quick-start)  
  - [Library Usage](#library-usage)  
  - [CLI Usage](#cli-usage)  
- [How It Works](#how-it-works)  
  - [Image Steganography](#image-steganography-dct-based)  
  - [Audio Steganography](#audio-steganography-spread-spectrum)  
- [FFI Examples](#ffi-foreign-function-interface)  
- [Performance](#performance)  
- [Compression Resistance Tests](#compression-resistance-tests)  
- [Future Features](#future-features-roadmap)  
- [Contributing](#contributing)

## Features

- **🖼️ Image Steganography**: Hide data in PNG/JPEG images using DCT-based embedding
- **🎵 Audio Steganography**: Hide data in WAV files using spread spectrum techniques
- **🔒 Compression Resistant**: Data survives JPEG compression and lossy audio encoding
- **🔐 Encryption**: Optional AES-GCM encryption for embedded data
- **🛠️ CLI Tool**: Easy-to-use command-line interface
- **🌐 FFI Support**: C-compatible API for use in other languages (Python, JavaScript, etc.)
- **⚡ Fast**: Optimized implementation with benchmarks
- **✅ Well-Tested**: Comprehensive test suite with >90% coverage

## Installation

### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
slient_layer = "0.1.0"
```

### As a CLI Tool

```bash
cargo install slient_layer
```

## Quick Start

### Library Usage

#### Image Steganography

```rust
use slient_layer::{embed_image, extract_image};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embed secret data in an image
    let secret = b"This is a secret message!";
    embed_image(
        Path::new("input.png"),
        Path::new("output.png"),
        secret,
        Some("password123")
    )?;

    // Extract the secret data
    let extracted = extract_image(
        Path::new("output.png"),
        Some("password123")
    )?;
    
    assert_eq!(secret, extracted.as_slice());
    println!("Secret: {}", String::from_utf8(extracted)?);
    Ok(())
}
```

#### Audio Steganography

```rust
use slient_layer::{embed_audio, extract_audio};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"Hidden in audio!";
    
    // Embed in WAV file
    embed_audio(
        Path::new("input.wav"),
        Path::new("output.wav"),
        secret,
        Some("password")
    )?;

    // Extract from WAV file
    let extracted = extract_audio(
        Path::new("output.wav"),
        Some("password")
    )?;
    
    assert_eq!(secret, extracted.as_slice());
    Ok(())
}
```

#### Advanced Usage with Options

```rust
use slient_layer::{ImageSteganography, Steganography, EmbedOptions, ExtractOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let carrier = std::fs::read("input.png")?;
    let secret = b"Advanced secret data";
    
    let steg = ImageSteganography::new();
    
    // Check capacity
    let capacity = steg.capacity(&carrier)?;
    println!("Carrier capacity: {} bytes", capacity);
    
    // Embed with custom options
    let options = EmbedOptions {
        password: Some("strong_password".to_string()),
        strength: 7,  // 1-10, higher = more robust
        use_ecc: true,
        seed: Some(42),
    };
    
    let embedded = steg.embed(&carrier, secret, &options)?;
    
    // Verify embedded data
    let extract_opts = ExtractOptions {
        password: Some("strong_password".to_string()),
        seed: Some(42),
    };
    
    if steg.verify(&embedded, &extract_opts)? {
        println!("✓ Data verified");
    }
    
    let extracted = steg.extract(&embedded, &extract_opts)?;
    assert_eq!(secret, extracted.as_slice());
    
    Ok(())
}
```

### CLI Usage

#### Embed Data

```bash
# Embed a text message in an image
slient embed -i input.png -o output.png -m "Secret message" -p mypassword

# Embed a file in an image
slient embed -i photo.jpg -o stego.jpg -f secret.txt -p mypassword --strength 7

# Embed in audio
slient embed -i audio.wav -o stego.wav -m "Hidden message" -p password
```

#### Extract Data

```bash
# Extract and print as text
slient extract -i output.png -p mypassword --as-text

# Extract to file
slient extract -i stego.jpg -o extracted.txt -p mypassword

# Extract from audio
slient extract -i stego.wav -p password --as-text
```

#### Check Capacity

```bash
# Check how much data can be hidden
slient capacity -i image.png
# Output: Capacity of image.png: 15420 bytes (15 KB)
```

#### Verify Embedded Data

```bash
# Check if file contains hidden data
slient verify -i output.png -p mypassword
# Output: ✓ File contains embedded data
```

## How It Works

### Image Steganography (DCT-Based)

Slient Layer uses **Discrete Cosine Transform (DCT)** for image steganography, the same technique used in JPEG compression. This makes the hidden data resistant to JPEG compression:

1. **Block Division**: Image is split into 8×8 pixel blocks
2. **DCT Transform**: Each block is transformed to frequency domain
3. **Mid-Frequency Embedding**: Data is embedded in middle-frequency coefficients (less affected by compression)
4. **Quantization Index Modulation (QIM)**: Robust embedding technique that survives lossy compression
5. **IDCT Transform**: Blocks are transformed back to spatial domain

**Key Benefits:**
- Survives JPEG compression (quality 75+) with <5% data loss
- Imperceptible visual changes
- Large capacity (typically 10-20% of image size)

### Audio Steganography (Spread Spectrum)

For audio files, Slient Layer uses **Spread Spectrum** techniques:

1. **Frame Processing**: Audio is divided into overlapping frames
2. **FFT Transform**: Each frame is transformed to frequency domain
3. **Pseudo-Random Spreading**: Data is spread across multiple frequency bands using PN sequences
4. **Magnitude Modulation**: Frequency magnitudes are slightly modified
5. **IFFT & Overlap-Add**: Frames are transformed back and combined

**Key Benefits:**
- Resistant to MP3 encoding (128 kbps+)
- Inaudible to human ear
- Robust against noise and filtering

## FFI (Foreign Function Interface)

Slient Layer can be used from other programming languages through its C-compatible FFI.

### Python Example (using ctypes)
```python
from ctypes import *

# Load library
lib = CDLL("./target/release/slient_layer.dll")

# Define function signatures
lib.slient_embed_image.argtypes = [
    c_char_p,
    c_char_p,
    POINTER(c_ubyte),
    c_size_t,
    c_char_p,
]
lib.slient_embed_image.restype = c_int

lib.slient_extract_image.argtypes = [
    c_char_p,
    c_char_p,
    POINTER(POINTER(c_ubyte)),
    POINTER(c_size_t),
]
lib.slient_extract_image.restype = c_int

lib.slient_free_data.argtypes = [POINTER(c_ubyte)]

# Embed
secret = b"Hello from Python!"
secret_buf = (c_ubyte * len(secret)).from_buffer_copy(secret)
result = lib.slient_embed_image(
    b"input.jpg", b"output.jpg", secret_buf, len(secret), b"password"
)

if result == 0:
    print("✓ Embedded successfully")

data_ptr = POINTER(c_ubyte)()
data_len = c_size_t()

result = lib.slient_extract_image(
    b"output.jpg", b"password", byref(data_ptr), byref(data_len)
)

if result == 0:
    extracted = bytes(data_ptr[: data_len.value])
    print(f"Extracted: {extracted.decode('utf-8')}")
    lib.slient_free_data(data_ptr)
```

## Performance

Benchmarks on an Intel i7-9750H @ 2.60GHz:

| Operation | Image (512×512) | Audio (2 sec @ 44.1kHz) |
|-----------|----------------|-------------------------|
| Embed     | ~45 ms         | ~120 ms                 |
| Extract   | ~40 ms         | ~110 ms                 |
| Capacity  | ~15 KB         | ~5 KB                   |

Run benchmarks yourself:

```bash
cargo bench
```

## Compression Resistance Tests

The library has been tested with:

- **JPEG Compression**: Quality 75-95 → <3% data loss
- **JPEG Compression**: Quality 50-75 → <5% data loss
- **MP3 Encoding**: 128 kbps+ → <5% data loss
- **PNG Optimization**: 100% data retention

## Future Features (Roadmap)

- [ ] Video steganography (MP4, AVI)
- [ ] Additional embedding algorithms (LSB-matching, F5)
- [ ] Reed-Solomon error correction
- [ ] Multi-file embedding
- [ ] GUI application
- [ ] WASM support for browser usage

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
