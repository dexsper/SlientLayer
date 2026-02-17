//! FFI (Foreign Function Interface) for using slient_layer from other languages
//!
//! This module provides C-compatible API for embedding and extracting data.

use crate::audio_steg::{embed_audio, extract_audio};
use crate::image_steg::{embed_image, extract_image};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::slice;

/// Result code for FFI operations
#[repr(C)]
pub enum SlientResult {
    Success = 0,
    ErrorIo = 1,
    ErrorImage = 2,
    ErrorAudio = 3,
    ErrorEncryption = 4,
    ErrorDecryption = 5,
    ErrorInvalidData = 6,
    ErrorInsufficientCapacity = 7,
    ErrorInvalidKey = 8,
    ErrorVerificationFailed = 9,
    ErrorUnsupportedFormat = 10,
    ErrorUnknown = 99,
}

impl From<crate::error::SlientError> for SlientResult {
    fn from(err: crate::error::SlientError) -> Self {
        match err {
            crate::error::SlientError::Io(_) => SlientResult::ErrorIo,
            crate::error::SlientError::Image(_) => SlientResult::ErrorImage,
            crate::error::SlientError::Audio(_) => SlientResult::ErrorAudio,
            crate::error::SlientError::Encryption(_) => SlientResult::ErrorEncryption,
            crate::error::SlientError::Decryption(_) => SlientResult::ErrorDecryption,
            crate::error::SlientError::InvalidData(_) => SlientResult::ErrorInvalidData,
            crate::error::SlientError::InsufficientCapacity { .. } => {
                SlientResult::ErrorInsufficientCapacity
            }
            crate::error::SlientError::InvalidKey(_) => SlientResult::ErrorInvalidKey,
            crate::error::SlientError::VerificationFailed => SlientResult::ErrorVerificationFailed,
            crate::error::SlientError::UnsupportedFormat(_) => SlientResult::ErrorUnsupportedFormat,
            _ => SlientResult::ErrorUnknown,
        }
    }
}

/// Embed data into an image file
///
/// # Safety
/// - All pointers must be valid and non-null
/// - Strings must be null-terminated UTF-8
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_embed_image(
    input_path: *const c_char,
    output_path: *const c_char,
    data: *const u8,
    data_len: usize,
    password: *const c_char,
) -> SlientResult {
    if input_path.is_null() || output_path.is_null() || data.is_null() {
        return SlientResult::ErrorInvalidData;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let input = CStr::from_ptr(input_path).to_str().ok()?;
        let output = CStr::from_ptr(output_path).to_str().ok()?;
        let data_slice = slice::from_raw_parts(data, data_len);

        let pwd = if password.is_null() {
            None
        } else {
            Some(CStr::from_ptr(password).to_str().ok()?)
        };

        embed_image(Path::new(input), Path::new(output), data_slice, pwd).ok()?;
        Some(SlientResult::Success)
    });

    result.unwrap_or(Some(SlientResult::ErrorUnknown)).unwrap_or(SlientResult::ErrorUnknown)
}

/// Extract data from an image file
///
/// # Safety
/// - All pointers must be valid and non-null
/// - out_data will be allocated and must be freed with slient_free_data
/// - out_len will be set to the length of extracted data
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_extract_image(
    input_path: *const c_char,
    password: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> SlientResult {
    if input_path.is_null() || out_data.is_null() || out_len.is_null() {
        return SlientResult::ErrorInvalidData;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let input = CStr::from_ptr(input_path).to_str().ok()?;

        let pwd = if password.is_null() {
            None
        } else {
            Some(CStr::from_ptr(password).to_str().ok()?)
        };

        let extracted = extract_image(Path::new(input), pwd).ok()?;

        let len = extracted.len();
        let ptr = libc::malloc(len) as *mut u8;
        if ptr.is_null() {
            return None;
        }

        std::ptr::copy_nonoverlapping(extracted.as_ptr(), ptr, len);
        *out_data = ptr;
        *out_len = len;

        Some(SlientResult::Success)
    });

    result.unwrap_or(Some(SlientResult::ErrorUnknown)).unwrap_or(SlientResult::ErrorUnknown)
}

/// Embed data into an audio file
///
/// # Safety
/// - All pointers must be valid and non-null
/// - Strings must be null-terminated UTF-8
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_embed_audio(
    input_path: *const c_char,
    output_path: *const c_char,
    data: *const u8,
    data_len: usize,
    password: *const c_char,
) -> SlientResult {
    if input_path.is_null() || output_path.is_null() || data.is_null() {
        return SlientResult::ErrorInvalidData;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let input = CStr::from_ptr(input_path).to_str().ok()?;
        let output = CStr::from_ptr(output_path).to_str().ok()?;
        let data_slice = slice::from_raw_parts(data, data_len);

        let pwd = if password.is_null() {
            None
        } else {
            Some(CStr::from_ptr(password).to_str().ok()?)
        };

        embed_audio(Path::new(input), Path::new(output), data_slice, pwd).ok()?;
        Some(SlientResult::Success)
    });

    result.unwrap_or(Some(SlientResult::ErrorUnknown)).unwrap_or(SlientResult::ErrorUnknown)
}

/// Extract data from an audio file
///
/// # Safety
/// - All pointers must be valid and non-null
/// - out_data will be allocated and must be freed with slient_free_data
/// - out_len will be set to the length of extracted data
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_extract_audio(
    input_path: *const c_char,
    password: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> SlientResult {
    if input_path.is_null() || out_data.is_null() || out_len.is_null() {
        return SlientResult::ErrorInvalidData;
    }

    let result = std::panic::catch_unwind(|| unsafe {
        let input = CStr::from_ptr(input_path).to_str().ok()?;

        let pwd = if password.is_null() {
            None
        } else {
            Some(CStr::from_ptr(password).to_str().ok()?)
        };

        let extracted = extract_audio(Path::new(input), pwd).ok()?;

        let len = extracted.len();
        let ptr = libc::malloc(len) as *mut u8;
        if ptr.is_null() {
            return None;
        }

        std::ptr::copy_nonoverlapping(extracted.as_ptr(), ptr, len);
        *out_data = ptr;
        *out_len = len;

        Some(SlientResult::Success)
    });

    result.unwrap_or(Some(SlientResult::ErrorUnknown)).unwrap_or(SlientResult::ErrorUnknown)
}

/// Free data allocated by slient_extract_* functions
///
/// # Safety
/// - ptr must have been allocated by slient_extract_* functions
/// - ptr must not be used after calling this function
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_free_data(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { libc::free(ptr as *mut libc::c_void) };
    }
}

/// Get library version
///
/// # Safety
/// - Returns a static string, no need to free
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slient_version() -> *const c_char {
    static VERSION_CSTRING: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    VERSION_CSTRING
        .get_or_init(|| CString::new(crate::VERSION).unwrap())
        .as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        unsafe {
            let version = slient_version();
            assert!(!version.is_null());
            let version_str = CStr::from_ptr(version).to_str().unwrap();
            assert!(!version_str.is_empty());
        }
    }
}
