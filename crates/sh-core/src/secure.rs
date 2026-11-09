//! DPAPI protection for the Worker shared secret (port of `src/Secure.cpp`).
//!
//! User-scope `CryptProtectData` with application entropy, stored as base64
//! without line breaks: byte-compatible with blobs the C++ build wrote.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Application entropy: a blob protected by another program on this account
/// cannot be dropped into our config and decrypted by us. No trailing NUL.
const ENTROPY: &[u8] = b"SplitHello/config/v1";

/// Encrypts `plaintext`; empty on failure (callers never fall back to writing
/// the secret in the clear).
pub fn protect(plaintext: &str) -> String {
    if plaintext.is_empty() {
        return String::new();
    }
    match platform::protect(plaintext.as_bytes()) {
        Some(blob) => STANDARD.encode(blob),
        None => String::new(),
    }
}

/// Decrypts a base64 blob; empty when it is not ours (another Windows user,
/// damaged file). Callers keep such a blob instead of discarding it.
pub fn unprotect(base64_blob: &str) -> String {
    if base64_blob.is_empty() {
        return String::new();
    }
    let compact: String = base64_blob
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let Ok(raw) = STANDARD.decode(compact) else {
        tracing::warn!("DPAPI: base64 cozulemedi");
        return String::new();
    };
    if raw.is_empty() {
        return String::new();
    }
    platform::unprotect(&raw)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

#[cfg(windows)]
mod platform {
    use super::ENTROPY;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::w;

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    /// Copies the system-allocated output, wipes it, and frees it.
    ///
    /// # Safety
    /// `output` must come from a successful Crypt*Data call.
    unsafe fn take(output: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: the API returned `cbData` valid bytes at `pbData`.
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
        let copy = bytes.to_vec();
        bytes.fill(0);
        // SAFETY: the buffer was allocated by the API with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        }
        copy
    }

    pub fn protect(plaintext: &[u8]) -> Option<Vec<u8>> {
        let input = blob(plaintext);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: all pointers reference live buffers for the duration of the call.
        let result = unsafe {
            CryptProtectData(
                &input,
                w!("SplitHello"),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        match result {
            // SAFETY: the call succeeded and filled `output`.
            Ok(()) => Some(unsafe { take(output) }),
            Err(error) => {
                tracing::error!("DPAPI sifreleme hatasi: {error}");
                None
            }
        }
    }

    pub fn unprotect(raw: &[u8]) -> Option<Vec<u8>> {
        let input = blob(raw);
        let entropy = blob(ENTROPY);
        let mut output = CRYPT_INTEGER_BLOB::default();
        // SAFETY: all pointers reference live buffers for the duration of the call.
        let result = unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        match result {
            // SAFETY: the call succeeded and filled `output`.
            Ok(()) => Some(unsafe { take(output) }),
            Err(error) => {
                tracing::warn!(
                    "DPAPI cozme hatasi ({error}). Config baska bir Windows kullanicisina ait olabilir."
                );
                None
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn protect(_: &[u8]) -> Option<Vec<u8>> {
        None
    }
    pub fn unprotect(_: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_foreign_blobs() {
        let blob = protect("0123456789abcdef");
        assert!(!blob.is_empty());
        assert!(!blob.contains('\n'));
        assert_eq!(unprotect(&blob), "0123456789abcdef");
        // Valid base64 that DPAPI cannot decrypt, like a blob from another user.
        assert_eq!(
            unprotect("bm90LWEtZHBhcGktYmxvYi1ub3QtYS1kcGFwaS1ibG9i"),
            ""
        );
        assert_eq!(unprotect("not base64 !!!"), "");
        assert_eq!(protect(""), "");
    }
}
