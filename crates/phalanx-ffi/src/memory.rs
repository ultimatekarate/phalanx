// crates/phalanx-ffi/src/memory.rs
//
// Deallocation functions for heap-allocated data returned to the C/Dart caller.
// Every `char*` or `uint8_t*` returned by the FFI must be freed through these functions.
// Dart's `calloc.free()` MUST NOT be used — the allocator is Rust's global allocator.

use std::ffi::CString;
use std::os::raw::c_char;

/// Frees a null-terminated C string allocated by Rust.
///
/// # Safety
/// * `ptr` must have been returned by a `phalanx_*` function that documents
///   "caller must free with `phalanx_free_string`".
/// * `ptr` must not have been freed previously (double-free is UB).
/// * Passing a null pointer is a safe no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_free_string(ptr: *mut c_char) {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. Null is a safe no-op; otherwise `ptr` was
    // produced by a `CString::into_raw` in this crate and the caller
    // guarantees it is freed exactly once, so `CString::from_raw` reclaims
    // unique ownership and drops it.
    unsafe {
        if !ptr.is_null() {
            // Reconstruct the CString so Rust's allocator frees it.
            drop(CString::from_raw(ptr));
        }
    }
}

/// Frees a byte buffer allocated by Rust.
///
/// # Safety
/// * `ptr` must have been returned by a `phalanx_*` function that documents
///   "caller must free with `phalanx_free_bytes`".
/// * `len` must be the exact length returned alongside the pointer.
/// * `ptr` must not have been freed previously (double-free is UB).
/// * Passing a null pointer is a safe no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_free_bytes(ptr: *mut u8, len: u32) {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. Null is a safe no-op; otherwise `ptr`/`len`
    // were produced together by `leak_bytes_to_c` and the caller
    // guarantees they are freed exactly once with the original length (see
    // the inner block for the capacity-equals-length reconstruction).
    unsafe {
        if !ptr.is_null() {
            // SAFETY: every producer of FFI byte buffers uses `leak_bytes_to_c`,
            // which feeds the helper a `Box<[u8]>`. `Box<[u8]>` has `capacity == len`
            // by construction (it's a slice, not a Vec with reserved tail), so
            // reconstructing as `Vec::from_raw_parts(ptr, len, len)` matches the
            // allocator's record.
            let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
        }
    }
}

/// Internal helper: hand a `Box<[u8]>` to the C side, writing the pointer and
/// length to caller-provided out-params.
///
/// Taking `Box<[u8]>` (not `Vec<u8>`) enforces the capacity-equals-length
/// invariant that `phalanx_free_bytes` relies on. A `Box<[u8]>` is a slice
/// header on the heap; its layout records exactly `len` bytes, never more. A
/// `Vec<u8>` with a larger reserved capacity would leak the tail and corrupt
/// the heap on free — but the type system here makes that wrong shape
/// unrepresentable.
///
/// Truncation note: `boxed.len()` is `usize`; if it exceeds `u32::MAX` we
/// saturate. No mobile FFI payload is realistically anywhere near 4 GiB, but
/// the saturation is loud rather than wrapping silently.
///
/// # Safety
/// * `out_ptr` and `out_len` must be valid, writable pointers.
/// * The caller is responsible for freeing the returned pointer via
///   `phalanx_free_bytes(ptr, len)`.
pub(crate) unsafe fn leak_bytes_to_c(
    mut boxed: Box<[u8]>,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) {
    let len = u32::try_from(boxed.len()).unwrap_or(u32::MAX);
    // SAFETY: out_ptr / out_len are valid per the function contract.
    unsafe {
        *out_ptr = boxed.as_mut_ptr();
        *out_len = len;
    }
    // The caller now owns the allocation; forget the Box so Drop doesn't free it.
    std::mem::forget(boxed);
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::undocumented_unsafe_blocks,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn free_string_null_is_noop() {
        unsafe {
            phalanx_free_string(std::ptr::null_mut());
        }
    }

    #[test]
    fn free_bytes_null_is_noop() {
        unsafe {
            phalanx_free_bytes(std::ptr::null_mut(), 0);
            phalanx_free_bytes(std::ptr::null_mut(), 100);
        }
    }

    #[test]
    fn free_string_roundtrip() {
        unsafe {
            let original = "did:key:z6MkTest";
            let cstr = CString::new(original).expect("valid cstring");
            let raw = cstr.into_raw();

            let read_back = CStr::from_ptr(raw).to_str().expect("valid utf8");
            assert_eq!(read_back, original);

            phalanx_free_string(raw);
        }
    }

    #[test]
    fn free_bytes_roundtrip() {
        unsafe {
            let data: Vec<u8> = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG SOI marker
            let len = data.len() as u32;
            let mut boxed = data.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);

            let slice = std::slice::from_raw_parts(ptr, len as usize);
            assert_eq!(slice, &[0xFF, 0xD8, 0xFF, 0xE0]);

            phalanx_free_bytes(ptr, len);
        }
    }
}
