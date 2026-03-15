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
#[no_mangle]
pub unsafe extern "C" fn phalanx_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Reconstruct the CString so Rust's allocator frees it.
        drop(CString::from_raw(ptr));
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_free_bytes(ptr: *mut u8, len: u32) {
    if !ptr.is_null() {
        // Reconstruct the Vec so Rust's allocator frees it.
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}
