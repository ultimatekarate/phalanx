use phalanx_core::engine::PhalanxEngine;
use std::os::raw::{c_char, c_int};
use std::ffi::CStr;

/// Manages the global singleton instance of the PhalanxEngine for the FFI layer.
/// This pointer is opaque to the host language and must be passed back 
/// to all engine-dependent functions.
pub struct OpaqueEngine(*mut PhalanxEngine);

#[no_mangle]
pub extern "C" fn phalanx_init_engine(identity_path: *const c_char) -> *mut PhalanxEngine {
    // 1. Safety check for null pointer
    if identity_path.is_null() { return std::ptr::null_mut(); }
    
    // 2. Convert C-string to Rust path
    let c_str = unsafe { CStr::from_ptr(identity_path) };
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // 3. Initialize engine (Simplified for sync FFI example)
    // Note: In Phase 3, we wrap the engine in a Runtime handle to manage async tasks.
    let engine = PhalanxEngine::new_at_path(path);
    Box::into_raw(Box::new(engine))
}

#[no_mangle]
pub extern "C" fn phalanx_free_engine(engine: *mut PhalanxEngine) {
    if !engine.is_null() {
        unsafe { drop(Box::from_raw(engine)); }
    }
}