use std::os::raw::{c_char, c_int};
use std::ffi::CStr;
use std::ptr;
use phalanx_core::engine::PhalanxEngine;

#[no_mangle]
pub extern "C" fn phalanx_engine_new(storage_path: *const c_char) -> *mut PhalanxEngine {
    if storage_path.is_null() {
        return ptr::null_mut();
    }

    // Safely convert C string to Rust string
    let c_str = unsafe { CStr::from_ptr(storage_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(), // Invalid UTF-8
    };

    // Initialize the engine (Synchronously)
    match PhalanxEngine::new_at_path(path_str) {
        Ok(engine) => {
            // Success: Move engine to heap and return raw pointer
            Box::into_raw(Box::new(engine))
        },
        Err(e) => {
            // Failure: Log error and return Null
            eprintln!("Failed to init Phalanx Engine: {}", e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn phalanx_engine_free(ptr: *mut PhalanxEngine) {
    if ptr.is_null() {
        return;
    }
    // Take ownership back to Rust to drop it safely
    unsafe {
        let _ = Box::from_raw(ptr);
    }
}