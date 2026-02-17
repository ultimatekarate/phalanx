use phalanx_core::base::engine::PhalanxEngine;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

#[cfg(target_os = "android")]
pub mod jni;

/// Initializes the Phalanx storage engine.
///
/// # Safety
/// The caller must ensure `storage_path` is a valid, null-terminated C-string
/// pointer. Passing a null or dangling pointer will cause Undefined Behavior.
#[no_mangle]
pub unsafe extern "C" fn phalanx_engine_new(storage_path: *const c_char) -> *mut PhalanxEngine {
    if storage_path.is_null() {
        return ptr::null_mut();
    }

    let c_str = CStr::from_ptr(storage_path);
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(), // Invalid UTF-8
    };

    // Initialize the engine (Synchronously)
    match PhalanxEngine::new_at_path(path_str) {
        Ok(engine) => {
            // Success: Move engine to heap and return raw pointer
            Box::into_raw(Box::new(engine))
        }
        Err(e) => {
            // Failure: Log error and return Null
            eprintln!("Failed to init Phalanx Engine: {}", e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn phalanx_engine_free(ptr: *mut PhalanxEngine) {
    if !ptr.is_null() {
        // SAFETY: We explicitly trust the caller to pass a valid pointer 
        // derived from phalanx_init or similar constructors.
        let _ = Box::from_raw(ptr);
    }
}
