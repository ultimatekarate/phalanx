// crates/phalanx-ffi/src/logcat.rs
//
// Cross-platform diagnostic logging. On Android, writes directly to logcat
// via __android_log_write. On other platforms, falls back to eprintln.
//
// Usage: phalanx_log!("message {}", value);

#[cfg(target_os = "android")]
pub fn log_to_logcat(msg: &str) {
    use std::ffi::CString;
    // ANDROID_LOG_INFO = 4
    const ANDROID_LOG_INFO: i32 = 4;
    let tag = CString::new("PhalanxFFI").unwrap_or_default();
    let msg = CString::new(msg).unwrap_or_default();
    unsafe {
        android_log_sys::__android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
pub fn log_to_logcat(msg: &str) {
    eprintln!("{msg}");
}

/// Write a diagnostic message to Android logcat (or stderr on other platforms).
macro_rules! phalanx_log {
    ($($arg:tt)*) => {
        $crate::logcat::log_to_logcat(&format!($($arg)*))
    };
}

pub(crate) use phalanx_log;
