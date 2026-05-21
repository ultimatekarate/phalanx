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

/// `io::Write` sink that buffers one formatted log line and flushes it to
/// Android logcat as a single entry. Backs the `tracing` fmt layer's writer.
pub struct LogcatWriter {
    buf: Vec<u8>,
}

impl std::io::Write for LogcatWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            log_to_logcat(String::from_utf8_lossy(&self.buf).trim_end());
            self.buf.clear();
        }
        Ok(())
    }
}

impl Drop for LogcatWriter {
    fn drop(&mut self) {
        let _ = std::io::Write::flush(self);
    }
}

/// `MakeWriter` routing `tracing` fmt-layer output to Android logcat.
pub struct LogcatMakeWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogcatMakeWriter {
    type Writer = LogcatWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogcatWriter { buf: Vec::new() }
    }
}
