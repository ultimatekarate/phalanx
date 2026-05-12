// crates/phalanx-ffi/src/panic_safety.rs
//
// Panic boundary for `extern "C"` exports. Workspace lints prevent explicit
// panics in our own code, but third-party dependencies (c2pa, postcard,
// libp2p internals, …) can still panic on malformed input. A panic that
// unwinds across an `extern "C"` boundary aborts the process — for a
// mobile app, that means a hard crash with no chance to surface a
// useful error. Wrap the panic-prone exports in `ffi_panic_safe` so
// the body's panic becomes a status code the caller can handle.

/// Run `body` under `catch_unwind`; on panic, log and return `fallback`.
///
/// Apply to FFI exports that touch third-party stacks where panic safety
/// isn't audited (currently: `phalanx_create`'s bootstrap and
/// `phalanx_export_c2pa`'s c2pa pipeline). Don't bother with leaf exports
/// like `phalanx_free_bytes` — wrapping them is pure overhead.
///
/// The generic `T` makes the fallback match the FFI function's return
/// type at compile time:
/// - `i32`-returning exports → `PhalanxError::Panic.code()`
/// - pointer-returning exports → `std::ptr::null_mut()`
///
/// OOM-aborts cannot be caught this way; the global allocator aborts
/// directly, bypassing the unwind machinery. This boundary covers
/// "ordinary" panics only.
pub(crate) fn ffi_panic_safe<F, T>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_payload) => {
            tracing::error!(
                target: "phalanx::ffi",
                "panic caught in FFI body; returning fallback"
            );
            fallback
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::undocumented_unsafe_blocks
)]
mod tests {
    use super::*;
    use crate::error::PhalanxError;

    #[test]
    fn happy_path_returns_body_value() {
        let r: i32 = ffi_panic_safe(PhalanxError::Panic.code(), || 42);
        assert_eq!(r, 42);
    }

    #[test]
    fn panic_returns_fallback() {
        let r: i32 = ffi_panic_safe(PhalanxError::Panic.code(), || panic!("boom"));
        assert_eq!(r, PhalanxError::Panic.code());
    }

    #[test]
    fn panic_with_pointer_fallback_returns_null() {
        let r: *mut u8 = ffi_panic_safe(std::ptr::null_mut(), || panic!("boom"));
        assert!(r.is_null());
    }
}
