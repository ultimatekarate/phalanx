// crates/phalanx-ffi/src/atrace.rs
//
// Bridges Phalanx `tracing` spans to the Android systrace / Perfetto buffer.
//
// The crypto hot-path spans listed in `phalanx_proto::telemetry::spans::BRIDGED`
// are mirrored to ATrace `begin`/`end` sections, so a Perfetto capture renders
// them as named track-event slices alongside `simpleperf` CPU samples.
//
// `ATrace_*` is API 23+, and the app's minSdk may be lower, so the symbols are
// resolved at runtime from `libandroid.so`; if they are absent the layer is an
// inert no-op. The struct and `Layer` impl compile on every target — only the
// FFI calls are Android-gated — so non-Android builds still type-check this file.

use std::collections::HashMap;
use std::ffi::CString;

use tracing::span::Id;
use tracing::Subscriber;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use phalanx_proto::telemetry::spans;

#[cfg(target_os = "android")]
mod sys {
    use std::os::raw::c_char;

    pub type BeginFn = unsafe extern "C" fn(*const c_char);
    pub type EndFn = unsafe extern "C" fn();

    pub struct AtraceFns {
        pub begin: BeginFn,
        pub end: EndFn,
    }

    /// Resolve `ATrace_beginSection` / `ATrace_endSection` from `libandroid.so`.
    /// Returns `None` on API < 23 (symbols absent) so the caller degrades to a
    /// no-op layer rather than the `.so` failing to load on old devices.
    pub fn resolve() -> Option<AtraceFns> {
        // SAFETY: libandroid.so is a core system library mapped into every
        // Android process; `Library::new` only obtains a handle to it.
        let lib = unsafe { libloading::Library::new("libandroid.so") }.ok()?;

        let fns = {
            // SAFETY: when present, `ATrace_beginSection` matches the `BeginFn`
            // ABI declared from the NDK <android/trace.h>.
            let begin = unsafe { lib.get::<BeginFn>(b"ATrace_beginSection\0") }.ok()?;
            // SAFETY: when present, `ATrace_endSection` matches the `EndFn` ABI.
            let end = unsafe { lib.get::<EndFn>(b"ATrace_endSection\0") }.ok()?;
            AtraceFns {
                begin: *begin,
                end: *end,
            }
        };

        // The fn pointers must outlive the handle; leak it so libandroid.so
        // stays mapped for the process lifetime (a core lib, never unloaded).
        std::mem::forget(lib);
        Some(fns)
    }
}

/// `tracing` layer mirroring the `spans::BRIDGED` spans to Android ATrace.
pub struct AtraceLayer {
    #[cfg(target_os = "android")]
    fns: Option<sys::AtraceFns>,
    /// Pre-built NUL-terminated section names keyed by span name — avoids a
    /// per-enter allocation on the crypto hot path.
    names: HashMap<&'static str, CString>,
}

impl AtraceLayer {
    #[must_use]
    pub fn new() -> Self {
        let names = spans::BRIDGED
            .iter()
            .filter_map(|&name| CString::new(name).ok().map(|c| (name, c)))
            .collect();
        Self {
            #[cfg(target_os = "android")]
            fns: sys::resolve(),
            names,
        }
    }

    #[cfg(target_os = "android")]
    fn emit_begin(&self, name: &CString) {
        if let Some(fns) = &self.fns {
            // SAFETY: `name` is a valid NUL-terminated C string for the call;
            // `fns.begin` matches the NDK `ATrace_beginSection` ABI.
            unsafe { (fns.begin)(name.as_ptr()) };
        }
    }

    #[cfg(not(target_os = "android"))]
    fn emit_begin(&self, _name: &CString) {}

    #[cfg(target_os = "android")]
    fn emit_end(&self) {
        if let Some(fns) = &self.fns {
            // SAFETY: `fns.end` matches the NDK `ATrace_endSection` ABI; it
            // pairs 1:1 with `emit_begin` on the same thread.
            unsafe { (fns.end)() };
        }
    }

    #[cfg(not(target_os = "android"))]
    fn emit_end(&self) {}
}

impl Default for AtraceLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for AtraceLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            if let Some(name) = self.names.get(span.name()) {
                self.emit_begin(name);
            }
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            // Gated on the same membership test as `on_enter`, so `begin` and
            // `end` always pair regardless of the per-layer filter.
            if self.names.contains_key(span.name()) {
                self.emit_end();
            }
        }
    }
}

/// Per-layer filter selecting exactly the `spans::BRIDGED` spans. Attaching it
/// to `AtraceLayer` both restricts the layer to those spans and *enables* their
/// (TRACE-level) callsites without loosening the global event filter.
#[must_use]
pub fn bridged_filter() -> FilterFn {
    fn is_bridged(meta: &tracing::Metadata<'_>) -> bool {
        meta.is_span() && spans::BRIDGED.contains(&meta.name())
    }
    let predicate: fn(&tracing::Metadata<'_>) -> bool = is_bridged;
    FilterFn::new(predicate)
}
