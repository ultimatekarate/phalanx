// crates/phalanx-ffi/src/observability.rs
//
// Installs the process-wide `tracing` subscriber on Android.
//
// Before this, the FFI bootstrap installed no subscriber at all, so every
// `tracing` event and span emitted on-device was silently dropped. This wires
// one in: events to logcat, and the crypto hot-path spans to ATrace/Perfetto.
//
// `init_android_observability` compiles on every target — `phalanx-ffi` also
// builds as an `rlib` for desktop integration tests, where the bootstrap path
// runs and must compile — but only installs a subscriber on Android.

use std::sync::Once;

static INIT: Once = Once::new();

/// Install the Android `tracing` subscriber (logcat + ATrace). Idempotent, and
/// a no-op on non-Android targets.
pub fn init_android_observability() {
    INIT.call_once(|| {
        #[cfg(target_os = "android")]
        install();
    });
}

#[cfg(target_os = "android")]
fn install() {
    use tracing_subscriber::fmt;
    use tracing_subscriber::prelude::*;

    // Events -> logcat, filtered by the shared per-target levels.
    let logcat = fmt::layer()
        .with_ansi(false)
        .with_writer(crate::logcat::LogcatMakeWriter)
        .with_filter(phalanx_node::vitals::telemetry_filter());

    // Bridged crypto spans -> ATrace/Perfetto. The layer's own filter both
    // selects those spans and enables their TRACE-level callsites.
    let atrace = crate::atrace::AtraceLayer::new().with_filter(crate::atrace::bridged_filter());

    let _ = tracing_subscriber::registry()
        .with(logcat)
        .with(atrace)
        .try_init();
}
