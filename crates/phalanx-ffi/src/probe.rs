// crates/phalanx-ffi/src/probe.rs
//
// MobileProbe: Atomics-based HardwareProbe for Flutter/mobile.
//
// Flutter pushes sensor readings (battery, thermal, lifecycle) into atomics.
// Rust reads them lock-free from the homeostatic integrals.
// This is the sensory nervous system — the ears of the Larynx.

use phalanx_node::vitals::{
    BatteryLevel, Celsius, HardwareProbe, LifecycleEvent, ThermalThresholds,
};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use tokio::sync::mpsc;

/// Lock-free hardware probe driven by FFI calls from the Flutter layer.
///
/// All sensor state is stored in atomics. The `SystemGovernor` reads these
/// on its homeostatic tick without contention. Flutter writes are fire-and-forget.
pub struct MobileProbe {
    battery_level: AtomicU8,
    thermal_celsius: AtomicI32,
    is_charging: AtomicBool,
    is_background: AtomicBool,
    /// Total device RAM in bytes. Set once from Flutter during init.
    /// 0 means unavailable (falls back to reference device default).
    total_ram_bytes: AtomicU64,
    /// Lifecycle event sender. Mutex only guards the Option (take-once pattern),
    /// not the hot path. The mpsc::Sender itself is lock-free.
    lifecycle_tx: Mutex<Option<mpsc::Sender<LifecycleEvent>>>,
    /// Corresponding receiver, taken once by `lifecycle_events()`.
    lifecycle_rx: Mutex<Option<mpsc::Receiver<LifecycleEvent>>>,
    /// Platform-specific thermal thresholds.
    thresholds: ThermalThresholds,
}

impl MobileProbe {
    /// Create a new MobileProbe with default sensor values.
    ///
    /// `total_ram_bytes`: device RAM in bytes (from Flutter's platform API).
    /// Pass 0 if unavailable — falls back to reference device default.
    ///
    /// Defaults:
    /// - Battery: 100% (assume full charge on cold start)
    /// - Thermal: 25°C (room temperature)
    /// - Charging: false
    /// - Background: false (app starts in foreground)
    pub fn new(thresholds: ThermalThresholds, total_ram_bytes: u64) -> Self {
        let (tx, rx) = mpsc::channel(16);
        Self {
            battery_level: AtomicU8::new(100),
            thermal_celsius: AtomicI32::new(25),
            is_charging: AtomicBool::new(false),
            is_background: AtomicBool::new(false),
            total_ram_bytes: AtomicU64::new(total_ram_bytes),
            lifecycle_tx: Mutex::new(Some(tx)),
            lifecycle_rx: Mutex::new(Some(rx)),
            thresholds,
        }
    }

    // --- FFI write methods (called from Dart via extern "C" functions) ---

    /// Update battery level. Called by Flutter every ~10s.
    pub fn set_battery(&self, level: u8, charging: bool) {
        self.battery_level.store(level.min(100), Ordering::Relaxed);
        self.is_charging.store(charging, Ordering::Relaxed);
    }

    /// Update thermal reading. Called by Flutter every ~10s.
    pub fn set_thermal(&self, celsius: i32) {
        self.thermal_celsius.store(celsius, Ordering::Relaxed);
    }

    /// Update foreground/background state. Called on iOS/Android lifecycle events.
    pub fn set_lifecycle(&self, is_foreground: bool) {
        self.is_background.store(!is_foreground, Ordering::Relaxed);

        // Push lifecycle event to the governor's event channel.
        let event = if is_foreground {
            LifecycleEvent::Foregrounded
        } else {
            LifecycleEvent::Backgrounded
        };

        // Best-effort: if the lock is poisoned or channel full, don't block the UI thread.
        if let Ok(guard) = self.lifecycle_tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.try_send(event);
            }
        }
    }

    /// Set total device RAM in bytes. Called once from Flutter during init
    /// (after `phalanx_create`/`phalanx_restore`) via `phalanx_update_device_ram`.
    /// 0 means unavailable — the probe falls back to the reference-device default.
    pub fn set_device_ram(&self, bytes: u64) {
        self.total_ram_bytes.store(bytes, Ordering::Relaxed);
    }
}

impl HardwareProbe for MobileProbe {
    fn battery_level(&self) -> Option<BatteryLevel> {
        Some(BatteryLevel::new(
            self.battery_level.load(Ordering::Relaxed),
        ))
    }

    fn thermal_reading(&self) -> Option<Celsius> {
        Some(Celsius(self.thermal_celsius.load(Ordering::Relaxed)))
    }

    fn is_charging(&self) -> bool {
        self.is_charging.load(Ordering::Relaxed)
    }

    fn is_background(&self) -> bool {
        self.is_background.load(Ordering::Relaxed)
    }

    fn can_capture_in_background(&self) -> bool {
        // Android foreground service: yes. iOS: no.
        // Conservative default — Flutter overrides per-platform.
        false
    }

    fn thermal_thresholds(&self) -> ThermalThresholds {
        self.thresholds
    }

    fn total_ram_bytes(&self) -> Option<u64> {
        let val = self.total_ram_bytes.load(Ordering::Relaxed);
        if val > 0 {
            Some(val)
        } else {
            None
        }
    }

    fn lifecycle_events(&self) -> Option<mpsc::Receiver<LifecycleEvent>> {
        // Take-once: the first caller (SystemGovernor) gets the receiver.
        // Subsequent calls return None.
        match self.lifecycle_rx.lock() {
            Ok(mut guard) => guard.take(),
            _ => None,
        }
    }
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
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    #[test]
    fn default_values_on_cold_start() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        let battery = probe.battery_level().expect("battery should be Some");
        assert_eq!(battery.get(), 100);
        assert!(!probe.is_charging());
        assert!(!probe.is_background());

        let thermal = probe.thermal_reading().expect("thermal should be Some");
        assert_eq!(thermal.0, 25);
    }

    #[test]
    fn battery_updates_visible_through_trait() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        probe.set_battery(75, true);
        let battery = probe.battery_level().expect("battery should be Some");
        assert_eq!(battery.get(), 75);
        assert!(probe.is_charging());

        probe.set_battery(42, false);
        let battery = probe.battery_level().expect("battery should be Some");
        assert_eq!(battery.get(), 42);
        assert!(!probe.is_charging());
    }

    #[test]
    fn battery_clamps_at_100() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        probe.set_battery(255, false);
        let battery = probe.battery_level().expect("battery should be Some");
        assert_eq!(battery.get(), 100);
    }

    #[test]
    fn battery_zero_is_valid() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        probe.set_battery(0, false);
        let battery = probe.battery_level().expect("battery should be Some");
        assert_eq!(battery.get(), 0);
    }

    #[test]
    fn thermal_updates_visible_through_trait() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        probe.set_thermal(40);
        assert_eq!(probe.thermal_reading().expect("some").0, 40);

        probe.set_thermal(85);
        assert_eq!(probe.thermal_reading().expect("some").0, 85);
    }

    #[test]
    fn thermal_negative_values_are_valid() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        // Arctic field conditions
        probe.set_thermal(-20);
        assert_eq!(probe.thermal_reading().expect("some").0, -20);
    }

    #[test]
    fn lifecycle_foreground_background() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        assert!(!probe.is_background());

        probe.set_lifecycle(false);
        assert!(probe.is_background());

        probe.set_lifecycle(true);
        assert!(!probe.is_background());
    }

    #[test]
    fn lifecycle_events_take_once() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        let rx1 = probe.lifecycle_events();
        assert!(rx1.is_some(), "First call should return Some(receiver)");

        let rx2 = probe.lifecycle_events();
        assert!(rx2.is_none(), "Second call should return None");
    }

    #[tokio::test]
    async fn lifecycle_events_forwarded_to_channel() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        let mut rx = probe.lifecycle_events().expect("should get receiver");

        probe.set_lifecycle(false);
        probe.set_lifecycle(true);

        let event1 = rx.try_recv().expect("should have Backgrounded event");
        assert!(matches!(event1, LifecycleEvent::Backgrounded));

        let event2 = rx.try_recv().expect("should have Foregrounded event");
        assert!(matches!(event2, LifecycleEvent::Foregrounded));
    }

    #[test]
    fn can_capture_in_background_defaults_false() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);
        assert!(!probe.can_capture_in_background());
    }

    #[test]
    fn rapid_updates_dont_panic() {
        let probe = MobileProbe::new(ThermalThresholds::default(), 0);

        for i in 0..1000u16 {
            let level = (i % 101) as u8;
            let charging = i % 3 == 0;
            let celsius = (i as i32 % 100) - 20;

            probe.set_battery(level, charging);
            probe.set_thermal(celsius);
            probe.set_lifecycle(i % 2 == 0);

            let _ = probe.battery_level();
            let _ = probe.thermal_reading();
            let _ = probe.is_charging();
            let _ = probe.is_background();
        }
    }

    #[test]
    fn concurrent_reads_and_writes_dont_panic() {
        use std::sync::Arc;
        use std::thread;

        let probe = Arc::new(MobileProbe::new(ThermalThresholds::default(), 0));

        let writer = {
            let probe = probe.clone();
            thread::spawn(move || {
                for i in 0..500u16 {
                    probe.set_battery((i % 101) as u8, i % 2 == 0);
                    probe.set_thermal((i as i32) % 80);
                    probe.set_lifecycle(i % 3 != 0);
                }
            })
        };

        let reader = {
            let probe = probe.clone();
            thread::spawn(move || {
                for _ in 0..500 {
                    let _ = probe.battery_level();
                    let _ = probe.thermal_reading();
                    let _ = probe.is_charging();
                    let _ = probe.is_background();
                }
            })
        };

        writer.join().expect("writer thread panicked");
        reader.join().expect("reader thread panicked");
    }
}
