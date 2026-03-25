// crates/phalanx-node/src/vitals/hardware.rs
//
// Hardware abstraction layer: battery, thermal, and lifecycle probing.

use std::fs;
use std::path::PathBuf;

/// Battery charge level, 0-100. Clamped on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatteryLevel(u8);

impl BatteryLevel {
    #[must_use]
    pub fn new(pct: u8) -> Self {
        Self(pct.min(100))
    }

    #[must_use]
    pub fn get(&self) -> u8 {
        self.0
    }
}

/// Temperature in degrees Celsius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Celsius(pub i32);

/// Platform-specific SoC thermal envelope thresholds.
/// Different SoCs have different thermal envelopes:
/// Snapdragon throttles ~42°C, Apple A-series ~40°C, desktop CPUs ~75°C.
#[derive(Debug, Clone, Copy)]
pub struct ThermalThresholds {
    pub fair: Celsius,
    pub serious: Celsius,
    pub critical: Celsius,
}

impl Default for ThermalThresholds {
    fn default() -> Self {
        Self::desktop()
    }
}

impl ThermalThresholds {
    /// Desktop/Linux defaults (existing hardcoded values).
    pub fn desktop() -> Self {
        Self {
            fair: Celsius(45),
            serious: Celsius(60),
            critical: Celsius(75),
        }
    }

    /// Mobile defaults (tighter thermal envelope).
    pub fn mobile() -> Self {
        Self {
            fair: Celsius(40),
            serious: Celsius(50),
            critical: Celsius(65),
        }
    }
}

/// App lifecycle events pushed by the mobile OS.
/// Desktop returns `None` from `lifecycle_events()` (no foreground/background concept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// App moved to foreground — resume capture immediately.
    Foregrounded,
    /// App moved to background — transition to Dormant.
    Backgrounded,
}

/// Platform-abstracted hardware probing for battery, thermal, and lifecycle state.
///
/// `SysfsProbe` implements this for Linux/desktop (existing logic).
/// Mobile runtimes inject their own implementation via `phalanx-ffi`.
pub trait HardwareProbe: Send + Sync {
    /// Current battery charge level. Returns `None` if no battery (e.g., desktop AC).
    fn battery_level(&self) -> Option<BatteryLevel>;

    /// Current SoC/CPU temperature. Returns `None` if no thermal sensor available.
    fn thermal_reading(&self) -> Option<Celsius>;

    /// Whether the device is currently charging.
    fn is_charging(&self) -> bool;

    /// Whether the app is currently in the background (mobile only).
    fn is_background(&self) -> bool;

    /// Whether the platform allows camera capture in the background.
    /// Android (foreground service): true. iOS: false. Desktop: true.
    fn can_capture_in_background(&self) -> bool;

    /// Platform-specific thermal thresholds for this SoC.
    fn thermal_thresholds(&self) -> ThermalThresholds;

    /// Total device RAM in bytes. Used to derive memory critical threshold.
    /// Returns `None` if unavailable (test environments, no /proc/meminfo).
    fn total_ram_bytes(&self) -> Option<u64> {
        None
    }

    /// Optional event channel for OS lifecycle transitions (foreground/background).
    /// Mobile implementations push callbacks into this channel.
    /// Desktop returns `None`.
    fn lifecycle_events(&self) -> Option<tokio::sync::mpsc::Receiver<LifecycleEvent>> {
        None
    }
}

/// Default hardware probe for Linux/desktop using sysfs.
/// Reads `/sys/class/thermal/` and `/sys/class/power_supply/`.
pub struct SysfsProbe {
    thermal_path: Option<PathBuf>,
    battery_path: Option<PathBuf>,
    thresholds: ThermalThresholds,
}

impl SysfsProbe {
    pub fn new() -> Self {
        let thermal = Self::find_path("/sys/class/thermal", "temp", &["cpu", "soc", "tsens"]);
        let battery = Self::find_path("/sys/class/power_supply", "capacity", &["battery"]);
        Self {
            thermal_path: thermal,
            battery_path: battery,
            thresholds: ThermalThresholds::desktop(),
        }
    }

    pub fn find_path(base: &str, file: &str, keys: &[&str]) -> Option<PathBuf> {
        let entries = fs::read_dir(base).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let type_str = fs::read_to_string(path.join("type")).ok()?.to_lowercase();
            if keys.iter().any(|k| type_str.contains(k)) {
                return Some(path.join(file));
            }
        }
        None
    }
}

impl Default for SysfsProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareProbe for SysfsProbe {
    fn battery_level(&self) -> Option<BatteryLevel> {
        let raw = self
            .battery_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())?;
        let pct = raw.trim().parse::<u8>().ok()?;
        Some(BatteryLevel::new(pct))
    }

    fn thermal_reading(&self) -> Option<Celsius> {
        let raw = self
            .thermal_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())?;
        let millidegrees = raw.trim().parse::<i32>().ok()?;
        Some(Celsius(millidegrees / 1000))
    }

    fn is_charging(&self) -> bool {
        // Desktop: assume AC power (always charging / not battery-constrained)
        true
    }

    fn is_background(&self) -> bool {
        // Desktop: no foreground/background concept
        false
    }

    fn can_capture_in_background(&self) -> bool {
        // Desktop: always able to capture
        true
    }

    fn thermal_thresholds(&self) -> ThermalThresholds {
        self.thresholds
    }

    fn total_ram_bytes(&self) -> Option<u64> {
        let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
        let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }
}
