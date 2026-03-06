// crates/phalanx-node/src/hardware/discovery.rs
use std::fs;
use std::path::{Path, PathBuf};

/// A verified map of hardware sensor paths.
#[derive(Debug, Clone)]
pub struct HardwareManifest {
    pub thermal_temp_path: PathBuf,
    pub battery_capacity_path: PathBuf,
}

pub struct HardwareScanner;

impl HardwareScanner {
    /// Scans the Linux/Android sysfs to find authoritative sensor paths.
    pub fn scan() -> Result<HardwareManifest, String> {
        let thermal = Self::find_cpu_thermal()
            .ok_or_else(|| "Hardware Error: No valid CPU thermal zone detected".to_string())?;

        let battery = Self::find_primary_battery()
            .ok_or_else(|| "Hardware Error: No primary battery supply detected".to_string())?;

        Ok(HardwareManifest {
            thermal_temp_path: thermal,
            battery_capacity_path: battery,
        })
    }

    fn find_cpu_thermal() -> Option<PathBuf> {
        let thermal_base = Path::new("/sys/class/thermal");
        let entries = fs::read_dir(thermal_base).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(tz_type) = fs::read_to_string(path.join("type")) {
                let name = tz_type.trim().to_lowercase();
                // Priority list for mobile SoCs (Qualcomm, Samsung, MTK)
                if name.contains("cpu") || name.contains("soc") || name.contains("cluster") {
                    return Some(path.join("temp"));
                }
            }
        }
        None
    }

    fn find_primary_battery() -> Option<PathBuf> {
        let power_base = Path::new("/sys/class/power_supply");
        let entries = fs::read_dir(power_base).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(ps_type) = fs::read_to_string(path.join("type")) {
                if ps_type.trim() == "Battery" {
                    return Some(path.join("capacity"));
                }
            }
        }
        None
    }
}
