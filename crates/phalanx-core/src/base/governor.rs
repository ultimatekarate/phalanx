// use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCost {
    Light, // e.g., signature verification
    Heavy, // e.g., FFTs, video encoding
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemStress {
    Nominal,  // 0, Cool & Charged. Full Speed.
    Fair,     // 1, Warm or < 50% Battery. Throttle background tasks.
    Serious,  // 2, Hot or < 20% Battery. Stop all forensics.
    Critical, // 3, Melting or < 5% Battery. Emergency shutdown.
}

pub struct SystemGovernor {
    // Cache the state to avoid expensive OS calls every millisecond
    current_state: std::sync::RwLock<SystemStress>,
}

impl SystemGovernor {
    pub fn check_permission(&self, task_cost: TaskCost) -> bool {
        let state = *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        match (state, task_cost) {
            (SystemStress::Nominal, _) => true,             // Do anything
            (SystemStress::Fair, TaskCost::Heavy) => false, // No FFTs
            (SystemStress::Fair, TaskCost::Light) => true,  // Signatures OK
            (SystemStress::Serious, _) => false,            // Only essential capture
            (SystemStress::Critical, _) => false,           // Survival mode
        }
    }

    // Call this every 5-10 seconds
    pub fn update_vitals(&self) {
        let thermal = self.get_thermal_status();
        let battery = self.get_battery_status();

        let new_state = std::cmp::max(thermal, battery);

        let mut guard = self
            .current_state
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = new_state;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn get_thermal_status(&self) -> SystemStress {
        SystemStress::Nominal // Desktops/Strongholds rarely throttle
    }

    fn get_battery_status(&self) -> SystemStress {
        // Placeholder for cross-platform battery crate or native bridge
        SystemStress::Nominal
    }

    #[cfg(target_os = "android")]
    fn get_thermal_status(&self) -> SystemStress {
        // TODO: In Phase 3, we'll link this to a JNI call to PowerManager
        SystemStress::Nominal
    }

    #[cfg(target_os = "ios")]
    fn get_thermal_status(&self) -> SystemStress {
        // TODO: Map to NSProcessInfo.thermalState
        SystemStress::Nominal
    }
    // Platform-Specific Logic (Simplified)
    #[cfg(target_os = "android")]
    fn get_thermal_status(&self) -> SystemStress {
        // JNI call to PowerManager.getThermalStatus()
        // Returns 0 (NONE) to 6 (SHUTDOWN)
        // Map 0-1 -> Nominal, 2 -> Fair, 3 -> Serious, 4+ -> Critical
    }
}
