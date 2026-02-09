use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemStress {
    Nominal,    // Cool & Charged. Full Speed.
    Fair,       // Warm or < 50% Battery. Throttle background tasks.
    Serious,    // Hot or < 20% Battery. Stop all forensics.
    Critical,   // Melting or < 5% Battery. Emergency shutdown.
}

pub struct SystemGovernor {
    // Cache the state to avoid expensive OS calls every millisecond
    current_state: std::sync::RwLock<SystemStress>,
}

impl SystemGovernor {
    pub fn check_permission(&self, task_cost: TaskCost) -> bool {
        let state = *self.current_state.read().unwrap();
        match (state, task_cost) {
            (SystemStress::Nominal, _) => true, // Do anything
            (SystemStress::Fair, TaskCost::Heavy) => false, // No FFTs
            (SystemStress::Fair, TaskCost::Light) => true,  // Signatures OK
            (SystemStress::Serious, _) => false, // Only essential capture
            (SystemStress::Critical, _) => false, // Survival mode
        }
    }
    
    // Call this every 5-10 seconds
    pub fn update_vitals(&self) {
        let thermal = self.get_thermal_status();
        let battery = self.get_battery_status();
        
        let new_state = std::cmp::max(thermal, battery);
        *self.current_state.write().unwrap() = new_state;
    }

    // Platform-Specific Logic (Simplified)
    #[cfg(target_os = "android")]
    fn get_thermal_status(&self) -> SystemStress {
        // JNI call to PowerManager.getThermalStatus()
        // Returns 0 (NONE) to 6 (SHUTDOWN)
        // Map 0-1 -> Nominal, 2 -> Fair, 3 -> Serious, 4+ -> Critical
    }

    #[cfg(target_os = "ios")]
    fn get_thermal_status(&self) -> SystemStress {
        // ObjC call to [NSProcessInfo processInfo].thermalState
        // Returns 0 (Nominal) to 3 (Critical)
    }
}