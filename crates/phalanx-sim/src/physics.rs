use phalanx_proto::types::UnitInterval;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PowerState {
    #[default]
    Normal,
    /// Focus strictly on self-preservation: Only accept local data
    Leaf,
}

/// The Physical Laws of the Simulation.
///
/// These constraints dictate how the network perceives time.
/// In the Sandbox, we use these to accelerate or decelerate "Network Time"
/// to test how the system behaves under high latency or rapid churn.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PhalanxPhysics {
    /// The fundamental unit of time: Round Trip Time (ms).
    /// Used as the base multiplier for all timeouts.
    pub tau_rtt: u64,

    /// The compute tax: How long we expect a CPU to take to sign/verify a shard.
    pub delta_cpu: u64,

    /// The Chaos Factor (Safety Margin).
    /// timeouts = jitter_factor * (tau + cpu).
    /// A higher jitter factor makes the network more tolerant of "Vampire" nodes.
    pub jitter_factor: u64,

    pub artificial_load: f32,
}

impl PhalanxPhysics {
    /// Optimized for high-latency mobile WANs.
    #[must_use]
    pub fn default_wan() -> Self {
        Self {
            tau_rtt: 300,
            delta_cpu: 20,
            jitter_factor: 3,
            artificial_load: 0.0,
        }
    }

    /// Optimized for local/CI environments.
    #[must_use]
    pub fn test_profile() -> Self {
        Self {
            tau_rtt: 50,
            delta_cpu: 100,
            jitter_factor: 5,
            artificial_load: 0.0,
        }
    }

    /// Derives the "Max Survival Time" for a shard in transit.
    /// If a shard doesn't arrive by this time, it is considered lost.
    #[must_use]
    pub fn shard_timeout(&self) -> std::time::Duration {
        let ms = self.jitter_factor * (self.tau_rtt + self.delta_cpu);
        std::time::Duration::from_millis(ms)
    }

    pub fn apply_system_load(&mut self, load: UnitInterval) {
        self.artificial_load = load.as_f32();
    }
}

/// Establishes the baseline laws of physics for the simulation.
impl Default for PhalanxPhysics {
    fn default() -> Self {
        Self {
            tau_rtt: 300,
            delta_cpu: 20,
            jitter_factor: 3,
            artificial_load: 0.0,
        }
    }
}
