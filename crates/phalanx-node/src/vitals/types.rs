// crates/phalanx-node/src/vitals/types.rs
//
// Hardened newtypes for the homeostasis API boundaries.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct IngestionScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FinalizationScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SybilEndowment(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct MemoryScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct StorageScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct BandwidthScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ConnectionScale(pub f64);

impl IngestionScale {
    pub fn as_throttle_delay(&self, base_delay_ms: u64) -> Duration {
        if self.0 <= 0.01 {
            Duration::from_millis(base_delay_ms * 100)
        } else {
            let multiplier = (1.0 / self.0) - 1.0;
            Duration::from_millis((base_delay_ms as f64 * multiplier) as u64)
        }
    }
}
