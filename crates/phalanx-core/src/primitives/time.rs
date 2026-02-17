use sntpc;
use std::net::UdpSocket;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// --- MOCKABLE CLOCK INTERFACE ---

/// Represents the source of truth for Network Time.
#[derive(Clone, Debug)]
pub struct TrustedClock {
    /// The difference between Local System Time and True Network Time in milliseconds.
    /// Positive = Local is behind. Negative = Local is ahead.
    offset_ms: Arc<RwLock<i64>>,
}

impl TrustedClock {
    pub fn new() -> Self {
        Self {
            offset_ms: Arc::new(RwLock::new(0)),
        }
    }

    /// Returns the current "True Time" (Local + Offset) in seconds.
    pub fn now(&self) -> u64 {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let offset_sec = *self.offset_ms.read().unwrap() / 1000;
        (local + offset_sec).max(0) as u64
    }

    /// Validates if a timestamp is within the acceptable window of True Time.
    /// Used to reject Replay Attacks (too old) or Time Travelers (too new).
    pub fn is_valid(&self, claimed_time: u64, tolerance_secs: u64) -> bool {
        let now = self.now();

        // We use saturating logic to avoid underflow
        let diff = if claimed_time > now {
            claimed_time - now
        } else {
            now - claimed_time
        };

        diff <= tolerance_secs
    }

    /// Updates the offset manually (for testing or NTP sync)
    pub fn set_offset(&self, ms: i64) {
        let mut w = self.offset_ms.write().unwrap();
        *w = ms;
    }

    pub async fn synchronize(&self) -> Result<(), String> {
        // 1. Bind a local UDP socket to an available port (0)
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => return Err(format!("Failed to bind UDP socket: {}", e)),
        };

        // 2. Set a timeout so we don't hang forever if NTP is down
        if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(2))) {
            return Err(format!("Failed to set socket timeout: {}", e));
        }

        // NTP uses UDP port 123
        match sntpc::simple_get_time("pool.ntp.org", &socket) {
            Ok(time) => {
                // Calculate offset: NTP Time - System Time
                // sntpc returns seconds + fraction. We just care about seconds roughly for this proof of concept,
                // but strictly we should use the precise offset provided by the library if available,
                // or compare sec/nsec.

                let ntp_sec = time.sec();
                // let ntp_frac = time.nsec();

                let system_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let system_sec = system_now.as_secs();

                // Simple offset calculation (Network - Local)
                // If Network is 1000 and Local is 990, offset is +10.
                // We store in milliseconds for better precision than raw seconds.
                let diff_sec = (ntp_sec as i64) - (system_sec as i64);
                let offset_ms = diff_sec * 1000;

                {
                    let mut w = self.offset_ms.write().unwrap();
                    *w = offset_ms;
                }

                info!("NTP Sync Complete. Offset: {}ms", offset_ms);
                Ok(())
            }
            Err(e) => {
                warn!("NTP Sync Failed: {:?}. Using local system time.", e);
                Err(format!("{:?}", e))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum TimeError {
    #[error("Timestamp is too far in the past (Replay Attack): {0}s difference")]
    Stale(u64),
    #[error("Timestamp is in the future (Time Traveler): {0}s difference")]
    Future(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PhalanxTimestamp(u64);

impl PhalanxTimestamp {
    /// Captures current network time.
    pub fn now(clock: &TrustedClock) -> Self {
        Self(clock.now())
    }

    /// Wraps a raw value.
    ///
    /// ARCHITECTURAL NOTE: This does NOT validate against the clock.
    /// This allows us to deserialize historical data (which is by definition "stale")
    /// without the constructor failing.
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Strict validation for LIVE traffic.
    ///  
    /// Call this immediately after receiving a packet from the network
    /// to ensure it isn't a replay attack.
    pub fn verify_freshness(
        &self,
        clock: &TrustedClock,
        tolerance_secs: u64,
    ) -> Result<(), TimeError> {
        let now = clock.now();

        // Check for Future (Time Travelers)
        if self.0 > now + tolerance_secs {
            return Err(TimeError::Future(self.0 - now));
        }

        // Check for Past (Replays)
        if self.0 < now.saturating_sub(tolerance_secs) {
            return Err(TimeError::Stale(now - self.0));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_timestamp_acceptance() {
        let clock = TrustedClock::new();
        let now = clock.now();

        // Timestamp is "now", tolerance is 5s
        assert!(clock.is_valid(now, 5), "Current time should be valid");

        // Timestamp is 2s ago, tolerance 5s
        assert!(clock.is_valid(now - 2, 5), "Recent past should be valid");

        // Timestamp is 2s future, tolerance 5s
        assert!(clock.is_valid(now + 2, 5), "Near future should be valid");
    }

    #[test]
    fn test_replay_attack_rejection() {
        let clock = TrustedClock::new();
        let now = clock.now();

        // Attack: Replaying a message from 1 minute ago
        let stale_timestamp = now - 60;
        assert!(
            !clock.is_valid(stale_timestamp, 5),
            "Old timestamp should be rejected"
        );
    }

    #[test]
    fn test_future_attack_rejection() {
        let clock = TrustedClock::new();
        let now = clock.now();

        // Attack: Message claiming to be from next year
        let future_timestamp = now + 3600;
        assert!(
            !clock.is_valid(future_timestamp, 5),
            "Far future timestamp should be rejected"
        );
    }

    #[test]
    fn test_clock_skew_correction() {
        let clock = TrustedClock::new();

        // SCENARIO: Local machine is 10 seconds BEHIND reality.
        // Real time is 100. Local thinks it is 90.
        // We set offset to +10,000ms.
        clock.set_offset(10_000);

        // Local system time (simulated)
        let local_sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // The clock.now() should return local + 10
        let adjusted_time = clock.now();

        assert!(
            adjusted_time >= local_sys_time + 9,
            "Clock did not apply positive offset"
        );
    }
}
