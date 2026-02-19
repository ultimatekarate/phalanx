use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    #[error("System clock drift detected (time went backwards): {0}")]
    ClockSkew(#[from] SystemTimeError),

    #[error("Time synchronization lock poisoned: {0}")]
    LockPoisoned(String),

    #[error("Invalid timestamp computation: {0}")]
    CalculationError(String),

    #[error("Timestamp is too far in the past (Replay Attack): {0}s difference")]
    Stale(u64),

    #[error("Timestamp is in the future (Time Traveler): {0}s difference")]
    Future(u64),

    #[error("NTP Sync failed: {0}")]
    NtpError(String),
}

pub type TimeResult<T> = Result<T, TimeError>;

/// PhalanxTimestamp is meant to enforce a strict boundary between forensic layer and transient layer.
/// If a process interacts with the global mesh, it MUST use this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PhalanxTimestamp(u64);

impl PhalanxTimestamp {
    /// Captures current network time safely using the provided clock.
    pub fn now_from(clock: &TrustedClock) -> TimeResult<Self> {
        clock.now()
    }

    /// Wraps a raw value.
    ///
    /// ARCHITECTURAL NOTE: This does NOT validate against the clock.
    /// This allows us to deserialize historical data (which is by definition "stale")
    /// without the constructor failing.
    #[must_use]
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Strict validation for LIVE traffic.
    ///  
    /// Call this immediately after receiving a packet from the network
    /// to ensure it isn't a replay attack.
    pub fn verify_freshness(&self, clock: &TrustedClock, tolerance_secs: u64) -> TimeResult<()> {
        let now_val = clock.now()?.as_u64();
        let claimed_val = self.0;

        // Check for Future (Time Travelers)
        if claimed_val > now_val + tolerance_secs {
            return Err(TimeError::Future(claimed_val - now_val));
        }

        // Check for Past (Replays)
        if claimed_val < now_val.saturating_sub(tolerance_secs) {
            return Err(TimeError::Stale(now_val - claimed_val));
        }

        Ok(())
    }

    #[must_use]
    pub fn abs_diff(&self, other: u64) -> u64 {
        self.0.abs_diff(other)
    }
}

impl From<u64> for PhalanxTimestamp {
    fn from(t: u64) -> Self {
        Self(t)
    }
}

// --- CLOCK INTERFACE ---

/// Represents the source of truth for Network Time.
#[derive(Clone, Debug)]
pub struct TrustedClock {
    /// The difference between Local System Time and True Network Time in milliseconds.
    /// Positive = Local is behind. Negative = Local is ahead.
    offset_ms: Arc<RwLock<i64>>,
}

impl TrustedClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            offset_ms: Arc::new(RwLock::new(0)),
        }
    }

    /// Returns the current "True Time" (Local + Offset) as a PhalanxTimestamp.
    ///
    /// # Forensic Safety
    /// Returns `TimeError` if the system clock is before UNIX_EPOCH or if
    /// the internal lock is poisoned.
    pub fn now(&self) -> TimeResult<PhalanxTimestamp> {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(TimeError::ClockSkew)?
            .as_secs() as i64;

        let offset_guard = self
            .offset_ms
            .read()
            .map_err(|_| TimeError::LockPoisoned("offset_ms read lock poisoned".to_string()))?;

        let offset_sec = *offset_guard / 1000;

        // Ensure we don't return negative time if offset is massive
        Ok(PhalanxTimestamp((local + offset_sec).max(0) as u64))
    }

    /// Updates the offset manually (for testing or NTP sync)
    pub fn set_offset(&self, new_offset: i64) -> TimeResult<()> {
        let mut w = self
            .offset_ms
            .write()
            .map_err(|_| TimeError::LockPoisoned("offset_ms write lock poisoned".to_string()))?;
        *w = new_offset;
        Ok(())
    }

    /// Performs an NTP synchronization to calculate the time offset.
    ///
    /// # Async Deadlock Warning
    /// This method performs blocking I/O (UDP socket operations).
    /// If called from an async context, it **MUST** be wrapped in `tokio::task::spawn_blocking`.
    pub fn synchronize(&self) -> TimeResult<()> {
        // 1. Bind a local UDP socket to an available port (0)
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| TimeError::NtpError(format!("UDP Bind failed: {}", e)))?;

        // 2. Set a timeout so we don't hang forever if NTP is down
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| TimeError::NtpError(format!("Socket configuration failed: {}", e)))?;

        match sntpc::simple_get_time("pool.ntp.org", &socket) {
            Ok(time) => {
                let ntp_sec = time.sec();

                let system_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(TimeError::ClockSkew)?;

                let system_sec = system_now.as_secs();

                // Simple offset calculation (Network - Local)
                let diff_sec = (ntp_sec as i64) - (system_sec as i64);
                let offset_ms = diff_sec * 1000;

                let mut w = self.offset_ms.write().map_err(|_| {
                    TimeError::LockPoisoned("offset_ms write lock poisoned".to_string())
                })?;

                *w = offset_ms;

                info!("NTP Sync Complete. Offset: {}ms", offset_ms);
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("{:?}", e);
                warn!("NTP Sync Failed: {}. Using local system time.", err_msg);
                Err(TimeError::NtpError(err_msg))
            }
        }
    }
}

impl Default for TrustedClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_timestamp_acceptance() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now_ts = clock.now()?;
        let now_val = now_ts.as_u64();

        // Timestamp is "now", tolerance is 5s
        assert!(
            PhalanxTimestamp::from_u64(now_val)
                .verify_freshness(&clock, 5)
                .is_ok(),
            "Current time should be valid"
        );

        // Timestamp is 2s ago, tolerance 5s
        assert!(
            PhalanxTimestamp::from_u64(now_val - 2)
                .verify_freshness(&clock, 5)
                .is_ok(),
            "Recent past should be valid"
        );

        // Timestamp is 2s future, tolerance 5s
        assert!(
            PhalanxTimestamp::from_u64(now_val + 2)
                .verify_freshness(&clock, 5)
                .is_ok(),
            "Near future should be valid"
        );

        Ok(())
    }

    #[test]
    fn test_replay_attack_rejection() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now_val = clock.now()?.as_u64();

        // Attack: Replaying a message from 60 seconds ago
        let stale_timestamp = PhalanxTimestamp::from_u64(now_val - 60);
        let result = stale_timestamp.verify_freshness(&clock, 5);

        assert!(
            matches!(result, Err(TimeError::Stale(_))),
            "Old timestamp should be rejected as Stale"
        );
        Ok(())
    }

    #[test]
    fn test_future_attack_rejection() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now_val = clock.now()?.as_u64();

        // Attack: Message claiming to be from an hour in the future
        let future_timestamp = PhalanxTimestamp::from_u64(now_val + 3600);
        let result = future_timestamp.verify_freshness(&clock, 5);

        assert!(
            matches!(result, Err(TimeError::Future(_))),
            "Far future timestamp should be rejected as Future"
        );
        Ok(())
    }

    #[test]
    fn test_clock_skew_correction() -> TimeResult<()> {
        let clock = TrustedClock::new();

        clock.set_offset(10_000)?;

        let local_sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(TimeError::ClockSkew)?
            .as_secs();

        let adjusted_time = clock.now()?.as_u64();

        assert!(
            adjusted_time >= local_sys_time + 9,
            "Clock did not apply positive offset"
        );

        Ok(())
    }
}
