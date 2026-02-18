use sntpc;
use std::net::UdpSocket;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use tracing::{info, warn};

use serde::{Deserialize, Serialize};

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
    /// 
    /// # Forensic Safety
    /// Returns `TimeError` if the system clock is before UNIX_EPOCH or if 
    /// the internal lock is poisoned.
    pub fn now(&self) -> TimeResult<u64> {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(TimeError::ClockSkew)?
            .as_secs() as i64;
        
        let offset_guard = self.offset_ms.read()
            .map_err(|_| TimeError::LockPoisoned("offset_ms read lock poisoned".to_string()))?;
        
        let offset_sec = *offset_guard / 1000;
        
        // Ensure we don't return negative time if offset is massive
        Ok((local + offset_sec).max(0) as u64)
    }

    /// Validates if a timestamp is within the acceptable window of True Time.
    /// Used to reject Replay Attacks (too old) or Time Travelers (too new).
    pub fn is_valid(&self, claimed_time: u64, tolerance_secs: u64) -> TimeResult<bool> {
        let now = self.now()?;

        // We use saturating logic to avoid underflow
        let diff = claimed_time.abs_diff(now);

        Ok(diff <= tolerance_secs)
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
    pub fn synchronize(&self) -> TimeResult<()> {
        // 1. Bind a local UDP socket to an available port (0)
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| TimeError::NtpError(format!("UDP Bind failed: {}", e)))?;

        // 2. Set a timeout so we don't hang forever if NTP is down
        socket.set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| TimeError::NtpError(format!("Socket configuration failed: {}", e)))?;

        // NTP uses UDP port 123
        match sntpc::simple_get_time("pool.ntp.org", &socket) {
            Ok(time) => {
                let ntp_sec = time.sec();
                
                let system_now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(TimeError::ClockSkew)?;
                
                let system_sec = system_now.as_secs();

                // Simple offset calculation (Network - Local)
                // If Network is 1000 and Local is 990, offset is +10.
                let diff_sec = (ntp_sec as i64) - (system_sec as i64);
                let offset_ms = diff_sec * 1000;

                // Safe lock acquisition
                let mut w = self.offset_ms.write()
                    .map_err(|_| TimeError::LockPoisoned("offset_ms write lock poisoned".to_string()))?;
                
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PhalanxTimestamp(u64);

impl PhalanxTimestamp {
    /// Captures current network time safely.
    pub fn now(clock: &TrustedClock) -> TimeResult<Self> {
        Ok(Self(clock.now()?))
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
    ) -> TimeResult<()> {
        let now = clock.now()?;

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
    fn test_valid_timestamp_acceptance() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now = clock.now()?;

        // Timestamp is "now", tolerance is 5s
        assert!(clock.is_valid(now, 5)?, "Current time should be valid");

        // Timestamp is 2s ago, tolerance 5s
        assert!(clock.is_valid(now - 2, 5)?, "Recent past should be valid");

        // Timestamp is 2s future, tolerance 5s
        assert!(clock.is_valid(now + 2, 5)?, "Near future should be valid");
        
        Ok(())
    }

    #[test]
    fn test_replay_attack_rejection() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now = clock.now()?;

        // Attack: Replaying a message from 1 minute ago
        let stale_timestamp = now - 60;
        assert!(
            !clock.is_valid(stale_timestamp, 5)?,
            "Old timestamp should be rejected"
        );
        Ok(())
    }

    #[test]
    fn test_future_attack_rejection() -> TimeResult<()> {
        let clock = TrustedClock::new();
        let now = clock.now()?;

        // Attack: Message claiming to be from next year
        let future_timestamp = now + 3600;
        assert!(
            !clock.is_valid(future_timestamp, 5)?,
            "Far future timestamp should be rejected"
        );
        Ok(())
    }

    #[test]
    fn test_clock_skew_correction() -> TimeResult<()> {
        let clock = TrustedClock::new();

        // SCENARIO: Local machine is 10 seconds BEHIND reality.
        // Real time is 100. Local thinks it is 90.
        // We set offset to +10,000ms.
        clock.set_offset(10_000)?;

        // Local system time (simulated)
        let local_sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(TimeError::ClockSkew)?
            .as_secs();

        // The clock.now() should return local + 10
        let adjusted_time = clock.now()?;

        assert!(
            adjusted_time >= local_sys_time + 9,
            "Clock did not apply positive offset"
        );

        Ok(())
    }
}