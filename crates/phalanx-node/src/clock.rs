// crates/phalanx-node/src/clock.rs

use phalanx_proto::prelude::*;
use sntpc::{NtpContext, NtpTimestampGenerator};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// NTP Generator Helper
// ============================================================================

/// Handles local timestamp generation for the NTP handshake.
/// Modern NTP libraries require this to prevent spoofing and manage request states.
#[derive(Copy, Clone, Default)]
struct PhalanxNtpGenerator;

impl NtpTimestampGenerator for PhalanxNtpGenerator {
    fn init(&mut self) {}

    fn timestamp_sec(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as u64
    }

    fn timestamp_subsec_micros(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .subsec_micros()
    }
}

// ============================================================================
// Trusted Clock Implementation
// ============================================================================

#[derive(Clone, Debug)]
pub struct TrustedClock {
    /// The difference between Local System Time and True Network Time in milliseconds.
    /// Positive = Local is behind. Negative = Local is ahead.
    offset_ms: Arc<RwLock<i64>>,
}

pub type TimeResult<T> = Result<T, TimeError>;

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

        // Note: Converts offset to seconds.
        // If PhalanxTimestamp requires milliseconds in the future, remove the `/ 1000`.
        let offset_sec = *offset_guard / 1000;

        // Ensure we don't return negative time if offset is massive
        Ok(PhalanxTimestamp((local + offset_sec).max(0) as u64))
    }

    /// Updates the offset manually (for testing or external sync mechanisms)
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
        use std::net::ToSocketAddrs; // Required for resolution

        // 1. Resolve the hostname to a concrete SocketAddr
        // NTP always uses port 123
        let addr = "pool.ntp.org:123"
            .to_socket_addrs()
            .map_err(|e| TimeError::NtpError(format!("DNS lookup failed: {}", e)))?
            .next()
            .ok_or_else(|| TimeError::NtpError("No address found for NTP pool".into()))?;

        // 2. Setup the socket
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| TimeError::NtpError(format!("UDP Bind failed: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| TimeError::NtpError(format!("Socket config failed: {}", e)))?;

        let context = NtpContext::new(PhalanxNtpGenerator::default());

        // 3. Pass the resolved 'addr' (SocketAddr) instead of the string
        match sntpc::get_time(addr, &socket, context) {
            Ok(time) => {
                let ntp_sec = time.sec();
                let system_sec = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(TimeError::ClockSkew)?
                    .as_secs();

                let diff_sec = (ntp_sec as i64) - (system_sec as i64);
                let offset_ms = diff_sec * 1000;

                let mut w = self.offset_ms.write().map_err(|_| {
                    TimeError::LockPoisoned("offset_ms write lock poisoned".to_string())
                })?;

                *w = offset_ms;
                tracing::info!("NTP Sync Complete. Offset: {}ms", offset_ms);
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("{:?}", e);
                tracing::warn!("NTP Sync Failed: {}. Using local system time.", err_msg);
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_clock_skew_correction() {
        let clock = TrustedClock::new();

        // Apply 10 second offset (10,000 ms)
        clock.set_offset(10_000).unwrap();

        let local_sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let adjusted_time = clock.now().unwrap().0; // Assuming PhalanxTimestamp is a tuple struct

        // Verify the math hits the offset (+10 seconds)
        // Using >= local_sys_time + 9 to account for execution delay during the test
        assert!(
            adjusted_time >= local_sys_time + 9,
            "Clock did not apply positive offset correctly"
        );
    }
}
