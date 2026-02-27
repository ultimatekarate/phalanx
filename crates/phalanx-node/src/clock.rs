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
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_clock_skew_correction() {
        let clock = TrustedClock::new();

        // Apply 10 second offset
        clock.set_offset(10_000).unwrap();

        let local_sys_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let adjusted_time = clock.now().unwrap().as_u64();

        // Verify the math hits the offset
        assert!(
            adjusted_time >= local_sys_time + 9,
            "Clock did not apply positive offset correctly"
        );
    }
}
