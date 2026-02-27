/// Internal driver handling Time Drift and I/O.
struct CameraDriver {
    fps_interval: Duration,

    // Time Drift Compensation Anchors
    start_system_time: SystemTime,
    start_monotonic: Instant,

    frame_counter: u64,
    width: u32,
    height: u32,
}

impl CameraDriver {
    fn connect(_index: usize, fps: u32) -> Result<Self, String> {
        // [STUB] Real implementation would use `nokhwa` here.
        // For robustness testing, we use a reliable Mock Driver.
        // To enable Real Hardware:
        // 1. Add `nokhwa` to imports.
        // 2. Initialize Camera::new(Index(index), ...) inside here.

        Ok(Self {
            fps_interval: Duration::from_millis(1000 / fps as u64),
            // Anchor strictly ONCE upon connection
            start_system_time: SystemTime::now(),
            start_monotonic: Instant::now(),
            frame_counter: 0,
            width: 640,
            height: 480,
        })
    }

    fn capture_frame(&mut self) -> Result<VideoFrame, String> {
        // 1. Simulate Hardware Wait (Blocking I/O)
        thread::sleep(self.fps_interval);

        // 2. Time Drift Correction
        // Calculate current time based on Monotonic elapsed + System Anchor
        let elapsed = self.start_monotonic.elapsed();
        let frame_time = self.start_system_time + elapsed;

        let timestamp_ms = frame_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        // 3. Generate Data (Visual Noise Pattern)
        // 640x480 * 3 bytes (RGB)
        let mut fake_data = vec![0u8; (self.width * self.height * 3) as usize];
        // Simple moving pattern so we can "see" the video changing
        fake_data[0] = (self.frame_counter % 255) as u8;

        self.frame_counter += 1;

        // 4. Simulate Random Crash (Optional - Uncomment to test Watchdog)
        // if self.frame_counter % 100 == 0 { return Err("USB Disconnect".into()); }

        Ok(VideoFrame {
            data: fake_data,
            timestamp: timestamp_ms,
            sequence: self.frame_counter,
            width: self.width,
            height: self.height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_time_drift_compensation() {
        let config = HardwareConfig {
            camera_fps: 50,
            audio_sample_rate: 44100,
            audio_channels: 2,
        };
        let cam = PhalanxCameraThread::new(&config);
        let mut rx = cam.subscribe();

        // Use 0 as index
        cam.start_watchdog(0);

        // Consume 5 frames to check delta
        let mut previous_ts = 0;
        for _ in 0..5 {
            if let Ok(frame) = rx.recv().await {
                if previous_ts > 0 {
                    let diff = frame.timestamp - previous_ts;
                    // At 50 FPS, diff should be ~20ms. Allow slight scheduling jitter (15-30ms).
                    assert!(
                        diff >= 15 && diff <= 30,
                        "Time drift detected! Delta: {}ms",
                        diff
                    );
                }
                previous_ts = frame.timestamp;
            }
        }
        cam.stop();
    }

    #[tokio::test]
    async fn test_spawn_bridge_integration() {
        // Verifies the spawn() method correctly pumps VideoShards to the channel
        let (tx, mut rx) = mpsc::channel(10);
        let config = HardwareConfig {
            camera_fps: 10, // Fast enough for test
            audio_sample_rate: 44100,
            audio_channels: 2,
        };

        let cam = PhalanxCameraThread::new(&config);

        cam.spawn(Some(0), tx, config, "test_volley".to_string(), None);

        // Wait for 1 shard (which requires 10 frames at 10fps = ~1 sec)
        // Set timeout to 2s to be safe
        let shard = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;

        assert!(shard.is_ok(), "Timed out waiting for shard via bridge");
        assert!(shard.unwrap().is_some(), "Received empty shard");
    }
}
