use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

// Bridge Imports
use crate::base::config::HardwareConfig;
use crate::primitives::shards::{self, StorageSequence, VideoShard};

/// Represents a raw frame captured from the sensor.
/// The "Truth" from the hardware before sharding/encryption.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
}

/// The main handle for the Camera Subsystem.
pub struct PhalanxCameraThread {
    fps: u32,
    running: Arc<AtomicBool>,
    frame_tx: broadcast::Sender<VideoFrame>,
}

impl PhalanxCameraThread {
    /// Creates the handle. Does NOT start the thread yet.
    pub fn new(config: &HardwareConfig) -> Self {
        // Buffer ~2 seconds of frames to absorb system lag
        let (tx, _) = broadcast::channel(config.camera_fps as usize * 2);

        Self {
            fps: config.camera_fps,
            running: Arc::new(AtomicBool::new(false)),
            frame_tx: tx,
        }
    }

    /// Allows other components (UI, Recorder) to tap into the raw stream
    pub fn subscribe(&self) -> broadcast::Receiver<VideoFrame> {
        self.frame_tx.subscribe()
    }

    /// INTERNAL: Starts the Watchdog thread (Hardware I/O).
    fn start_watchdog(&self, device_index: usize) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("PhalanxCameraThread Watchdog is already running.");
            return;
        }

        let running_flag = self.running.clone();
        let tx = self.frame_tx.clone();
        let target_fps = self.fps;

        // THREAD A: The Watchdog
        // Isolates the app from driver crashes / USB disconnects
        thread::spawn(move || {
            info!(
                index = device_index,
                fps = target_fps,
                "Camera Watchdog: STARTED"
            );

            while running_flag.load(Ordering::Relaxed) {
                // 1. Connection Attempt
                match CameraDriver::connect(device_index, target_fps) {
                    Ok(mut driver) => {
                        info!("Camera Hardware: CONNECTED");

                        // 2. Hot Loop (Capture)
                        while running_flag.load(Ordering::Relaxed) {
                            match driver.capture_frame() {
                                Ok(frame) => {
                                    // Broadcast. If no subscribers, drop (safe).
                                    let _ = tx.send(frame);
                                }
                                Err(e) => {
                                    error!(error = %e, "Camera Hardware: CRASHED. Restarting...");
                                    break; // Break inner loop -> Trigger Reconnect
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Camera Hardware: Unreachable. Retrying in 5s...");
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            info!("Camera Watchdog: STOPPED");
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// COMPATIBILITY BRIDGE
    /// Matches the signature expected by main.rs.
    /// Spawns the Watchdog AND the Processor to feed the main channel.
    pub fn spawn(
        self,
        index: Option<usize>,
        tx: mpsc::Sender<VideoShard>,
        hw_config: HardwareConfig,
        volley_id: String,
        secret_key: Option<[u8; 32]>,
    ) {
        // 1. Ignite the Hardware Watchdog
        let device_idx = index.unwrap_or(0);
        self.start_watchdog(device_idx);

        let mut rx = self.subscribe();
        let fps = hw_config.camera_fps;

        // 2. Spawn the Processor (Thread B)
        // Consumes raw frames, compresses, shards, encrypts -> Main Channel
        tokio::spawn(async move {
            info!("Camera Processor: STARTED");

            let mut frame_buffer = Vec::new();
            let mut sequence_id = StorageSequence(0);

            // "While the camera is producing frames..."
            while let Ok(frame) = rx.recv().await {
                // A. Compression (Simulated or Real JPEG)
                // Using the dimensions provided by the frame itself
                if let Ok(jpeg) = shards::compress_frame(frame.data, frame.width, frame.height) {
                    frame_buffer.push(jpeg);
                }

                // B. Batching
                if frame_buffer.len() >= fps as usize {
                    let chunk = frame_buffer.split_off(0); // Take all

                    let mut shard = shards::create_video_shard(
                        chunk,
                        sequence_id,
                        fps as u8,
                        volley_id.clone(),
                    );

                    // C. Encryption
                    if let Some(key) = secret_key {
                        if let Err(e) = shard.encrypt(&key) {
                            error!("Encryption failed for seq {}: {}", sequence_id, e);
                            continue; // Skip secure frames if encryption fails
                        }
                    }

                    // D. Transmission
                    if tx.send(shard).await.is_err() {
                        error!("Main channel closed. Stopping Camera Processor.");
                        self.stop(); // Kill the watchdog too
                        break;
                    }

                    sequence_id += 1;
                }
            }
        });
    }
}

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
