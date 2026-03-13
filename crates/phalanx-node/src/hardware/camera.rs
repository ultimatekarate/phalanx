// crates/phalanx-node/src/hardware/camera.rs

use crate::config::HardwareConfig;
use crate::vitals::SystemGovernor;
use phalanx_forensics::judge::PayloadCipher;
use phalanx_forensics::reassembler::compress_frame;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_lens::ForensicLens;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{ForensicMetrics, StorageSequence, VideoShard};
use phalanx_proto::types::{BlackLevel, Fps, PowerState};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use phalanx_proto::prelude::*;

/// Default analog black level offset for 8-bit sensors.
/// Accounts for the analog black offset inherent in most CMOS sensors.
const DEFAULT_BLACK_LEVEL: f32 = 16.0;

// =====================================================================
// ADAPTIVE FPS DUTY CYCLING
// =====================================================================

/// Compute target FPS based on the current power state.
///
/// - Normal: full base FPS
/// - Conserving: half base FPS (`.max(1)` enforced by `Fps::new()`)
/// - Leaf: 1/5th base FPS (`.max(1)` enforced by `Fps::new()`)
/// - Dormant: zero FPS (no capture — platform-dependent; see `can_capture_in_background()`)
///
/// `Fps::new()` internally enforces `.max(1)`, preventing zero-FPS bugs from
/// integer floor division (e.g., base 4 / 5 = 0 → clamped to 1).
/// `Fps::zero()` is explicitly opt-in for Dormant only.
pub fn target_fps(base: Fps, power: PowerState) -> Fps {
    match power {
        PowerState::Normal => base,
        PowerState::Conserving => Fps::new(base.get() / 2),
        PowerState::Leaf => Fps::new(base.get() / 5),
        PowerState::Dormant => Fps::zero(),
    }
}

/// Computes the effective FPS interval, handling asymmetric ramp:
/// - Ramping UP (fewer → more frames): Instant — every frame not captured is lost evidence.
/// - Ramping DOWN (more → fewer frames): Smooth over 1 second — prevents burst of old-rate
///   frames flooding the egress pipeline.
///
/// Returns the new interval to use for frame capture timing.
pub fn compute_adaptive_interval(current_interval: Duration, target: Fps) -> Duration {
    match target.as_interval() {
        None => {
            // Dormant — no capture. Return a large interval as a sentinel.
            Duration::from_secs(3600)
        }
        Some(target_interval) => {
            if target_interval < current_interval {
                // Ramping UP (shorter interval = higher FPS): instant transition
                target_interval
            } else if target_interval > current_interval {
                // Ramping DOWN (longer interval = lower FPS): smooth over 1s
                // Blend: move 50% of the way toward target each call.
                // At 30fps this converges within ~1s (30 steps × 50% each).
                let current_ms = current_interval.as_millis() as f64;
                let target_ms = target_interval.as_millis() as f64;
                let blended_ms = current_ms + (target_ms - current_ms) * 0.5;
                Duration::from_millis(blended_ms as u64)
            } else {
                current_interval
            }
        }
    }
}

/// Extracts the Y (luma) plane from an RGB pixel buffer.
///
/// Uses the ITU-R BT.601 coefficients: Y = 0.299·R + 0.587·G + 0.114·B.
/// The ForensicLens operates on the Y-plane to compute sensor fingerprints
/// (Moiré energy + PRNU variance) before the JPEG compression stage
/// destroys the raw sensor signal.
fn extract_y_plane(rgb_data: &[u8], width: usize, height: usize) -> Vec<u8> {
    let pixel_count = width * height;
    let mut y_plane = Vec::with_capacity(pixel_count);

    for i in 0..pixel_count {
        let base = i * 3;
        // Safe access via .get() — returns 0 for out-of-bounds (satisfies indexing_slicing = "deny")
        let r = rgb_data.get(base).copied().unwrap_or(0) as f32;
        let g = rgb_data.get(base + 1).copied().unwrap_or(0) as f32;
        let b = rgb_data.get(base + 2).copied().unwrap_or(0) as f32;

        // BT.601 luma conversion — truncated to u8 (matches sensor ADC precision)
        let y = (0.299 * r + 0.587 * g + 0.114 * b) as u8;
        y_plane.push(y);
    }

    y_plane
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
        // Add `nokhwa` to imports.
        // Initialize Camera::new(Index(index), ...) inside here.

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
        // Simulate Hardware Wait (Blocking I/O)
        thread::sleep(self.fps_interval);

        // Time Drift Correction
        // Calculate current time based on Monotonic elapsed + System Anchor
        let elapsed = self.start_monotonic.elapsed();
        let frame_time = self.start_system_time + elapsed;

        let timestamp_ms = frame_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        // Generate Data (Visual Noise Pattern)
        // 640x480 * 3 bytes (RGB)
        let mut fake_data = vec![0u8; (self.width * self.height * 3) as usize];
        // Simple moving pattern so we can "see" the video changing
        fake_data[0] = (self.frame_counter % 255) as u8;

        self.frame_counter += 1;

        // Simulate Random Crash (Optional - Uncomment to test Watchdog)
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

/// Configuration bundle for `PhalanxCameraThread::spawn()`.
///
/// Groups the capture pipeline parameters to keep the spawn signature ergonomic.
/// - `lens` — ForensicLens implementation for sensor fingerprinting. Default: `ScalarLens`.
/// - `governor` — Optional SystemGovernor for adaptive FPS duty cycling.
///   When provided, the camera processor reads `current_power_state()` each batch
///   cycle and adjusts frame batching accordingly. When `None`, full FPS is used.
pub struct CameraSpawnConfig {
    pub hw_config: HardwareConfig,
    pub recording_id: String,
    pub secret_key: Option<[u8; 32]>,
    pub lens: Arc<dyn ForensicLens>,
    pub governor: Option<Arc<SystemGovernor>>,
}

/// The main handle for the Camera Subsystem.
pub struct PhalanxCameraThread {
    fps: Fps,
    running: Arc<AtomicBool>,
    frame_tx: broadcast::Sender<VideoFrame>,
}

impl PhalanxCameraThread {
    /// Creates the handle. Does NOT start the thread yet.
    pub fn new(config: &HardwareConfig) -> Self {
        // Buffer ~2 seconds of frames to absorb system lag
        let (tx, _) = broadcast::channel(config.camera_fps.get() as usize * 2);

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
                fps = target_fps.get(),
                "Camera Watchdog: STARTED"
            );

            while running_flag.load(Ordering::Relaxed) {
                // Connection Attempt — driver stays raw (hardware boundary)
                match CameraDriver::connect(device_index, target_fps.get()) {
                    Ok(mut driver) => {
                        info!("Camera Hardware: CONNECTED");

                        // Hot Loop (Capture)
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
        config: CameraSpawnConfig,
    ) {
        let CameraSpawnConfig {
            hw_config,
            recording_id,
            secret_key,
            lens,
            governor,
        } = config;

        // Ignite the Hardware Watchdog
        let device_idx = index.unwrap_or(0);
        self.start_watchdog(device_idx);

        let mut rx = self.subscribe();
        let base_fps = hw_config.camera_fps;

        // Spawn the Processor (Thread B)
        // Consumes raw frames, analyzes sensor fingerprint, compresses,
        // shards, encrypts -> Main Channel
        //
        // Each batch cycle, the processor reads the current PowerState
        // and adjusts frame batching accordingly. Asymmetric ramp:
        // - UP (more capture): instant — every frame we don't capture is lost evidence
        // - DOWN (less capture): smooth over 1s — prevents burst flooding egress
        tokio::spawn(async move {
            info!("Camera Processor: STARTED");

            let mut frame_buffer = Vec::new();
            let mut sequence_id = StorageSequence(0);
            // Safety fallback: if no frame arrives before batching triggers,
            // the shard carries all-zero metrics (a forensic signal itself).
            #[allow(unused_assignments)]
            let mut latest_metrics = ForensicMetrics::default();

            // "While the camera is producing frames..."
            while let Ok(frame) = rx.recv().await {
                // Read current power state to determine effective FPS
                let effective_fps = match &governor {
                    Some(gov) => {
                        let power = gov.current_power_state();
                        let target = target_fps(base_fps, power);

                        // Dormant: skip capture entirely (platform-dependent)
                        if target.get() == 0 {
                            continue; // Drop frame — Dormant means no capture
                        }
                        target
                    }
                    None => base_fps,
                };

                // Forensic Lens Analysis (BEFORE compression)
                // Extract Y (luma) plane from raw RGB data — the ForensicLens
                // operates on luminance to compute Moiré energy + PRNU variance.
                // Must happen before JPEG compression destroys the raw sensor signal.
                let y_plane =
                    extract_y_plane(&frame.data, frame.width as usize, frame.height as usize);
                latest_metrics = lens.analyze(
                    &y_plane,
                    frame.width as usize,
                    frame.height as usize,
                    BlackLevel(DEFAULT_BLACK_LEVEL),
                );

                // Compression (Simulated or Real JPEG)
                // Using the dimensions provided by the frame itself
                if let Ok(jpeg) = compress_frame(frame.data, frame.width, frame.height) {
                    frame_buffer.push(jpeg);
                }

                // Batching — uses effective FPS from power state
                if frame_buffer.len() >= effective_fps.get() as usize {
                    let chunk = frame_buffer.split_off(0); // Take all
                    let recording_id = RecordingId::new(recording_id.clone());

                    let shard_result = create_video_shard(
                        chunk,
                        sequence_id,
                        effective_fps,
                        recording_id,
                        latest_metrics,
                    );

                    match shard_result {
                        Ok(mut actual_shard) => {
                            // Encryption
                            if let Some(key) = secret_key {
                                if let Err(e) =
                                    actual_shard.payload.apply_encryption(&SymmetricKey(key))
                                {
                                    error!("Encryption failed for seq {}: {}", sequence_id, e);
                                    continue; // Skip secure frames if encryption fails
                                }
                            }

                            // Transmission
                            if tx.send(actual_shard).await.is_err() {
                                error!("Main channel closed. Stopping Camera Processor.");
                                self.stop(); // Kill the watchdog too
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Transient video encoding failure: {:?}. Skipping shard.", e);
                        }
                    }

                    sequence_id += 1;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HardwareConfig;
    use phalanx_lens::scalar::ScalarLens;
    use phalanx_proto::types::{ChannelCount, SampleRate};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_time_drift_compensation() {
        let config = HardwareConfig {
            camera_fps: Fps::new(50),
            audio_sample_rate: SampleRate::new(44100),
            audio_channels: ChannelCount::new(2),
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
            camera_fps: Fps::new(10),
            audio_sample_rate: SampleRate::new(44100),
            audio_channels: ChannelCount::new(2),
        };

        let cam = PhalanxCameraThread::new(&config);

        cam.spawn(
            Some(0),
            tx,
            CameraSpawnConfig {
                hw_config: config,
                recording_id: "test_recording".to_string(),
                secret_key: None,
                lens: Arc::new(ScalarLens),
                governor: None, // No governor — full FPS
            },
        );

        // Wait for 1 shard (which requires 10 frames at 10fps = ~1 sec)
        // Set timeout to 2s to be safe
        let shard = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;

        assert!(shard.is_ok(), "Timed out waiting for shard via bridge");
        assert!(shard.unwrap().is_some(), "Received empty shard");
    }

    // --- Adaptive FPS Tests ---

    #[test]
    fn test_target_fps_normal_returns_base() {
        let base = Fps::new(30);
        assert_eq!(target_fps(base, PowerState::Normal).get(), 30);
    }

    #[test]
    fn test_target_fps_conserving_halves() {
        let base = Fps::new(30);
        assert_eq!(target_fps(base, PowerState::Conserving).get(), 15);
    }

    #[test]
    fn test_target_fps_leaf_fifths() {
        let base = Fps::new(30);
        assert_eq!(target_fps(base, PowerState::Leaf).get(), 6);
    }

    #[test]
    fn test_target_fps_dormant_zero() {
        let base = Fps::new(30);
        assert_eq!(target_fps(base, PowerState::Dormant).get(), 0);
    }

    #[test]
    fn test_target_fps_floor_guard() {
        // Base 4 FPS / 5 = 0 → clamped to 1 by Fps::new()
        let base = Fps::new(4);
        assert_eq!(
            target_fps(base, PowerState::Leaf).get(),
            1,
            "Floor guard: 4/5=0 should clamp to 1"
        );
    }

    #[test]
    fn test_target_fps_conserving_floor_guard() {
        // Base 1 FPS / 2 = 0 → clamped to 1 by Fps::new()
        let base = Fps::new(1);
        assert_eq!(
            target_fps(base, PowerState::Conserving).get(),
            1,
            "Floor guard: 1/2=0 should clamp to 1"
        );
    }

    #[test]
    fn test_adaptive_interval_ramp_up_instant() {
        // Going from low FPS (long interval) to high FPS (short interval)
        // should be INSTANT — no smoothing
        let current = Duration::from_millis(100); // 10 FPS
        let target = Fps::new(30); // 30 FPS = ~33ms

        let result = compute_adaptive_interval(current, target);
        assert_eq!(
            result,
            Duration::from_millis(33),
            "Ramp UP should be instant"
        );
    }

    #[test]
    fn test_adaptive_interval_ramp_down_smooth() {
        // Going from high FPS (short interval) to low FPS (long interval)
        // should be SMOOTH — blended partway
        let current = Duration::from_millis(33); // ~30 FPS
        let target = Fps::new(10); // 10 FPS = 100ms

        let result = compute_adaptive_interval(current, target);
        // Blended: 33 + (100-33)*0.5 = 33 + 33.5 = 66.5 → 66ms
        assert!(
            result > current && result < Duration::from_millis(100),
            "Ramp DOWN should blend, got {:?}",
            result
        );
    }

    #[test]
    fn test_adaptive_interval_dormant_returns_sentinel() {
        let current = Duration::from_millis(33);
        let target = Fps::zero();

        let result = compute_adaptive_interval(current, target);
        assert_eq!(
            result,
            Duration::from_secs(3600),
            "Dormant should return large sentinel"
        );
    }
}
