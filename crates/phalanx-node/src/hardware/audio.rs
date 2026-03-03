// crates/phalanx-node/src/hardware/audio.rs

use crate::config::HardwareConfig;
use phalanx_forensics::reassembler::create_audio_shard;
use phalanx_proto::evidence::AudioShard;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::prelude::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use std::thread;
use tokio::sync::{broadcast, mpsc}; // Bring in AudioWeaver

pub struct PhalanxAudioThread {
    sample_rate: u32,
    channels: u8,
    running: Arc<AtomicBool>,
    frame_tx: broadcast::Sender<AudioFrame>,
}

impl PhalanxAudioThread {
    /// Creates the handle. Does NOT start the thread yet.
    pub fn new(config: &HardwareConfig) -> Self {
        // Buffer ~1 second of audio chunks
        let (tx, _) = broadcast::channel(100);

        Self {
            sample_rate: config.audio_sample_rate,
            channels: config.audio_channels,
            running: Arc::new(AtomicBool::new(false)),
            frame_tx: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AudioFrame> {
        self.frame_tx.subscribe()
    }

    /// INTERNAL: Starts the Hardware Watchdog.
    fn start_watchdog(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            warn!("PhalanxAudioThread Watchdog is already running.");
            return;
        }

        let running_flag = self.running.clone();
        let tx = self.frame_tx.clone();
        let rate = self.sample_rate;
        let channels = self.channels;

        // THREAD A: The Watchdog
        thread::spawn(move || {
            info!(rate, channels, "Audio Watchdog: STARTED");

            while running_flag.load(Ordering::Relaxed) {
                // 1. Connection Attempt
                match AudioDriver::connect(rate, channels) {
                    Ok(mut driver) => {
                        info!("Audio Hardware: CONNECTED");

                        // 2. Hot Loop (Capture)
                        while running_flag.load(Ordering::Relaxed) {
                            match driver.capture_chunk() {
                                Ok(frame) => {
                                    let _ = tx.send(frame);
                                }
                                Err(e) => {
                                    error!(error = %e, "Audio Hardware: CRASHED. Restarting...");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Audio Hardware: Unreachable. Retrying in 5s...");
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            info!("Audio Watchdog: STOPPED");
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// COMPATIBILITY BRIDGE
    pub fn spawn(
        self,
        tx: mpsc::Sender<AudioShard>,
        hw_config: HardwareConfig,
        volley_id: String,
        secret_key: Option<[u8; 32]>,
    ) {
        // 1. Ignite Hardware
        self.start_watchdog();

        let mut rx = self.subscribe();

        // Calculate bytes needed for 1 second of audio
        // e.g. 44100 * 2 (16-bit) * 2 (stereo) = 176,400 bytes
        let bytes_per_sec =
            (hw_config.audio_sample_rate * hw_config.audio_channels as u32 * 2) as usize;

        // 2. Spawn Processor (Thread B)
        tokio::spawn(async move {
            info!("Audio Processor: STARTED");

            let mut byte_buffer = Vec::new();
            let mut sequence_id = StorageSequence(0);

            while let Ok(frame) = rx.recv().await {
                // A. Buffer Data
                byte_buffer.extend_from_slice(&frame.data);

                // B. Batching
                if byte_buffer.len() >= bytes_per_sec {
                    let chunk = byte_buffer.split_off(0);

                    let volley_id = VolleyId::new(volley_id.clone());
                    // FIX: Added missing arguments (sample_rate, channels)
                    let shard_result = create_audio_shard(
                        chunk,
                        sequence_id,
                        hw_config.audio_sample_rate,
                        hw_config.audio_channels,
                        volley_id,
                    );

                    match shard_result {
                        Ok(mut actual_shard) => {
                            // C. Encryption
                            if let Some(key) = secret_key {
                                if let Err(e) = actual_shard.encrypt(&key) {
                                    error!(
                                        "Encryption failed for audio seq {}: {}",
                                        sequence_id, e
                                    );
                                    continue;
                                }
                            }

                            // D. Transmission
                            if tx.send(actual_shard).await.is_err() {
                                error!("Main channel closed (MeshSentinel dropped). Stopping Audio Processor.");
                                self.stop();
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Transient audio encoding failure: {:?}. Skipping shard.", e);
                        }
                    }

                    sequence_id += 1;
                }
            }
        });
    }
}

/// Internal driver handling Time Drift and I/O.
struct AudioDriver {
    interval: Duration,
    start_system_time: SystemTime,
    start_monotonic: Instant,
    sample_counter: u64,
    rate: u32,
    channels: u8,
}

impl AudioDriver {
    fn connect(rate: u32, channels: u8) -> Result<Self, String> {
        Ok(Self {
            interval: Duration::from_millis(100),
            start_system_time: SystemTime::now(),
            start_monotonic: Instant::now(),
            sample_counter: 0,
            rate,
            channels,
        })
    }

    fn capture_chunk(&mut self) -> Result<AudioFrame, String> {
        thread::sleep(self.interval);

        let elapsed = self.start_monotonic.elapsed();
        let frame_time = self.start_system_time + elapsed;

        let timestamp_ms = frame_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        // Mock Data: Sine Wave
        let samples_to_gen = (self.rate as f32 * 0.1) as usize;
        let bytes_needed = samples_to_gen * self.channels as usize * 2;

        let mut data = Vec::with_capacity(bytes_needed);

        for i in 0..samples_to_gen {
            let t = (self.sample_counter + i as u64) as f32 / self.rate as f32;
            let val = (t * 440.0 * 2.0 * std::f32::consts::PI).sin();
            let sample = (val * 32767.0) as i16;

            for _ in 0..self.channels {
                data.extend_from_slice(&sample.to_le_bytes());
            }
        }

        self.sample_counter += samples_to_gen as u64;

        Ok(AudioFrame {
            data,
            timestamp: timestamp_ms,
            sequence: self.sample_counter,
            sample_rate: self.rate,
            channels: self.channels,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audio_drift_compensation() {
        let config = HardwareConfig {
            camera_fps: 30,
            audio_sample_rate: 44100,
            audio_channels: 2,
        };
        let audio = PhalanxAudioThread::new(&config);
        let mut rx = audio.subscribe();

        // Manual start for test
        audio.start_watchdog();

        let mut previous_ts = 0;
        for _ in 0..5 {
            if let Ok(frame) = rx.recv().await {
                if previous_ts > 0 {
                    let diff = frame.timestamp - previous_ts;
                    assert!(diff >= 90 && diff <= 110, "Time drift! Delta: {}ms", diff);
                }
                previous_ts = frame.timestamp;
            }
        }
        audio.stop();
    }

    #[tokio::test]
    async fn test_audio_data_generation() {
        let config = HardwareConfig {
            camera_fps: 30,
            audio_sample_rate: 44100,
            audio_channels: 1,
        };
        let audio = PhalanxAudioThread::new(&config);
        let mut rx = audio.subscribe();

        audio.start_watchdog();

        let frame = rx.recv().await.unwrap();
        assert!(!frame.data.is_empty());
        assert_eq!(frame.data.len(), 8820);

        audio.stop();
    }
}
