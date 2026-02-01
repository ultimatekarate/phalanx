use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct PhalanxConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub hardware: HardwareConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub heartbeat_interval_secs: u64,
    pub pulse_timeout_secs: u64,
    pub chunk_size_bytes: usize,
    pub video_topic: String,
    pub audio_topic: String,
    pub control_topic: String,
    pub grace_period: u64
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub vault_path: String,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,
    pub max_peers: usize,
    pub stale_session_threshold: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HardwareConfig {
    pub camera_fps: u32,
    pub audio_sample_rate: u32,
    pub audio_channels: u8,
}

impl PhalanxConfig {
pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        // We use the toml crate to turn the string into our struct
        let config: PhalanxConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_default() -> Self {
        Self::load("phalanx.toml").expect("Critical Error: Missing phalanx.toml")
    }
}