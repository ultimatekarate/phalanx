use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::env;

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
    pub grace_period: u64,
    pub cleanup_interval_secs: u64,
    
    #[serde(default)] 
    pub bootstrap_peers: Vec<String>,
    #[serde(default = "default_service_key")]
    pub stronghold_service_key: String,
}

fn default_service_key() -> String {
    "phalanx/service/storage/v1".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub vault_path: String,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,
    pub max_peers: usize,
    pub stale_session_threshold: u64,
    pub shards_needed_to_archive: usize,
    
    // --- GOVERNANCE QUOTAS ---
    #[serde(default = "default_max_storage")]
    pub max_storage_bytes: u64,          // Total disk limit
    #[serde(default = "default_max_foreign")]
    pub max_foreign_storage_bytes: u64,  // Limit for non-owned data
}

fn default_max_storage() -> u64 { 1_000_000_000 } // 1GB
fn default_max_foreign() -> u64 { 500_000_000 }   // 500MB

#[derive(Debug, Deserialize, Clone)]
pub struct HardwareConfig {
    pub camera_fps: u32,
    pub audio_sample_rate: u32,
    pub audio_channels: u8,
}

impl PhalanxConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: PhalanxConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_default() -> Self {
        Self::load("phalanx.toml").expect("Critical Error: Missing phalanx.toml")
    }

    pub fn load_from_env() -> Self {
        let path = env::var("PHALANX_CONFIG_PATH")
            .unwrap_or_else(|_| "phalanx.toml".to_string());
            
        Self::load(&path).unwrap_or_else(|_| {
            eprintln!("Config not found at {}. Loading defaults.", path);
            Self::default()
        })
    }

    pub fn test_defaults() -> Self {
        Self {
            network: NetworkConfig {
                heartbeat_interval_secs: 1,      
                pulse_timeout_secs: 2,           
                chunk_size_bytes: 1024,          
                video_topic: "test/video".into(),
                audio_topic: "test/audio".into(),
                control_topic: "test/control".into(),
                grace_period: 10,
                cleanup_interval_secs: 5,
                bootstrap_peers: vec![],
                stronghold_service_key: "test/service/storage".to_string(),
            },
            storage: StorageConfig {
                vault_path: "sim_vault".into(),
                max_video_buffer: 10,
                max_audio_buffer: 10,
                max_peers: 5,
                stale_session_threshold: 5,      
                shards_needed_to_archive: 100,
                // Quotas
                max_storage_bytes: 100_000_000,         // 100 MB
                max_foreign_storage_bytes: 50_000_000,  // 50 MB
            },
            hardware: HardwareConfig {
                camera_fps: 10,                 
                audio_sample_rate: 16000,
                audio_channels: 1,
            },
        }
    }

    pub fn test_salvage_on_node_death() -> Self {
        Self {
            network: NetworkConfig {
                heartbeat_interval_secs: 1,      
                pulse_timeout_secs: 2,           
                chunk_size_bytes: 1024,          
                video_topic: "test/video".into(),
                audio_topic: "test/audio".into(),
                control_topic: "test/control".into(),
                grace_period: 10,
                cleanup_interval_secs: 1,
                bootstrap_peers: vec![],
                stronghold_service_key: "test/service/storage".to_string(),
            },
            storage: StorageConfig {
                vault_path: "sim_vault".into(),
                max_video_buffer: 10,
                max_audio_buffer: 10,
                max_peers: 5,
                stale_session_threshold: 0,      
                shards_needed_to_archive: 1,
                // Quotas
                max_storage_bytes: 100_000_000,
                max_foreign_storage_bytes: 50_000_000,
            },
            hardware: HardwareConfig {
                camera_fps: 10,                 
                audio_sample_rate: 16000,
                audio_channels: 1,
            },
        }
    }

}

impl Default for PhalanxConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                heartbeat_interval_secs: 30,
                pulse_timeout_secs: 60,
                chunk_size_bytes: 8192,
                video_topic: "phalanx/video".to_string(),
                audio_topic: "phalanx/audio".to_string(),
                control_topic: "phalanx/control".to_string(),
                grace_period: 10,
                cleanup_interval_secs: 60,
                bootstrap_peers: vec![],
                stronghold_service_key: "phalanx/service/storage/v1".to_string(),
            },
            storage: StorageConfig {
                vault_path: "./sim_vault".to_string(),
                max_video_buffer: 100,
                max_audio_buffer: 100,
                max_peers: 10,
                stale_session_threshold: 3600,
                shards_needed_to_archive: 10,
                // Default Mobile Limits
                max_storage_bytes: 5_000_000_000,        // 5 GB Total
                max_foreign_storage_bytes: 1_000_000_000, // 1 GB Foreign
            },
            hardware: HardwareConfig {
                camera_fps: 30,
                audio_sample_rate: 44100,
                audio_channels: 2,
            },
        }
    }
}