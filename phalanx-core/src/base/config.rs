use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::env;
use crate::base::types::{ByteCapacity, MeshTopic}; 

/// The Physical Laws of the Simulation.
/// 
/// These constraints dictate how the network perceives time.
/// In the Sandbox, we use these to accelerate or decelerate "Network Time"
/// to test how the system behaves under high latency or rapid churn.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PhalanxPhysics {
    /// The fundamental unit of time: Round Trip Time (ms).
    /// Used as the base multiplier for all timeouts.
    pub tau_rtt: u64,      
    
    /// The compute tax: How long we expect a CPU to take to sign/verify a shard.
    pub delta_cpu: u64,    
    
    /// The Chaos Factor (Safety Margin).
    /// timeouts = jitter_factor * (tau + cpu).
    /// A higher jitter factor makes the network more tolerant of "Vampire" nodes.
    pub jitter_factor: u64 
}

impl PhalanxPhysics {
    /// Optimized for high-latency mobile WANs.
    pub fn default_wan() -> Self {
        Self {
            tau_rtt: 300,
            delta_cpu: 20,
            jitter_factor: 3,
        }
    }

    /// Optimized for local/CI environments.
    pub fn test_profile() -> Self {
        Self {
            tau_rtt: 50,
            delta_cpu: 100,
            jitter_factor: 5,
        }
    }

    /// Derives the "Max Survival Time" for a shard in transit.
    /// If a shard doesn't arrive by this time, it is considered lost.
    pub fn shard_timeout(&self) -> std::time::Duration {
        let ms = self.jitter_factor * (self.tau_rtt + self.delta_cpu);
        std::time::Duration::from_millis(ms)
    }
}

/// The Root Configuration for the Phalanx Engine.
#[derive(Debug, Deserialize, Clone)]
pub struct PhalanxConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub hardware: HardwareConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String, 
    pub max_chunk_size_bytes: usize, 
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub control_topic: MeshTopic,
    pub cleanup_interval_secs: u64,
    #[serde(default)] 
    pub bootstrap_peers: Vec<String>,
    #[serde(default = "default_service_key")]
    pub guardian_service_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub vault_path: String,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,
    pub max_peers: usize,
    pub stale_session_threshold: u64,
    pub shards_needed_to_archive: usize,
    #[serde(default = "default_max_storage")]
    pub max_storage_bytes: ByteCapacity,          
    #[serde(default = "default_max_foreign")]
    pub max_foreign_storage_bytes: ByteCapacity,  
}

#[derive(Debug, Deserialize, Clone)]
pub struct HardwareConfig {
    pub camera_fps: u32,
    pub audio_sample_rate: u32,
    pub audio_channels: u8,
}

// --- Helper Functions and Initializers ---

fn default_service_key() -> String { "phalanx/service/storage/v1".to_string() }
fn default_protocol_version() -> String { "/phalanx/1.0.0".to_string() }
fn default_max_storage() -> ByteCapacity { ByteCapacity(1_000_000_000) } 
fn default_max_foreign() -> ByteCapacity { ByteCapacity(500_000_000) }   

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
        let path = env::var("PHALANX_CONFIG").unwrap_or_else(|_| "phalanx.toml".to_string());
        Self::load(path).unwrap_or_else(|_| Self::default())
    }

    /// Restored: Specifically for simulation environments (src/sim.rs).
    pub fn test_defaults() -> Self {
        let mut cfg = Self::default();
        cfg.network.cleanup_interval_secs = 5; // Aggressive cleanup for tests
        cfg
    }

    pub fn test_salvage_on_node_death() -> Self {
        let mut cfg = Self::default();
        cfg.storage.vault_path = "sim_vault".to_string();
        // Aggressive cleanup to trigger salvage within the test's sleep window
        cfg.network.cleanup_interval_secs = 1; 
        cfg
    }
}

impl Default for PhalanxConfig {
    /// Provides the standard clinical default configuration.
    /// 
    /// Behavior: This implementation mirrors the structure required for 
    /// local development, providing safe defaults for topics and buffer sizes.
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                protocol_version: default_protocol_version(),
                max_chunk_size_bytes: 8192,
                video_topic: "phalanx/video".into(),
                audio_topic: "phalanx/audio".into(),
                control_topic: "phalanx/control".into(),
                cleanup_interval_secs: 60,
                bootstrap_peers: vec![],
                guardian_service_key: "phalanx/service/storage/v1".to_string(),
            },
            storage: StorageConfig {
                vault_path: "./sim_vault".to_string(),
                max_video_buffer: 100,
                max_audio_buffer: 100,
                max_peers: 10,
                stale_session_threshold: 3600,
                shards_needed_to_archive: 10,
                max_storage_bytes: default_max_storage(),
                max_foreign_storage_bytes: default_max_foreign(),
            },
            hardware: HardwareConfig {
                camera_fps: 10,
                audio_sample_rate: 16000,
                audio_channels: 1,
            },
        }
    }
}
