use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::Sender;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioShard {
    pub timestamp: u64,
    pub sequence_id: u32,
    pub data: Vec<u8>,
    pub sample_rate: u32,
    pub channels: u8,
}

pub struct PhalanxAudioThread {
    pub sample_rate: u32,
}