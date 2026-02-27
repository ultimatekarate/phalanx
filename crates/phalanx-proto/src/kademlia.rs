// crates/phalanx-proto/src/kademlia.rs

use crate::identity::NetworkId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadKind {
    ShardPointer = 0,
    NodeDiscovery = 1,
    SecurityPolicy = 2,
    Unspecified = 65535,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPayload {
    pub version: u16,
    pub variant: PayloadKind,
    pub expires_at_unix: Option<u64>,
    pub data: Vec<u8>,
}

impl DhtPayload {
    pub const CURRENT_VERSION: u16 = 1;
    pub const MAX_PAYLOAD_SIZE: usize = 65536;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderEntry {
    pub network_id: NetworkId,
    pub expiration: u64,
    pub reputation_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtProviderSet {
    pub providers: Vec<ProviderEntry>,
}

impl DhtProviderSet {
    pub const MAX_PROVIDERS: usize = 20;
}
