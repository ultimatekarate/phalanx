// crates/phalanx-stronghold/src/error.rs

use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::CorroborationError;
use phalanx_proto::identity::{Did, RecordingId};

#[derive(Debug, thiserror::Error)]
pub enum StrongholdError {
    #[error("Storage failure: {0}")]
    Storage(String),

    #[error("Community not found: {0:?}")]
    CommunityNotFound(CommunityId),

    #[error("Recording not found: {0}")]
    RecordingNotFound(RecordingId),

    #[error("Recording not decrypted: {0} (grant required)")]
    RecordingEncrypted(RecordingId),

    #[error("DID not a member of any known community: {0}")]
    UnknownDid(Did),

    #[error("Grant error: {0}")]
    Grant(String),

    #[error("Corroboration failed: {0}")]
    Corroboration(#[from] CorroborationError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Export error: {0}")]
    Export(String),

    #[error("Community expired")]
    CommunityExpired,

    #[error("Vouch verification failed: {0}")]
    VouchVerification(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
