use crate::crucible::AmalgamError;
use phalanx_proto::prelude::{GuardianError, ShardError};

pub trait ForensicPromotion {
    fn promote(self, is_authoritative: bool) -> GuardianError;
}

impl ForensicPromotion for AmalgamError {
    fn promote(self, is_authoritative: bool) -> GuardianError {
        if !is_authoritative {
            return match self {
                AmalgamError::SequenceConflict(seq) => {
                    GuardianError::SequenceConflict(seq.0.into())
                }
                _ => GuardianError::AmbiguousOwnership,
            };
        }
        match self {
            AmalgamError::UnauthorizedHandover => GuardianError::PolicyViolation(
                "Unauthorized Handover: Origin DID mismatch".to_string(),
            ),
            AmalgamError::IdentityMismatch => GuardianError::PolicyViolation(
                "Identity Mismatch: Frame DID does not match Recording owner".to_string(),
            ),
            AmalgamError::AmbiguousOwnership => GuardianError::PolicyViolation(
                "Ambiguous Ownership: additional evidence needed".to_string(),
            ),
            AmalgamError::SequenceConflict(seq) => GuardianError::SequenceConflict(seq.0.into()),
        }
    }
}

/// ShardError promotion: shard-level errors are never authoritative
/// (ShardMold::is_authoritative always returns false), so this always
/// maps to PolicyViolation with the Display output.
impl ForensicPromotion for ShardError {
    fn promote(self, is_authoritative: bool) -> GuardianError {
        if is_authoritative {
            GuardianError::PolicyViolation(self.to_string())
        } else {
            GuardianError::AmbiguousOwnership
        }
    }
}
