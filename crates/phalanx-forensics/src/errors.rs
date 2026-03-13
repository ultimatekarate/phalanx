use crate::crucible::AmalgamError;
use phalanx_proto::prelude::GuardianError;

pub trait ForensicPromotion {
    fn promote(self) -> GuardianError;
}

impl ForensicPromotion for AmalgamError {
    fn promote(self) -> GuardianError {
        match self {
            AmalgamError::UnauthorizedHandover => GuardianError::PolicyViolation(
                "Unauthorized Handover: Origin DID mismatch".to_string(),
            ),
            AmalgamError::IdentityMismatch => GuardianError::PolicyViolation(
                "Identity Mismatch: Frame DID does not match Recording owner".to_string(),
            ),
            AmalgamError::AmbiguousOwnership => GuardianError::PolicyViolation(
                "Ambiguous Ownership: We require additional evidence to determine ownership. Dropping packet.".to_string(),
            ),
            AmalgamError::SequenceConflict(seq) => GuardianError::SequenceConflict(seq.0.into()),
        }
    }
}
