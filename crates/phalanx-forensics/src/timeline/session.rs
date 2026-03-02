// crates/phalanx-forensics/src/timeline/session.rs

use phalanx_proto::prelude::*;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::evidence::{WitnessEnvelope, Evidence};
use phalanx_proto::storage::ShardError;
use crate::evidence::witness::WitnessAuthority; // Import our Verbs

pub trait ChronosAuthority {
    /// The Verb "To Seal": The only valid way to produce a WitnessEnvelope.
    /// This method enforces the causality chain by injecting the last_hash.
    fn seal_evidence(&mut self, evidence: Evidence) -> Result<WitnessEnvelope, ShardError>;
}

impl ChronosAuthority for CausalitySession {
    fn seal_evidence(&mut self, evidence: Evidence) -> Result<WitnessEnvelope, ShardError> {
        // 1. Perform the Seal using the WitnessAuthority Verb
        let envelope = WitnessEnvelope::sign_envelope(
            evidence,
            &self.identity,
            self.peer_id.clone(),
            self.last_hash, // Inject current causality anchor
        )?;

        // 2. Advance the Causality Chain
        // We use the signature hash of the just-sealed envelope as the anchor for the next
        self.last_hash = Some(envelope.calculate_anchor());

        Ok(envelope)
    }
}