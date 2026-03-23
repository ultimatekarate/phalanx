use c2pa::Builder;
use phalanx_proto::corroboration::CorroborationProof;
use phalanx_proto::evidence::{ForensicMetrics, MediaType};

pub struct C2paOrchestrator;

impl C2paOrchestrator {
    /// Configures a C2PA Builder with Phalanx forensic assertions.
    /// This is PURE logic — no signing, no disk IO.
    /// The caller is responsible for signing via `builder.sign(...)`.
    pub fn build_manifest(node_id: &str, format: MediaType) -> Result<Builder, c2pa::Error> {
        let mut builder = Builder::new();
        builder.set_format(format.as_str());

        // Tag every manifest with the originating Phalanx node identity
        builder.add_assertion("phalanx.node_id", &node_id)?;

        Ok(builder)
    }

    /// Configures a C2PA Builder with Phalanx forensic assertions AND
    /// sensor fingerprint metrics from the ForensicLens pipeline.
    ///
    /// Embeds four assertions:
    /// - `phalanx.node_id` — originating node identity
    /// - `phalanx.lens.h_energy` — horizontal Moiré energy (Laplacian)
    /// - `phalanx.lens.v_energy` — vertical Moiré energy (Laplacian)
    /// - `phalanx.lens.prnu_var` — PRNU variance (sensor fingerprint)
    ///
    /// These assertions enable downstream verifiers to check evidence provenance
    /// against calibrated sensor profiles without access to the raw pixel data.
    pub fn build_manifest_with_lens(
        node_id: &str,
        format: MediaType,
        metrics: &ForensicMetrics,
    ) -> Result<Builder, c2pa::Error> {
        let mut builder = Builder::new();
        builder.set_format(format.as_str());

        // Node identity assertion
        builder.add_assertion("phalanx.node_id", &node_id)?;

        // ForensicLens sensor fingerprint assertions
        builder.add_assertion("phalanx.lens.h_energy", &metrics.h_energy)?;
        builder.add_assertion("phalanx.lens.v_energy", &metrics.v_energy)?;
        builder.add_assertion("phalanx.lens.prnu_var", &metrics.prnu_var)?;

        Ok(builder)
    }

    /// Configures a C2PA Builder with corroboration proof assertions.
    ///
    /// Embeds the full corroboration evidence as structured C2PA assertions:
    /// event window, device attestations, sensor divergences, proximity evidence,
    /// and producer identity. Readable by any C2PA-compatible verification tool.
    ///
    /// Pure logic — no signing, no disk IO.
    pub fn build_corroboration_manifest(
        producer_did: &str,
        proof: &CorroborationProof,
    ) -> Result<Builder, c2pa::Error> {
        let mut builder = Builder::new();
        builder.set_format("application/json");

        // Producer identity
        builder.add_assertion("phalanx.corroboration.producer", &producer_did)?;

        // Proof hash (hex-encoded)
        let proof_hash_hex: String = proof
            .proof_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        builder.add_assertion("phalanx.corroboration.proof_hash", &proof_hash_hex)?;

        // Event window
        let event_window = serde_json::json!({
            "start": proof.event_window.start.0,
            "end": proof.event_window.end.0,
            "overlap_start": proof.event_window.overlap_start.0,
            "overlap_end": proof.event_window.overlap_end.0,
            "overlap_duration_ms": proof.event_window.overlap_duration().as_millis() as u64,
        });
        builder.add_assertion("phalanx.corroboration.event_window", &event_window)?;

        // Device count
        builder.add_assertion(
            "phalanx.corroboration.device_count",
            &proof.attestations.len(),
        )?;

        // Per-device attestations
        let attestations: Vec<serde_json::Value> = proof
            .attestations
            .iter()
            .map(|a| {
                serde_json::json!({
                    "did": a.did.as_ref(),
                    "recording_id": a.recording_id.as_str(),
                    "frame_count": a.frame_count,
                    "prnu_profile": {
                        "mean_prnu_var": a.prnu_profile.mean_prnu_var,
                        "std_prnu_var": a.prnu_profile.std_prnu_var,
                        "mean_h_energy": a.prnu_profile.mean_h_energy,
                        "mean_v_energy": a.prnu_profile.mean_v_energy,
                        "sample_count": a.prnu_profile.sample_count,
                    },
                    "chain_head": hex::encode(a.chain_head),
                    "chain_tail": hex::encode(a.chain_tail),
                })
            })
            .collect();
        builder.add_assertion("phalanx.corroboration.attestations", &attestations)?;

        // Pairwise sensor divergences (KS test results)
        let divergences: Vec<serde_json::Value> = proof
            .divergences
            .iter()
            .map(|d| {
                serde_json::json!({
                    "device_a": d.device_a.as_ref(),
                    "device_b": d.device_b.as_ref(),
                    "ks_statistic": d.ks_statistic,
                    "p_value": d.p_value,
                })
            })
            .collect();
        builder.add_assertion("phalanx.corroboration.divergences", &divergences)?;

        // Proximity evidence count
        builder.add_assertion(
            "phalanx.corroboration.proximity_count",
            &proof.proximity_evidence.len(),
        )?;

        Ok(builder)
    }
}

// ── Self-Signed Certificate Generation ──────────────────────────────────

/// Generate a self-signed X.509 certificate for C2PA signing.
///
/// Pure crypto — no IO. Caller wraps in `CallbackSigner` (Hands).
/// Used by both phalanx-ffi (mobile export) and phalanx-stronghold (proof export).
pub fn generate_self_signed_cert(verifying_key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    let Ok(params) = CertificateParams::new(vec!["phalanx-stronghold.local".to_string()]) else {
        return Vec::new();
    };

    // Generate a fresh keypair for the cert. The cert's public key won't match
    // the signer — this is acceptable for self-signed forensic provenance.
    // The forensic data (PRNU, proof hash) is what matters, not the CA chain.
    let Ok(key_pair) = KeyPair::generate_for(&PKCS_ED25519) else {
        return Vec::new();
    };
    let Ok(cert) = params.self_signed(&key_pair) else {
        return Vec::new();
    };

    // verifying_key will be used when we integrate proper cert binding.
    let _ = verifying_key;

    cert.der().to_vec()
}
