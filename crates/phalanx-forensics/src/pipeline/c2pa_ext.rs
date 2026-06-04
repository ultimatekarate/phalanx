use c2pa::Builder;
use phalanx_proto::corroboration::CorroborationProof;
use phalanx_proto::evidence::{ForensicMetrics, MediaType};

pub struct C2paOrchestrator;

impl C2paOrchestrator {
    /// Configures a C2PA Builder with Phalanx forensic assertions.
    /// This is PURE logic — no signing, no disk IO.
    /// The caller is responsible for signing via `builder.sign(...)`.
    pub fn build_manifest(node_id: &str, format: MediaType) -> Result<Builder, c2pa::Error> {
        let mut builder = Builder::default();
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
        let mut builder = Builder::default();
        builder.set_format(format.as_str());

        // Node identity assertion
        builder.add_assertion("phalanx.node_id", &node_id)?;

        // ForensicLens sensor fingerprint assertions
        builder.add_assertion("phalanx.lens.h_energy", &metrics.h_energy)?;
        builder.add_assertion("phalanx.lens.v_energy", &metrics.v_energy)?;
        builder.add_assertion("phalanx.lens.prnu_var", &metrics.prnu_var)?;

        // C2PA requires a c2pa.actions assertion whose first action is a
        // creation/open action; without it validators report
        // `assertion.action.malformed`. Phalanx originates the media from
        // device sensors, so the creation action is `c2pa.created`.
        builder.add_assertion(
            "c2pa.actions",
            &serde_json::json!({ "actions": [ { "action": "c2pa.created" } ] }),
        )?;

        Ok(builder)
    }

    /// Configures a C2PA Builder with corroboration proof assertions.
    ///
    /// Embeds the full corroboration evidence as structured C2PA assertions:
    /// event window, device attestations, sensor divergences, proximity evidence,
    /// and producer identity. Readable by any C2PA-compatible verification tool.
    ///
    /// Pure logic — no signing, no disk IO.
    #[allow(clippy::cast_possible_truncation)] // Epoch millis fit in u64 for centuries.
    pub fn build_corroboration_manifest(
        producer_did: &str,
        proof: &CorroborationProof,
    ) -> Result<Builder, c2pa::Error> {
        let mut builder = Builder::default();
        builder.set_format("image/jpeg");

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

        // Each contributing recording is a C2PA ingredient, referenced by its
        // encrypted evidence hash chain. This establishes the provenance link:
        // device capture → encrypted shard → corroboration proof → C2PA manifest.
        for attestation in &proof.attestations {
            let mut ingredient = c2pa::Ingredient::new_v2(
                format!("phalanx:recording:{}", attestation.recording_id.as_str()),
                "application/octet-stream",
            );
            ingredient
                .set_hash(hex::encode(attestation.chain_head))
                .set_relationship(c2pa::Relationship::ComponentOf);
            builder.add_ingredient(ingredient);
        }

        Ok(builder)
    }
}

// ── Self-Signed Certificate Generation ──────────────────────────────────

/// Generate a self-signed X.509 certificate for C2PA signing.
///
/// Returns the certificate in PEM format (what `CallbackSigner` expects).
/// The certificate's public key matches the provided signing key, so C2PA
/// validators can verify the signature chain.
///
/// Pure crypto — no IO. Caller wraps in `CallbackSigner` (Hands).
/// Used by both phalanx-ffi (mobile export) and phalanx-stronghold (proof export).
pub fn generate_self_signed_cert(signing_key: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose,
        PKCS_ED25519,
    };

    let Ok(mut params) = CertificateParams::new(vec!["phalanx-stronghold.local".to_string()])
    else {
        return Vec::new();
    };

    // C2PA §14.5 requires: digitalSignature key usage, an allowed EKU
    // (email_protection is the first checked by c2pa-rs), and an
    // AuthorityKeyIdentifier extension.
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    params.use_authority_key_identifier_extension = true;

    // C2PA COSE verification requires the signing certificate's subject to
    // carry an Organization (O) attribute — `c2pa`'s verifier reads it via
    // `subject().iter_organization()` and treats its absence as a missing
    // certificate chain, surfaced as `claimSignature.mismatch`. rcgen's default
    // DN has no Organization, so set one explicitly.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Phalanx");
    dn.push(DnType::CommonName, "Phalanx Self-Signed Signer");
    params.distinguished_name = dn;

    // Wrap the identity's Ed25519 secret key in PKCS8 DER so rcgen can use it.
    // Ed25519 PKCS8 format: fixed ASN.1 prefix (16 bytes) + 34-byte octet string
    // wrapping the 32-byte secret key.
    let secret_bytes = signing_key.to_bytes();
    let mut pkcs8_der = Vec::with_capacity(48);
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 } OCTET STRING { OCTET STRING (32 bytes) } }
    pkcs8_der.extend_from_slice(&[
        0x30, 0x2E, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE, 5 bytes
        0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ]);
    pkcs8_der.extend_from_slice(&secret_bytes);

    let pkcs8_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            pkcs8_der,
        )),
        &PKCS_ED25519,
    );

    let Ok(key_pair) = pkcs8_key else {
        return Vec::new();
    };
    let Ok(cert) = params.self_signed(&key_pair) else {
        return Vec::new();
    };

    cert.pem().into_bytes()
}
