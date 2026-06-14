// crates/phalanx-stronghold/src/signing.rs
//
// C2PA signer construction for the Stronghold.
//
// Hands layer — wiring only. Crypto logic lives in the Laboratory (c2pa_ext).
// Two paths: file-based cert/key (production) or self-signed (development/forensic).

use c2pa::{CallbackSigner, SigningAlg, create_signer};
use phalanx_forensics::c2pa_ext::generate_self_signed_cert;
use phalanx_proto::identity::PhalanxIdentity;

use crate::config::CorroborationConfig;
use crate::error::StrongholdError;

/// Create a C2PA signer for proof export.
///
/// If `c2pa_cert_path` and `c2pa_key_path` are configured, uses the on-disk
/// certificate and key pair (production path — CA-issued certs).
///
/// Otherwise, generates a self-signed X.509 certificate from the Stronghold's
/// identity keypair (development/forensic path — no CA required).
pub fn create_stronghold_signer(
    identity: &PhalanxIdentity,
    config: &CorroborationConfig,
) -> Result<Box<dyn c2pa::Signer>, StrongholdError> {
    // Production path: cert and key files on disk.
    if let (Some(cert_path), Some(key_path)) = (&config.c2pa_cert_path, &config.c2pa_key_path) {
        let signer = create_signer::from_files(cert_path, key_path, SigningAlg::Ed25519, None)
            .map_err(|e| StrongholdError::Export(format!("Failed to load C2PA cert/key: {e}")))?;
        return Ok(signer);
    }

    // Self-signed path: use the Stronghold's identity keypair.
    let cert_pem = generate_self_signed_cert(&identity.keypair);

    if cert_pem.is_empty() {
        return Err(StrongholdError::Export(
            "Failed to generate self-signed certificate".to_string(),
        ));
    }

    // Clone the signing key for the callback closure.
    let signing_key = identity.keypair.clone();

    let callback = move |_context: *const (), data: &[u8]| -> c2pa::Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    };

    let signer = CallbackSigner::new(callback, SigningAlg::Ed25519, cert_pem);
    Ok(Box::new(signer))
}
