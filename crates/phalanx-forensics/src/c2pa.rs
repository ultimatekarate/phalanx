use c2pa::{Manifest, Ingredient, ManifestStore};
use phalanx_proto::evidence::{MediaType};
use phalanx_proto::identity::SignerIdentity;

pub struct C2paOrchestrator;

impl C2paOrchestrator {
    /// Creates a C2PA Manifest in-memory.
    /// This is PURE logic — no disk IO.
    pub fn build_manifest_blob(
        signer: &SignerIdentity,
        volley_hash: &[u8; 32],
        format: MediaType,
    ) -> Result<Vec<u8>, ForensicError> {
        let mut manifest = Manifest::new("phalanx.mesh.v1");
        
        // Add Phalanx-specific assertions
        manifest.add_assertion("phalanx.node_id", &signer.0.to_string())
            .map_err(|_| ForensicError::ManifestGenerationFailed)?;

        // Set the format based on our Typed Enum
        let mime = format.as_str();

        // Generate the manifest store bytes
        let mut output = Vec::new();
        let mut store = ManifestStore::new();
        
        // Note: Real signing requires a Private Key (The Hands provide this)
        // For the Lab, we prepare the unsigned manifest structure.
        store.serialize_unsigned(&manifest, mime, &mut output)
            .map_err(|_| ForensicError::ManifestGenerationFailed)?;

        Ok(output)
    }
}