use c2pa::Builder;
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
}
