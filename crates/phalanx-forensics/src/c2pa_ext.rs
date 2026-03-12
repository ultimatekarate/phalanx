use c2pa::Builder;
use phalanx_proto::evidence::MediaType;

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
}
