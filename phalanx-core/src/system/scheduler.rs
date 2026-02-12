// We get here when a Sentinel node auto-promotes to a Guardian.
// That likely means the node is a mobile device, which means that thermal load
// must be managed.

// Pseudocode for now.


pub fn triage_process(envelope: &WitnessEnvelope, governor: &SystemGovernor) {
    // 1. Always check the Signature (Lightweight)
    if !envelope.verify_signature() {
        return; // Reject bad signatures immediately
    }

    // 2. Ask permission for Forensics (Heavyweight)
    if governor.check_permission(TaskCost::Heavy) {
        // We are on a Desktop, or a plugged-in Phone with a cooling fan
        let report = forensics::run_full_suite(&envelope.shard);
        network::gossip_verification(report);
    } else {
        // We are on a hot phone. Skip the FFT.
        // Just gossip the raw shard so a stronger node can verify it later.
        println!("Skipping forensics due to thermal load.");
        network::gossip_raw(envelope);
    }
}