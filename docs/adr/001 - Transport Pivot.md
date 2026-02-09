## ADR 001: The Transport Pivot (Integrity vs. Continuity)

### Context

The initial hypothesis was to utilize standard WebRTC (similar to Zoom or Google Meet) to achieve low-latency video transmission over UDP. However, this approach failed due to the "Lie of Smoothness." WebRTC optimizes for *Quality of Experience (QoE)*; when packets are dropped, it employs "Packet Loss Concealment" (PLC) to interpolate pixels and smooth over glitches. In a legal context, software-generated pixel interpolation is inadmissible and can be argued by defense counsel as "tampering" or "manufacturing evidence."

### Decision

We engineered **Crucible**, a custom ingestion engine, to replace WebRTC.

* **Mechanism:** Instead of skipping gaps to maintain visual flow, Crucible materializes gaps as cryptographically signed "Tombstones."
* **Constraint:** Zero percent interpolation is permitted.

### Consequences

* **Positive:** The stream is treated as a sparse set cover problem. The viewer sees exactly what was received, with verified cryptographic proof of exactly what was lost.
* **Negative:** The viewing experience may be jittery or contain visual artifacts (black frames) where data is missing, prioritizing forensic accuracy over viewer comfort.
