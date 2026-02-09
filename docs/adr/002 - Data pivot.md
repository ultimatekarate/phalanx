## ADR 002: The Data Pivot (File-Based vs. Shard-Based)

**Context**: The standard industry practice is to record video to `.mp4` containers and hash the file upon completion. This introduced the "Atom Vulnerability": MP4 files require a global header (the MOOV atom) to be written at the *end* of the recording. If the device is destroyed, power is cut, or the application crashes mid-recording, this header is never written, rendering the entire file corrupt and unreadable.

**Decision**: We implemented the **Witness Envelope** architecture.

**Mechanism:** A custom serialization format where every "Volley" (a discrete temporal unit) is wrapped in its own self-sovereign identity structure containing independent metadata.

**Consequences**:

* **Positive:** **Atomic Validity.** If a device is destroyed at 10:05, the evidence captured at 10:04 remains functionally independent, playable, and legally admissible.
* **Positive:** Eliminates the single point of failure associated with global file headers.
