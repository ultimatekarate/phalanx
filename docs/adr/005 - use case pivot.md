# ADR 005: The Use-Case Pivot (Viewership vs. Archival)

**Context**: The original goal was to build a "P2P Twitch" for distributed live streaming, allowing users to broadcast events to multiple peers in real-time. This failed due to the "Fan-Out Bottleneck." Mobile networks have highly asymmetric bandwidth (low upload speeds). Attempting to serve a live stream to multiple viewing peers saturated the uploader's bandwidth, causing buffer bloat and dropped frames, which compromised the quality of the forensic recording.

**Decision**: We shifted the protocol's primary objective to **Streaming Upload** (The "Lifeboat" Protocol).

**Mechanism:** We abandoned the "One-to-Many" broadcast model in favor of a "One-to-One" (or One-to-Few) offload model. The goal changed from *broadcasting* the event to *evacuating* the data.

**Consequences:**

* **Positive:** We optimize for "Save Rate" rather than "View Rate."
* **Outcome:** The network functions as a "Bucket Brigade" for data safekeeping rather than a Content Delivery Network (CDN) for entertainment.
