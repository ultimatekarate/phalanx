# 🏛️ Phalanx: Architectural Design Pivots & Decision Records

This document outlines the critical "Fork in the Road" moments where Phalanx diverged from standard industry practices to solve specific forensic constraints.

---

## 1. The Transport Pivot: Integrity vs. Continuity

From WebRTC (Real-Time) → Crucible (Forensic Integrity)

* **The Hypothesis:** Use standard WebRTC (like Zoom/Meet) for low-latency video transmission over UDP.
* **The Failure (The "Lie of Smoothness"):** WebRTC optimizes for *Quality of Experience (QoE)*. When packets drop, it uses "Packet Loss Concealment" (PLC) to interpolate pixels and smooth over glitches. In a legal context, software-generated pixel interpolation can be argued as "tampering" or "manufacturing evidence."
* **The Pivot:** We engineered **Crucible**, a custom ingestion engine.
  * *Mechanism:* Instead of skipping gaps to maintain flow, Crucible materializes gaps as cryptographically signed "Tombstones."
  * *Outcome:* We treat the stream as a sparse set cover problem. 0% interpolation is allowed. The viewer sees exactly what was received, with verified proof of what was lost.

## 2. The Data Pivot: File-Based vs. Shard-Based

From MP4 Containers → Witness Envelopes

* **The Hypothesis:** Record video to standard `.mp4` files and hash the file upon completion.
* **The Failure (The "Atom Vulnerability"):** MP4 files require a global header (MOOV atom) to be written at the *end* of the recording. If the device is destroyed, power is cut, or the app crashes mid-recording, the header is never written, rendering the entire file corrupt and unreadable.
* **The Pivot:** We invented the **Witness Envelope**.
  * *Mechanism:* A custom serialization format where every "Volley" (temporal unit) is wrapped in its own self-sovereign identity structure with independent metadata.
  * *Outcome:* **Atomic Validity.** If a phone is destroyed at 10:05, the evidence from 10:04 is functionally independent, playable, and legally admissible.

## 3. The Consensus Pivot: Global vs. Local

From Blockchain Ledger → Recursive Assembly (Merkle Tree)

* **The Hypothesis:** Hash every frame and broadcast it to a public ledger/blockchain for immutability.
* **The Failure (The "Throughput Trap"):** Public blockchains are too slow (15 TPS) and expensive. Private blockchains are too heavy for mobile battery life. The latency of "Global Consensus" caused buffer overflows on the recording device.
* **The Pivot:** We shifted to **Recursive Assembly**.
  * *Mechanism:* We don't need the world to agree the video exists; we need to prove the *Sensor* saw it. We use a local **"Merkle Tree of Time"**—smelting Shards into Volleys, and Volleys into Archives locally.
  * *Outcome:* We achieve "Chain of Custody" without the network overhead of "Global Consensus."

## 4. The Routing Pivot: Equality vs. Biology

From Standard Gossipsub → Vampire Routing

* **The Hypothesis:** Use standard P2P gossip where every node is an equal peer that relays messages to maximize network health.
* **The Failure (The "Tragedy of the Commons"):** In high-stress scenarios (protests, disasters), relaying heavy video traffic drains the battery of the very phones trying to record evidence.
* **The Pivot:** We implemented **Vampire Routing** (Biological Resource Governance).
* *Mechanism:* We derived a utility function based on the derivative of battery drain ($\frac{dE}{dt}$). Nodes dynamically demote themselves to "Leaf Mode" (Listen-Only) when under stress.
* *Outcome:* The network degrades gracefully. The mesh sacrifices "Routing Efficiency" to preserve "Witness Survivability."

## 5. The Use-Case Pivot: Viewership vs. Archival

From Distributed Live Streaming → Streaming Upload (The "Lifeboat" Protocol)

* **The Hypothesis:** Build a "P2P Twitch" or "Periscope" where users could broadcast live protests to multiple peers for real-time viewing.
* **The Failure (The "Fan-Out" Bottleneck):** Mobile networks have highly asymmetric bandwidth (low upload speeds). Trying to serve a live video stream to multiple viewing peers saturated the uploader's bandwidth, causing buffer bloat and dropped frames. The "Real-Time" requirement compromised the quality of the recording itself.
* **The Pivot:** We shifted to **Streaming Upload**.
  * *Mechanism:* We abandoned the "One-to-Many" broadcast model for a "One-to-One" (or One-to-Few) offload model. The goal changed from *broadcasting* the event to *evacuating* the data.
  * *Outcome:* We treat the network as a "Bucket Brigade" for safekeeping, not a content delivery network (CDN) for entertainment. We optimize for "Save Rate," not "View Rate."
