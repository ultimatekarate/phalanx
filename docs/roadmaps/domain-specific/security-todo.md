# 🛡️ Phalanx Hardening Roadmap

## Phase 1: Critical Security (The "Moat")

*These tasks address vulnerabilities that currently allow attackers to trivially join, map, or block the network.*

- [x] **Implement Private Swarms (PSK)**
  - **Defense Against:** Sybil Attacks, Eclipse Attacks, Unauthorized Discovery.
  - **Task:** Update `network.rs` to require a `swarm.key` file to establish any connection.
  - **Task:** Reject all peers who fail the Pre-Shared Key handshake (using `libp2p-pnet`).

- [x] **Implement Payload Encryption (E2EE)**
  
  - **Defense Against:** Eavesdropping (Internal & External).
  - **Task:** Add encryption library (e.g., `chacha20poly1305`).
  - **Task:** Refactor `WitnessEnvelope` to wrap the `VideoShard` in an encrypted blob.
  - **Task:** Ensure only the intended Stronghold (via Public Key) can decrypt the evidence.

- [x] **Enforce Time Drift Boundaries**
  
  - **Defense Against:** Timejacking, Replay Attacks.
  - **Task:** In `shards.rs`, add validation logic to reject packets with timestamps >5 minutes in the future or >24 hours in the past.

## Phase 2: Resilience & Anti-Abuse (The "Shield")

*These tasks prevent the system from being overwhelmed by spam or resource exhaustion.*

- [x] **Storage Quotas per Identity (DID)**
  - **Defense Against:** Storage Exhaustion (Spam).
  - **Task:** In `storage.rs`, track disk usage by `owner_did`.
  - **Task:** Implement an Eviction Policy: If disk is full, delete the oldest foreign shards from the Peer ID occupying the most space.

- [x] **Rate Limiting (The "Vampire Hunter")**
  
  - **Defense Against:** Battery Drain, Denial of Service.
  - **Task:** In `sentinel.rs`, track message rates per Peer ID.
  - **Task:** Implement a "Penalty Box": If a peer exceeds X requests/sec, ignore them for Y minutes.

- [x] **Protocol Version Enforcement**

  - **Defense Against:** Protocol Downgrade Attacks, Zombie Nodes.
  - **Task:** In `lib.rs` (Identify), strictly reject peers reporting incompatible protocol versions.

## Phase 3: Physical & Forensic Integrity (The "Vault")

*These tasks protect the data at rest and the device itself.*

- [ ] **Hardware-Backed Identity Storage**
  
  - **Defense Against:** Physical Extraction ($5 Wrench Attack).
  - **Task:** Move `identity.bin` from plain filesystem to OS Secure Store (Android Keystore / iOS Secure Enclave).
  - **Task:** Encrypt the local vault index so stolen devices don't reveal metadata.

- [ ] **Routing Table Sanity Checks**

  - **Defense Against:** Routing Table Poisoning.
  - **Task:** Configure Kademlia to periodically ping random buckets. Aggressively evict nodes that do not respond correctly.

- [x] **Sensor Attestation Metadata**
  
  - **Defense Against:** Sensor Spoofing / Deepfakes.
  - **Task:** Embed OS-level metadata (GPS confidence, camera driver hash) into the signed `VideoShard` to prove physical authenticity.
  