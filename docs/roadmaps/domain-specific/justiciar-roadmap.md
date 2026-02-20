# Justiciar: Retrieval and Playback

## Phase 1: Identity & Authentication

* [x] **Key Management Integration**: Implement the `PhalanxIdentity` loader for existing BIP-39 mnemonics.
* [ ] **Proof of Ownership**: Create a challenge-response protocol to prove `Did` ownership before a Stronghold releases `.phlx` archives.

## **Phase 2: Network Discovery & Routing**

* [x] **Kademlia Service Search**: Implement `GetProviders` queries to find nodes advertising the `guardian_service_key`.
* [ ] **Direct Dialing**: Establish authenticated `noise` protocol links to discovered Stronghold nodes.

## Phase 3: Data Retrieval Protocol

* [ ] **Archive Indexing**: Implement "List Volleys" requests for specific DIDs to browse available `.vid.phlx` and `.aud.phlx` files.
* [ ] **Reliable Fragment Fetching**: Build a Request/Response layer for individual shard fetching to handle interrupted downloads.

## Phase 4: Reconstruction & Decryption

* [x] **Client-Side Crucible**: Port `Macro Layer` reassembly logic to align `StorageSequence` shards chronologically.
* [x] **E2EE Decryption**: Implement `DataPayload::decrypt` logic using session keys to unlock raw JPEG/PCM data.

## Phase 5: Forensic Presentation

* [ ] **Stream Recomposition**: Buffer decrypted JPEG frames into GStreamer/FFmpeg `appsrc` for playback.
* [ ] **Export Pipeline**: Create a "Save to Disk" feature to transcode `Volley` artifacts into `.mp4` or `.wav` containers.
* [ ] **Integrity Verification**: Display the "Witness Chain" to verify shard signatures against the original owner's DID.
