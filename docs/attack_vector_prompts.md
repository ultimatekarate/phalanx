# Phalanx Attack Vector Prompts — Advanced Threats

Supplemental to `ATTACK_SURFACE_PROMPTS.md`. These prompts cover Eclipse & Routing Table Poisoning, Time-Dilation Attacks, Serialization/Decompression Bombs, and Pollution Attacks. Each prompt is self-contained.

---

## ECLIPSE & ROUTING TABLE POISONING

### E1 — No Swarm Connection Limits (Full Eclipse)

In crates/phalanx-node/src/network/orchestrator.rs around lines 72-74, the libp2p swarm is configured with only an idle connection timeout. There are no calls to with_max_incoming_connections(), with_max_outgoing_connections(), or with_max_established_connections(). libp2p defaults to unlimited connections, so an attacker can open hundreds of inbound connections and monopolize all peer slots, isolating the node from the honest network (eclipse attack).

Fix: Add connection limits to the swarm configuration in orchestrator.rs:

```rust
.with_swarm_config(|c| {
    c.with_idle_connection_timeout(Duration::from_secs(60))
     .with_max_established_per_peer(Some(2))
     .with_max_pending_incoming(Some(64))
     .with_max_established_incoming(Some(128))
     .with_max_established_outgoing(Some(64))
     .with_max_established(Some(192))
})
```

Make all limits configurable via NetworkConfig rather than hardcoded. Add a test that verifies the swarm rejects connections beyond the configured maximum.

### E2 — No Gossipsub Peer Scoring

In crates/phalanx-transport/src/builder.rs around lines 82-90, gossipsub is configured with ValidationMode::Strict and signed messages, but no peer scoring parameters. Without scoring, gossipsub cannot penalize peers that send invalid messages, flood topics, or graft excessively. An attacker's Sybil peers can fill all mesh slots (default mesh_n=8) and partition the victim from honest peers.

Fix: Configure gossipsub with peer scoring using PeerScoreParams and PeerScoreThresholds. Add topic-specific scoring that penalizes:

1. Invalid messages (AppSpecificWeight negative score)
2. Excessive message rate (TopicScoreParams with TimeInMeshQuantum)
3. First-message delivery failures
4. Mesh message delivery failures

Use gossipsub::ConfigBuilder::default().peer_score() and .peer_score_thresholds() to wire the scoring into the builder. Set gossip_lazy, mesh_n, mesh_n_low, and mesh_n_high explicitly rather than relying on defaults.

### E3 — Kademlia Default Configuration (No Bucket Hardening)

In crates/phalanx-node/src/network/orchestrator.rs around lines 39-41, Kademlia is initialized with Config::new(protocol) using all defaults. There is no bucket_size override, no replication_factor tuning, and no routing table refresh configuration. An attacker can poison the routing table by flooding specific k-buckets with Sybil node IDs clustered near the target's ID.

Fix: Harden the Kademlia configuration:

```rust
let mut kad_config = kad::Config::new(kad_protocol);
kad_config.set_replication_factor(NonZeroUsize::new(20).unwrap());
kad_config.set_query_timeout(Duration::from_secs(30));
kad_config.set_record_ttl(Some(Duration::from_secs(3600)));
kad_config.set_provider_record_ttl(Some(Duration::from_secs(3600)));
kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
```

Additionally, implement a custom RecordStore that validates provider records against the local peer reputation system before accepting them. Reject provider records from peers with reputation below a configurable threshold (e.g., 30).

### E4 — Default Reputation 1.0 Enables Sybil DHT Poisoning

In crates/phalanx-node/src/trust.rs around lines 515-531, evaluate_reputation() returns 1.0 (maximum baseline) for any peer not yet tracked. In crates/phalanx-node/src/persistence/kademlia.rs around lines 272-276, this score is used directly for DHT provider insertion via try_insert_weighted(). Combined with the 20-provider cap per key (DhtProviderSet::MAX_PROVIDERS), an attacker can create 20 Sybil identities, each getting score 1.0, and fill all provider slots for any DHT key.

Fix: Change the default reputation for unknown peers from 1.0 to a low value (e.g., 0.1). In trust.rs, change the None arm of evaluate_reputation() to return 0.1 instead of 1.0. Then in kademlia.rs, add a minimum reputation threshold for provider insertion (e.g., 0.3). This forces new peers to build reputation before they can become providers. Add a comment explaining that 0.1 is the "stranger" score and 0.3 is the "known peer" threshold.

### E5 — No IP/ASN Diversity Enforcement

Nowhere in the phalanx codebase is there any tracking of peer IP addresses, subnets, or autonomous system numbers. The IngressGovernor in crates/phalanx-forensics/src/policy.rs tracks only NetworkId and TrustLevel. An attacker running 100 nodes from a single datacenter is indistinguishable from 100 geographically distributed nodes.

Fix: Add IP diversity tracking to the IngressGovernor. Add a field `peer_subnets: HashMap<IpNetwork, HashSet<NetworkId>>` that tracks how many peers share the same /24 subnet (IPv4) or /48 subnet (IPv6). When try_allocate() is called, check if the peer's subnet already has more than `max_peers_per_subnet` (default: 3) active slots. If so, reject the allocation. The peer's IP address should be extracted from the libp2p ConnectedPoint when the connection is established and passed through to the governor. Add max_peers_per_subnet to the policy config.

### E6 — Lazy Peer Registration Has No Rate Limit

In crates/phalanx-node/src/trust.rs around lines 280-300, when an unknown peer triggers any trust operation, it is immediately registered via lazy registration with no rate limiting. An attacker can trigger registrations for thousands of Sybil identities per second by sending messages from new peer IDs, bloating the peer tracking HashMap and consuming memory.

Fix: Add a rate limiter to the lazy registration path. Track registration timestamps in a separate structure (e.g., a VecDeque of recent registration Instants). Before registering a new peer, check if the registration rate exceeds a threshold (e.g., 10 new peers per second). If exceeded, reject the registration and log a warning. Also add a maximum total peer count (e.g., 10,000) beyond which new registrations are refused entirely. Evict the lowest-reputation peers when approaching the limit.

### E7 — Reputation Recovery Too Aggressive

In crates/phalanx-forensics/src/policy.rs around lines 21-51, accumulate_reputation() recovers peer reputation by recovery_step (default 5 points) every interval_secs (default 60 seconds). With max reputation at 100, a fully penalized peer recovers completely in 20 minutes. This allows an attacker to cycle between attacks and recovery indefinitely.

Fix: Implement exponential backoff on reputation recovery. Track the number of times a peer has been penalized in its PeerRecord. Each subsequent offense doubles the recovery interval:

```rust
effective_interval = base_interval * 2^(offense_count - 1)
```

Cap offense_count at 10 (so max recovery time = base * 1024 = ~17 hours at 60s base). Also reduce the default recovery_step from 5 to 2, making full recovery take 50 intervals even without backoff. Add a `offense_count: u32` field to PeerRecord and increment it on each penalty event.

---

## TIME-DILATION ATTACKS

### T1 — NTP Failure Silently Falls Back to Timestamp Zero

In crates/phalanx-node/src/clock.rs around lines 174-177, the TrustedClockTrait implementation calls self.now() which returns a Result, and on error falls back to PhalanxTimestamp::from_millis(0) — Unix epoch. If NTP synchronization fails (lines 126-170) and the local clock errors, all timestamps become 0. Evidence timestamped normally (e.g., year 2026) appears to be billions of milliseconds in the "future" relative to timestamp 0, which may either pass or fail freshness checks depending on tolerance.

Fix: Replace the fallback from PhalanxTimestamp::from_millis(0) with a strategy that preserves the last known good time. Add a field `last_known_good: AtomicU64` to TrustedClock that is updated on every successful now() call. On error, return PhalanxTimestamp::from_millis(last_known_good) instead of 0. Additionally, add an NTP health flag that is checked by the SystemGovernor — if NTP has not successfully synchronized in the last 5 minutes, escalate the power state to Degraded and log a warning. Never silently return epoch zero.

### T2 — Temporal Tolerance Expands Without Upper Bound

In crates/phalanx-node/src/vitals.rs around lines 321-327, temporal_tolerance() returns base_temporal_drift plus Duration::from_secs_f64(l_integral). The l_integral field accumulates latency pressure via record_latency_pressure() (lines 300-305) with exponential decay, but there is no upper bound. An attacker who sends evidence with artificially large age values (e.g., timestamp = now - 60 seconds) inflates l_integral, expanding the tolerance window. After sustained attack, tolerance can grow to minutes or hours, accepting arbitrarily stale or future-dated evidence.

Fix: Add a hard cap to temporal_tolerance(). After computing `base + expansion`, clamp the result:

```rust
fn temporal_tolerance(&self) -> Duration {
    self.with_state(|s| {
        let base = self.config.base_temporal_drift;
        let expansion = Duration::from_secs_f64(s.l_integral);
        let total = base + expansion;
        let max_tolerance = self.config.max_temporal_tolerance; // new config field
        total.min(max_tolerance)
    })
}
```

Add `max_temporal_tolerance: Duration` to the SystemGovernorConfig with a default of 10 seconds. Also add rate limiting to record_latency_pressure(): ignore pressure values above a threshold (e.g., 30 seconds) to prevent a single stale packet from spiking the integral.

### T3 — Sticky Trust Optimization Skips Temporal Gate Entirely

In crates/phalanx-forensics/src/gate.rs around lines 108-113, when an envelope's prev_hash matches the current anchor (is_anchored == true), the code returns Ok(self) immediately, skipping the temporal gate at lines 115-128. This means anchored evidence is never checked for freshness. An attacker who knows the anchor hash can submit evidence with timestamps years in the future, and it will be accepted without any temporal validation.

Fix: Restructure the gate so that temporal validation is NEVER skipped. Move the temporal gate check (lines 115-128) ABOVE the anchor optimization (lines 108-113). The anchor optimization should only skip non-cryptographic, non-temporal checks like replay detection or duplicate filtering — never signature verification or temporal freshness. The corrected order should be: (1) signature verification (always), (2) temporal freshness (always), (3) anchor-based optimizations for other checks.

### T4 — Tolerance Passed as Untyped u64 (Unit Confusion Risk)

In crates/phalanx-forensics/src/gate.rs around lines 74-84, the IntegrityGate trait accepts tolerance as a raw u64 with no documentation of units. PhalanxTimestamp stores milliseconds internally. If any caller passes tolerance in seconds instead of milliseconds, the window becomes 1000x larger. The same untyped u64 appears in the promote() method at line 262.

Fix: Replace the raw u64 tolerance parameter with Duration throughout the gate API. Change the IntegrityGate trait signature:

```rust
fn check_integrity(
    self,
    node_id: &NetworkId,
    clock: &dyn TrustedClock,
    tolerance: Duration,  // was: u64
    anchor: Option<SignatureHash>,
) -> Result<Self, ShardError>;
```

Update verify_freshness() in judge.rs to accept Duration and convert internally to milliseconds for comparison. Update all callers (ingestion.rs, retrieval.rs, etc.) to pass Duration directly from temporal_tolerance(). This makes unit confusion impossible at the type level.

### T5 — PhalanxTimestamp::now() Uses Wall Clock, Panics on Backward Clock

In crates/phalanx-proto/src/time.rs around lines 25-32, PhalanxTimestamp::now() calls SystemTime::now().duration_since(UNIX_EPOCH).expect("System clock went backwards"). This has two problems: (1) it uses the wall clock which can be manipulated by an attacker with NTP access or root privileges, and (2) it panics with expect() if the system clock goes backward, which is an instant DoS on any clock adjustment.

Fix: Replace the expect() with a proper error return. Change now() to return Result<Self, TimeError> instead of Self. For callers that need infallible timestamps, provide a now_or_last() method that falls back to the last known good timestamp (stored in a thread-local or AtomicU64) rather than panicking. For the wall-clock issue, add a comment documenting that PhalanxTimestamp::now() is only for non-security-critical uses — all security-critical timestamp validation must go through TrustedClock which applies NTP offset correction.

### T6 — TTL Set From Dynamic Tolerance at Acceptance Time

In crates/phalanx-node/src/actors/ingestion.rs around lines 165-173, the TTL passed to storage is set to the current temporal_tolerance() value at the time of ingestion. Because tolerance is dynamic and can be inflated by the attacker (see T2), an attacker can: (1) inflate the tolerance via latency pressure, (2) send valid evidence that gets accepted with the inflated TTL, (3) this evidence persists far longer than intended because its TTL was set during the inflated window.

Fix: Decouple the storage TTL from the dynamic tolerance. Use a fixed, configured TTL for storage persistence (e.g., `config.evidence_ttl = Duration::from_secs(300)`). The dynamic tolerance should only be used for the freshness check at ingestion time, not for determining how long evidence lives in storage. Add `evidence_ttl: Duration` to the node config with a sensible default. In ingestion.rs, replace `ttl: tolerance` with `ttl: self.config.evidence_ttl`.

---

## SERIALIZATION & DECOMPRESSION BOMBS

### S1 — Unbounded LZ4 Decompression (Decompression Bomb)

In crates/phalanx-forensics/src/reassembler.rs around lines 73-75, decompress_payload() calls lz4_flex::decompress_size_prepended() with no output size limit. The LZ4 format includes a prepended size header that the decompressor trusts — an attacker can craft a 1 KB compressed payload with a header claiming 4 GB decompressed size, causing an immediate 4 GB allocation. The same function is called in crates/phalanx-node/src/actors/playback.rs around lines 79-84.

Fix: Replace the direct lz4_flex::decompress_size_prepended() call with a bounded decompression wrapper:

```rust
const MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub fn decompress_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 4 {
        return Err("Payload too small for LZ4 header".into());
    }
    let claimed_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if claimed_size > MAX_DECOMPRESSED_SIZE {
        return Err(format!(
            "Decompressed size {} exceeds limit {}",
            claimed_size, MAX_DECOMPRESSED_SIZE
        ));
    }
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| format!("LZ4 Decompression error: {}", e))
}
```

Apply the same check in playback.rs. Make MAX_DECOMPRESSED_SIZE configurable.

### S2 — gate::unmarshal() Deserializes Arbitrary Types Without Size Bounds

In crates/phalanx-forensics/src/gate.rs around lines 22-30, the unmarshal() function calls postcard::from_bytes() on untrusted data with no pre-validation of the input size or the resulting structure's memory footprint. Postcard will allocate memory for Vec fields based on the serialized length prefix — an attacker can craft a small serialized payload that claims to contain a Vec with billions of elements.

Fix: Add a maximum input size parameter to unmarshal():

```rust
pub fn unmarshal<T: serde::de::DeserializeOwned>(
    data: &[u8],
    context: &str,
    max_input_bytes: usize,
) -> Result<T, ShardError> {
    if data.len() > max_input_bytes {
        return Err(ShardError::SerializationError(
            format!("{}: input {} bytes exceeds limit {}", context, data.len(), max_input_bytes)
        ));
    }
    postcard::from_bytes(data).map_err(|e| {
        warn!(event = "deserialization_failure", context, error = %e);
        ShardError::SerializationError(e.to_string())
    })
}
```

Update all call sites to pass an appropriate max_input_bytes for their context (e.g., 1 MiB for shard chunks, 16 MiB for volley data, 256 bytes for control messages). Search for all calls to unmarshal() and postcard::from_bytes() across the codebase and ensure every one has a size check.

### S3 — Shard Assembly Allocates Unbounded Total Payload

In crates/phalanx-forensics/src/reassembler.rs around lines 215-232, ShardMold::assemble() sums the sizes of all accumulated chunks into total_size and calls Vec::with_capacity(total_size) without any upper bound. With 10,000 chunks (the clamped maximum) each potentially megabytes in size, total_size can reach tens of gigabytes.

Fix: Add a maximum assembled payload size check before allocation:

```rust
const MAX_ASSEMBLED_PAYLOAD: usize = 128 * 1024 * 1024; // 128 MiB

fn assemble(&self, _key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
    let total_size: usize = acc.parts.values().map(|v| v.len()).sum();
    if total_size > MAX_ASSEMBLED_PAYLOAD {
        tracing::warn!(
            total_size,
            limit = MAX_ASSEMBLED_PAYLOAD,
            "Shard assembly rejected: total payload exceeds limit"
        );
        return None;
    }
    let mut full_payload = Vec::with_capacity(total_size);
    // ... rest of assembly
}
```

### S4 — Network Codec MAX_PAYLOAD_SIZE Insufficient Against Nested Allocation

In crates/phalanx-transport/src/codec.rs around lines 17-37, the length-prefixed read enforces MAX_PAYLOAD_SIZE (10 MB from phalanx-proto/src/lib.rs line 55) on the wire payload, but postcard deserialization can amplify memory usage beyond the wire size. A 10 MB postcard payload containing a VolleyResponse with nested Vec<ForensicUnit> where each unit has large Vec<u8> fields can trigger allocations far exceeding 10 MB as postcard builds the deserialized structure.

Fix: Reduce MAX_PAYLOAD_SIZE from 10 MB to 2 MB (2_097_152 bytes) in phalanx-proto/src/lib.rs. After deserialization in codec.rs, add post-deserialization validation that checks the size of key fields in the deserialized VolleyRequest/VolleyResponse:

```rust
fn validate_response_size(resp: &VolleyResponse) -> io::Result<()> {
    match resp {
        VolleyResponse::Success(units) => {
            if units.len() > 1000 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Too many units in response"));
            }
            // Check individual unit sizes if needed
        }
        _ => {}
    }
    Ok(())
}
```

Apply similar validation to VolleyRequest after deserialization in read_request().

### S5 — ShardGapReport missing_indices Unbounded

In crates/phalanx-proto/src/evidence.rs, the DataPayload::Missing variant contains a ShardGapReport which has a missing_indices: Vec<u32> field. An attacker can serialize a ShardGapReport claiming millions of missing indices, causing a massive Vec allocation during deserialization even though the actual useful data is tiny.

Fix: Add a maximum length for missing_indices. In the ShardGapReport struct, add a validation method:

```rust
impl ShardGapReport {
    pub const MAX_MISSING_INDICES: usize = 10_000;

    pub fn validate(&self) -> Result<(), ShardError> {
        if self.missing_indices.len() > Self::MAX_MISSING_INDICES {
            return Err(ShardError::InvalidConfiguration(
                format!("missing_indices count {} exceeds limit {}", self.missing_indices.len(), Self::MAX_MISSING_INDICES)
            ));
        }
        Ok(())
    }
}
```

Call validate() immediately after deserializing any Evidence that may contain a ShardGapReport. Also add #[serde(deserialize_with = "...")] to enforce the limit during deserialization itself if possible.

---

## POLLUTION ATTACKS

### P1 — Crucible Capacity Shared Across All Peers (No Per-Peer Quota)

In crates/phalanx-forensics/src/crucible.rs around line 125, the Crucible has a global max_capacity of 1000 active VolleyId contexts. There is no per-peer quota. A single attacker can send shards for 1000+ unique VolleyIds with minimal data, filling all context slots. When the 1001st arrives, legitimate evidence is silently dropped (lines 190-192 return Ok(None)).

Fix: Add per-peer context tracking to the Crucible. Add a field `contexts_per_peer: HashMap<NetworkId, usize>` that counts how many active contexts each peer has. Add a `max_contexts_per_peer: usize` config (default: 50). In the ingest path, before creating a new context, check if the peer already has max_contexts_per_peer active contexts. If so, reject the shard with an error rather than silently dropping. This ensures no single peer can monopolize more than 5% of the total capacity. Also change the silent Ok(None) drop at capacity to return Err(ShardError::CapacityExceeded) so callers can react.

### P2 — WAL Has No Aggregate Size Limit (Disk Exhaustion)

In crates/phalanx-node/src/persistence/vault.rs, record_chunk() writes encrypted chunks to the WAL with a per-frame limit of 16 MiB (MAX_WAL_CHUNK_BYTES) but no aggregate WAL size limit. An attacker sending thousands of valid-format garbage chunks can grow the WAL to hundreds of gigabytes, filling the disk. This also makes node restart slow since read_all_chunks() reads the entire WAL sequentially.

Fix: Add WAL size accounting. Track the current WAL file size in the Guardian struct:

```rust
wal_bytes_written: u64,
max_wal_bytes: u64, // new config field, default 1 GiB
```

In record_chunk(), before writing, check if wal_bytes_written + frame_size > max_wal_bytes. If so, return an error (GuardianError::StorageFailure("WAL size limit exceeded")). Increment wal_bytes_written after each successful write. Add a WAL compaction/rotation mechanism: when the WAL reaches 80% capacity, trigger a flush of completed volleys to permanent storage and truncate the WAL. Initialize wal_bytes_written from the actual file size on startup.

### P3 — Reassembler Shard Buffer Explosion via Attacker-Controlled total_chunks

In crates/phalanx-forensics/src/reassembler.rs around line 188, the total_chunks field is clamped to 10,000 but comes from the attacker's ShardChunk. An attacker can send one chunk claiming total_chunks=10000, creating a ShardBuffer that waits for 9,999 more chunks that never arrive. The buffer slot is held indefinitely. Repeat with 1000 different ShardIds and all reassembler capacity is consumed with incomplete shards.

Fix: Add a timeout to incomplete shard buffers. In the Crucible that wraps the Reassembler (line 97), ensure flush_stale() is called periodically and that the TTL applies to individual shard contexts, not just volleys. Add a maximum age for incomplete shards (e.g., 30 seconds). If a shard has not received a new chunk within this window, evict it. Also validate total_chunks against the actual chunks received so far — if a peer claims total_chunks=10000 but only ever sends 1, deprioritize that shard after a few seconds. Reduce the total_chunks clamp from 10,000 to 1,000.

### P4 — No Per-Peer Byte-Rate Accounting in IngressGovernor

In crates/phalanx-forensics/src/policy.rs around lines 97-163, the IngressGovernor tracks active_slots as a HashMap<NetworkId, TrustLevel> — counting peer slots, not bytes. A single peer holding one slot can send unlimited data through it. There is no bandwidth accounting, no bytes-per-second tracking, and no mechanism to throttle a peer that sends disproportionately large payloads.

Fix: Add byte-rate tracking to IngressGovernor. Add fields:

```rust
peer_bytes: HashMap<NetworkId, (u64, Instant)>, // (bytes_this_window, window_start)
max_bytes_per_peer_per_minute: u64, // default: 50 MiB
```

Add a method `record_bytes(&mut self, peer: &NetworkId, byte_count: u64) -> bool` that returns false if the peer has exceeded their byte budget for the current window. Call this from the ingestion actor after receiving each chunk, passing the chunk's byte size. When a peer exceeds their budget, revoke their slot and add them to a temporary throttle list.

### P5 — No Message Size Validation Before Queuing in MeshSentinel

In crates/phalanx-node/src/actors/meshsentinel.rs around lines 216-230, when a NetworkEvent::DataReceived arrives, the raw data: Vec<u8> is immediately queued to the ingestion channel via try_send() without any size check. An attacker can send a single 500 MiB gossipsub message, and it gets queued as-is. With a channel capacity of ~200 slots, this can consume 100 GB of memory.

Fix: Add a maximum message size check at the MeshSentinel layer before queuing:

```rust
const MAX_GOSSIP_MESSAGE_BYTES: usize = 1_048_576; // 1 MiB

// In the DataReceived handler, before try_send:
if data.len() > MAX_GOSSIP_MESSAGE_BYTES {
    tracing::warn!(
        peer = %origin,
        size = data.len(),
        limit = MAX_GOSSIP_MESSAGE_BYTES,
        "Dropped oversized gossip message"
    );
    // Optionally penalize the peer's reputation
    return;
}
```

This is the first line of defense — cheap to check and prevents large payloads from ever entering the processing pipeline. Make MAX_GOSSIP_MESSAGE_BYTES configurable via NetworkConfig. Ensure this limit is smaller than or equal to gossipsub's max_transmit_size.

### P6 — max_storage_bytes Configured But Not Enforced on Ingestion

In crates/phalanx-node/src/config.rs around lines 80-82, max_storage_bytes and max_foreign_storage_bytes are defined in the configuration, but in crates/phalanx-node/src/actors/storage.rs, the storage actor's handle_ingest() never checks the current storage usage against these limits before persisting new chunks. The limits are only enforced on egress salvage in vault.rs.

Fix: Add storage accounting to the storage actor. Track current storage usage:

```rust
struct StorageActor {
    current_storage_bytes: u64,
    max_storage_bytes: u64, // from config
    // ...
}
```

In handle_ingest(), before calling reassembler.ingest_chunk(), check if current_storage_bytes + chunk_size > max_storage_bytes. If so, reject the chunk and return an error. Update current_storage_bytes after successful persistence and after successful eviction/deletion. Initialize from actual disk usage on startup by summing WAL + volley + gap file sizes.

### P7 — Incomplete Shards Block Reassembly Indefinitely

In crates/phalanx-forensics/src/reassembler.rs around lines 211-213, the is_ready() check requires acc.received_count == acc.total_chunks before assembly proceeds. If an attacker sends chunks 1-99 of a 100-chunk shard but never sends chunk 100, the buffer holds all 99 chunks in memory indefinitely. There is no timeout or partial-assembly mechanism.

Fix: Add a per-shard inactivity timeout. Track the last chunk arrival time in ShardBuffer:

```rust
struct ShardBuffer {
    parts: BTreeMap<u32, Vec<u8>>,
    total_chunks: u32,
    received_count: u32,
    last_activity: Instant, // new field
}
```

In the Crucible's flush_stale() method, also evict shard buffers where Instant::now() - last_activity > shard_timeout (default: 30 seconds). Update last_activity on every chunk insertion. When evicting, log the ShardId and completion percentage for debugging. This prevents attackers from holding buffer slots hostage with incomplete shards.

### P8 — No Content Validation Beyond Format Tag

In crates/phalanx-node/src/actors/ingestion.rs around lines 88-94, incoming evidence is routed by gossipsub topic string (/phalanx/video, /phalanx/audio) but the actual payload content is not validated against the claimed format. An attacker can send 1 byte of garbage on the /phalanx/video topic and it passes topic routing. The only subsequent validation is cryptographic (signature, temporal) — there is no check that a VideoShard actually contains plausible video data (minimum size, valid header bytes, etc.).

Fix: Add lightweight content validation in the ingestion actor after deserialization. For VideoShard, check:

1. Payload is not empty
2. Payload meets a minimum size (e.g., 64 bytes — smaller than any valid video frame)
3. Optionally check for known container magic bytes (MP4: ftyp, WebM: 0x1A45DFA3)

For AudioShard, apply similar checks. This is not deep media validation — just enough to reject obviously garbage payloads before they consume storage and processing resources. Add a `validate_content()` method to the Evidence trait that each variant implements.

---

## PROTOCOL & TRANSPORT LAYER

### N1 — DHT Ownership Verification Uses String Matching Instead of Cryptographic Signatures

In crates/phalanx-forensics/src/kademlia.rs around lines 93-104, `verify_ownership()` checks DHT record ownership by converting the binary payload to a UTF-8 lossy string and checking if it `contains()` the expected owner prefix. This is not cryptographic verification — an attacker can craft any payload that includes the expected prefix substring anywhere in the data, passing the ownership check for any DHT key.

Fix: Replace the string-matching ownership check with actual cryptographic signature verification. The DHT record payload should include:

1. The owner's DID (public key)
2. A signature over the record key + record value from the owner's signing key
3. A timestamp to prevent replay

```rust
fn verify_ownership(&self, expected_owner_prefix: &str) -> bool {
    // Deserialize the payload to extract the embedded signature
    let signed_record: SignedDhtRecord = match postcard::from_bytes(&self.data) {
        Ok(r) => r,
        Err(_) => return false,
    };
    // Verify the signature using the owner's public key
    let owner_key = match VerifyingKey::from_bytes(&signed_record.owner_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    owner_key.verify_strict(&signed_record.signed_payload, &signed_record.signature).is_ok()
}
```

Define a `SignedDhtRecord` struct in phalanx-proto that wraps the payload with the owner's public key and signature. Update all DHT record creation paths to sign records before publishing.

### N2 — Relay Protocol Has No Hop Limit (Amplification Attack)

In crates/phalanx-node/src/network/orchestrator.rs around lines 44 and 98-99, the libp2p relay behaviour is enabled with default configuration. The defaults do not restrict the number of relay hops, the number of simultaneous relay circuits, or the bandwidth consumed per circuit. An attacker can:

1. Use the node as a relay to amplify traffic toward a victim
2. Create relay loops between colluding nodes to multiply bandwidth consumption
3. Exhaust the node's connection slots with relay circuits, crowding out direct peers

Fix: Configure the relay with explicit resource limits:

```rust
use libp2p::relay;

let relay_config = relay::Config {
    max_reservations: 32,
    max_reservations_per_peer: 2,
    max_circuits: 64,
    max_circuits_per_peer: 2,
    max_circuit_duration: Duration::from_secs(120),
    max_circuit_bytes: 1_048_576, // 1 MiB per circuit
    ..Default::default()
};
```

Make all limits configurable via NetworkConfig. If Phalanx nodes are not intended to serve as public relays, consider disabling the relay behaviour entirely for non-bootstrap nodes.

### N3 — Optional PSK With Silent Fallback to Unencrypted Transport

In crates/phalanx-transport/src/builder.rs around lines 41-59, the transport is built with PSK (pre-shared key) encryption only if a PSK is provided in the config. If no PSK is provided, the transport falls back to Noise-only with no warning. There is no mechanism to require PSK across the mesh — a node configured with a PSK will silently accept connections from nodes without one if the Noise handshake succeeds, because PSK is applied at the transport layer before Noise.

Fix: Add a `require_psk: bool` field to NetworkConfig (default: false). When `require_psk` is true and no PSK is configured, panic at startup with a clear error message. When `require_psk` is true and a connection is received without the PSK layer, reject it. Log a warning at startup if PSK is not configured and `require_psk` is false, so operators are aware the mesh is not using pre-shared key isolation. Add a comment explaining that PSK provides network-level isolation (only nodes with the key can connect) while Noise provides per-connection authentication.
