# Phalanx Protocol Specification (v1.0 DRAFT)

**Status:** DRAFT-01  
**Date:** 2026-02-09  
**Maintainer:** Joe Volzer  

---

## 1. Abstract

The Phalanx Protocol is a decentralized system for the capture, verification, and preservation of forensic media. This document defines the wire format, cryptographic primitives, and data structures required to participate in the Phalanx network.

Compliance with this specification ensures that evidence captured by a **Sentinel** (Mobile Client) can be cryptographically verified by a **Guardian** (Node) and admissible in legal or archival contexts.

---

## 2. Cryptographic Primitives

Phalanx enforces a strict "No Negotiation" policy on cryptography. All implementations must use the following suite:

| Function | Primitive | Configuration |
| :--- | :--- | :--- |
| **Hashing** | **BLAKE3** | 256-bit output. Default keyed mode for MACs. |
| **Signatures** | **Ed25519** | Strict verification (no malleability). |
| **Encryption** | **XChaCha20-Poly1305** | 192-bit nonce (randomized). |
| **Key Exchange** | **X25519** | Ephemeral-Static Diffie-Hellman. |

---

## 3. Wire Format & Serialization

All data structures are serialized using **Postcard** (a deterministic, no-std, embedded-friendly format).

* **Endianness:** Little Endian (LE).
* **Integer Encoding:** VarInt (Variable-length integers) to save bandwidth.
* **Strings:** UTF-8, length-prefixed.

---

## 4. Data Structures

### 4.1. The Atoms: `VideoShard` & `AudioShard`

The `VideoShard` is the primary container. It represents a "Slice of Time." It *owns* the corresponding `AudioShard` captured during that window.

```rust
struct VideoShard {
    /// Universally Unique ID (UUIDv7 - Time Ordered)
    id: u128,

    /// The previous shard's hash (The Blockchain Link)
    prev_hash: Option<[u8; 32]>,

    /// The Video Payload (Visuals)
    /// Format: H.264/H.265 NAL Unit (Keyframe or Delta)
    video_data: Vec<u8>,

    /// The Audio Payload (Sound)
    /// Wrapped in a struct to handle variable sample rates/durations.
    audio: Option<AudioShard>, // Option allows video-only recording

    /// Physical sensor data attesting to the reality of the shard
    metadata: ForensicMetadata,
}

struct AudioShard {
    /// Audio Codec
    /// 0 = Opus (Default - VBR)
    /// 1 = PCM (f32 - Analysis Mode)
    codec: u8,

    /// Sample Rate (e.g., 48000)
    sample_rate: u32,

    /// The exact number of samples in this chunk.
    /// CRITICAL: Used to calculate the exact duration of this shard
    /// to prevent "Audio Drift" over long recordings.
    sample_count: u32,

    /// The raw payload bytes
    payload: Vec<u8>,
}
```

#### Why these structures?

1. Drift Correction: By tracking sample_count explicitly in the AudioShard, the player can detect if the audio is drifting ahead/behind the video (common in variable frame rate recording) and insert silence/overlap to correct it.
2. Variable Chunking: This allows the audio chunk to be 35ms while the video frame is 33ms without breaking the decoder.
3. A bunch of other good reasons to add later.

### 4.2 Forensics Metadata

```rust
struct ForensicMetadata {
    /// Capture Timestamp (Unix Milliseconds)
    timestamp_ms: u64,

    /// Time Source Confidence
    /// 0=System, 1=NTP, 2=Cellular(SIB), 3=Atomic(GNSS)
    time_source: u8,

    /// Geospatial Location (If available)
    /// Format: [Latitude, Longitude, Altitude] (f64)
    gps: Option<[f64; 3]>,

    /// Device Orientation Log (sampled at 100Hz+)
    /// Used for Rolling Shutter (Jello) verification.
    /// Format: Vec of [w, x, y, z] quaternions.
    gyro_log: Vec<[f32; 4]>,

    /// Camera Sensor Characteristics
    /// Used to distinguish Global Shutter vs Rolling Shutter.
    sensor: SensorProfile,
}

struct SensorProfile {
    /// Readout time in milliseconds (e.g., 14.2ms).
    /// 0.0 implies Global Shutter.
    readout_speed: f32,
    
    /// The focal length in 35mm equivalent (e.g., 24.0mm)
    focal_length: f32,
}
```

### 4.3 The WitnessEnvelope

``` rust
struct WitnessEnvelope {
    /// Magic Bytes: "PHLX" (0x50 0x48 0x4C 0x58)
    magic: u32,

    /// Protocol Version (currently 1)
    version: u8,

    /// The serialized `VideoShard` bytes
    payload: Vec<u8>,

    /// The Ed25519 Public Key of the Sentinel (Identity)
    sender_pubkey: [u8; 32],

    /// The Ed25519 Signature of `payload`
    signature: [u8; 64],
}
```

## 5. Network Protocol

### 5.1. Peer Discovery

Nodes use Kademlia DHT to find peers.

* Protocol ID: /phalanx/kad/1.0.0
* Bootstrap Nodes: Hardcoded public keys of trusted community Guardians.

### 5.2. PubSub Topics (Gossip)

Data is disseminated via libp2p-gossipsub. Topics are segmented by Geohash (Precision 4) (approx 20km x 20km) to ensure local relevance.

* Topic Format: /phalanx/shard/{geohash_4}
* Example: /phalanx/shard/dp3w (Chicago Area)

### 5.3. Verification Flow

* Sentinel captures VideoShard.
* Sentinel signs it -> WitnessEnvelope.
* Sentinel publishes to /phalanx/shard/{local_geo}.
* Guardian subscribes to topic.
* Guardian verifies signature (Fast Path).
* Guardian runs ForensicAssembler (Slow Path - FFT/Jello).
* Guardian archives valid shards to Stronghold storage.

### 6. Security Considerations

## 6.1. Replay Attacks

## 6.2. Deepfake Injection

## 6.3. Sybil & Identity Inflation

## 6.4. Eclipse & Routing Isolation

## 6.5. Metadata Correlation & Sentinel Privacy

## 6.6. Timejacking & NTP Spoofing

## 6.7. Sensor Fuzzing & Hardware Emulation

## 6.8. Resource Exhaustion (DDoS) & Spam

## 6.9. Cryptographic Downgrade & Key Substitution
