# ADR 003: The Consensus Pivot (Global vs. Local)

**Context**: We hypothesized that hashing every frame to a public ledger/blockchain would ensure immutability. This failed due to the "Throughput Trap." Public blockchains have low throughput (e.g., 15 TPS) and high costs, while private blockchains are too heavy for mobile battery life. The latency required to achieve "Global Consensus" caused buffer overflows on the recording device, compromising the recording itself.

**Decision**: We shifted to **Recursive Assembly** using a local "Merkle Tree of Time."

**Mechanism:** The system does not attempt to prove the world agrees the video exists, but rather that the *Sensor* saw it. Shards are smelted into Volleys, and Volleys into Archives locally.

**Consequences**:

* **Positive:** Achieves a rigorous "Chain of Custody" without the network overhead and latency of global consensus.
* **Positive:** Significantly reduces battery and bandwidth consumption on the client device.
