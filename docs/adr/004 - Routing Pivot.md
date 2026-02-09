## ADR 004: The Routing Pivot (Equality vs. Biology)

**Context**: Standard P2P gossip protocols (like Gossipsub) treat every node as an equal peer that relays messages to maximize network health. In high-stress scenarios (protests, disasters), this created a "Tragedy of the Commons," where relaying heavy video traffic drained the batteries of the very phones trying to record critical evidence.

**Decision**: We implemented **Vampire Routing** (Biological Resource Governance).

**Mechanism:** We derived a utility function based on the derivative of battery drain ($\frac{dE}{dt}$). Nodes dynamically demote themselves to "Leaf Mode" (Listen-Only) when they detect they are under resource stress.

**Consequences**:

* **Positive:** The network degrades gracefully under load.
* **Trade-off:** The mesh explicitly sacrifices "Routing Efficiency" (bandwidth throughput) to preserve "Witness Survivability" (device uptime).
