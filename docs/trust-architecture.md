# Trust Architecture: From Surveillance to Empowerment

**Subject:** Reframing "Extreme Verification" as "Citizen Armor" to secure user opt-in.

## I. The Core Reframe

**The Problem:** Users fear "Surveillance" (Data collected *by* a powerful entity *against* them).
**The Solution:** Phalanx offers a "Black Box Flight Recorder" (Data collected *by* the user *for* their own defense).
**The Promise:** "We don't know where you are. We only know *that you know* where you are. We can't see your data until you explicitly choose to publish evidence."

---

## II. The 6 Pillars of Trust

### 1. The "Local-First" Vault (Air-Gapped by Default)

* **Mechanism:** Phalanx records heavily invasive data (GPS, Barometer, Audio), but writes it exclusively to the device's encrypted storage.
* **Network Rule:** The Sentry never transmits raw sensor data to the Guardian node by default. It only transmits the Hash (the fingerprint) to anchor the timeline.
* **User Control:** Raw data leaves the device *only* when the user explicitly hits "Publish Evidence."

### 2. Radical Transparency (Reproducible Builds)

* **Requirement:** Phalanx must be 100% Open Source.
* **Verification:** We support Reproducible Builds (akin to Signal/Tor).
  * *The Guarantee:* A user can download the source code, compile it themselves, and verify bit-for-bit that the binary on the App Store matches their local version. This proves no backdoors were inserted by the developer or the App Store.

### 3. The "Privacy Dial" (Granularity Control)

Do not force a binary "All or Nothing." Give users a slider to control their exposure risk.

* **Level 1 (Lite):** Signs Video + Timestamp. (Low verification, High privacy).
* **Level 2 (Standard):** Signs Video + Timestamp + Rough Location (City Level).
* **Level 3 (Witness Mode):** Signs Video + Timestamp + Exact GPS + Barometer + Wi-Fi Environment.
  * *UX Warning:* "You are in Witness Mode. Your exact location will be cryptographically burned into this video forever. Do you accept?"

### 4. Zero-Knowledge Proofs (The Roadmap)

* **The Goal:** Prove facts without revealing data.
* **The Scenario:** A user wants to prove they were in a conflict zone (e.g., Ukraine) without revealing their safe house coordinates.
* **The Mechanism:** ZK-SNARKs allow the user to prove "I was within the borders of Ukraine at 12:00 PM" mathematically, without ever revealing the coordinate "50.45, 30.52".

### 5. The "Burner" Identity (DidComm)

* **No PII:** Phalanx requires NO email, NO phone number, and NO social login.
* **Key-Based ID:** The user is identified *only* by their Ed25519 Public Key.
* **The Benefit:** If Phalanx servers are seized, authorities find a database of random numbers, not a list of names and addresses.

### 6. The Warrant Canary

* **The Signal:** A cryptographically signed statement on the Phalanx website footer: *"As of [Date], Phalanx Foundation has NOT received any National Security Letters or court orders to compromise our protocol."*
* **The Dead Man's Switch:** If the government forces a backdoor, the Foundation stops updating the date. The community sees the "Canary" has died and knows the tool is compromised.

---

## III. The Marketing Narrative
>
> "The police have body cams to protect their narrative.
> The government has satellites to protect their borders.
> **Phalanx is the Black Box for the Citizen.**
> It records your truth, encrypts it on *your* device, and only reveals it when *you* pull the trigger.
> It is the only witness that cannot be bribed, intimidated, or silenced."
