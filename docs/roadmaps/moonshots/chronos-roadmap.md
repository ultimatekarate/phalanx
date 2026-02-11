# Project Chronos: Trusted Time Consensus

* **1. The "Network" Layer (NTP)**
  * [ ] **Stop trusting `System.currentTimeMillis()`:** It is user-mutable.
  * [ ] **Implement SNTP Client:** Query `time.google.com` or `pool.ntp.org` on app launch.
  * [ ] **Calculate Offset:** Store the delta between `System Time` and `NTP Time`. Apply this offset to every `VideoShard`.
  * [ ] **Safety Check:** If the delta is > 5 seconds, flag the device environment as "Suspicious/Manual Override."

* **2. The "Space" Layer (GNSS/Atomic)**
  * [ ] **Raw NMEA Parsing:** Do not just ask Android for `Location.getTime()`. Hook into the raw NMEA stream.
  * [ ] **Extract `$GPZDA`:** This is the "Zulu Date & Time" sentence coming directly from the satellite's atomic clock.
  * [ ] **Hyper-Accuracy:** This is your "Gold Standard." It is stratum-0 precision. If NTP disagrees with GPS by > 1s, trust GPS.

* **3. The "Cellular" Layer (Carrier Time)**
  * [ ] **SIB Decoding (Android Only):** Extract the "System Information Block" type 16 (SIB16) from the LTE/5G radio frame.
  * [ ] **Why:** This time comes from the cell tower hardware. It is extremely hard to spoof without specialized "Stingray" hardware.
  * [ ] **Fallback:** Use this when GPS is blocked (indoors) and Wi-Fi is down (protest dead zone).

* **4. The "Consensus Engine" (The Judge)**
  * [ ] **The "Time Jury":** Write a simple logic block that polls all three sources (NTP, GPS, Cell).
  * [ ] **Majority Vote:** If 2 out of 3 sources agree on the time, sign the `VideoShard` with that time.
  * [ ] **The "Veto":** If all sources disagree (e.g., GPS says 2024, NTP says 2021), **refuse to sign**. Do not create evidence when reality is fracturing.

* **5. The Metadata Commit**
  * [ ] **Update `WitnessEnvelope`:** Add a new field: `time_confidence: TrustedTimeSource`.
    * `Enum: { Atomic(GNSS), Network(NTP), Carrier(SIB), Unverifiable(System) }`
  * [ ] **UI Feedback:** Display a "Verified Clock" icon in the viewfinder so the user knows their timeline is admissible.
