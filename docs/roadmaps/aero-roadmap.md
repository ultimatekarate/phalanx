# Project Aero: Environmental Pressure Consensus

* **1. The "Sensor" Layer (Raw Hardware)**
  * [ ] **Bypass OS Altitude:** Do not use `Location.getAltitude()`. It is fused and smoothed.
  * [ ] **Log Raw Pascals:** Hook into `Sensor.TYPE_PRESSURE` (Android) or `CMAltimeter` (iOS).
  * [ ] **High-Frequency Logging:** Capture at 10Hz to detect the "Staircase Signature" (rhythmic 20cm jolts).
  * [ ] **Temperature Compensation:** Log the sensor temperature to rule out thermal drift artifacts.

* **2. The "Physics" Layer (Vertical Truth)**
  * [ ] **The "Elevator Check":** If the accelerometer shows Z-axis movement, the pressure *must* change.
  * [ ] **The "Spoof Trap":** If the GPS claims user is moving up a mountain but pressure remains static at 1013 hPa, flag as **Spoofed Location**.
  * [ ] **The "Flatline Check":** If pressure variance is exactly 0.000 for 60 seconds, flag as **Simulator/Injector**. Real sensors have noise.

* **3. The "Reference" Layer (Guardian Proxy)**
  * [ ] **Privacy Firewall:** The Mobile App *never* calls the Weather API.
  * [ ] **Geohash Query:** Guardian rounds user location to 20km grid (Geohash Level 5).
  * [ ] **METAR Fetch:** Guardian queries NOAA/OpenMeteo for the local Sea Level Pressure (QNH) of that grid.
  * [ ] **Hypsometric Adjustment:** Guardian calculates expected pressure at the user's claimed GPS altitude.

* **4. The "Consensus Engine" (The Judge)**
  * [ ] **The "Physics Jury":** Compare `Claimed_Pressure` vs `Calculated_Expected_Pressure`.
  * [ ] **The Threshold:** Allow a tolerance of +/- 10 hPa for HVAC pressurization and sensor error.
  * [ ] **The "Veto":** If the delta is > 25 hPa (e.g., User claims Denver but pressure says Miami), **flag evidence as Physically Impossible**.

* **5. The Metadata Commit**
  * [ ] **Update `WitnessEnvelope`:** Add new field: `environment_context`.
    * `Struct: { raw_hpa: f32, vertical_velocity: f32, sensor_temp: f32 }`
  * [ ] **UI Feedback:** Display a "Barometer Active" icon so the user knows vertical movement is being tracked for verification.
