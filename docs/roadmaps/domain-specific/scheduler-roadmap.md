# Scheduler roadmap

- [ ] Dependencies: Add battery crate.
- [ ] Platform Bridges: Implement get_thermal_state for Android (JNI) and iOS (ObjC).
- [ ] The Governor: Create the SystemStress state machine.
- [ ] The Scheduler: Wrap FFT calls in a if governor.allow() { ... } block.
  - [ ] Think of a way to do this in a clean way. It feels like it's going to become a mess.
- [ ] The Protocol: Add Pending status to WitnessEnvelope so nodes can request help.
  