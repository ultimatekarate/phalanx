# Scheduler roadmap

- [ ] Dependencies: Add battery crate.
- [ ] Platform Bridges: Implement get_thermal_state for Android (JNI) and iOS (ObjC).
- [ ] The Governor: Create the SystemStress state machine.
- [ ] The Scheduler: Wrap your FFT calls in a if governor.allow() { ... } block.
- [ ] The Protocol: Add Pending status to WitnessEnvelope so nodes can request help.
  