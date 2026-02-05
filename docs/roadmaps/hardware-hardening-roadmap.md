# Hardware Hardening Roadmap

## Audio Module (`audio.rs`)

- [ ] **Implement CPAL Integration**
  - [ ] Add `cpal` to dependencies.
  - [ ] Replace simulation loop with `device.build_input_stream`.
  - [ ] Implement `f32` to `u8` PCM conversion.
- [ ] **Implement Audio Buffering**
  - [ ] Accumulate samples until they match `config.chunk_size_bytes` (don't send tiny 10ms packets).

## Camera Module (`camera.rs`)

- [ ] **Fix Time Drift**
  - [ ] Replace simple `sleep()` with `Instant` delta calculation (Spin-wait or precise sleep).
- [ ] **Implement Hot-Plug/Reconnection**
  - [ ] Wrap `capture_frame` in a `Result`.
  - [ ] If Error > 5 times sequentially:
    - [ ] Log warning.
    - [ ] Drop `camera` object.
    - [ ] Attempt `HardwareCamera::new()` every 2 seconds until successful.
- [ ] **Fix Blocking Send**
  - [ ] Switch from `blocking_send` to `try_send`.
  - [ ] If `Full`: Log "Frame Dropped" (or implement a ring buffer to drop oldest).
