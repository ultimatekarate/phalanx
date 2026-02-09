# Hardware Hardening Roadmap

## Audio Module (`audio.rs`)

- [ ] **Implement CPAL Integration**
  - [ ] Add `cpal` to dependencies.
  - [ ] Replace simulation loop with `device.build_input_stream`.
  - [ ] Implement `f32` to `u8` PCM conversion.
- [ ] **Variable Audio Chunking**
  - [ ] "Jitter Buffer": grab whatever audio has happened since the last frame of video.
  - [ ] Create a thread-safe "Moat" where audio samples wait to be picked up by the video frame.
  - [ ] Update Audio loop to fill the "moat".
  - [ ] Update Camera loop to drain the "moat" and seal the shard.

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
- [ ] **Thumbnail FFT for Moire Patterns**
  - [ ] Downsample the frame to 512x512
  - [ ] Convert to Gray scale.
  - [ ] FFT Magic- Thank you Dr. Guo.
- [ ] **PRNU Analysis**
  - [ ] Have user film a blank wall.
  - [ ] Use this video to produce a unique PRNU signature.
  