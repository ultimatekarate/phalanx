# Phalanx Mobile-First Roadmap

This roadmap outlines the transition of Phalanx from a headless Rust daemon to a full-featured mobile application deployable on Android and iOS, using Flutter for the UI and the existing Rust core for logic.

## Phase 1: The Rust Core Bridge (FFI)

*Goal: Compile the existing Rust code into a library that a mobile app can talk to.*

- [ ] **Refactor for Library Mode**
  - [ ] **Task:** In `Cargo.toml`, add `crate-type = ["cdylib", "staticlib"]` to compile as a C-compatible library.
  - [ ] **Task:** Create `src/ffi.rs` to expose public API methods:
    - `phalanx_init(config_json: *const c_char)`
    - `phalanx_start_camera()`
    - `phalanx_get_status() -> *const c_char`
  - [ ] **Task:** Use `flutter_rust_bridge` (FRB) to automatically generate the glue code between Dart and Rust.

- [ ] **Cross-Compilation Setup**
  - [ ] **Task:** Install Android NDK and iOS SDK toolchains.
  - [ ] **Task:** Create a build script (`build_mobile.sh`) that runs `cargo ndk` (for Android) and `cargo lipo` (for iOS) to generate the `.so` and `.a` binary files.

## Phase 2: The Flutter Shell (UI Layer)

*Goal: Create the visual interface that controls the Rust engine.*

- [ ] **Project Initialization**
  - [ ] **Task:** `flutter create phalanx_mobile`.
  - [ ] **Task:** Configure the native platforms (Android/iOS) to link the Rust binaries generated in Phase 1.

- [ ] **Feature: The "Viewfinder" (Camera Preview)**
  - [ ] **Task:** Implement Texture Hardware Mapping to avoid copying frames.
    - **Rust:** writes frame data directly to a GPU texture ID (OpenGL/Vulkan).
    - **Flutter:** Renders that Texture ID using a `Texture()` widget.
  - [ ] **Task:** Implement a platform channel or FFI stream to notify Flutter when a new frame is ready.

- [ ] **Feature: The "Red Button" (Recording)**
  - [ ] **Task:** Create a large, tactile `FloatingActionButton`.
  - [ ] **Logic:**
    - On Tap: Call `phalanx_start_volley()`.
    - Visual Feedback: Animate a red "Pulse" ring around the button.
    - Haptic Feedback: Vibrate device on start/stop.

## Phase 3: Mobile-Specific Integrations

*Goal: Access hardware sensors that `std` Rust cannot reach.*

- [ ] **Background Execution**
  - [ ] **Task:** Implement `WorkManager` (Android) and `BackgroundTasks` (iOS) to keep the Rust P2P node alive when the screen is off.
  - [ ] **Task:** Implement a "Foreground Service" (Android persistent notification) to ensure the Sentinel stays active during operations.

- [ ] **Permissions Management**
  - [ ] **Task:** Implement the Flutter permission request flow for:
    - `CAMERA`
    - `MICROPHONE`
    - `ACCESS_FINE_LOCATION` (for metadata attestation)
    - `READ/WRITE_EXTERNAL_STORAGE` (for saving evidence)

## Phase 4: UI Implementation Roadmap

*Goal: A "Dark Mode" tactical interface designed for low-light/high-stress environments.*

- [ ] **Screen 1: The HUD (Head-Up Display)**
  - [ ] **Live Feed:** Full-screen camera preview.
  - [ ] **Overlays:**
    - **Peer Count:** Top-right corner icon (Green = Connected, Red = Isolated).
    - **Storage:** Bottom-left bar (Visual representation of quotas).
    - **Upload Queue:** An animated icon showing shards leaving the device.

- [ ] **Screen 2: The Vault (Gallery)**
  - [ ] **Task:** A grid view of recorded Volleys using thumbnails.
  - [ ] **Visuals:** Add a "Lock" icon for verified/archived footage and a "Sync" icon for uploading footage.
  - [ ] **Action:** Tap to play, long-press to "Emergency Delete".

- [ ] **Screen 3: Network Radar**
  - [ ] **Task:** A visualization of the mesh.
  - [ ] **Visuals:** A radar-sweep animation showing discovered peers (dots) relative to your position.

## Phase 5: Testing & Deployment

- [ ] **Simulator Testing:** Verify the Flutter UI layouts work on different screen sizes.
- [ ] **Device Farm:** Test on low-end Android devices to verify thermal performance.
- [ ] **CI/CD:** Set up pipelines to build APK/IPA files automatically.
