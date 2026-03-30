#!/usr/bin/env bash
# =====================================================================
# Phalanx Mobile Build Pipeline
#
# Builds the Rust FFI library for Android and iOS targets, generates
# Dart bindings, and builds the Flutter app for deployment.
#
# Usage:
#   ./scripts/build_mobile.sh           # Build both platforms
#   ./scripts/build_mobile.sh android   # Android only
#   ./scripts/build_mobile.sh ios       # iOS only
#
# Prerequisites:
#   cargo install cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim  (macOS only)
#   Flutter SDK in PATH
#   cbindgen (optional, for header generation)
# =====================================================================

set -euo pipefail

# Ensure Flutter and Android SDK CMake/Ninja are on PATH.
export PATH="$PATH:/c/Users/joevo/git-repo/flutter/bin"
export PATH="$PATH:$(ls -d $HOME/AppData/Local/Android/Sdk/cmake/*/bin 2>/dev/null | head -1)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FFI_CRATE="$PROJECT_ROOT/crates/phalanx-ffi"
FLUTTER_APP="$PROJECT_ROOT/flutter_app"
JNI_LIBS="$FLUTTER_APP/android/app/src/main/jniLibs"

PLATFORM="${1:-all}"

# =====================================================================
# Android SDK / NDK environment
# =====================================================================
ANDROID_SDK="${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}"
ANDROID_NDK="$(ls -d "$ANDROID_SDK/ndk/"* 2>/dev/null | sort -V | tail -1)"
ANDROID_CMAKE="$(ls -d "$ANDROID_SDK/cmake/"* 2>/dev/null | sort -V | tail -1)"

if [ -n "$ANDROID_CMAKE" ]; then
  export PATH="$ANDROID_CMAKE/bin:$PATH"
fi

if [ -n "$ANDROID_NDK" ]; then
  export ANDROID_NDK_HOME="$ANDROID_NDK"
  # Ensure the NDK sysroot is visible to cc-rs for C/C++ dependencies
  export ANDROID_NDK_ROOT="$ANDROID_NDK"
fi

echo "=== PHALANX MOBILE BUILD ==="
echo "Platform: $PLATFORM"
echo ""

# =====================================================================
# Step 1: Generate C header via cbindgen
# =====================================================================
echo "[1/5] Generating phalanx.h via cbindgen..."
if command -v cbindgen &> /dev/null; then
  cbindgen --config "$FFI_CRATE/cbindgen.toml" \
          --crate phalanx-ffi \
          --output "$FFI_CRATE/phalanx.h"
  echo "  -> $FFI_CRATE/phalanx.h generated"
else
  echo "  -> cbindgen not found, skipping header generation"
fi

# =====================================================================
# Step 2: Build Rust FFI for Android targets
# =====================================================================
if [ "$PLATFORM" = "all" ] || [ "$PLATFORM" = "android" ]; then
  echo ""
  echo "[2/5] Building phalanx-ffi for Android..."
  cd "$PROJECT_ROOT"

  # Force Ninja generator — CMake defaults to MSBuild on Windows, which
  # fails when cross-compiling for Android via cargo-ndk.
  export CMAKE_GENERATOR=Ninja

  # Stub for AOSP-internal log/log.h required by fdk-aac-sys.
  # See: https://github.com/mstorsjo/fdk-aac/issues/124
  # Use Windows-native path — NDK's clang.exe doesn't understand MINGW /c/ paths.
  STUB_DIR="$(cygpath -w "$FFI_CRATE/android-stubs")"
  export CFLAGS_aarch64_linux_android="-I${STUB_DIR}"
  export CFLAGS_armv7_linux_androideabi="-I${STUB_DIR}"
  export CFLAGS_x86_64_linux_android="-I${STUB_DIR}"
  export CXXFLAGS_aarch64_linux_android="-I${STUB_DIR}"
  export CXXFLAGS_armv7_linux_androideabi="-I${STUB_DIR}"
  export CXXFLAGS_x86_64_linux_android="-I${STUB_DIR}"

  # NOTE: armeabi-v7a (32-bit ARM) disabled — raptorq 2.0.1 uses NEON
  # intrinsics that are unstable on 32-bit ARM (rust-lang/rust#111800).
  # Re-enable when raptorq ships a fix or when we pin a compatible version.
  cargo ndk \
    -t arm64-v8a \
    -t x86_64 \
    -o "$JNI_LIBS" \
    build --release -p phalanx-ffi

  echo "  -> .so files placed in $JNI_LIBS"
else
  echo "[2/5] Skipping Android build"
fi

# =====================================================================
# Step 3: Build Rust FFI for iOS targets (macOS only)
# =====================================================================
if [ "$PLATFORM" = "all" ] || [ "$PLATFORM" = "ios" ]; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo ""
    echo "[3/5] Building phalanx-ffi for iOS..."
    cd "$PROJECT_ROOT"

    # Device (ARM64 — all modern iPhones)
    cargo build --target aarch64-apple-ios --release -p phalanx-ffi
    echo "  -> aarch64-apple-ios built"

    # Simulator (ARM64 — Apple Silicon Macs)
    cargo build --target aarch64-apple-ios-sim --release -p phalanx-ffi
    echo "  -> aarch64-apple-ios-sim built"

    # Copy to iOS Frameworks directory
    IOS_FRAMEWORKS="$FLUTTER_APP/ios/Frameworks"
    mkdir -p "$IOS_FRAMEWORKS"
    cp "target/aarch64-apple-ios/release/libphalanx_ffi.a" "$IOS_FRAMEWORKS/libphalanx_ffi_device.a"
    cp "target/aarch64-apple-ios-sim/release/libphalanx_ffi.a" "$IOS_FRAMEWORKS/libphalanx_ffi_sim.a"
    echo "  -> Static libraries copied to $IOS_FRAMEWORKS"

    # Copy header for Swift bridging
    if [ -f "$FFI_CRATE/phalanx.h" ]; then
      cp "$FFI_CRATE/phalanx.h" "$IOS_FRAMEWORKS/phalanx.h"
      echo "  -> phalanx.h copied to $IOS_FRAMEWORKS"
    fi
  else
    echo "[3/5] Skipping iOS build (not on macOS)"
  fi
else
  echo "[3/5] Skipping iOS build"
fi

# =====================================================================
# Step 4: Generate Dart FFI bindings (optional — requires ffigen)
# =====================================================================
echo ""
echo "[4/5] Generating Dart FFI bindings..."
cd "$FLUTTER_APP"
if grep -q "^  ffigen:" "$FLUTTER_APP/pubspec.yaml" 2>/dev/null; then
  dart run ffigen
  echo "  -> lib/ffi/phalanx_bindings.dart generated"
else
  echo "  -> ffigen not in pubspec.yaml, skipping (using hand-written bindings)"
fi

# =====================================================================
# Step 5: Flutter build
# =====================================================================
echo ""
echo "[5/5] Flutter build..."
cd "$FLUTTER_APP"
flutter pub get

if [ "$PLATFORM" = "all" ] || [ "$PLATFORM" = "android" ]; then
  echo "  Building APK..."
  flutter build apk --release
  echo "  -> APK: $FLUTTER_APP/build/app/outputs/flutter-apk/app-release.apk"
fi

if [ "$PLATFORM" = "ios" ] && [[ "$OSTYPE" == "darwin"* ]]; then
  echo "  Building iOS..."
  flutter build ios --release --no-codesign
  echo "  -> iOS build complete (sign with Xcode for deployment)"
fi

echo ""
echo "=== BUILD COMPLETE ==="
