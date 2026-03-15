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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FFI_CRATE="$PROJECT_ROOT/crates/phalanx-ffi"
FLUTTER_APP="$PROJECT_ROOT/flutter_app"
JNI_LIBS="$FLUTTER_APP/android/app/src/main/jniLibs"

PLATFORM="${1:-all}"

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

  cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
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
if dart pub deps 2>/dev/null | grep -q ffigen; then
  dart run ffigen
  echo "  -> lib/ffi/phalanx_bindings.dart generated"
else
  echo "  -> ffigen not in dependencies, skipping (using hand-written bindings)"
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
