#!/usr/bin/env bash
# =====================================================================
# Phalanx Mobile Build Pipeline
#
# Builds the Rust FFI library for Android targets and prepares
# the Flutter app for deployment.
#
# Prerequisites:
#   cargo install cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   Flutter SDK in PATH
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FFI_CRATE="$PROJECT_ROOT/crates/phalanx-ffi"
FLUTTER_APP="$PROJECT_ROOT/flutter_app"
JNI_LIBS="$FLUTTER_APP/android/app/src/main/jniLibs"

echo "=== PHALANX MOBILE BUILD ==="

# Step 1: Build Rust FFI for Android targets
echo "[1/4] Building phalanx-ffi for Android..."
cd "$PROJECT_ROOT"

cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o "$JNI_LIBS" \
  build --release -p phalanx-ffi

echo "  -> .so files placed in $JNI_LIBS"

# Step 2: Generate C header (optional, for reference)
echo "[2/4] Generating phalanx.h via cbindgen..."
if command -v cbindgen &> /dev/null; then
  cbindgen --config "$FFI_CRATE/cbindgen.toml" \
           --crate phalanx-ffi \
           --output "$FFI_CRATE/phalanx.h"
  echo "  -> $FFI_CRATE/phalanx.h generated"
else
  echo "  -> cbindgen not found, skipping header generation"
fi

# Step 3: Flutter dependencies
echo "[3/4] Flutter pub get..."
cd "$FLUTTER_APP"
flutter pub get

# Step 4: Flutter build
echo "[4/4] Building Flutter APK..."
flutter build apk --release

echo ""
echo "=== BUILD COMPLETE ==="
echo "APK: $FLUTTER_APP/build/app/outputs/flutter-apk/app-release.apk"
