#!/usr/bin/env bash
# =====================================================================
# Phalanx iOS Rust Build Script
#
# Compiles phalanx-ffi as a static library (.a) for iOS targets.
# Called from Xcode Build Phases → "Run Script" phase.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#   Minimum deployment target: iOS 14+
#   Bitcode: disabled (Apple deprecated it in Xcode 14)
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
FFI_CRATE="$PROJECT_ROOT/crates/phalanx-ffi"
OUTPUT_DIR="$SCRIPT_DIR/Frameworks"

mkdir -p "$OUTPUT_DIR"

echo "=== Building phalanx-ffi for iOS ==="

# Determine build configuration
if [ "${CONFIGURATION:-Release}" = "Debug" ]; then
    PROFILE="debug"
    CARGO_FLAGS=""
else
    PROFILE="release"
    CARGO_FLAGS="--release"
fi

cd "$PROJECT_ROOT"

# Device target (ARM64 — all modern iPhones/iPads)
echo "[1/3] Building for aarch64-apple-ios (device)..."
cargo build --target aarch64-apple-ios $CARGO_FLAGS -p phalanx-ffi

# Simulator target (ARM64 — Apple Silicon Macs)
echo "[2/3] Building for aarch64-apple-ios-sim (simulator)..."
cargo build --target aarch64-apple-ios-sim $CARGO_FLAGS -p phalanx-ffi

# Create universal library for simulator (if x86_64 target is installed)
DEVICE_LIB="target/aarch64-apple-ios/${PROFILE}/libphalanx_ffi.a"
SIM_LIB="target/aarch64-apple-ios-sim/${PROFILE}/libphalanx_ffi.a"

echo "[3/3] Copying static libraries..."

# For Xcode: copy the appropriate library based on SDK
# The Xcode build phase selects the right one based on SDKROOT
if [ -f "$DEVICE_LIB" ]; then
    cp "$DEVICE_LIB" "$OUTPUT_DIR/libphalanx_ffi_device.a"
    echo "  -> Device library: $OUTPUT_DIR/libphalanx_ffi_device.a"
fi

if [ -f "$SIM_LIB" ]; then
    cp "$SIM_LIB" "$OUTPUT_DIR/libphalanx_ffi_sim.a"
    echo "  -> Simulator library: $OUTPUT_DIR/libphalanx_ffi_sim.a"
fi

# Create XCFramework-compatible fat library
# This lets Xcode pick the right slice automatically
if [ -f "$DEVICE_LIB" ] && [ -f "$SIM_LIB" ]; then
    echo "  -> Creating XCFramework..."
    rm -rf "$OUTPUT_DIR/PhalanxFFI.xcframework"
    xcodebuild -create-xcframework \
        -library "$DEVICE_LIB" \
        -library "$SIM_LIB" \
        -output "$OUTPUT_DIR/PhalanxFFI.xcframework" 2>/dev/null || {
            echo "  -> XCFramework creation failed (non-fatal). Using individual .a files."
        }
fi

# Generate C header for Swift bridging
if command -v cbindgen &> /dev/null; then
    echo "  -> Generating phalanx.h..."
    cbindgen --config "$FFI_CRATE/cbindgen.toml" \
             --crate phalanx-ffi \
             --output "$OUTPUT_DIR/phalanx.h"
fi

echo ""
echo "=== iOS Rust build complete ==="
echo "Link libphalanx_ffi.a in Xcode → Build Phases → Link Binary With Libraries"
echo "Add to Header Search Paths: $OUTPUT_DIR"
