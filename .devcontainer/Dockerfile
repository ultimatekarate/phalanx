FROM ubuntu:24.04

ARG RUST_VERSION=1.93.1
ARG FLUTTER_VERSION=3.27.4
ARG ANDROID_API=24
ARG NDK_VERSION=27.2.12479018

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

# ── System dependencies ────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    nasm \
    pkg-config \
    curl \
    git \
    ca-certificates \
    unzip \
    xz-utils \
    clang \
    libssl-dev \
    # Android SDK requirements
    openjdk-17-jdk-headless \
    # Lean 4 (optional proofs)
    elan \
    && rm -rf /var/lib/apt/lists/*

# ── Rust ───────────────────────────────────────────────────────────────
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal && \
    rustup component add clippy rustfmt && \
    # Android cross-compilation targets
    rustup target add aarch64-linux-android x86_64-linux-android && \
    # iOS targets (for code completion / check only — can't link on Linux)
    rustup target add aarch64-apple-ios aarch64-apple-ios-sim && \
    cargo install cargo-ndk cbindgen

# ── Android SDK + NDK ──────────────────────────────────────────────────
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=${ANDROID_HOME}
ENV ANDROID_NDK_HOME=${ANDROID_HOME}/ndk/${NDK_VERSION}
ENV PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${PATH}"

RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    curl -sSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    -o /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-tools && \
    mv /tmp/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip && \
    yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager \
    "platform-tools" \
    "platforms;android-${ANDROID_API}" \
    "ndk;${NDK_VERSION}" \
    "cmake;3.22.1"

# ── Flutter ────────────────────────────────────────────────────────────
ENV FLUTTER_HOME=/opt/flutter
ENV PATH="${FLUTTER_HOME}/bin:${FLUTTER_HOME}/bin/cache/dart-sdk/bin:${PATH}"

RUN git clone --depth 1 --branch ${FLUTTER_VERSION} \
    https://github.com/flutter/flutter.git ${FLUTTER_HOME} && \
    flutter precache --android --no-ios --no-web --no-linux --no-macos --no-windows && \
    flutter config --no-analytics && \
    dart --disable-analytics

# ── Workspace setup ────────────────────────────────────────────────────
WORKDIR /workspace
