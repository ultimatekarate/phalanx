# ===========================
# 1. BUILD STAGE (Heavy)
# ===========================
FROM rust:1.75-slim-bookworm as builder

WORKDIR /usr/src/phalanx

# Create a dummy project to cache dependencies
# This prevents re-downloading crates if only source code changes
RUN USER=root cargo new --bin phalanx
WORKDIR /usr/src/phalanx/phalanx
COPY ./Cargo.toml ./Cargo.lock ./
RUN cargo build --release
# Remove the dummy source
RUN rm src/*.rs

# Copy actual source code
COPY ./src ./src

# Build the actual binary
# We touch main.rs to ensure cargo knows to rebuild
RUN touch src/main.rs
RUN cargo build --release

# ===========================
# 2. RUNTIME STAGE (Lean)
# ===========================
# Use Google's Distroless for maximum security (no shell, no package manager)
# OR debian:bookworm-slim for easier debugging if you need shell access
FROM debian:bookworm-slim 

# Install minimal runtime dependencies (SSL/Certificates are critical for libp2p)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /usr/src/phalanx/phalanx/target/release/phalanx /usr/local/bin/phalanx

# Create directories for persistence
RUN mkdir -p /app/vault /app/config

# Define volumes for data persistence
VOLUME ["/app/vault", "/app/config"]

# Set environment variable for config loading (We will need to update main.rs to use this)
ENV PHALANX_CONFIG_PATH="/app/config/phalanx.toml"

# The Sentinel never sleeps
CMD ["phalanx"]