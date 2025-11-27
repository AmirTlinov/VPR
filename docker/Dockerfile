# VPR VPN - Multi-stage build for server and client binaries
# Supports both native (musl) and cross-compilation targets

# ============================================================================
# Stage 1: Build environment
# ============================================================================
FROM rust:1.87-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git \
    perl \
    make \
    cmake \
    clang \
    lld

# Set up Rust environment
ENV RUSTFLAGS="-C target-feature=-crt-static -C link-arg=-fuse-ld=lld"
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY src/vpr-crypto/Cargo.toml src/vpr-crypto/
COPY src/masque-core/Cargo.toml src/masque-core/
COPY src/vpn-server/Cargo.toml src/vpn-server/
COPY src/vpn-client/Cargo.toml src/vpn-client/
COPY src/tauri-app/Cargo.toml src/tauri-app/

# Create dummy source files for dependency caching
RUN mkdir -p src/vpr-crypto/src src/masque-core/src src/vpn-server/src src/vpn-client/src src/tauri-app/src && \
    echo "fn main() {}" > src/vpr-crypto/src/lib.rs && \
    echo "fn main() {}" > src/masque-core/src/lib.rs && \
    echo "fn main() {}" > src/vpn-server/src/main.rs && \
    echo "fn main() {}" > src/vpn-client/src/main.rs && \
    echo "fn main() {}" > src/tauri-app/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release --package vpn-server --package vpn-client 2>/dev/null || true

# Copy actual source code
COPY src/ src/

# Touch sources to rebuild with real code
RUN touch src/*/src/*.rs

# Build release binaries
RUN cargo build --release --package vpn-server --package vpn-client

# Strip binaries for smaller size
RUN strip target/release/vpn-server target/release/vpn-client

# ============================================================================
# Stage 2: VPN Server runtime
# ============================================================================
FROM alpine:3.21 AS server

# Install runtime dependencies
RUN apk add --no-cache \
    libcap \
    iptables \
    iproute2 \
    ca-certificates \
    tini

# Create non-root user
RUN addgroup -g 1000 vpr && \
    adduser -u 1000 -G vpr -D -h /app vpr

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/vpn-server /usr/local/bin/

# Set capabilities for TUN device and network
RUN setcap cap_net_admin,cap_net_bind_service,cap_net_raw+eip /usr/local/bin/vpn-server

# Create directories
RUN mkdir -p /app/secrets /app/certs && \
    chown -R vpr:vpr /app

# Default configuration
ENV VPR_BIND="0.0.0.0:4433" \
    VPR_TUN_NAME="vpr0" \
    VPR_TUN_ADDR="10.9.0.1" \
    VPR_POOL_START="10.9.0.2" \
    VPR_POOL_END="10.9.0.254" \
    VPR_MTU="1400"

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ss -uln | grep -q ":4433" || exit 1

# Expose QUIC/UDP port
EXPOSE 4433/udp

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Run as root (required for TUN device creation)
CMD ["vpn-server", \
     "--bind", "0.0.0.0:4433", \
     "--tun-name", "vpr0", \
     "--tun-addr", "10.9.0.1", \
     "--pool-start", "10.9.0.2", \
     "--pool-end", "10.9.0.254", \
     "--mtu", "1400", \
     "--noise-dir", "/app/secrets", \
     "--noise-name", "server", \
     "--cert", "/app/certs/server.crt", \
     "--key", "/app/certs/server.key", \
     "--enable-forwarding", \
     "--idle-timeout", "300"]

# ============================================================================
# Stage 3: VPN Client runtime
# ============================================================================
FROM alpine:3.21 AS client

# Install runtime dependencies
RUN apk add --no-cache \
    libcap \
    iproute2 \
    ca-certificates \
    tini

# Create non-root user
RUN addgroup -g 1000 vpr && \
    adduser -u 1000 -G vpr -D -h /app vpr

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/vpn-client /usr/local/bin/

# Set capabilities for TUN device
RUN setcap cap_net_admin,cap_net_bind_service,cap_net_raw+eip /usr/local/bin/vpn-client

# Create directories
RUN mkdir -p /app/secrets && \
    chown -R vpr:vpr /app

# Default configuration
ENV VPR_SERVER="" \
    VPR_SERVER_NAME="" \
    VPR_ALLOW_INSECURE="0"

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Run as root (required for TUN device creation)
CMD ["vpn-client"]

# ============================================================================
# Stage 4: Test runner (integration tests)
# ============================================================================
FROM alpine:3.21 AS test-runner

RUN apk add --no-cache \
    bash \
    curl \
    iproute2 \
    iputils \
    bind-tools \
    ca-certificates \
    jq

WORKDIR /test

# Copy test scripts
COPY docker/scripts/ /test/scripts/

RUN chmod +x /test/scripts/*.sh

ENTRYPOINT ["/bin/bash"]
CMD ["/test/scripts/run-tests.sh"]
