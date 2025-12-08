# VPR VPN - Multi-stage build with cargo-chef for optimal caching
#
# Build stages:
#   1. chef     - Install cargo-chef
#   2. planner  - Generate dependency recipe
#   3. builder  - Build dependencies then source
#   4. server   - VPN server runtime
#   5. client   - VPN client runtime
#   6. test-runner - Integration test runner
#
# Usage:
#   docker build --target server -t vpr-server .
#   docker build --target client -t vpr-client .

# ============================================================================
# Stage 1: Chef base with cargo-chef installed
# ============================================================================
FROM rust:1.91-alpine AS chef

RUN apk add --no-cache musl-dev && \
    cargo install cargo-chef --locked

WORKDIR /build

# ============================================================================
# Stage 2: Planner - analyze dependencies and create recipe
# ============================================================================
FROM chef AS planner

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo chef prepare --recipe-path recipe.json

# ============================================================================
# Stage 3: Builder - build dependencies then source
# ============================================================================
FROM chef AS builder

# Install build dependencies
RUN apk add --no-cache \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    git \
    perl \
    make \
    cmake \
    clang \
    lld

# Set up Rust environment for fast linking
ENV RUSTFLAGS="-C target-feature=-crt-static -C link-arg=-fuse-ld=lld"
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

# Copy and build dependencies (cached unless Cargo.toml/lock changes)
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# Build release binaries
RUN cargo build --release --package masque-core --bin vpn-server --bin vpn-client

# Strip binaries
RUN strip target/release/vpn-server target/release/vpn-client

# ============================================================================
# Stage 4: VPN Server runtime
# ============================================================================
FROM alpine:3.23 AS server

LABEL org.opencontainers.image.title="VPR VPN Server"
LABEL org.opencontainers.image.description="Post-quantum secure VPN server with MASQUE protocol"
LABEL org.opencontainers.image.source="https://github.com/AmirTlinov/VPR"

# Install runtime dependencies
RUN apk add --no-cache \
    libcap \
    iptables \
    iproute2 \
    ca-certificates \
    tini && \
    # Create non-root user
    addgroup -g 1000 vpr && \
    adduser -u 1000 -G vpr -D -h /app vpr && \
    # Create directories
    mkdir -p /app/secrets /app/certs && \
    chown -R vpr:vpr /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/vpn-server /usr/local/bin/

# Set capabilities for TUN device and network
RUN setcap cap_net_admin,cap_net_bind_service,cap_net_raw+eip /usr/local/bin/vpn-server

# Default configuration via environment
ENV VPR_BIND="0.0.0.0:4433" \
    VPR_TUN_NAME="vpr0" \
    VPR_TUN_ADDR="10.9.0.1" \
    VPR_POOL_START="10.9.0.2" \
    VPR_POOL_END="10.9.0.254" \
    VPR_MTU="1400" \
    RUST_LOG="info"

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ss -uln | grep -q ":4433" || exit 1

EXPOSE 4433/udp

ENTRYPOINT ["/sbin/tini", "--"]
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
# Stage 5: VPN Client runtime
# ============================================================================
FROM alpine:3.23 AS client

LABEL org.opencontainers.image.title="VPR VPN Client"
LABEL org.opencontainers.image.description="Post-quantum secure VPN client with MASQUE protocol"
LABEL org.opencontainers.image.source="https://github.com/AmirTlinov/VPR"

# Install runtime dependencies
RUN apk add --no-cache \
    libcap \
    iproute2 \
    ca-certificates \
    tini && \
    # Create non-root user
    addgroup -g 1000 vpr && \
    adduser -u 1000 -G vpr -D -h /app vpr && \
    # Create directories
    mkdir -p /app/secrets && \
    chown -R vpr:vpr /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/vpn-client /usr/local/bin/

# Set capabilities for TUN device
RUN setcap cap_net_admin,cap_net_bind_service,cap_net_raw+eip /usr/local/bin/vpn-client

# Default configuration
ENV VPR_SERVER="" \
    VPR_SERVER_NAME="" \
    VPR_ALLOW_INSECURE="0" \
    RUST_LOG="info"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["vpn-client"]

# ============================================================================
# Stage 6: Test runner
# ============================================================================
FROM alpine:3.23 AS test-runner

LABEL org.opencontainers.image.title="VPR Integration Test Runner"

RUN apk add --no-cache \
    bash \
    curl \
    iproute2 \
    iputils \
    bind-tools \
    ca-certificates \
    jq \
    netcat-openbsd \
    openssl

WORKDIR /test

# Copy test scripts
COPY docker/scripts/ /test/scripts/

RUN chmod +x /test/scripts/*.sh

ENTRYPOINT ["/bin/bash"]
CMD ["/test/scripts/run-tests.sh"]
