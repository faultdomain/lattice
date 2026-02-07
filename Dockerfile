# =============================================================================
# FIPS 140-3 Compliant Build
# =============================================================================
# All cryptographic operations use FIPS 140-3 validated modules:
# - Lattice (Rust): aws-lc-rs FIPS module
# =============================================================================

ARG FIPS=true

# -----------------------------------------------------------------------------
# Stage 1: Build Go CLIs with Go 1.25 native FIPS support
# -----------------------------------------------------------------------------
FROM golang:1.25-bookworm AS go-builder

ARG TARGETARCH
ARG FIPS

# Versions from versions.toml - use scripts/docker-build.sh to build
# or pass --build-arg to override
ARG HELM_VERSION

WORKDIR /build

# Go 1.24 native FIPS - no CGO required!
# GOFIPS140=latest selects the FIPS crypto module at build time
ENV GOFIPS140=${FIPS:+latest}
ENV CGO_ENABLED=0

# Build helm from source with FIPS
# Must use 'make build' to set proper ldflags (k8s version defaults)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    git clone --depth 1 --branch v${HELM_VERSION} https://github.com/helm/helm.git /build/helm && \
    cd /build/helm && \
    make build && \
    cp bin/helm /usr/local/bin/helm

# -----------------------------------------------------------------------------
# Stage 2: Build Rust application with BuildKit cache
# -----------------------------------------------------------------------------
FROM rust:latest AS rust-builder

ARG FIPS

# Install build dependencies for aws-lc-rs FIPS
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    cmake \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Copy helm from go-builder (needed by build.rs to pre-render charts)
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm

WORKDIR /app
COPY Cargo.toml Cargo.lock versions.toml ./
COPY crates ./crates
COPY scripts/runtime ./scripts
# Charts are needed by build.rs to pre-render manifests at compile time
COPY test-charts ./test-charts

# Build with BuildKit cache mounts for incremental compilation
# - registry/git: caches downloaded crates
# - target: caches compiled artifacts (the expensive part)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build -p lattice-operator && \
    cp /app/target/debug/lattice-operator /usr/local/bin/lattice-operator

# -----------------------------------------------------------------------------
# Stage 3: Runtime image (minimal)
# -----------------------------------------------------------------------------
FROM debian:trixie-slim

# Install only CA certificates for TLS
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Lattice operator binary (manifests are embedded at build time)
COPY --from=rust-builder /usr/local/bin/lattice-operator /usr/local/bin/lattice-operator

# Copy CAPI providers from source (pre-downloaded YAML manifests)
COPY test-providers /providers

# Copy runtime scripts for templating (bootstrap-cluster.sh, etc.)
COPY scripts/runtime /scripts

# Create non-root user
RUN useradd -r -u 1000 -m lattice && \
    chown -R lattice:lattice /providers /scripts

USER lattice

# Set scripts location for templating
ENV LATTICE_SCRIPTS_DIR=/scripts
# Set providers directory for native CAPI installation
ENV PROVIDERS_DIR=/providers

ENTRYPOINT ["/usr/local/bin/lattice-operator"]
