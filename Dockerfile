# =============================================================================
# FIPS 140-3 Compliant Build
# =============================================================================
# All cryptographic operations use FIPS 140-3 validated modules:
# - Lattice (Rust): aws-lc-rs FIPS module
# Runtime: Red Hat UBI 9 Minimal (FIPS-validated OS)
# Builder: AlmaLinux 9 (RHEL 9-compatible glibc for binary compatibility)
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
# Stage 2: Build Rust application on RHEL 9-compatible base
# -----------------------------------------------------------------------------
# AlmaLinux 9 provides glibc 2.34 (same as UBI 9 runtime), ensuring binary
# compatibility. Using rust:latest (Debian) would produce binaries linked
# against a newer glibc that won't run on the UBI 9 runtime.
FROM almalinux:9 AS rust-builder

ARG FIPS

# Install Rust toolchain via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Install build dependencies for aws-lc-rs FIPS
# - clang-devel: libclang for bindgen (aws-lc-rs)
# - cmake, golang, perl: aws-lc-rs FIPS module build
# - protobuf-compiler + protobuf-devel: prost/tonic code generation
#   (protobuf-devel provides google/protobuf/timestamp.proto etc.)
RUN dnf install -y 'dnf-command(config-manager)' && \
    dnf config-manager --set-enabled crb && \
    dnf install -y epel-release && \
    dnf install -y \
        protobuf-compiler \
        protobuf-devel \
        clang-devel \
        cmake \
        golang \
        gcc \
        make \
        perl \
    && dnf clean all

# Copy helm from go-builder (needed by build.rs to pre-render charts)
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm

WORKDIR /app
COPY Cargo.toml Cargo.lock versions.toml ./
COPY crates ./crates
COPY scripts/runtime ./scripts

# Build with BuildKit cache mounts for incremental compilation
# - registry/git: caches downloaded crates
# - target: caches compiled artifacts (the expensive part)
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release -p lattice-operator && \
    cp /app/target/release/lattice-operator /usr/local/bin/lattice-operator

# -----------------------------------------------------------------------------
# Stage 3: Runtime image (FIPS-validated Red Hat UBI 9 Minimal)
# -----------------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/ubi-minimal

# Install CA certificates for TLS and shadow-utils for useradd
RUN microdnf install -y \
    ca-certificates \
    shadow-utils \
    && microdnf clean all

# Copy Lattice operator binary (manifests are embedded at build time)
COPY --from=rust-builder /usr/local/bin/lattice-operator /usr/local/bin/lattice-operator

# Copy CAPI providers downloaded by build.rs during compilation
COPY --from=rust-builder /app/test-providers /providers

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
