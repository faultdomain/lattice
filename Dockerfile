# =============================================================================
# FIPS 140-3 Compliant Build
# =============================================================================
# All cryptographic operations use FIPS 140-3 validated modules:
# - Lattice (Rust): aws-lc-rs FIPS module
# - kubectl/helm/clusterctl (Go 1.24+): Native FIPS crypto module
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
ARG KUBECTL_VERSION
ARG HELM_VERSION
ARG CLUSTERCTL_VERSION
ARG CAPI_VERSION

WORKDIR /build

# Go 1.24 native FIPS - no CGO required!
# GOFIPS140=latest selects the FIPS crypto module at build time
ENV GOFIPS140=${FIPS:+latest}
ENV CGO_ENABLED=0

# Build kubectl from source with FIPS
RUN git clone --depth 1 --branch v${KUBECTL_VERSION} https://github.com/kubernetes/kubernetes.git /build/kubernetes && \
    cd /build/kubernetes && \
    go build -o /usr/local/bin/kubectl ./cmd/kubectl

# Build helm from source with FIPS
# Must use 'make build' to set proper ldflags (k8s version defaults)
RUN git clone --depth 1 --branch v${HELM_VERSION} https://github.com/helm/helm.git /build/helm && \
    cd /build/helm && \
    make build && \
    cp bin/helm /usr/local/bin/helm

# Build clusterctl from source with FIPS
RUN git clone --depth 1 --branch v${CLUSTERCTL_VERSION} https://github.com/kubernetes-sigs/cluster-api.git /build/cluster-api && \
    cd /build/cluster-api && \
    go build -o /usr/local/bin/clusterctl ./cmd/clusterctl

# -----------------------------------------------------------------------------
# Stage 2: Build Lattice with aws-lc-rs FIPS
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

# Copy helm from go-builder (FIPS-compliant, built from source)
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm

WORKDIR /app

# Copy workspace structure
COPY Cargo.toml Cargo.lock versions.toml ./
COPY crates ./crates
COPY scripts ./scripts

# Build with FIPS if enabled, otherwise standard build
RUN if [ -n "$FIPS" ]; then \
        echo "Building with FIPS support..." && \
        cargo build --release --features fips -p lattice-operator; \
    else \
        echo "Building without FIPS..." && \
        cargo build --release -p lattice-operator; \
    fi

# -----------------------------------------------------------------------------
# Stage 3: Runtime image (minimal)
# -----------------------------------------------------------------------------
FROM debian:trixie-slim

# Re-declare ARGs for this stage
ARG CAPI_VERSION
ARG RKE2_VERSION
ARG CAPMOX_VERSION
ARG CAPA_VERSION
ARG CAPO_VERSION

# Install only CA certificates for TLS
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy FIPS-compliant Go binaries
COPY --from=go-builder /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY --from=go-builder /usr/local/bin/helm /usr/local/bin/helm
COPY --from=go-builder /usr/local/bin/clusterctl /usr/local/bin/clusterctl

# Copy Lattice operator binary
COPY --from=rust-builder /app/target/release/lattice-operator /usr/local/bin/lattice-operator

# Copy helm charts from source (pre-downloaded)
COPY test-charts /charts

# Copy CAPI providers from source (pre-downloaded)
COPY test-providers /providers

# Copy scripts for templating
COPY scripts /scripts

# Create clusterctl config with local provider repositories (all providers)
RUN echo "providers:" > /providers/clusterctl.yaml && \
    echo "  - name: \"cluster-api\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/cluster-api/v${CAPI_VERSION}/core-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"CoreProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"kubeadm\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/bootstrap-kubeadm/v${CAPI_VERSION}/bootstrap-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"BootstrapProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"kubeadm\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/control-plane-kubeadm/v${CAPI_VERSION}/control-plane-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"ControlPlaneProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"rke2\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/bootstrap-rke2/v${RKE2_VERSION}/bootstrap-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"BootstrapProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"rke2\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/control-plane-rke2/v${RKE2_VERSION}/control-plane-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"ControlPlaneProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"docker\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/infrastructure-docker/v${CAPI_VERSION}/infrastructure-components-development.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"InfrastructureProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"proxmox\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/infrastructure-proxmox/v${CAPMOX_VERSION}/infrastructure-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"InfrastructureProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"aws\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/infrastructure-aws/v${CAPA_VERSION}/infrastructure-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"InfrastructureProvider\"" >> /providers/clusterctl.yaml && \
    echo "  - name: \"openstack\"" >> /providers/clusterctl.yaml && \
    echo "    url: \"file:///providers/infrastructure-openstack/v${CAPO_VERSION}/infrastructure-components.yaml\"" >> /providers/clusterctl.yaml && \
    echo "    type: \"InfrastructureProvider\"" >> /providers/clusterctl.yaml

# Set environment variables for air-gapped clusterctl operation
ENV GOPROXY=off
ENV CLUSTERCTL_DISABLE_VERSIONCHECK=true

# Enable FIPS mode at runtime for Go binaries (kubectl, helm, clusterctl)
# Using fips140=on (not =only) because =only rejects X25519 in TLS handshakes,
# which breaks connections to servers that offer X25519 (like RKE2 with BoringCrypto)
ENV GODEBUG=fips140=on

# Create non-root user
RUN useradd -r -u 1000 -m lattice && \
    chown -R lattice:lattice /charts /providers /scripts

USER lattice

# Set chart location for runtime
ENV LATTICE_CHARTS_DIR=/charts
# Set scripts location for templating
ENV LATTICE_SCRIPTS_DIR=/scripts
# Set clusterctl config for offline CAPI installation
ENV CLUSTERCTL_CONFIG=/providers/clusterctl.yaml

ENTRYPOINT ["/usr/local/bin/lattice-operator"]
