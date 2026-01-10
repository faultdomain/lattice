# Build stage
FROM rust:latest AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy everything needed for build
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
COPY benches ./benches

# Build the binary
RUN cargo build --release

# Runtime stage - rust:latest is Debian trixie, so use matching runtime
FROM debian:trixie-slim

# Install runtime dependencies and tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl
ARG TARGETARCH
RUN ARCH=$(echo ${TARGETARCH:-amd64} | sed 's/arm64/arm64/;s/amd64/amd64/') && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Install clusterctl for pivot operations (latest version)
RUN ARCH=$(echo ${TARGETARCH:-amd64} | sed 's/arm64/arm64/;s/amd64/amd64/') && \
    CLUSTERCTL_VERSION=$(curl -s https://api.github.com/repos/kubernetes-sigs/cluster-api/releases/latest | grep '"tag_name"' | cut -d'"' -f4) && \
    curl -L "https://github.com/kubernetes-sigs/cluster-api/releases/download/${CLUSTERCTL_VERSION}/clusterctl-linux-${ARCH}" -o /usr/local/bin/clusterctl && \
    chmod +x /usr/local/bin/clusterctl

# Install helm for CNI manifest generation
RUN ARCH=$(echo ${TARGETARCH:-amd64} | sed 's/arm64/arm64/;s/amd64/amd64/') && \
    curl -fsSL https://get.helm.sh/helm-v3.16.0-linux-${ARCH}.tar.gz | tar xz && \
    mv linux-${ARCH}/helm /usr/local/bin/helm && \
    rm -rf linux-${ARCH}

# Copy binary from builder
COPY --from=builder /app/target/release/lattice /usr/local/bin/lattice

# Create non-root user with home directory for helm cache
RUN useradd -r -u 1000 -m lattice
USER lattice

# Set writable locations for helm and kubectl cache
ENV HOME=/home/lattice
ENV HELM_CACHE_HOME=/home/lattice/.cache/helm
ENV HELM_CONFIG_HOME=/home/lattice/.config/helm
ENV HELM_DATA_HOME=/home/lattice/.local/share/helm

ENTRYPOINT ["/usr/local/bin/lattice"]
