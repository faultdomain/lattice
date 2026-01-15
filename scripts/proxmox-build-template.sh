#!/bin/bash
# Build a CAPI-compatible Proxmox VM template using kubernetes-sigs/image-builder
#
# Creates a template with containerd, kubelet, kubeadm pre-installed
# and configured for Cluster API bootstrap.
#
# Usage: ./proxmox-build-template.sh
#
# Required:
#   PROXMOX_URL      - Proxmox API URL (e.g., https://10.0.0.97:8006)
#   PROXMOX_TOKEN    - API token ID (e.g., root@pam!lattice)
#   PROXMOX_SECRET   - API token secret
#   PROXMOX_NODE     - Proxmox node name
#
# Optional:
#   PROXMOX_TEMPLATE_ID  - Template VM ID (default: 9000)
#   PROXMOX_STORAGE      - Storage pool (default: local-lvm)
#   PROXMOX_BRIDGE       - Network bridge (default: vmbr0)
#   PROXMOX_ISO_POOL     - ISO storage pool (default: local)
#   KUBERNETES_VERSION   - Kubernetes version (default: 1.31.0)
#   BUILD_MEMORY         - VM memory in MB (default: 16384)

set -euo pipefail

: "${PROXMOX_URL:?Required}"
: "${PROXMOX_TOKEN:?Required}"
: "${PROXMOX_SECRET:?Required}"
: "${PROXMOX_NODE:?Required}"

TEMPLATE_ID="${PROXMOX_TEMPLATE_ID:-9000}"
STORAGE="${PROXMOX_STORAGE:-local-lvm}"
BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
ISO_POOL="${PROXMOX_ISO_POOL:-local}"
K8S_VERSION="${KUBERNETES_VERSION:-1.32.0}"
MEMORY="${BUILD_MEMORY:-16384}"
IMAGE_BUILDER_DIR="${IMAGE_BUILDER_DIR:-/tmp/image-builder}"

echo "=== Proxmox CAPI Template Builder ==="
echo "URL: $PROXMOX_URL"
echo "Node: $PROXMOX_NODE"
echo "Template ID: $TEMPLATE_ID"
echo "Storage: $STORAGE"
echo "K8s Version: $K8S_VERSION"
echo "Memory: ${MEMORY}MB"
echo ""

# Clone or update image-builder
if [ -d "$IMAGE_BUILDER_DIR" ]; then
    echo "Updating image-builder..."
    cd "$IMAGE_BUILDER_DIR"
    git fetch origin
    git reset --hard origin/main
else
    echo "Cloning image-builder..."
    git clone https://github.com/kubernetes-sigs/image-builder.git "$IMAGE_BUILDER_DIR"
    cd "$IMAGE_BUILDER_DIR"
fi

cd images/capi

# Patch boot command to fix IPv4-only network hang
echo ""
echo "Patching boot command for IPv4-only networks..."
UBUNTU_JSON="packer/proxmox/ubuntu-2204.json"
if ! grep -q "ipv6.disable=1" "$UBUNTU_JSON"; then
    sed -i.bak 's|--- autoinstall|--- ipv6.disable=1 autoinstall|' "$UBUNTU_JSON"
    echo "  Added ipv6.disable=1 to kernel command"
fi

echo ""
echo "Installing dependencies..."
make deps-proxmox

# Export for packer (image-builder expects these specific names)
export PROXMOX_URL="${PROXMOX_URL}/api2/json"
export PROXMOX_USERNAME="$PROXMOX_TOKEN"
export PROXMOX_TOKEN="$PROXMOX_SECRET"
export PROXMOX_NODE
export PROXMOX_ISO_POOL="$ISO_POOL"
export PROXMOX_BRIDGE="$BRIDGE"
export PROXMOX_STORAGE_POOL="$STORAGE"

# Build packer flags
K8S_SERIES="v${K8S_VERSION%.*}"  # e.g., v1.31.0 -> v1.31
K8S_DEB_VERSION="${K8S_VERSION}-1.1"
PACKER_FLAGS="--var 'kubernetes_semver=v${K8S_VERSION}'"
PACKER_FLAGS+=" --var 'kubernetes_series=${K8S_SERIES}'"
PACKER_FLAGS+=" --var 'kubernetes_deb_version=${K8S_DEB_VERSION}'"
PACKER_FLAGS+=" --var 'vmid=${TEMPLATE_ID}'"
PACKER_FLAGS+=" --var 'memory=${MEMORY}'"

[[ "$STORAGE" == *"lvm"* ]] && PACKER_FLAGS+=" --var 'disk_format=raw'"

export PACKER_FLAGS

echo ""
echo "Building Ubuntu 22.04 CAPI image..."
echo "Packer flags: $PACKER_FLAGS"
echo ""

make build-proxmox-ubuntu-2204

echo ""
echo "=== Template $TEMPLATE_ID built successfully ==="
echo "Set PROXMOX_TEMPLATE_ID=$TEMPLATE_ID in your LatticeCluster"
