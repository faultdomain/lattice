#!/bin/bash
# E2E test with Proxmox provider (CAPMOX)
#
# Required environment variables for credentials:
#   PROXMOX_URL - Proxmox API URL (e.g., https://10.0.0.97:8006)
#   PROXMOX_TOKEN - API token ID (e.g., root@pam!lattice)
#   PROXMOX_SECRET - API token secret
#
# The installer will create the credentials secret automatically.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Verify required credentials
if [[ -z "$PROXMOX_URL" ]]; then
    echo "Error: PROXMOX_URL environment variable required"
    exit 1
fi
if [[ -z "$PROXMOX_TOKEN" ]]; then
    echo "Error: PROXMOX_TOKEN environment variable required"
    exit 1
fi
if [[ -z "$PROXMOX_SECRET" ]]; then
    echo "Error: PROXMOX_SECRET environment variable required"
    exit 1
fi

export LATTICE_MGMT_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/proxmox-mgmt.yaml"
export LATTICE_WORKLOAD_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/proxmox-workload.yaml"
export LATTICE_MGMT_PROVIDER=proxmox
export LATTICE_WORKLOAD_PROVIDER=proxmox

echo "Proxmox URL: $PROXMOX_URL"
echo "Management cluster config: $LATTICE_MGMT_CLUSTER_CONFIG"
echo "Workload cluster config: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
echo

RUST_LOG=info cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
