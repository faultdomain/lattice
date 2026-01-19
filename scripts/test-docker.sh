#!/bin/bash
# E2E test with Docker provider (CAPD)
# No external dependencies - runs entirely in kind clusters

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export LATTICE_MGMT_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/docker-mgmt.yaml"
export LATTICE_WORKLOAD_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/docker-workload.yaml"
export LATTICE_MGMT_PROVIDER=docker
export LATTICE_WORKLOAD_PROVIDER=docker
export LATTICE_ENABLE_INDEPENDENCE_TEST=true
export LATTICE_ENABLE_MESH_TEST=true

echo "Using management cluster config: $LATTICE_MGMT_CLUSTER_CONFIG"
echo "Using workload cluster config: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
echo

RUST_LOG=info cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
