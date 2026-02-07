#!/bin/bash
# E2E test with Docker provider (CAPD)
# No external dependencies - runs entirely in kind clusters

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Clean up previous test runs
echo "Cleaning up previous test runs..."
kind delete cluster --name lattice-bootstrap 2>/dev/null || true
kind delete cluster --name e2e-mgmt 2>/dev/null || true
kind delete cluster --name e2e-workload 2>/dev/null || true
kind delete cluster --name e2e-workload2 2>/dev/null || true

# Clean up any orphaned CAPD containers
docker rm -f $(docker ps -aq --filter "name=e2e-mgmt" --filter "name=e2e-workload") 2>/dev/null || true

echo "Cleanup complete."
echo

export LATTICE_MGMT_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/docker-mgmt.yaml"
export LATTICE_WORKLOAD_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/docker-workload.yaml"
export LATTICE_WORKLOAD2_CLUSTER_CONFIG="$REPO_ROOT/crates/lattice-cli/tests/e2e/fixtures/clusters/docker-workload2.yaml"
export LATTICE_ENABLE_INDEPENDENCE_TEST=true
export LATTICE_ENABLE_HIERARCHY_TEST=true
export LATTICE_ENABLE_MESH_TEST=true

echo "Management cluster config: $LATTICE_MGMT_CLUSTER_CONFIG"
echo "Workload cluster config: $LATTICE_WORKLOAD_CLUSTER_CONFIG"
echo "Workload2 cluster config: $LATTICE_WORKLOAD2_CLUSTER_CONFIG"
echo

RUST_LOG=info cargo test -p lattice-cli --features provider-e2e --test e2e unified_e2e -- --nocapture
