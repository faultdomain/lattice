#!/usr/bin/env bash
# Rebuild the lattice image, push to registry, and restart operators.
#
# Usage:
#   ./scripts/dev/redeploy.sh [kubeconfig...]
#
# If no kubeconfigs are provided, uses the current kubectl context.
# Multiple kubeconfigs are restarted bottom-up (last argument first).
#
# Examples:
#   ./scripts/dev/redeploy.sh
#   ./scripts/dev/redeploy.sh /tmp/mgmt-kubeconfig
#   ./scripts/dev/redeploy.sh /tmp/mgmt-kubeconfig /tmp/workload-kubeconfig
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="ghcr.io/evan-hines-js/lattice:latest"
NAMESPACE="lattice-system"
LABEL="app=lattice-operator"

# Step 1: Build and push
echo "=== Building and pushing $IMAGE ==="
"$SCRIPT_DIR/docker-build.sh" -t "$IMAGE" --push

# Step 2: Collect kubeconfigs
KUBECONFIGS=("$@")
if [ ${#KUBECONFIGS[@]} -eq 0 ]; then
    KUBECONFIGS=("")  # empty string means use current context
fi

# Step 3: Delete operator pods (bottom-up order for multi-cluster)
echo "=== Restarting operators ==="
for (( i=${#KUBECONFIGS[@]}-1; i>=0; i-- )); do
    kc="${KUBECONFIGS[$i]}"
    if [ -n "$kc" ]; then
        echo "Deleting operator pods (kubeconfig: $kc)..."
        kubectl --kubeconfig "$kc" delete pod -n "$NAMESPACE" -l "$LABEL" --wait=false 2>/dev/null || true
    else
        echo "Deleting operator pods (current context)..."
        kubectl delete pod -n "$NAMESPACE" -l "$LABEL" --wait=false 2>/dev/null || true
    fi
done

# Step 4: Wait for rollout (bottom-up order)
for (( i=${#KUBECONFIGS[@]}-1; i>=0; i-- )); do
    kc="${KUBECONFIGS[$i]}"
    if [ -n "$kc" ]; then
        echo "Waiting for rollout (kubeconfig: $kc)..."
        kubectl --kubeconfig "$kc" rollout status deployment/lattice-operator -n "$NAMESPACE" --timeout=120s
    else
        echo "Waiting for rollout (current context)..."
        kubectl rollout status deployment/lattice-operator -n "$NAMESPACE" --timeout=120s
    fi
done

echo "=== Done ==="
