#!/usr/bin/env bash
# Build Docker image using versions from versions.toml
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSIONS_FILE="$PROJECT_ROOT/versions.toml"

# Parse versions.toml
get_version() {
    local section=$1
    local key=$2
    awk -v section="[$section]" -v key="$key" '
        $0 == section { in_section=1; next }
        /^\[/ { in_section=0 }
        in_section && $1 == key { gsub(/[" ]/, "", $3); print $3 }
    ' "$VERSIONS_FILE"
}

KUBECTL_VERSION=$(get_version "kubernetes" "version")
HELM_VERSION=$(get_version "helm" "version")
CLUSTERCTL_VERSION=$(get_version "clusterctl" "version")
CAPI_VERSION=$(get_version "capi" "version")
RKE2_VERSION=$(get_version "rke2" "version")
CAPMOX_VERSION=$(get_version "capmox" "version")
CAPA_VERSION=$(get_version "capa" "version")
CAPO_VERSION=$(get_version "capo" "version")

echo "Building with versions from versions.toml:"
echo "  kubectl: $KUBECTL_VERSION"
echo "  helm: $HELM_VERSION"
echo "  clusterctl: $CLUSTERCTL_VERSION"
echo "  capi: $CAPI_VERSION"
echo "  rke2: $RKE2_VERSION"
echo "  capmox: $CAPMOX_VERSION"
echo "  capa: $CAPA_VERSION"
echo "  capo: $CAPO_VERSION"

docker build \
    --build-arg KUBECTL_VERSION="$KUBECTL_VERSION" \
    --build-arg HELM_VERSION="$HELM_VERSION" \
    --build-arg CLUSTERCTL_VERSION="$CLUSTERCTL_VERSION" \
    --build-arg CAPI_VERSION="$CAPI_VERSION" \
    --build-arg RKE2_VERSION="$RKE2_VERSION" \
    --build-arg CAPMOX_VERSION="$CAPMOX_VERSION" \
    --build-arg CAPA_VERSION="$CAPA_VERSION" \
    --build-arg CAPO_VERSION="$CAPO_VERSION" \
    "$@" \
    "$PROJECT_ROOT"
