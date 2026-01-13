#!/bin/bash
# Bootstrap script for workload clusters
# Called via postKubeadmCommands/postRKE2Commands after cluster init
#
# Template variables (substituted by minijinja):
#   {{ endpoint }}     - Bootstrap endpoint (e.g., https://cell.example.com:8443)
#   {{ cluster_name }} - Cluster name
#   {{ token }}        - Bootstrap token
#   {{ ca_cert_path }} - CA cert path (written by caller)

set -euo pipefail

ENDPOINT="{{ endpoint }}"
CLUSTER_NAME="{{ cluster_name }}"
TOKEN="{{ token }}"
CA_CERT="{{ ca_cert_path }}"

MANIFEST_FILE="/tmp/bootstrap-manifests.yaml"

# Auto-detect kubeconfig path based on bootstrap type
if [ -f "/etc/rancher/rke2/rke2.yaml" ]; then
  KUBECONFIG="/etc/rancher/rke2/rke2.yaml"
elif [ -f "/etc/kubernetes/admin.conf" ]; then
  KUBECONFIG="/etc/kubernetes/admin.conf"
else
  echo "ERROR: No kubeconfig found at /etc/rancher/rke2/rke2.yaml or /etc/kubernetes/admin.conf"
  exit 1
fi

echo "Bootstrapping cluster $CLUSTER_NAME from $ENDPOINT"

# Untaint control plane so pods can schedule (CAPI controllers don't have tolerations)
# Remove kubeadm taint and RKE2 taints (RKE2 taints both control-plane and etcd nodes)
kubectl --kubeconfig="$KUBECONFIG" taint nodes --all node-role.kubernetes.io/control-plane:NoSchedule- || true
kubectl --kubeconfig="$KUBECONFIG" taint nodes --all node-role.kubernetes.io/etcd:NoExecute- || true

# Fetch manifests with retry and exponential backoff
echo "Fetching bootstrap manifests from parent..."
RETRY_DELAY=5
MAX_RETRIES=12
RETRY_COUNT=0

while true; do
  HTTP_CODE=$(curl -sf --cacert "$CA_CERT" "$ENDPOINT/api/clusters/$CLUSTER_NAME/manifests" \
    -H "Authorization: Bearer $TOKEN" \
    -o "$MANIFEST_FILE" \
    -w "%{http_code}" 2>/dev/null) || HTTP_CODE=$?

  if [ "$HTTP_CODE" = "200" ]; then
    echo "Successfully fetched bootstrap manifests"
    break
  elif [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "401" ]; then
    # 409 Conflict = token already used, 401 = token expired/invalid
    # Expected if another node already bootstrapped - continue gracefully
    echo "Bootstrap token already used or expired (HTTP $HTTP_CODE), continuing..."
    rm -f "$MANIFEST_FILE"
    break
  else
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
      echo "Failed to fetch manifests after $MAX_RETRIES attempts (HTTP $HTTP_CODE)"
      rm -f "$MANIFEST_FILE"
      break
    fi
    echo "Failed to fetch manifests (HTTP $HTTP_CODE), retrying in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
  fi
done

# Apply manifests if we have them (CRDs need time to propagate)
if [ -f "$MANIFEST_FILE" ] && [ -s "$MANIFEST_FILE" ]; then
  echo "Applying bootstrap manifests..."
  RETRY_DELAY=5
  MAX_RETRIES=6
  RETRY_COUNT=0

  while true; do
    if kubectl --kubeconfig="$KUBECONFIG" apply --server-side --force-conflicts -f "$MANIFEST_FILE" 2>&1; then
      echo "Successfully applied bootstrap manifests"
      break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
      echo "Failed to apply manifests after $MAX_RETRIES attempts, continuing anyway..."
      break
    fi
    echo "Failed to apply manifests, retrying in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
    RETRY_DELAY=$((RETRY_DELAY < 60 ? RETRY_DELAY * 2 : 60))
  done
else
  echo "No bootstrap manifests to apply (may have been applied by another node)"
fi

# Cleanup
rm -f "$MANIFEST_FILE"
