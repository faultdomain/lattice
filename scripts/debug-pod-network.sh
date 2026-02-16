#!/usr/bin/env bash
# Debug network policies for a pod by checking Cilium drops and ztunnel logs
# on the correct node where each pod is scheduled.
#
# Usage: ./scripts/debug-pod-network.sh <docker-container> <namespace> <pod-or-deploy>
# Example: ./scripts/debug-pod-network.sh e2e-workload-control-plane-6c7sf monitoring deploy/vm-victoria-metrics-operator
# Example: ./scripts/debug-pod-network.sh e2e-workload-control-plane-6c7sf keda keda-operator-5f465f7c75-z96gg

set -euo pipefail

CONTAINER="${1:?Usage: $0 <docker-container> <namespace> <pod-or-deploy>}"
NS="${2:?Usage: $0 <docker-container> <namespace> <pod-or-deploy>}"
TARGET="${3:?Usage: $0 <docker-container> <namespace> <pod-or-deploy>}"
KUBECTL="docker exec $CONTAINER kubectl --kubeconfig=/etc/kubernetes/super-admin.conf"
DURATION="${4:-15}"

# Resolve target to a list of pod names
resolve_pods() {
    local pods=""
    if [[ "$TARGET" == deploy/* || "$TARGET" == deployment/* ]]; then
        local deploy_name="${TARGET#*/}"
        # Try common label conventions
        for label in "app.kubernetes.io/name=$deploy_name" "app=$deploy_name"; do
            pods=$($KUBECTL get pod -n "$NS" -l "$label" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
            [[ -n "$pods" ]] && break
        done
    else
        pods="$TARGET"
    fi
    if [[ -z "$pods" ]]; then
        echo "ERROR: Could not find pods for $TARGET in namespace $NS" >&2
        echo "Available pods:" >&2
        $KUBECTL get pods -n "$NS" -o wide >&2
        exit 1
    fi
    echo "$pods"
}

# Find the ztunnel or cilium pod on a given node
find_pod_on_node() {
    local label="$1" node="$2" pod_ns="$3"
    $KUBECTL get pod -n "$pod_ns" -l "$label" -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    if item['spec']['nodeName'] == '$node':
        print(item['metadata']['name'])
        break
"
}

# Shared namespace-level info (printed once)
print_namespace_info() {
    echo "=== Namespace Labels ==="
    $KUBECTL get ns "$NS" -o jsonpath='{.metadata.labels}' | python3 -m json.tool 2>/dev/null || true

    echo ""
    echo "=== CiliumNetworkPolicies in $NS ==="
    $KUBECTL get cnp -n "$NS" -o wide 2>/dev/null || echo "(none)"

    echo ""
    echo "=== CNP Rules ==="
    $KUBECTL get cnp -n "$NS" -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    sel = item['spec'].get('endpointSelector', {}).get('matchLabels', {})
    ingress = item['spec'].get('ingress', [])
    egress = item['spec'].get('egress', [])
    print(f'--- {name} (selector: {sel}) ---')
    for i, r in enumerate(ingress):
        entities = r.get('fromEntities', [])
        eps = r.get('fromEndpoints', [])
        ports = [p['port'] for tp in r.get('toPorts', []) for p in tp.get('ports', [])]
        src = f'entities={entities}' if entities else f'endpoints={eps}'
        print(f'  ingress[{i}]: {src} ports={ports}')
    for i, r in enumerate(egress):
        entities = r.get('toEntities', [])
        eps = r.get('toEndpoints', [])
        fqdns = r.get('toFQDNs', [])
        cidrs = r.get('toCIDR', [])
        ports = [p['port'] for tp in r.get('toPorts', []) for p in tp.get('ports', [])]
        dst = entities or eps or fqdns or cidrs
        print(f'  egress[{i}]: to={dst} ports={ports}')
" 2>/dev/null || true

    echo ""
    echo "=== AuthorizationPolicies in $NS ==="
    $KUBECTL get authorizationpolicy -n "$NS" -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    spec = item.get('spec', {})
    sel = spec.get('selector', {}).get('matchLabels', {})
    action = spec.get('action', 'ALLOW')
    rules = spec.get('rules', [])
    print(f'--- {name} (action={action}, selector={sel}) ---')
    for r in rules:
        froms = [f.get('source', {}).get('principals', []) for f in r.get('from', [])]
        tos = [t.get('operation', {}).get('ports', []) for t in r.get('to', [])]
        print(f'  from={froms} to_ports={tos}')
" 2>/dev/null || true

    echo ""
    echo "=== PeerAuthentication in $NS ==="
    $KUBECTL get peerauthentication -n "$NS" -o json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    spec = item.get('spec', {})
    sel = spec.get('selector', {}).get('matchLabels', {})
    mode = spec.get('mtls', {}).get('mode', 'unset')
    port_mtls = spec.get('portLevelMtls', {})
    print(f'--- {name} (selector={sel}, mode={mode}, portMtls={port_mtls}) ---')
" 2>/dev/null || true
}

# Per-pod diagnostics: ztunnel logs + cilium drops on the pod's node
diagnose_pod() {
    local pod="$1"
    local pod_ip node sa ztunnel cilium

    pod_ip=$($KUBECTL get pod -n "$NS" "$pod" -o jsonpath='{.status.podIP}')
    node=$($KUBECTL get pod -n "$NS" "$pod" -o jsonpath='{.spec.nodeName}')
    sa=$($KUBECTL get pod -n "$NS" "$pod" -o jsonpath='{.spec.serviceAccountName}')

    echo ""
    echo "========================================"
    echo "Pod: $pod  IP: $pod_ip  Node: $node  SA: $sa"
    echo "========================================"

    $KUBECTL get pod -n "$NS" "$pod" -o wide

    ztunnel=$(find_pod_on_node "app=ztunnel" "$node" "istio-system")
    cilium=$(find_pod_on_node "k8s-app=cilium" "$node" "kube-system")

    echo ""
    echo "--- Ztunnel access logs for $pod_ip (ztunnel: $ztunnel) ---"
    $KUBECTL logs -n istio-system "$ztunnel" --tail=500 2>/dev/null | grep -v "xds\|RBAC update" | grep "$pod_ip" || echo "(no traffic logged)"

    echo ""
    echo "--- Ztunnel denials on this node ---"
    $KUBECTL logs -n istio-system "$ztunnel" --tail=500 2>/dev/null | grep -i "denied\|policy rejection" || echo "(no denials)"

    echo ""
    echo "--- Cilium drops for $pod_ip (cilium: $cilium, ${DURATION}s capture) ---"
    $KUBECTL exec -n kube-system "$cilium" -- timeout "$DURATION" cilium monitor --type drop 2>&1 | grep "$pod_ip" || echo "(no drops in ${DURATION}s)"

    echo ""
    echo "--- Cilium endpoints on this node ($NS) ---"
    $KUBECTL exec -n kube-system "$cilium" -- cilium endpoint list 2>/dev/null | grep -i "$NS" || echo "(no endpoints found)"
}

# Main
PODS=$(resolve_pods)
POD_COUNT=$(echo "$PODS" | wc -w | tr -d ' ')
echo "Found $POD_COUNT pod(s) for $TARGET in $NS"
echo ""

print_namespace_info

for pod in $PODS; do
    diagnose_pod "$pod"
done
