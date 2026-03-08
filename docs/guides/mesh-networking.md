# Mesh Networking

Lattice enforces a default-deny network posture using two enforcement layers: Cilium (L4 eBPF) and Istio ambient mesh (L7 identity). Traffic between services is only allowed when both sides explicitly agree — this is the bilateral agreement model.

## Default-Deny Posture

When a cluster is provisioned, Lattice installs:

- **Cilium `CiliumClusterwideNetworkPolicy`**: Denies all ingress by default (no ingress rules = implicit deny)
- **Istio `AuthorizationPolicy`**: Empty `spec: {}` denies all L7 traffic by default

No service can send or receive traffic until explicit policies are generated from bilateral agreements.

### System Namespace Exclusions

The following namespaces are excluded from default-deny to avoid breaking infrastructure:

- `kube-system`, `kube-public`, `kube-node-lease`
- `lattice-system`
- `cilium-system`
- `istio-system`
- `cert-manager`
- All CAPI namespaces (`capi-system`, `capd-system`, `capa-system`, `capo-system`, `capmox-system`, etc.)

These are excluded because they have circular dependencies on the policy infrastructure itself — Cilium can't enforce policies on its own control plane.

## Bilateral Mesh Agreements

Traffic between two services requires **both sides to agree**:

1. The **caller** declares an outbound dependency on the callee
2. The **callee** allows inbound from the caller

If either side doesn't agree, no policies are generated and traffic is denied.

### Declaring Dependencies

Dependencies are declared in the `resources` section of a LatticeService:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: frontend
  namespace: default
spec:
  replicas: 2
  workload:
    containers:
      main:
        image: my-registry.io/frontend:latest
    service:
      ports:
        http:
          port: 8080
    resources:
      # This service calls backend-api (outbound)
      backend-api:
        type: service
        direction: outbound

      # This service calls the cache (outbound)
      redis-cache:
        type: service
        direction: outbound
```

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: backend-api
  namespace: default
spec:
  replicas: 3
  workload:
    containers:
      main:
        image: my-registry.io/backend:latest
    service:
      ports:
        http:
          port: 8080
    resources:
      # Allow frontend to call us (inbound)
      frontend:
        type: service
        direction: inbound

      # We call the database (outbound)
      postgres:
        type: service
        direction: outbound
```

### Direction Values

| Direction | Meaning |
|-----------|---------|
| `outbound` | This service calls the target service |
| `inbound` | The target service calls this service (allow it) |
| `both` | Bidirectional communication |

### What Gets Generated

When `frontend` declares `backend-api: outbound` AND `backend-api` declares `frontend: inbound`, Lattice generates:

**For `backend-api` (the callee):**
- A **CiliumNetworkPolicy** allowing HBONE ingress (port 15008) from cluster pods
- An **Istio AuthorizationPolicy** allowing requests from `frontend`'s SPIFFE identity

**For `frontend` (the caller):**
- Egress policies allowing outbound to `backend-api`

If only one side declares the dependency, nothing is generated and traffic remains denied.

## LatticeMeshMember CRD

For advanced use cases, you can create `LatticeMeshMember` resources directly. LatticeService creates these automatically, but direct creation gives full control:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: my-service
  namespace: default
spec:
  target:
    selector:
      app: my-service
  ports:
    - port: 8080
      name: http
      peerAuth: Strict            # Require mTLS (default)
  allowedCallers:
    - namespace: default
      name: frontend
    - namespace: default
      name: monitoring-agent
  dependencies:
    - namespace: default
      name: postgres
    - namespace: default
      name: redis
  allowPeerTraffic: false        # Deny pods of this service from talking to each other
  ambient: true                  # Enable Istio ambient mesh (L7). Default: true
```

### Port mTLS Modes

| Mode | Description |
|------|-------------|
| `Strict` | Require mTLS for all traffic (default) |
| `Permissive` | Allow plaintext from any source |
| `Webhook` | Allow plaintext from kube-apiserver only (for admission webhooks) |

### Target Selection

```yaml
# Select by pod labels
target:
  selector:
    app: my-service

# Select entire namespace
target:
  namespace: my-namespace
```

## External Egress

Services can communicate with endpoints outside the mesh using egress rules.

### Entity Egress

Access Cilium-managed entities:

```yaml
workload:
  resources:
    kube-api:
      type: external-service
      direction: outbound
      params:
        endpoints:
          api: entity:kube-apiserver:6443
    internet:
      type: external-service
      direction: outbound
      params:
        endpoints:
          web: entity:world:443
```

### CIDR Egress

Access IP ranges:

```yaml
workload:
  resources:
    internal-network:
      type: external-service
      direction: outbound
      params:
        endpoints:
          db: 10.0.0.0/8:5432
```

### FQDN Egress

Access external services by DNS name:

```yaml
workload:
  resources:
    payment-api:
      type: external-service
      direction: outbound
      params:
        endpoints:
          stripe: api.stripe.com:443
    cloud-storage:
      type: external-service
      direction: outbound
      params:
        endpoints:
          s3: "*.s3.amazonaws.com:443"
```

FQDN egress generates:
- An Istio **ServiceEntry** registering the external host in the mesh
- An **AuthorizationPolicy** granting this service access
- Cilium DNS rules for FQDN lookup caching

## Two-Layer Enforcement

### Layer 1: Cilium (L4 eBPF)

Cilium enforces at the network layer using eBPF. In Istio ambient mode, pod-to-pod traffic is wrapped in HBONE (port 15008). Cilium policies:

- Allow HBONE ingress from cluster entities (broad L4 allow for mesh traffic)
- Allow DNS egress (TCP/UDP port 53 to kube-dns)
- Allow specific egress for entity, CIDR, and FQDN rules
- Allow direct TCP ingress on permissive ports (non-strict mTLS)

### Layer 2: Istio (L7 Identity)

Inside the HBONE tunnel, Istio ztunnel enforces identity-based policies using SPIFFE identities:

```
lattice.<cluster-name>.local/ns/<namespace>/sa/<service-account>
```

Istio AuthorizationPolicies specify allowed SPIFFE principals per port, providing fine-grained identity verification that Cilium's L4 enforcement cannot.

### Why Two Layers?

- Cilium catches unauthorized traffic before it reaches the mesh (fast, kernel-level)
- Istio verifies cryptographic identity inside the tunnel (strong, identity-based)
- If either layer denies traffic, the connection fails
- Compromising one layer doesn't compromise the other

## Debugging Mesh Issues

Always check ztunnel logs first when debugging connectivity:

```bash
kubectl logs -n istio-system -l app=ztunnel --tail=100 | grep -i "denied\|RBAC\|allow"
```

Ztunnel logs show:
- The exact RBAC decision (allowed/denied)
- Source and destination SPIFFE identities
- The policy that matched

This is faster and more reliable than guessing from application-level errors.

### Common Issues

**Traffic denied between services that should communicate:**
1. Check both services declare the dependency (bilateral agreement)
2. Verify the direction is correct (`outbound` on caller, `inbound` on callee)
3. Check ztunnel logs for the specific denial reason
4. Verify the service account names match SPIFFE principals

**External egress failing:**
1. Check FQDN egress rules are correctly specified
2. Verify DNS resolution works from the pod
3. Check Cilium DNS rules are generated (`kubectl get cnp`)

**Services in the same namespace can't communicate:**
- Peer traffic is denied by default. Set `allowPeerTraffic: true` if pods of the same service need to communicate, or declare explicit bilateral dependencies between services.
