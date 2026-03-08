# Security

Lattice enforces a defense-in-depth security model with multiple enforcement layers, all configured as default-deny.

## Cedar Policy Authorization

Cedar policies control access to secrets and external resources. Policies follow a default-deny model — if no policy permits an action, it is denied.

### CedarPolicy CRD

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: allow-prod-db-access
  namespace: lattice-system
spec:
  description: "Allow payment service to access production database credentials"
  policies: |
    permit(
      principal == Lattice::Service::"payments/payment-api",
      action == Lattice::Action::"AccessSecret",
      resource == Lattice::SecretPath::"vault-prod:database/prod/credentials"
    );
  priority: 0
  enabled: true
  propagate: true
```

### Policy Language

Cedar policies use three components:

- **Principal**: `Lattice::Service::"<namespace>/<service-name>"` — the service identity requesting access
- **Action**: `Lattice::Action::"AccessSecret"` — the operation being performed
- **Resource**: `Lattice::SecretPath::"<provider-name>:<remote-key>"` — the secret being accessed

### Policy Examples

**Allow a service to access a specific secret:**

```cedar
permit(
  principal == Lattice::Service::"default/my-api",
  action == Lattice::Action::"AccessSecret",
  resource == Lattice::SecretPath::"vault-prod:database/prod/credentials"
);
```

**Allow all services in a namespace to access secrets under a path:**

```cedar
permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {
  principal.namespace == "production" &&
  resource.path like "secret/data/production/*"
};
```

**Deny a specific service (overrides permits):**

```cedar
forbid(
  principal == Lattice::Service::"default/untrusted-service",
  action == Lattice::Action::"AccessSecret",
  resource
);
```

**Restrict access by provider:**

```cedar
permit(
  principal == Lattice::Service::"default/my-api",
  action == Lattice::Action::"AccessSecret",
  resource
) when {
  resource.provider == "vault-prod"
};
```

### Policy Evaluation Rules

- **Default-deny**: No policies = all access denied
- **`forbid` overrides `permit`**: A `forbid` policy always wins, regardless of any `permit` policies
- **Priority**: Higher priority policies are evaluated first
- **Propagation**: Policies with `propagate: true` are distributed to child clusters

### Policy Status

```bash
kubectl get cedarpolicy -n lattice-system
```

| Phase | Description |
|-------|-------------|
| `Pending` | Not yet validated |
| `Valid` | Policy parsed and active |
| `Invalid` | Syntax or validation errors (check `status.validation_errors`) |

The status also reports `permit_count` and `forbid_count` for quick verification.

### When Policies Are Evaluated

Cedar policies are evaluated during `ServiceCompiler::compile()`, before ESO ExternalSecret objects are created. If access is denied:

- The ExternalSecret is never generated
- The service compilation fails with a clear error identifying the denied secret path
- The service status reports the denial reason

## OIDC Authentication

Configure cluster-wide OIDC authentication for Kubernetes API server access.

### OIDCProvider CRD

```yaml
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: corporate-sso
  namespace: lattice-system
spec:
  issuerUrl: https://accounts.google.com
  clientId: my-lattice-cluster
  usernameClaim: email
  groupsClaim: groups
  usernamePrefix: "oidc:"
  groupsPrefix: "oidc:"
  audiences:
    - my-lattice-cluster
  requiredClaims:
    - name: email_verified
      value: "true"
  caBundle: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  jwksRefreshIntervalSeconds: 3600
  propagate: true
  allowChildOverride: false
```

### Spec Fields

| Field | Description | Default |
|-------|-------------|---------|
| `issuerUrl` | OIDC issuer URL (must serve `.well-known/openid-configuration`) | Required |
| `clientId` | OIDC client ID | Required |
| `clientSecret` | Optional secret reference for token introspection | — |
| `usernameClaim` | JWT claim to use as username | `sub` |
| `groupsClaim` | JWT claim to use as groups | `groups` |
| `usernamePrefix` | Prefix added to usernames | — |
| `groupsPrefix` | Prefix added to groups | — |
| `audiences` | Allowed token audiences | Client ID only |
| `requiredClaims` | Claims that must be present (each has `name` and optional `value`) | — |
| `caBundle` | PEM CA certificate for self-signed IdP certs | — |
| `jwksRefreshIntervalSeconds` | JWKS cache refresh interval | 3600 |
| `propagate` | Distribute to child clusters | `true` |
| `allowChildOverride` | Allow children to define their own OIDC | `false` |

### Provider Hierarchy

When `propagate: true`, the OIDC configuration is distributed to child clusters. Inherited providers take precedence unless the parent sets `allowChildOverride: true`.

## Network Security Layers

### Layer 1: Cilium (L4 eBPF)

A `CiliumClusterwideNetworkPolicy` denies all ingress by default. Traffic is only allowed when explicit Cilium policies are generated from bilateral mesh agreements.

Cilium enforces at the kernel level before traffic reaches userspace, providing fast, low-overhead network segmentation.

### Layer 2: Istio Ambient (L7 Identity)

An `AuthorizationPolicy` with empty `spec: {}` denies all traffic by default. Service-to-service communication requires matching AuthorizationPolicies generated from bilateral agreements.

Istio verifies cryptographic SPIFFE identities inside HBONE tunnels:

```
lattice.<cluster-name>.local/ns/<namespace>/sa/<service-account>
```

### Why Two Layers

Compromising one layer doesn't compromise the other:
- Cilium catches unauthorized traffic before it enters the mesh (fast, kernel-level)
- Istio verifies cryptographic identity inside the tunnel (strong, identity-based)
- Both must allow traffic for a connection to succeed

See [Mesh Networking](./mesh-networking.md) for details on configuring bilateral agreements.

## FIPS 140-3 Compliance

All Lattice cryptographic operations use FIPS 140-2/140-3 validated implementations.

### Crypto Stack

| Component | Implementation |
|-----------|---------------|
| TLS | `rustls` with `aws-lc-rs` backend |
| Hashing | SHA-256/384/512 via `aws-lc-rs` |
| Signatures | ECDSA P-256/P-384 or RSA 2048+ |
| Random | FIPS-validated RNG in `aws-lc-rs` |

### Disallowed Algorithms

- No MD5
- No SHA-1
- No RSA keys below 2048 bits
- No non-FIPS cipher suites

### TLS Configuration

Approved cipher suites for API servers:

```
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

Minimum TLS version: 1.2. TLS 1.3 AES-GCM suites are automatically enabled.

### Bootstrap Provider Considerations

- **RKE2**: FIPS-compliant out of the box. Use `bootstrap: rke2` in your cluster spec for environments requiring FIPS-native Kubernetes.
- **Kubeadm**: Requires explicit FIPS cipher suite configuration in the API server.
