# Cedar Authorization for LatticeService

## Introduction

A Cedar-based authorization extension for LatticeService that enables fine-grained user-to-resource access control based on OIDC identity. Policies are embedded in LatticeServices and evaluated locally, maintaining cluster independence. LatticeServicePolicy resources enable subtree-wide policy inheritance through recursive copy-down during pivot, identical to CloudProvider propagation.

## Glossary

- **Cedar**: AWS's open-source policy language for fine-grained authorization
- **LatticeService**: Kubernetes CRD defining service configuration, bilateral agreements, and embedded authorization policies
- **LatticeServicePolicy**: CRD for selector-based policies applying to multiple services within a cluster subtree
- **OIDC_Provider**: External identity provider issuing JWT tokens with user claims
- **Policy_Evaluator**: Local component evaluating Cedar policies against requests
- **Bilateral_Agreements**: Existing service-to-service authorization via `resources` field (generates Cilium/Istio policies)

## Architecture

### Authorization Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Request Flow                             │
├─────────────────────────────────────────────────────────────────┤
│  1. Cilium L4 (eBPF)         - Service identity, network policy │
│  2. Istio L7 (AuthzPolicy)   - Service identity, mTLS           │
│  3. Cedar (this design)      - User identity, OIDC/JWT claims   │
└─────────────────────────────────────────────────────────────────┘
```

- **Bilateral agreements** (`resources` field): Service-to-service authorization
- **Cedar policies** (`authorization` field): User-to-resource authorization

These are complementary. Bilateral agreements gate which services can communicate. Cedar gates what users can do within those services.

### Policy Inheritance Model

LatticeServicePolicy resources are copied to child clusters during pivot, identical to CloudProvider propagation:

```
Root Cluster
├── LatticeServicePolicy: security-baseline (selector: *)
├── LatticeServicePolicy: audit-requirements (selector: *.production)
│
└── pivot → us-east-1 receives [security-baseline, audit-requirements]
     │
     us-east-1 Cluster
     ├── LatticeServicePolicy: security-baseline (inherited)
     ├── LatticeServicePolicy: audit-requirements (inherited)
     ├── LatticeServicePolicy: regional-compliance (local)
     │
     └── pivot → workload-1 receives [security-baseline, audit-requirements, regional-compliance]
          │
          workload-1 Cluster
          ├── LatticeServicePolicy: security-baseline (inherited)
          ├── LatticeServicePolicy: audit-requirements (inherited)
          ├── LatticeServicePolicy: regional-compliance (inherited)
          └── LatticeService: order-api (embedded policies)
```

Each cluster maintains local copies. No runtime dependency on parent clusters.

### Subtree Independence and Partition Tolerance

**Each subtree operates independently with its own policy copies. This is fundamental to the architecture.**

```
                    Root Cluster
                    ├── PolicyA (v2)
                    │
        ┌───────────┴───────────┐
        │                       │
   us-east-1                 eu-west-1
   ├── PolicyA (v2)          ├── PolicyA (v1)  ← stale, but operational
   │   (synced)              │   (disconnected)
   │                         │
   workload-1                workload-2
   └── PolicyA (v2)          └── PolicyA (v1)  ← continues with last-known
```

**Key principles:**

1. **Eventual consistency, not strong consistency**: When Root updates PolicyA to v2, connected children (us-east-1) receive the update on next sync. Disconnected children (eu-west-1) continue operating with v1. This is acceptable and by design.

2. **Partitions don't break authorization**: If eu-west-1 loses connectivity to Root, it continues making authorization decisions based on its local policy copies. Services keep running. Users keep authenticating. No degradation.

3. **Break-glass via subtree root**: In emergencies (e.g., a policy is causing outages in a disconnected subtree), operators can apply a corrective LatticeServicePolicy directly to that subtree's root cluster. The fix propagates down the disconnected subtree immediately, without waiting for reconnection to the parent.

```
# Emergency: eu-west-1 is partitioned and has a bad policy
# Apply fix directly to eu-west-1 (the subtree's local root)

kubectl --context eu-west-1 apply -f - <<EOF
apiVersion: lattice.io/v1
kind: LatticeServicePolicy
metadata:
  name: emergency-override
  namespace: lattice-system
spec:
  selector:
    matchLabels: {}
  authorization:
    cedar:
      policies: |
        // Emergency: permit all while investigating
        permit(principal, action, resource);
EOF
```

4. **No "split-brain" risk**: Each subtree is authoritative for itself. There's no conflict resolution needed because children don't push policies upstream. Policies only flow downward.

5. **Reconnection is safe**: When a partitioned subtree reconnects, it receives updated policies on the next pivot/sync cycle. Local emergency overrides can be removed once the root policy is corrected.

### Computational Efficiency of Tree Propagation

The tree structure provides significant computational benefits:

```
Root                    ← only cares about [us-east-1, eu-west-1]
├── us-east-1           ← only cares about [workload-1, workload-2]
│   ├── workload-1
│   └── workload-2
└── eu-west-1           ← only cares about [workload-3]
    └── workload-3
```

**Each node only manages its direct children.** The same logic applied recursively propagates policies to the entire subtree without:

- **Global coordination**: No need for distributed consensus or leader election
- **Cycle detection**: Trees are acyclic by definition; no deduplication needed
- **Full-tree visibility**: Root doesn't need to know about workload-1; us-east-1 handles that
- **O(n) messaging**: Each policy update is sent once per edge, not broadcast to all nodes

This "gossip without cycles" pattern means:
1. Root updates PolicyA → pushes to us-east-1 and eu-west-1
2. us-east-1 receives PolicyA → pushes to workload-1 and workload-2
3. eu-west-1 receives PolicyA → pushes to workload-3
4. Done. No acknowledgments needed, no retries across the whole tree.

If a subtree is partitioned, it simply doesn't receive the update. When it reconnects, it receives the current state—no need to replay history or resolve conflicts.

### Evaluation Order

```
Bilateral Agreements (Cilium L4 → Istio L7)
  │
  ↓ pass
JWT Validation (signature, expiry, issuer, audience)
  │
  ↓ valid
LatticeServicePolicy forbid rules (all matching policies)
  │
  ↓ no forbid matches
LatticeService embedded Cedar policies
  │
  ↓ permit matches (or no policies defined)
LatticeServicePolicy permit rules (if no embedded permit matched)
  │
  ↓ permit matches
ALLOW
```

Default behavior: If no Cedar policy explicitly permits a request, deny it.

---

## Requirements

### Requirement 1: LatticeService Cedar Policy Embedding

**User Story:** As a developer, I want to embed Cedar authorization policies in my LatticeService, so that I can define who can access which paths and methods on my service.

#### Acceptance Criteria

1. WHEN a LatticeService includes an `authorization.cedar` field, THE system SHALL parse and validate the Cedar policy syntax at admission time
2. WHEN Cedar policies contain syntax errors, THE system SHALL reject the LatticeService with a clear validation error in the status conditions
3. WHEN a LatticeService is updated, THE Policy_Evaluator SHALL reload policies without dropping in-flight requests
4. WHEN a LatticeService is deleted, THE system SHALL remove its policies from evaluation
5. THE embedded policies SHALL only apply to requests targeting that specific service

### Requirement 2: OIDC Integration

**User Story:** As a developer, I want to authorize requests based on OIDC token claims, so that I can enforce role-based access control for my service's users.

#### Acceptance Criteria

1. WHEN a LatticeService specifies `authorization.oidc`, THE system SHALL validate incoming JWT tokens against the configured issuer and audience
2. WHEN a valid JWT is present, THE Policy_Evaluator SHALL extract claims and make them available as Cedar principal attributes
3. WHEN a JWT is missing, expired, or invalid, THE system SHALL deny the request before policy evaluation
4. THE system SHALL support standard claims: `sub`, `iss`, `aud`, `exp`, `iat`, `roles`, `groups`, `scope`
5. WHEN custom claims are present in the JWT, THE system SHALL make them available to Cedar policies via `principal.claims`

### Requirement 3: Cedar Entity Model

**User Story:** As a policy author, I want a well-defined entity model, so that I can write precise authorization rules.

#### Acceptance Criteria

1. THE system SHALL define `Principal` entities from OIDC tokens with attributes:
   - `sub`: Subject identifier
   - `roles`: Set of role strings (claim path configurable)
   - `groups`: Set of group strings (claim path configurable)
   - `claims`: Full claims object for custom attributes

2. THE system SHALL define `Action` entities mapped from HTTP methods:
   - `Action::"read"` ← GET, HEAD, OPTIONS
   - `Action::"write"` ← POST, PUT, PATCH
   - `Action::"delete"` ← DELETE

3. THE system SHALL define `Resource` entities with attributes:
   - `path`: Request path (e.g., `/api/orders/123`)
   - `service`: Target service name
   - `namespace`: Target service namespace
   - `method`: Raw HTTP method
   - `headers`: Request headers (selected safe headers only)

4. THE system SHALL provide a Cedar schema defining these entities that developers can reference
5. WHEN evaluating policies, THE system SHALL construct entities from the request context and OIDC token

### Requirement 4: Policy Evaluation Semantics

**User Story:** As a platform engineer, I want deterministic policy evaluation, so that authorization decisions are predictable and auditable.

#### Acceptance Criteria

1. WHEN no Cedar policy explicitly permits a request, THE system SHALL deny the request (default deny)
2. WHEN a Cedar `forbid` policy matches, THE system SHALL deny the request regardless of any `permit` policies
3. WHEN a Cedar `permit` policy matches and no `forbid` matches, THE system SHALL allow the request
4. THE Policy_Evaluator SHALL run locally within the cluster with no external dependencies at evaluation time
5. WHEN bilateral agreements deny a request, THE system SHALL NOT evaluate Cedar policies (bilateral is evaluated first)

### Requirement 5: Composition with Bilateral Agreements

**User Story:** As a platform engineer, I want Cedar authorization to complement bilateral agreements, so that both service-to-service and user-to-resource authorization are enforced.

#### Acceptance Criteria

1. WHEN a request arrives, THE system SHALL first evaluate bilateral agreements (Cilium L4, Istio L7 identity)
2. WHEN bilateral agreements permit, THE system SHALL then evaluate Cedar policies for user authorization
3. THE system SHALL NOT allow Cedar policies to override bilateral agreement denials
4. WHEN a service has no Cedar policies defined, THE system SHALL allow all requests that pass bilateral checks (backwards compatibility)
5. THE LatticeService CRD SHALL clearly separate `resources` (bilateral) from `authorization` (Cedar)

### Requirement 6: Local Evaluation and Cluster Independence

**User Story:** As a platform engineer, I want authorization to work independently of parent clusters, so that cluster self-management is maintained.

#### Acceptance Criteria

1. THE Policy_Evaluator SHALL run as a local component within each cluster
2. WHEN the parent cluster is unavailable, THE system SHALL continue evaluating policies using locally stored configuration indefinitely
3. WHEN a cluster pivots, THE system SHALL include all applicable LatticeServicePolicies and Cedar schemas in the pivot payload
4. THE system SHALL NOT require network calls to parent clusters during policy evaluation
5. WHEN JWKS cannot be refreshed due to network issues, THE system SHALL continue operating with cached keys for a configurable grace period (default: 24 hours)
6. WHEN a subtree is partitioned from its parent, THE subtree SHALL remain fully operational using its last-known policy state
7. THE system SHALL support applying LatticeServicePolicies directly to any cluster, enabling break-glass remediation for partitioned subtrees

### Requirement 7: LatticeServicePolicy Inheritance

**User Story:** As a security team member, I want to define policies that automatically apply to all services in a cluster subtree, so that I can enforce organization-wide security requirements.

#### Acceptance Criteria

1. WHEN a cluster pivots, THE parent SHALL include all local LatticeServicePolicy resources in the pivot payload
2. WHEN a child cluster receives LatticeServicePolicies, THE system SHALL store them as local resources marked with `inherited: true`
3. WHEN the child cluster provisions its own children, THE system SHALL include its LatticeServicePolicies (including inherited ones) in their pivot payloads
4. THE system SHALL evaluate inherited LatticeServicePolicies identically to locally-defined ones
5. WHEN a LatticeServicePolicy is updated in a parent cluster, THE change SHALL propagate to children on next sync cycle (eventual consistency, not immediate)
6. WHEN a child cluster is disconnected from its parent, THE child SHALL continue using its last-received policies without degradation
7. THE system SHALL allow locally-applied LatticeServicePolicies to coexist with inherited ones, enabling break-glass overrides

### Requirement 8: LatticeServicePolicy Selectors

**User Story:** As a security team member, I want to target policies to specific services using selectors, so that I can apply different rules to different service categories.

#### Acceptance Criteria

1. THE LatticeServicePolicy SHALL support `selector.matchLabels` for label-based matching
2. THE LatticeServicePolicy SHALL support `selector.matchExpressions` for complex label queries
3. THE LatticeServicePolicy SHALL support `selector.namespaceSelector` to target services in specific namespaces
4. WHEN multiple LatticeServicePolicies match a service, THE system SHALL evaluate all of them
5. WHEN a selector is empty (`{}`), THE policy SHALL match all LatticeServices in the cluster

### Requirement 9: Performance

**User Story:** As a platform engineer, I want low-latency authorization, so that it doesn't impact service response times.

#### Acceptance Criteria

1. WHEN evaluating policies, THE system SHALL respond within 5 milliseconds for p99 (excluding JWT validation network time)
2. THE system SHALL cache compiled Cedar policies to avoid parsing on each request
3. THE system SHALL cache JWKS keys with configurable refresh interval (default: 1 hour)
4. WHEN policies are updated, THE system SHALL compile and cache them asynchronously before swapping into active evaluation
5. THE Policy_Evaluator SHALL support concurrent evaluation without lock contention

### Requirement 10: Observability

**User Story:** As a developer, I want to understand why requests are allowed or denied, so that I can debug authorization issues.

#### Acceptance Criteria

1. WHEN a request is denied, THE system SHALL return a reason indicating: policy type (LatticeServicePolicy or LatticeService), policy name, and denial reason
2. THE system SHALL emit metrics:
   - `cedar_evaluation_duration_seconds` (histogram)
   - `cedar_decisions_total{decision=allow|deny,policy_type=service|global}`
   - `cedar_policy_errors_total`
   - `cedar_jwt_validation_total{result=valid|expired|invalid_signature|missing}`
3. WHEN authorization decisions are made, THE system SHALL log: principal sub, action, resource path, decision, and matching policy ID
4. THE system SHALL support a debug mode that returns full policy evaluation traces (disabled by default)
5. WHEN policy syntax is invalid, THE system SHALL surface errors in LatticeService/LatticeServicePolicy status conditions

### Requirement 11: Configuration Schema

**User Story:** As a developer, I want a clear configuration interface, so that I can easily define authorization rules.

#### Acceptance Criteria

1. THE LatticeService CRD SHALL support the following authorization schema:

```yaml
apiVersion: lattice.io/v1
kind: LatticeService
metadata:
  name: order-api
  namespace: orders
spec:
  # Existing bilateral agreements (unchanged)
  resources:
    inventory-service:
      direction: outbound
    payment-service:
      direction: outbound

  # New: Cedar authorization
  authorization:
    oidc:
      issuer: https://corp.okta.com
      audience: order-api
      jwksUri: https://corp.okta.com/.well-known/jwks.json  # optional
      claimMappings:
        roles: realm_access.roles    # JSONPath to roles claim
        groups: groups               # JSONPath to groups claim
    cedar:
      policies: |
        // Order managers can read and write orders
        permit(
          principal,
          action in [Action::"read", Action::"write"],
          resource
        ) when {
          principal.roles.contains("order-manager") &&
          resource.path like "/api/orders/*"
        };

        // Viewers can only read
        permit(
          principal,
          action == Action::"read",
          resource
        ) when {
          principal.roles.contains("viewer")
        };

        // Block access to admin endpoints without admin role
        forbid(
          principal,
          action,
          resource
        ) when {
          resource.path like "/admin/*" &&
          !principal.roles.contains("admin")
        };
```

2. THE LatticeServicePolicy CRD SHALL support the following schema:

```yaml
apiVersion: lattice.io/v1
kind: LatticeServicePolicy
metadata:
  name: security-baseline
  namespace: lattice-system
spec:
  selector:
    matchLabels: {}  # matches all services
    # matchLabels:
    #   environment: production
    # matchExpressions:
    #   - key: tier
    #     operator: In
    #     values: [frontend, backend]
    # namespaceSelector:
    #   matchLabels:
    #     compliance: pci

  authorization:
    cedar:
      policies: |
        // Baseline: require authentication for all write operations
        forbid(
          principal,
          action in [Action::"write", Action::"delete"],
          resource
        ) when {
          !context.authenticated
        };

        // Baseline: no access to /admin without admin role
        forbid(
          principal,
          action,
          resource
        ) when {
          resource.path like "/admin/*" &&
          !principal.roles.contains("admin")
        };

        // Baseline: block deprecated API versions
        forbid(
          principal,
          action,
          resource
        ) when {
          resource.path like "/api/v1/*"
        };
```

3. WHEN `authorization` is omitted, THE system SHALL skip Cedar evaluation (bilateral only, backwards compatible)
4. WHEN `authorization.oidc` is specified without `authorization.cedar`, THE system SHALL require a valid JWT but permit all actions (authentication without fine-grained authorization)
5. THE system SHALL validate the complete configuration at admission time

---

## Example Scenarios

### Scenario 1: Developer Service with Role-Based Access

```yaml
apiVersion: lattice.io/v1
kind: LatticeService
metadata:
  name: user-api
spec:
  authorization:
    oidc:
      issuer: https://auth.example.com
      audience: user-api
    cedar:
      policies: |
        // Users can read their own profile
        permit(
          principal,
          action == Action::"read",
          resource
        ) when {
          resource.path == "/api/users/" + principal.sub
        };

        // Admins can read any profile
        permit(
          principal,
          action == Action::"read",
          resource
        ) when {
          principal.roles.contains("admin") &&
          resource.path like "/api/users/*"
        };

        // Only admins can delete users
        permit(
          principal,
          action == Action::"delete",
          resource
        ) when {
          principal.roles.contains("admin") &&
          resource.path like "/api/users/*"
        };
```

### Scenario 2: Security Team Global Policy

```yaml
apiVersion: lattice.io/v1
kind: LatticeServicePolicy
metadata:
  name: pci-compliance
spec:
  selector:
    namespaceSelector:
      matchLabels:
        compliance: pci
  authorization:
    cedar:
      policies: |
        // PCI: No access without MFA claim
        forbid(
          principal,
          action,
          resource
        ) when {
          !principal.claims.amr.contains("mfa")
        };

        // PCI: Audit all access (permit with logging, actual logging via observability)
        permit(
          principal,
          action,
          resource
        ) when {
          principal.claims.amr.contains("mfa")
        };
```

### Scenario 3: Regional Compliance

```yaml
# Applied at eu-west-1 cluster, inherited by all children
apiVersion: lattice.io/v1
kind: LatticeServicePolicy
metadata:
  name: gdpr-requirements
spec:
  selector:
    matchLabels: {}
  authorization:
    cedar:
      policies: |
        // GDPR: Block access to PII endpoints without data-processor role
        forbid(
          principal,
          action,
          resource
        ) when {
          resource.path like "/api/*/pii/*" &&
          !principal.roles.contains("data-processor")
        };

        // GDPR: Require EU residency claim for EU data
        forbid(
          principal,
          action,
          resource
        ) when {
          resource.path like "/api/eu/*" &&
          principal.claims.region != "EU"
        };
```

### Scenario 4: Break-Glass for Partitioned Subtree

A network partition has isolated `ap-south-1` from the root cluster. A misconfigured inherited policy is blocking legitimate traffic. The security team needs to fix it without waiting for reconnection.

```yaml
# Apply directly to ap-south-1 cluster (the partitioned subtree's root)
# This does NOT require connectivity to the parent
apiVersion: lattice.io/v1
kind: LatticeServicePolicy
metadata:
  name: emergency-permit-payments
  namespace: lattice-system
  annotations:
    lattice.io/break-glass: "true"
    lattice.io/incident: "INC-2024-1234"
    lattice.io/expires: "2024-12-01T00:00:00Z"
spec:
  selector:
    matchLabels:
      app: payment-service
  authorization:
    cedar:
      policies: |
        // EMERGENCY: Override inherited deny for payment-service
        // Incident: INC-2024-1234
        // Remove after root policy is fixed and connectivity restored
        permit(
          principal,
          action,
          resource
        ) when {
          principal.roles.contains("payment-operator")
        };
```

Once applied to `ap-south-1`, the fix immediately propagates to all its children (`ap-south-1-workload-1`, `ap-south-1-workload-2`, etc.) through normal inheritance. When connectivity is restored:

1. Root policy is corrected
2. `ap-south-1` syncs and receives the fix
3. Emergency override is removed from `ap-south-1`
4. Children receive the corrected policy on next sync

---

## Implementation Notes

### Policy Evaluator Deployment

The Policy_Evaluator runs as:
- A sidecar container alongside Envoy, OR
- A cluster-local service called by Envoy's ext_authz

Recommendation: Cluster-local service for shared caching and simpler updates.

### JWKS Caching

```
┌─────────────────────────────────────────────────────────────────┐
│                     Policy Evaluator                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │  JWKS Cache     │  │  Policy Cache   │  │  Entity Store  │  │
│  │  (refresh: 1h)  │  │  (compiled)     │  │  (from request)│  │
│  └─────────────────┘  └─────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │
         ↓ refresh (background, non-blocking)
┌─────────────────────────────────────────────────────────────────┐
│                     OIDC Provider                               │
│                  (external, e.g., Okta)                         │
└─────────────────────────────────────────────────────────────────┘
```

### Pivot Payload Addition

The pivot command payload includes:

```protobuf
message PivotCommand {
  // Existing fields...
  repeated bytes capi_resources = 1;

  // New fields for Cedar
  repeated LatticeServicePolicy service_policies = 10;
  bytes cedar_schema = 11;
}
```

---

## Migration Path

1. **Phase 1**: LatticeService `authorization` field (service-level policies)
2. **Phase 2**: LatticeServicePolicy CRD (subtree-wide policies with inheritance)
3. **Phase 3**: Policy simulation/dry-run tooling
4. **Phase 4**: Policy impact analysis and audit mode

---

## Design Decisions

### Mutability of Inherited Policies

**Decision:** Read-Only with Override

Inherited policies are read-only in child clusters to maintain parent as source of truth. Children can add local LatticeServicePolicies alongside inherited ones. Cedar's `forbid` rules trump `permit`, so:
- Parents can enforce guardrails children cannot bypass (using `forbid`)
- Children can add stricter rules locally (additional `forbid` or narrower `permit`)

### Maximum Policy Size/Complexity Limits

**Decision:** Defer to Phase 2

Trust developers initially; Cedar compilation will catch pathological policies. Revisit after implementation experience reveals actual usage patterns.

### Exempting Services from Inherited Policies

**Decision:** No exemption mechanism - use selector expressiveness

No special opt-out for services. Instead, policy authors use selector expressions to define scope:

```yaml
selector:
  matchExpressions:
    - {key: security-tier, operator: NotIn, values: [sandbox]}
```

This keeps control with policy authors (security team), not service owners. Services can't exempt themselves - but policies can explicitly exclude services by label when appropriate.

### Policy Versioning and Rollback Strategy

**Decision:** No versioning (GitOps)

Rely on GitOps workflows. Policies are YAML in version control; rollback is `git revert` + apply. No need for in-cluster version history - keeps the CRD simple and aligns with how teams already manage Kubernetes resources.
