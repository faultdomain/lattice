# Lattice Operator - CLAUDE.md

## Project Overview

Lattice is a Kubernetes operator for multi-cluster lifecycle management. It provisions clusters via CAPI and makes them **fully self-managing** through a pivoting architecture. After pivot, each cluster owns its CAPI resources and operates independently.

---

## Core Architecture: Self-Managed Clusters via Pivoting

**Every cluster provisioned by Lattice MUST become fully self-managed. This is non-negotiable.**

### Pivot Flow

```
1. Parent cluster creates LatticeCluster CRD
2. CAPI provisions infrastructure
3. kubeadm postKubeadmCommands calls parent's bootstrap webhook
4. Agent installed, establishes outbound gRPC stream to parent
5. Parent sends PivotCommand with CAPI resources over stream
6. Agent imports CAPI resources locally via distributed move protocol
7. Cluster is now self-managing (parent can be deleted)
```

### Network Architecture: Outbound-Only

**Workload clusters NEVER accept inbound connections. All communication is outbound.**

```
┌─────────────────────────────────────────────────────────────────┐
│                     Parent Cluster (Cell)                       │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Lattice Operator                                         │ │
│  │  - Watches LatticeCluster CRDs, provisions new clusters   │ │
│  │  - gRPC Server: accepts agent connections (bidirectional) │ │
│  │  - Bootstrap Webhook: kubeadm postKubeadmCommands target  │ │
│  │  - K8s API Proxy: streams watch requests to children      │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
         ▲                                      ▲
         │ (1) kubeadm webhook call             │ (2) persistent gRPC stream
         │                                      │
┌────────┴──────────────────────────────────────┴─────────────────┐
│                     Child Cluster                               │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Lattice Operator                                         │ │
│  │  - Watches OWN LatticeCluster CRD, self-manages           │ │
│  │  - Agent: outbound gRPC stream to parent                  │ │
│  │  - CAPI: owns cluster lifecycle post-pivot                │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Independence from Parent

**Every cluster MUST be 100% operational even if the parent is deleted.**

The gRPC stream is for:
- Coordination during provisioning/pivot
- Optional health reporting
- K8s API proxy for parent visibility

It is NOT required for:
- Self-management (scaling, upgrades, node replacement)
- CAPI reconciliation
- Running workloads

### Why This Architecture

- **Outbound-only**: Firewall friendly, no attack surface on workload clusters
- **Self-managing**: Parent failure doesn't affect children
- **Scalable**: Parent doesn't become bottleneck as cluster count grows
- **Air-gapped**: Clusters operate independently once provisioned

---

## Security: Defense in Depth

### Service Mesh Bilateral Agreements

Traffic is only allowed when BOTH sides agree:
1. **Caller** declares outbound dependency (`resources.foo.direction: outbound`)
2. **Callee** allows inbound from caller (`resources.bar.direction: inbound`)

This generates:
- **Cilium CiliumNetworkPolicy** (L4 eBPF enforcement)
- **Istio AuthorizationPolicy** (L7 identity-based enforcement)

### Default-Deny Policies

- **Cilium**: `CiliumClusterwideNetworkPolicy` with no ingress rules (implicit deny)
- **Istio**: `AuthorizationPolicy` with empty `spec: {}` (deny all)
- System namespaces excluded: `kube-system`, `cilium-system`, `istio-system`, `lattice-system`, `cert-manager`, `capi-*`

### FIPS Requirements

All cryptographic operations MUST use FIPS 140-2/140-3 validated implementations:

```toml
rustls = { version = "0.23", default-features = false, features = ["aws-lc-rs", "std"] }
aws-lc-rs = { version = "1.12", features = ["fips"] }
```

- TLS: `rustls` with `aws-lc-rs` backend
- Hashing: SHA-256/384/512 only (no MD5, no SHA-1)
- Signatures: ECDSA P-256/P-384 or RSA 2048+

---

## Rust Style Guide

### Error Handling

```rust
// Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("cluster not found: {0}")]
    NotFound(String),
    #[error("CAPI error: {0}")]
    Capi(#[from] CAPIError),
}

// Never panic in library code - return Result
// Use ? operator, avoid .unwrap() except in tests
```

### Async Patterns

```rust
// Use tokio for all async I/O
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::select;

// Prefer message passing over shared state
// Never hold locks across .await points
// Use cancellation tokens for graceful shutdown
```

### Type Safety

```rust
// Use newtypes for domain concepts
pub struct ClusterName(String);

// Make invalid states unrepresentable
pub enum ClusterPhase {
    Pending,
    Provisioning,
    Pivoting,
    Ready,
    Failed,
}

// Use #[non_exhaustive] on public enums
```

### Controller Pattern

```rust
async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action> {
    // 1. Observe current state
    let current = observe(&cluster, &ctx).await?;

    // 2. Compute desired state
    let desired = compute_desired(&cluster)?;

    // 3. Apply one change at a time (idempotent)
    if current != desired {
        apply_change(&current, &desired, &ctx).await?;
    }

    // 4. Update status
    update_status(&cluster, &ctx).await?;

    // 5. Requeue
    Ok(Action::requeue(Duration::from_secs(60)))
}
```

---

## Testing Infrastructure

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Test Infrastructure                          │
├─────────────────────────────────────────────────────────────────┤
│  INTEGRATION TESTS (assume cluster exists, can run standalone)  │
│  ├─ integration/mesh.rs       - Mesh bilateral agreement tests  │
│  ├─ integration/capi.rs       - CAPI resource verification      │
│  ├─ integration/scaling.rs    - Worker scaling tests            │
│  ├─ integration/proxy.rs      - K8s API proxy through hierarchy │
│  └─ integration/pivot.rs      - Unpivot verification            │
├─────────────────────────────────────────────────────────────────┤
│  E2E TESTS (build everything, compose integration tests)        │
│  ├─ unified_e2e.rs          - Full lifecycle                      │
│  ├─ upgrade_e2e.rs        - Upgrade with mesh traffic           │
│  ├─ endurance_e2e.rs      - Infinite loop stress test           │
│  └─ docker_independence_e2e.rs - Parent deletion survival       │
└─────────────────────────────────────────────────────────────────┘
```

### Key Distinction

- **Integration tests**: Assume infrastructure exists. Fast, reusable, can run repeatedly.
- **E2E tests**: Build everything from scratch. Full flow, creates and destroys infrastructure.

E2E tests **compose** integration test modules at appropriate phases. This allows:
1. Fast iteration on specific test types (run mesh tests without 20-30 min setup)
2. Same test coverage whether running standalone or as part of E2E
3. Clear separation of concerns

### Test Initialization Patterns

```rust
// E2E tests (create their own infrastructure)
use super::context::init_e2e_test;
use super::helpers::DEFAULT_LATTICE_IMAGE;

#[tokio::test]
async fn test_full_e2e() {
    init_e2e_test();  // Sets up crypto provider + tracing
    // ... create clusters, run tests, cleanup
}

// Integration tests (use existing infrastructure)
use super::context::init_test_env;

#[tokio::test]
#[ignore]  // Run with --ignored flag
async fn test_mesh_standalone() {
    let ctx = init_test_env("Set LATTICE_WORKLOAD_KUBECONFIG");
    // ... run tests against ctx.workload_kubeconfig
}
```

### InfraContext Pattern

All tests use `InfraContext` for cluster connection info:

```rust
pub struct InfraContext {
    pub mgmt_kubeconfig: String,
    pub workload_kubeconfig: Option<String>,
    pub workload2_kubeconfig: Option<String>,
    pub provider: InfraProvider,
}

// From environment (standalone tests)
let ctx = InfraContext::from_env().expect("Set kubeconfig vars");

// Programmatic (E2E tests)
let ctx = InfraContext::new(mgmt, Some(workload), None, InfraProvider::Docker);
```

### Running Tests

```bash
# Full E2E (creates all infrastructure)
cargo test --features provider-e2e --test e2e unified_e2e -- --nocapture

# Integration tests on existing clusters
LATTICE_WORKLOAD_KUBECONFIG=/tmp/xxx-e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture

# Setup infrastructure only (leave running for iteration)
cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
```

### Centralized Constants

All shared constants live in `helpers.rs`:

```rust
pub const DEFAULT_LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";
pub const DOCKER_KIND_SUBNET: &str = "172.18.0.0/16";
```

### Coverage Requirements

- Target: 90%+ on all code
- Hard stop: Work halts if coverage drops below 80%
- Critical paths (pivot, provisioning): 95%+

### E2E Test Coverage

The E2E test (`unified_e2e.rs`) validates:
- Bootstrap → management cluster pivot
- Management → workload cluster provisioning and pivot
- Workload cluster independence (delete parent, verify self-scaling)
- Service mesh bilateral agreements (exact match verification)
- Randomized large-scale mesh (10-20 services, 400+ connection tests)

### Mesh Test Patterns

Mesh tests use **cycle-based waiting** instead of flat timeouts:

```rust
// Traffic generators emit cycle markers in their logs
info!("===CYCLE_START===");
// ... make all outbound connections
info!("===CYCLE_END===");

// Tests wait for N complete cycles, not arbitrary time
wait_for_cycles(kubeconfig, namespace, &service_names, min_cycles).await?;
```

This approach:
- Knows when traffic generators have actually run (vs just waiting)
- Catches failures faster (don't wait full timeout on early failure)
- Handles slow environments gracefully (waits for work, not time)

Mesh bilateral agreements are verified by:
1. Generating services with random inbound/outbound dependencies
2. Running traffic generators that attempt all connections
3. Verifying ALLOWED connections succeed
4. Verifying DENIED connections fail (must be denied, not just timeout)

---

## Agent-Cell Protocol

### gRPC Stream (mTLS, Outbound from Agent)

```protobuf
service LatticeAgent {
  rpc Connect(stream AgentMessage) returns (stream CellCommand);
}

// Agent → Cell
message AgentMessage {
  oneof payload {
    AgentReady ready = 1;
    PivotComplete pivot_complete = 2;
    Heartbeat heartbeat = 3;
  }
}

// Cell → Agent
message CellCommand {
  oneof command {
    PivotCommand pivot = 1;
    KubernetesRequest k8s_request = 2;
  }
}
```

### K8s API Proxy

Parent can access child's K8s API through the gRPC stream:
- Supports all verbs (get, list, watch, create, update, delete)
- Watch requests are streamed
- Path-based routing: `/clusters/{name}/api/...`

---

## Code Organization Principles

### No Duplication

- **One way to do things**: If two functions do similar work, consolidate them
- **Centralized constants**: All shared values in one place (e.g., `helpers.rs`)
- **Extract common patterns**: If code appears in 3+ places, extract it

### No Dead Code

- **Remove unused code immediately**: Don't comment out, delete
- **No backwards compatibility shims**: If something is unused, delete it completely
- **Clean as you go**: Every change should leave the codebase cleaner

### Consistent Patterns

- **Same initialization everywhere**: All tests use `init_e2e_test()` or `init_test_env()`
- **Same context pattern everywhere**: All integration tests receive `InfraContext`
- **Same helper functions**: Don't reinvent, use existing helpers

### File Organization

```
crates/lattice-cli/tests/e2e/
├── mod.rs              # Module declarations
├── helpers.rs          # Shared utilities + constants
├── providers.rs        # InfraProvider enum
├── context.rs          # InfraContext + init helpers
├── chaos.rs            # Chaos monkey for stress tests
├── mesh_tests.rs       # Mesh bilateral agreement core
│
├── integration/        # Integration tests (assume infra exists)
│   ├── mod.rs
│   ├── mesh.rs         # Mesh tests (wraps mesh_tests.rs)
│   ├── capi.rs         # CAPI resource verification
│   ├── scaling.rs      # Worker scaling
│   ├── proxy.rs        # K8s API proxy through hierarchy
│   ├── pivot.rs        # Unpivot verification
│   └── setup.rs        # Setup-only test + cleanup
│
├── unified_e2e.rs        # Full lifecycle E2E
├── upgrade_e2e.rs      # Upgrade with mesh traffic
├── endurance_e2e.rs    # Infinite loop stress test
└── docker_independence_e2e.rs  # Parent deletion survival
```

---

## Development Checklist

Before merging:

- [ ] Tests written first (TDD)
- [ ] Coverage >= 80% (target 90%+)
- [ ] No `.unwrap()` in non-test code
- [ ] All crypto uses FIPS implementations
- [ ] No clippy warnings
- [ ] Code formatted (`cargo fmt`)
- [ ] No duplicate code (consolidate if similar)
- [ ] No dead code (remove if unused)
- [ ] Uses existing patterns (InfraContext, init helpers, etc.)
