# Contributing to Lattice

## Prerequisites

- Rust (stable toolchain)
- Docker
- `kubectl`
- `kind` (for local clusters)
- `gh` CLI (for GitHub operations)

## Local Environment Setup

### 1. Clone and build

```bash
git clone <repo-url> && cd lattice-model
cargo build
cargo test
cargo clippy
```

### 2. Configure credentials

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

The `.env` file contains registry credentials used by both `docker compose` services and E2E tests. At minimum you need `GHCR_USER` and `GHCR_TOKEN` to push/pull the lattice operator image.

```bash
source .env
```

### 3. Create the Docker network

E2E tests use a shared Docker network for Kind/CAPD clusters:

```bash
docker network create --driver=bridge --subnet=172.18.0.0/16 --gateway=172.18.0.1 kind
```

### 4. Start infrastructure services

```bash
docker compose up -d
```

This starts:

| Service | Port | Purpose |
|---------|------|---------|
| `vault` | 8200 | Secrets backend for ESO integration tests |
| `keycloak` | 8080 | OIDC provider for auth tests |
| `registry-mirror` | 5555 | DockerHub pull-through cache |
| `ghcr-mirror` | 5556 | GHCR pull-through cache |

## Registry Pull-Through Caches

The `registry-mirror` and `ghcr-mirror` services are **optional but highly recommended**. They act as local caching proxies for DockerHub and GitHub Container Registry.

### Why use them

- **Avoid rate limits.** DockerHub enforces pull rate limits (100 pulls/6h anonymous, 200 authenticated). E2E tests pull many images across multiple clusters and will hit these limits quickly. The cache pulls each layer once and serves subsequent requests locally.
- **Faster repeated runs.** After the first E2E run warms the cache, image pulls come from local disk instead of the internet. This significantly reduces cluster provisioning time.
- **Persist across runs.** Cache data is stored in Docker volumes (`registry-mirror-data`, `ghcr-mirror-data`) that survive `docker compose down`. Only `docker volume rm` clears them.

### How they work

E2E tests automatically inject `registryMirrors` into every Docker provider `LatticeCluster` spec, pointing `docker.io` and `ghcr.io` pulls through the local caches at `172.18.0.1:5555` and `172.18.0.1:5556` respectively. No manual configuration is needed — just start the services and run tests.

If the caches aren't running, containerd falls back to pulling directly from the upstream registries. Tests still work, just slower and subject to rate limits.

### Authenticated proxying

Adding registry credentials to `.env` lets the caches authenticate upstream, which increases DockerHub's rate limit to 200 pulls/6h and is required for private GHCR images:

```bash
# .env
DOCKERHUB_USER=your-dockerhub-username
DOCKERHUB_TOKEN=dckr_pat_your_token_here
GHCR_USER=your-github-username
GHCR_TOKEN=ghp_your_token_here
```

Then restart the caches:

```bash
source .env
docker compose up -d registry-mirror ghcr-mirror
```

### Verifying the caches

```bash
# DockerHub cache
curl http://localhost:5555/v2/_catalog

# GHCR cache
curl http://localhost:5556/v2/_catalog
```

After an E2E run, these will return the cached repositories.

## Running Tests

### Unit tests

```bash
cargo test
```

### E2E tests

E2E tests build the operator image, provision clusters via CAPI, and run the full lifecycle. They require Docker and take 20-30 minutes.

```bash
# Full lifecycle (bootstrap, pivot, workload provisioning, mesh, scaling)
cargo test --features provider-e2e --test e2e unified_e2e -- --nocapture
```

### Integration tests (against existing clusters)

If you've already provisioned clusters (or used `test_setup_hierarchy_only`), you can run individual test suites without reprovisioning:

```bash
# Setup infrastructure only, leave running for iteration
cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture

# Then run specific tests against the existing clusters
LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture

LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_local_secrets_standalone -- --ignored --nocapture

LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_cedar_secret_standalone -- --ignored --nocapture
```

## Code Standards

- No `.unwrap()` in non-test code
- No dead code or commented-out code
- No clippy warnings
- All crypto uses FIPS implementations (`aws-lc-rs`)
- Coverage target: 90%+ (hard stop at 80%)

See [CLAUDE.md](CLAUDE.md) for the full style guide and architecture documentation.
