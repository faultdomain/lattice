# Local Testing Platform

Local development environment for Lattice using Docker Compose services (Vault, Keycloak) with kind clusters.

## Prerequisites

- Docker
- kind
- Rust toolchain
- `kubectl` and `kubectl oidc-login` plugin (for OIDC kubeconfig testing)

## Start Local Services

```bash
# Create the kind network (if not already created)
docker network create kind || true

# Start Vault and Keycloak
docker compose up -d
```

This starts:
- **Vault** at `http://localhost:8200` (dev token: `root`)
- **Keycloak** at `http://localhost:8080` (admin: `admin`/`admin`)

## Keycloak

The Keycloak instance imports a pre-configured `lattice` realm on startup.

### Test Users

| User | Password | Groups |
|------|----------|--------|
| `admin@lattice.dev` | `admin` | `lattice-admins` |
| `developer@lattice.dev` | `developer` | `lattice-developers` |
| `viewer@lattice.dev` | `viewer` | `lattice-viewers` |

### Admin Console

Access at `http://localhost:8080` with `admin`/`admin`. Select the `lattice` realm to manage users, groups, and client settings.

### Get a Token (CLI)

```bash
curl -s -X POST http://localhost:8080/realms/lattice/protocol/openid-connect/token \
  -d grant_type=password \
  -d client_id=lattice \
  -d username=admin@lattice.dev \
  -d password=admin | jq -r .access_token
```

## Create a Cluster

```bash
cargo run -- install -f examples/docker-cluster.yaml
```

## Configure OIDC Authentication

Apply an OIDCProvider CRD pointing to Keycloak:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: keycloak
  namespace: lattice-system
spec:
  issuerUrl: "http://lattice-keycloak:8080/realms/lattice"
  clientId: "lattice"
  usernameClaim: email
  groupsClaim: groups
```

```bash
kubectl apply -f -  # paste the YAML above
```

Verify the provider is ready:

```bash
kubectl get oidcprovider -n lattice-system
# NAME       ISSUER                                          CLIENTID   PHASE   AGE
# keycloak   http://lattice-keycloak:8080/realms/lattice     lattice    Ready   10s
```

## Get OIDC Kubeconfig

```bash
lattice kubeconfig --format=oidc > ~/.kube/lattice-oidc.yaml
```

Using this kubeconfig triggers the `kubectl oidc-login` browser flow on first `kubectl` command:

```bash
KUBECONFIG=~/.kube/lattice-oidc.yaml kubectl get pods
```

## Cedar Policies for OIDC Groups

Allow the `lattice-admins` group to access all clusters:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: oidc-admin-access
  namespace: lattice-system
spec:
  enabled: true
  priority: 100
  policies: |
    permit(
      principal in Lattice::Group::"lattice-admins",
      action,
      resource
    );
```

Deny viewers from production clusters:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: deny-viewers-prod
  namespace: lattice-system
spec:
  enabled: true
  priority: 50
  policies: |
    forbid(
      principal in Lattice::Group::"lattice-viewers",
      action,
      resource == Lattice::Cluster::"prod"
    );
```

## Vault Secrets

See the [Vault secrets documentation](providers/vault.md) for configuring SecretsProvider and ExternalSecrets.

Quick start:

```bash
# Write a test secret
curl -X POST http://localhost:8200/v1/secret/data/myapp/config \
  -H "X-Vault-Token: root" \
  -d '{"data":{"api_key":"test-key"}}'
```

## Running Integration Tests

### Full E2E (creates all infrastructure)

```bash
cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
```

### Standalone Tests (use existing clusters)

First, set up infrastructure:

```bash
cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
```

Then run individual test suites:

```bash
# OIDC tests (requires Keycloak)
LATTICE_MGMT_KUBECONFIG=/tmp/e2e-mgmt-kubeconfig \
cargo test --features provider-e2e --test e2e test_oidc_standalone -- --ignored --nocapture

# Cedar tests
LATTICE_MGMT_KUBECONFIG=/tmp/e2e-mgmt-kubeconfig \
cargo test --features provider-e2e --test e2e test_cedar_all_standalone -- --ignored --nocapture

# Secrets tests (requires Vault)
LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_secrets_standalone -- --ignored --nocapture

# Mesh tests
LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig \
cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
```
