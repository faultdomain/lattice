# Secrets Management

Lattice manages secrets through External Secrets Operator (ESO), routing secret references in your LatticeService specs to Kubernetes Secrets synced from external providers like HashiCorp Vault.

## SecretProvider

A `SecretProvider` configures an external secret backend. It creates an ESO `ClusterSecretStore` that ExternalSecrets can reference.

### Vault

```yaml
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
metadata:
  name: vault-prod
  namespace: lattice-system
spec:
  provider:
    vault:
      server: https://vault.example.com:8200
      path: secret
      version: v2
      auth:
        kubernetes:
          mountPath: kubernetes
          role: lattice
          serviceAccountRef:
            name: lattice-operator
```

### AWS Secrets Manager

```yaml
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
metadata:
  name: aws-secrets
  namespace: lattice-system
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: aws-credentials
            key: access-key-id
          secretAccessKeySecretRef:
            name: aws-credentials
            key: secret-access-key
```

### Local Webhook (Development)

For development without an external secret store, Lattice includes a webhook backend that serves Kubernetes Secrets as flat JSON:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
metadata:
  name: local-dev
  namespace: lattice-system
spec:
  provider:
    webhook:
      url: "http://webhook.lattice-system.svc:8787/secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}"
      method: GET
      result:
        jsonPath: "$"
```

The webhook serves secrets from the `lattice-secrets` namespace. Only secrets labeled `lattice.dev/secret-source: "true"` are accessible.

### SecretProvider Status

```bash
kubectl get secretprovider -n lattice-system
```

| Phase | Description |
|-------|-------------|
| `Pending` | Waiting for ESO CRD detection |
| `Ready` | ClusterSecretStore created and validated |
| `Failed` | Configuration or connectivity error |

## Declaring Secrets in LatticeService

Secrets are declared as resources with `type: secret`. The `id` field specifies the remote path (e.g., Vault path), and secret-specific parameters go in `params`:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: my-api
  namespace: default
spec:
  replicas: 3
  workload:
    containers:
      main:
        image: my-registry.io/my-api:latest
        variables:
          PORT: "8080"
          DB_PASSWORD: "${secret.database.password}"
          DATABASE_URL: "postgres://app:${secret.database.password}@db.svc:5432/mydb"
    resources:
      database:
        type: secret
        id: database/prod/credentials
        params:
          provider: vault-prod
          keys:
            - password
            - username
        direction: inbound
```

### Secret Reference Syntax

```
${secret.<resource-name>.<key>}
```

- `<resource-name>`: Must match a declared secret resource
- `<key>`: A specific field within the secret

## Five Secret Routing Paths

The Lattice compiler detects how secrets are used and routes them through the appropriate compilation path:

### Route 1: Pure Secret Environment Variable

When a variable contains only a secret reference:

```yaml
variables:
  DB_PASSWORD: "${secret.database.password}"
```

**Compiles to:** A Kubernetes `secretKeyRef` in the pod spec. No ExternalSecret is created — the kubelet injects the value directly from the synced Secret at pod start.

### Route 2: Mixed-Content Environment Variable

When a variable mixes secret references with other content:

```yaml
variables:
  DATABASE_URL: "postgres://app:${secret.database.password}@db.svc:5432/mydb"
```

**Compiles to:** An ESO ExternalSecret with a Go template in `spec.target.template.data`. ESO fetches the secret value and renders the template at sync time:

```
postgres://app:{{ .database_password }}@db.svc:5432/mydb
```

### Route 3: File Mount with Secrets

When file content contains secret references:

```yaml
containers:
  main:
    image: my-app:latest
    files:
      /etc/app/config.yaml:
        content: |
          database:
            host: db.svc
            password: ${secret.database.password}
```

**Compiles to:** An ESO ExternalSecret with `spec.target.template.data` containing the file content as a Go template. The rendered file is mounted into the container.

### Route 4: Image Pull Secrets

For container registry authentication, declare the secret resource and reference it in `imagePullSecrets` (a top-level field on the spec, flattened from RuntimeSpec):

```yaml
spec:
  replicas: 1
  imagePullSecrets:
    - registry-creds
  workload:
    containers:
      main:
        image: private-registry.io/my-app:latest
    resources:
      registry-creds:
        type: secret
        id: registry/dockerconfig
        params:
          provider: vault-prod
          secretType: kubernetes.io/dockerconfigjson
```

**Compiles to:** An ExternalSecret that creates a Kubernetes Secret of type `kubernetes.io/dockerconfigjson`. The pod spec references this secret in `imagePullSecrets`.

### Route 5: Bulk Secret Import (dataFrom)

When a secret resource declares no explicit `keys`, all keys are imported:

```yaml
resources:
  app-config:
    type: secret
    id: app/prod/config
    params:
      provider: vault-prod
    # No 'keys' in params — import everything
    direction: inbound
```

**Compiles to:** An ExternalSecret with `spec.dataFrom.extract`, which fetches all keys from the remote path and flattens them into a single Kubernetes Secret.

## Secret Reference in Files

Files can contain multiple secret references mixed with plain content:

```yaml
containers:
  main:
    files:
      /etc/app/database.conf:
        content: |
          [database]
          host = db.svc
          port = 5432
          username = ${secret.database.username}
          password = ${secret.database.password}
      /etc/app/cert.pem:
        content: "${secret.tls.cert}"
```

Each file with secret references gets its own ExternalSecret for independent sync and lifecycle management.

## Multiple Secret Providers

A service can consume secrets from multiple providers:

```yaml
resources:
  database:
    type: secret
    id: database/prod/credentials
    params:
      provider: vault-prod
      keys:
        - password
  api-keys:
    type: secret
    id: prod/api-keys
    params:
      provider: aws-secrets
      keys:
        - stripe-key
        - sendgrid-key
```

Each provider's secrets are compiled into separate ExternalSecrets referencing the appropriate ClusterSecretStore.

## Cedar Policy Authorization

Access to secrets is governed by Cedar policies. See the [Security guide](./security.md) for details on Cedar policy configuration.

Secret access is evaluated during service compilation — before ESO objects are created. If a Cedar policy denies access, the ExternalSecret is never generated and the service compilation fails with a clear error message.
