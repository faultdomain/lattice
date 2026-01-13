# Deployment Compilation Implementation Plan

This document outlines the plan to implement full deployment compilation for each Score spec feature in the LatticeService CRD.

## Current State

### Score Spec Features in CRD (`src/crd/service.rs`)

| Feature | CRD Field | Template Support | Status |
|---------|-----------|------------------|--------|
| Containers | `containers: BTreeMap<String, ContainerSpec>` | N/A | Defined |
| Container Image | `containers.*.image` | No | Defined |
| Container Command | `containers.*.command` | No | Defined |
| Container Args | `containers.*.args` | No | Defined |
| Environment Variables | `containers.*.variables` | `${...}` via TemplateString | Defined |
| Resource Limits | `containers.*.resources` | No | Defined |
| Liveness Probe | `containers.*.liveness_probe` | No | Defined |
| Readiness Probe | `containers.*.readiness_probe` | No | Defined |
| Files | `containers.*.files` | `${...}` in content/source | Defined |
| Volumes | `containers.*.volumes` | `${...}` in source | Defined |
| Resources (deps) | `resources: BTreeMap<String, ResourceSpec>` | `${...}` in params | Defined |
| Service Ports | `service.ports` | No | Defined |
| Replicas | `replicas.min/max` | No | Defined |
| Deploy Strategy | `deploy.strategy` | No | Defined |
| Canary Config | `deploy.canary` | No | Defined |

### Existing Infrastructure

1. **Template Engine** (`src/template/engine.rs`): Score-compatible `${...}` syntax with minijinja
2. **Template Context** (`src/template/context.rs`): Metadata, resources, cluster, env, config contexts
3. **Template Renderer** (`src/template/renderer.rs`): High-level API for rendering containers
4. **Resource Provisioners** (`src/template/provisioner.rs`): Service and ExternalService provisioners
5. **Workload Compiler** (`src/workload/mod.rs`): Generates Deployment, Service, ServiceAccount, HPA
6. **Service Compiler** (`src/compiler/mod.rs`): Orchestrates workload and policy compilation

### Gap Analysis

The main gap is **template rendering is not integrated into workload compilation**:

```
Current Flow:
  LatticeService --> WorkloadCompiler --> Deployment (with unrendered templates)

Required Flow:
  LatticeService --> TemplateRenderer --> ConfigMap/Secret + Deployment (with envFrom refs)
```

Specific gaps:
1. Environment variables contain raw `${...}` templates, not resolved values
2. Environment variables not compiled to ConfigMaps/Secrets
3. File mounts not compiled to ConfigMaps/Secrets
4. Volume mounts not compiled to PVC references
5. Resource provisioners for Postgres/Redis/Route not implemented
6. Canary deployment not generating Flagger resources

---

## Architectural Decision: ConfigMap/Secret for Environment Variables

**Decision**: All environment variables compile to ConfigMap/Secret resources, NOT inline values in Deployment.

### Rationale

| Aspect | Inline Rendering | ConfigMap/Secret (Chosen) |
|--------|------------------|---------------------------|
| Deployment manifest | Contains literal values | Contains references only |
| Secret visibility | Secrets visible in Deployment YAML | Secrets isolated in Secret resource |
| Config updates | Requires Deployment rollout | Can update ConfigMap independently |
| Debugging | `kubectl get deploy -o yaml` | `kubectl get configmap {name}-env -o yaml` |
| External Secrets | Hard to integrate | Natural fit with ExternalSecret CRD |
| GitOps | Secrets in repo or templated | Secrets managed separately |
| 12-Factor App | Violates config separation | Follows best practices |

### Architecture

```
+-------------------------------------------------------------+
|                    LatticeService CRD                       |
|  variables:                                                 |
|    DB_HOST: "${resources.postgres.host}"                    |
|    DB_PASSWORD: "${resources.postgres.password}"            |
|    LOG_LEVEL: "info"                                        |
+-------------------------------------------------------------+
                              |
                              v
                    +-------------------+
                    |     Compiler      |
                    |                   |
                    | 1. Render temps   |
                    | 2. Provisioner    |
                    |    declares       |
                    |    sensitivity    |
                    +-------------------+
                              |
              +---------------+---------------+
              v                               v
+---------------------------+   +---------------------------+
|   ConfigMap: {name}-env   |   |   Secret: {name}-secrets  |
|                           |   |                           |
| DB_HOST: "postgres..."    |   | DB_PASSWORD: "***"        |
| LOG_LEVEL: "info"         |   |                           |
| SERVICE_NAME: "api"       |   |                           |
+---------------------------+   +---------------------------+
              |                               |
              +---------------+---------------+
                              v
+-------------------------------------------------------------+
|                      Deployment                             |
|  spec:                                                      |
|    template:                                                |
|      spec:                                                  |
|        containers:                                          |
|          - name: main                                       |
|            envFrom:                                         |
|              - configMapRef:                                |
|                  name: {name}-env                           |
|              - secretRef:                                   |
|                  name: {name}-secrets                       |
+-------------------------------------------------------------+
```

### Sensitive Value Detection: Provisioner-Declared

**No guessing.** Sensitivity is determined by the **resource provisioner**, not variable names or heuristics.

Each provisioner declares which of its outputs are sensitive:

```rust
pub struct ResourceOutputs {
    /// Non-sensitive outputs -> ConfigMap
    pub outputs: BTreeMap<String, String>,

    /// Sensitive outputs -> Secret
    pub sensitive: BTreeMap<String, String>,
}
```

When a template like `${resources.postgres.password}` is rendered:
1. Look up the `postgres` resource's outputs
2. The `PostgresProvisioner` declared `password` as sensitive
3. Track that this variable's value came from a sensitive source
4. At compile time, route to Secret instead of ConfigMap

**The variable name is irrelevant** - what matters is where the value originated.

| Variable | Template | Provisioner Output | Sensitive? | Destination |
|----------|----------|-------------------|------------|-------------|
| `DB_HOST` | `${resources.postgres.host}` | `outputs["host"]` | No | ConfigMap |
| `DB_PASSWORD` | `${resources.postgres.password}` | `sensitive["password"]` | Yes | Secret |
| `DB_URL` | `${resources.postgres.connection_string}` | `sensitive["connection_string"]` | Yes | Secret |
| `LOG_LEVEL` | `"info"` | Literal | No | ConfigMap |

### Future: `${secrets.*}` Namespace

A separate `${secrets.*}` template namespace is planned for manual external secret mappings:

```yaml
variables:
  # Resource-provided (provisioner handles lookup)
  DB_PASSWORD: "${resources.postgres.password}"

  # Manual external secret reference (future feature)
  STRIPE_KEY: "${secrets.stripe-api.key}"
```

This will require explicit mapping configuration to ESO secret stores. **Not yet implemented.**

---

## Final Compiled Output Example

Given this LatticeService:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: api
spec:
  environment: prod
  containers:
    main:
      image: myapp:v1.0
      variables:
        DB_HOST: "${resources.postgres.host}"
        DB_PORT: "${resources.postgres.port}"
        DB_PASSWORD: "${resources.postgres.password}"
        REDIS_URL: "${resources.cache.url}"
        LOG_LEVEL: "info"
        SERVICE_NAME: "${metadata.name}"
      files:
        /etc/app/config.yaml:
          content: |
            database:
              host: ${resources.postgres.host}
              pool_size: 10
          mode: "0644"
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
      readinessProbe:
        httpGet:
          path: /health
          port: 8080
  resources:
    postgres:
      type: postgres
      direction: outbound
      id: main-db
    cache:
      type: redis
      direction: outbound
      id: shared-cache
    frontend:
      type: service
      direction: inbound
  service:
    ports:
      http:
        port: 8080
  replicas:
    min: 2
    max: 10
  deploy:
    strategy: canary
    canary:
      stepWeight: 10
      maxWeight: 50
```

The compiler produces these resources:

### 1. ConfigMap for Environment Variables (`api-env`)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-env
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
    lattice.dev/config-type: env
data:
  DB_HOST: "main-db-postgres.prod.svc.cluster.local"
  DB_PORT: "5432"
  REDIS_URL: "redis://shared-cache-redis.prod.svc.cluster.local:6379"
  LOG_LEVEL: "info"
  SERVICE_NAME: "api"
```

### 2. Secret for Sensitive Values (`api-secrets`)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-secrets
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
    lattice.dev/config-type: secrets
type: Opaque
stringData:
  DB_PASSWORD: "<resolved-from-secret-store>"
```

### 3. ConfigMap for File Mounts (`api-files`)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-files
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
    lattice.dev/config-type: files
data:
  config.yaml: |
    database:
      host: main-db-postgres.prod.svc.cluster.local
      pool_size: 10
```

### 4. ServiceAccount (`api`)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
```

### 5. Deployment (`api`)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
    lattice.dev/service: api
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: api
        app.kubernetes.io/managed-by: lattice
        lattice.dev/service: api
      annotations:
        # Hash triggers rollout when config changes
        lattice.dev/config-hash: "sha256:abc123..."
    spec:
      serviceAccountName: api
      containers:
        - name: main
          image: myapp:v1.0
          ports:
            - name: http
              containerPort: 8080
          envFrom:
            - configMapRef:
                name: api-env
            - secretRef:
                name: api-secrets
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
          volumeMounts:
            - name: files
              mountPath: /etc/app/config.yaml
              subPath: config.yaml
              readOnly: true
      volumes:
        - name: files
          configMap:
            name: api-files
            defaultMode: 0644
```

### 6. Service (`api`)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
spec:
  selector:
    app.kubernetes.io/name: api
  ports:
    - name: http
      port: 8080
      targetPort: 8080
```

### 7. HorizontalPodAutoscaler (`api`)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80
```

### 8. Flagger Canary (`api`)

```yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  service:
    port: 8080
  analysis:
    interval: 1m
    threshold: 5
    maxWeight: 50
    stepWeight: 10
    metrics:
      - name: request-success-rate
        thresholdRange:
          min: 99
        interval: 1m
      - name: request-duration
        thresholdRange:
          max: 500
        interval: 1m
```

### 9. CiliumNetworkPolicy (`api`)

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
spec:
  endpointSelector:
    matchLabels:
      app.kubernetes.io/name: api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/name: frontend
  egress:
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/name: main-db-postgres
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/name: shared-cache-redis
```

### 10. Istio AuthorizationPolicy (`api`)

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: api
  namespace: prod
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: lattice
spec:
  targetRefs:
    - kind: Service
      name: api
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/prod/sa/frontend"
```

---

## Updated GeneratedWorkloads Structure

```rust
/// Collection of all workload resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedWorkloads {
    // Core workloads
    pub deployment: Option<Deployment>,
    pub service: Option<Service>,
    pub service_account: Option<ServiceAccount>,
    pub hpa: Option<HorizontalPodAutoscaler>,

    // Progressive delivery
    pub canary: Option<Canary>,

    // Configuration resources
    pub env_config_map: Option<ConfigMap>,      // {name}-env
    pub secrets: Option<Secret>,                 // {name}-secrets
    pub files_config_map: Option<ConfigMap>,     // {name}-files
    pub files_secret: Option<Secret>,            // {name}-files-secret (for binary_content)
}
```

---

## Implementation Plan

### Phase 1: ConfigMap/Secret Types and Environment Variable Compilation

**Goal**: Environment variables compile to ConfigMap + Secret with proper sensitivity classification.

#### 1.1 Add ConfigMap/Secret Types

```rust
// src/workload/configmap.rs (new file)

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::workload::ObjectMeta;

/// Kubernetes ConfigMap
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMap {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_data: Option<BTreeMap<String, String>>,
}

impl ConfigMap {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            data: BTreeMap::new(),
            binary_data: None,
        }
    }
}

/// Kubernetes Secret
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub string_data: BTreeMap<String, String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

impl Secret {
    pub fn opaque(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            data: BTreeMap::new(),
            string_data: BTreeMap::new(),
            type_: Some("Opaque".to_string()),
        }
    }
}
```

#### 1.2 Implement Environment Compiler

```rust
// src/workload/env.rs (new file)

use std::collections::BTreeMap;
use crate::workload::{ConfigMap, Secret};

pub struct EnvCompiler;

impl EnvCompiler {
    /// Compile rendered environment variables into ConfigMap and Secret
    ///
    /// Sensitivity is determined by the provisioner, NOT by variable names.
    /// Each RenderedVariable carries a `sensitive` flag set during template rendering.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        variables: &BTreeMap<String, RenderedVariable>,
    ) -> CompiledEnv {
        let mut config_data = BTreeMap::new();
        let mut secret_data = BTreeMap::new();

        for (name, rendered) in variables {
            if rendered.sensitive {
                secret_data.insert(name.clone(), rendered.value.clone());
            } else {
                config_data.insert(name.clone(), rendered.value.clone());
            }
        }

        let config_map = if config_data.is_empty() {
            None
        } else {
            let mut cm = ConfigMap::new(format!("{}-env", service_name), namespace);
            cm.data = config_data;
            cm.metadata = cm.metadata
                .with_label("lattice.dev/config-type", "env");
            Some(cm)
        };

        let secret = if secret_data.is_empty() {
            None
        } else {
            let mut s = Secret::opaque(format!("{}-secrets", service_name), namespace);
            s.string_data = secret_data;
            s.metadata = s.metadata
                .with_label("lattice.dev/config-type", "secrets");
            Some(s)
        };

        CompiledEnv { config_map, secret }
    }
}

/// A rendered variable with its value and sensitivity flag
pub struct RenderedVariable {
    pub value: String,
    /// True if this value came from a sensitive provisioner output
    pub sensitive: bool,
}

pub struct CompiledEnv {
    pub config_map: Option<ConfigMap>,
    pub secret: Option<Secret>,
}
```

#### 1.3 Integrate with Template Renderer

Update `TemplateRenderer` to track sensitivity from provisioner outputs:

```rust
// src/template/renderer.rs (additions)

use crate::workload::env::RenderedVariable;

impl RenderConfig {
    /// Render all variables, tracking sensitivity from provisioner outputs
    pub fn render_variables(
        &self,
        variables: &BTreeMap<String, TemplateString>,
    ) -> Result<BTreeMap<String, RenderedVariable>, Error> {
        let mut result = BTreeMap::new();

        for (name, template) in variables {
            let rendered = self.render_template_with_sensitivity(template)?;
            result.insert(name.clone(), rendered);
        }

        Ok(result)
    }

    /// Render a single template, returning value and sensitivity flag
    fn render_template_with_sensitivity(
        &self,
        template: &TemplateString,
    ) -> Result<RenderedVariable, Error> {
        if !template.has_placeholders() {
            // Literal value - not sensitive
            return Ok(RenderedVariable {
                value: template.as_str().to_string(),
                sensitive: false,
            });
        }

        // Track if ANY referenced field is sensitive
        let mut sensitive = false;
        let value = self.engine.render(template.as_str(), |placeholder| {
            self.resolve_placeholder(placeholder, &mut sensitive)
        })?;

        Ok(RenderedVariable { value, sensitive })
    }

    /// Resolve a placeholder like "resources.postgres.password"
    fn resolve_placeholder(
        &self,
        placeholder: &str,
        sensitive: &mut bool,
    ) -> Result<String, Error> {
        if let Some(rest) = placeholder.strip_prefix("resources.") {
            let (resource_name, field) = rest.split_once('.')
                .ok_or_else(|| Error::invalid_placeholder(placeholder))?;

            let outputs = self.resource_outputs.get(resource_name)
                .ok_or_else(|| Error::resource_not_found(resource_name))?;

            // Check non-sensitive outputs first
            if let Some(value) = outputs.outputs.get(field) {
                return Ok(value.clone());
            }

            // Check sensitive outputs
            if let Some(value) = outputs.sensitive.get(field) {
                *sensitive = true;  // Mark this variable as sensitive
                return Ok(value.clone());
            }

            Err(Error::field_not_found(resource_name, field))
        } else if let Some(_rest) = placeholder.strip_prefix("secrets.") {
            // Future: ${secrets.*} namespace for manual ESO mappings
            Err(Error::not_implemented("${secrets.*} namespace not yet implemented"))
        } else if let Some(rest) = placeholder.strip_prefix("metadata.") {
            self.resolve_metadata(rest)
        } else {
            Err(Error::unknown_placeholder_namespace(placeholder))
        }
    }
}
```

#### 1.4 Update WorkloadCompiler

```rust
// src/workload/mod.rs (modifications)

impl WorkloadCompiler {
    pub fn compile(
        service: &LatticeService,
        namespace: &str,
        rendered: &RenderedService,  // Contains rendered vars, files, etc.
    ) -> GeneratedWorkloads {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");

        // Compile environment variables to ConfigMap/Secret
        let compiled_env = EnvCompiler::compile(
            name,
            namespace,
            &rendered.variables.values,
            &rendered.variables.origins,
        );

        // Compile file mounts
        let compiled_files = FileCompiler::compile(name, namespace, &rendered.files);

        // Build deployment with envFrom references
        let deployment = Self::compile_deployment(
            name,
            namespace,
            &service.spec,
            &compiled_env,
            &compiled_files,
        );

        GeneratedWorkloads {
            deployment: Some(deployment),
            service: Self::compile_service_if_needed(name, namespace, &service.spec),
            service_account: Some(Self::compile_service_account(name, namespace)),
            hpa: Self::compile_hpa_if_needed(name, namespace, &service.spec),
            canary: Self::compile_canary_if_needed(name, namespace, &service.spec),
            env_config_map: compiled_env.config_map,
            secrets: compiled_env.secret,
            files_config_map: compiled_files.config_map,
            files_secret: compiled_files.secret,
        }
    }

    fn compile_deployment(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
        env: &CompiledEnv,
        files: &CompiledFiles,
    ) -> Deployment {
        // ... existing deployment setup ...

        // Build envFrom references
        let mut env_from = vec![];
        if env.config_map.is_some() {
            env_from.push(EnvFromSource::ConfigMap {
                name: format!("{}-env", name),
            });
        }
        if env.secret.is_some() {
            env_from.push(EnvFromSource::Secret {
                name: format!("{}-secrets", name),
            });
        }

        // Build volume mounts from files
        let (volumes, volume_mounts) = files.to_pod_volumes();

        // ... rest of deployment ...
    }
}
```

**Files to create/modify**:
- `src/workload/configmap.rs` (new)
- `src/workload/env.rs` (new)
- `src/workload/mod.rs`
- `src/template/renderer.rs`
- `src/template/provisioner.rs` (update ResourceOutputs)

**Tests**:
- Literal value `"info"` goes to ConfigMap (not sensitive)
- `${resources.postgres.host}` goes to ConfigMap (provisioner declares non-sensitive)
- `${resources.postgres.password}` goes to Secret (provisioner declares sensitive)
- `${resources.postgres.connection_string}` goes to Secret (contains password, provisioner declares sensitive)
- Variable named `DB_PASSWORD` with literal value goes to ConfigMap (name doesn't matter, only origin)
- Empty Secret not created if no sensitive outputs referenced
- Deployment has correct `envFrom` references
- Mixed template `"postgresql://${resources.postgres.host}"` goes to ConfigMap (no sensitive refs)
- Mixed template with sensitive ref marks entire variable as sensitive

---

### Phase 2: File Mounts to ConfigMap/Secret Generation

**Goal**: Files with inline content compile to ConfigMaps; binary content to Secrets.

#### 2.1 Implement File Compiler

```rust
// src/workload/files.rs (new file)

use std::collections::BTreeMap;
use crate::workload::{ConfigMap, Secret, Volume, VolumeMount};

pub struct FileCompiler;

impl FileCompiler {
    /// Compile file mounts into ConfigMaps, Secrets, and volume mounts
    pub fn compile(
        service_name: &str,
        namespace: &str,
        files: &BTreeMap<String, RenderedFile>,
    ) -> CompiledFiles {
        let mut config_data = BTreeMap::new();
        let mut secret_data = BTreeMap::new();
        let mut volume_mounts = vec![];
        let mut file_modes: BTreeMap<String, u32> = BTreeMap::new();

        for (path, file) in files {
            let key = Self::path_to_key(path);

            if file.is_binary {
                // Binary content -> Secret (base64 encoded)
                secret_data.insert(key.clone(), file.content.clone());
            } else {
                // Text content -> ConfigMap
                config_data.insert(key.clone(), file.content.clone());
            }

            // Track file modes
            if let Some(mode) = &file.mode {
                file_modes.insert(key.clone(), Self::parse_mode(mode));
            }

            // Create volume mount for this file
            volume_mounts.push(FileMountInfo {
                path: path.clone(),
                key: key.clone(),
                is_binary: file.is_binary,
                mode: file.mode.clone(),
            });
        }

        let config_map = if config_data.is_empty() {
            None
        } else {
            let mut cm = ConfigMap::new(format!("{}-files", service_name), namespace);
            cm.data = config_data;
            cm.metadata = cm.metadata.with_label("lattice.dev/config-type", "files");
            Some(cm)
        };

        let secret = if secret_data.is_empty() {
            None
        } else {
            let mut s = Secret::opaque(format!("{}-files-secret", service_name), namespace);
            s.data = secret_data;  // Already base64
            s.metadata = s.metadata.with_label("lattice.dev/config-type", "files");
            Some(s)
        };

        CompiledFiles {
            config_map,
            secret,
            mounts: volume_mounts,
        }
    }

    /// Convert file path to ConfigMap key
    /// /etc/app/config.yaml -> etc-app-config.yaml
    fn path_to_key(path: &str) -> String {
        path.trim_start_matches('/')
            .replace('/', "-")
    }

    /// Parse octal mode string to integer
    fn parse_mode(mode: &str) -> u32 {
        let mode_str = mode.strip_prefix('0').unwrap_or(mode);
        u32::from_str_radix(mode_str, 8).unwrap_or(0o644)
    }
}

impl CompiledFiles {
    /// Convert to Pod volumes and container volume mounts
    pub fn to_pod_volumes(&self, service_name: &str) -> (Vec<Volume>, Vec<VolumeMount>) {
        let mut volumes = vec![];
        let mut mounts = vec![];

        // ConfigMap volume for text files
        if self.config_map.is_some() {
            volumes.push(Volume {
                name: "files".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: format!("{}-files", service_name),
                    default_mode: Some(0o644),
                }),
                ..Default::default()
            });
        }

        // Secret volume for binary files
        if self.secret.is_some() {
            volumes.push(Volume {
                name: "files-secret".to_string(),
                secret: Some(SecretVolumeSource {
                    secret_name: format!("{}-files-secret", service_name),
                    default_mode: Some(0o600),
                }),
                ..Default::default()
            });
        }

        // Create mount for each file
        for mount in &self.mounts {
            let volume_name = if mount.is_binary { "files-secret" } else { "files" };
            mounts.push(VolumeMount {
                name: volume_name.to_string(),
                mount_path: mount.path.clone(),
                sub_path: Some(mount.key.clone()),
                read_only: Some(true),
            });
        }

        (volumes, mounts)
    }
}

pub struct CompiledFiles {
    pub config_map: Option<ConfigMap>,
    pub secret: Option<Secret>,
    pub mounts: Vec<FileMountInfo>,
}

pub struct FileMountInfo {
    pub path: String,
    pub key: String,
    pub is_binary: bool,
    pub mode: Option<String>,
}

pub struct RenderedFile {
    pub content: String,
    pub is_binary: bool,
    pub mode: Option<String>,
}
```

**Files to create/modify**:
- `src/workload/files.rs` (new)
- `src/workload/mod.rs`

**Tests**:
- Text file creates ConfigMap entry
- Binary file creates Secret entry
- File paths converted to valid keys
- Volume mounts use correct subPath
- File modes parsed correctly
- Multiple files in same ConfigMap

---

### Phase 3: Resource Provisioners

**Goal**: All resource types resolve to connection info with explicit sensitivity declarations.

#### 3.1 Updated ResourceOutputs Structure

```rust
// src/template/provisioner.rs

/// Outputs from a resource provisioner
///
/// Provisioners explicitly declare which outputs are sensitive.
/// This determines whether values go to ConfigMap or Secret.
#[derive(Clone, Debug, Default)]
pub struct ResourceOutputs {
    /// Non-sensitive outputs -> ConfigMap
    pub outputs: BTreeMap<String, String>,

    /// Sensitive outputs -> Secret
    /// Accessing these marks the entire variable as sensitive
    pub sensitive: BTreeMap<String, String>,
}

impl ResourceOutputs {
    /// Get a field value and whether it's sensitive
    pub fn get(&self, field: &str) -> Option<(&str, bool)> {
        if let Some(v) = self.outputs.get(field) {
            Some((v.as_str(), false))
        } else if let Some(v) = self.sensitive.get(field) {
            Some((v.as_str(), true))
        } else {
            None
        }
    }
}
```

#### 3.2 ServiceProvisioner (Internal Services)

For `type: service` resources - dependencies on other LatticeServices in the cluster:

```rust
pub struct ServiceProvisioner<'a> {
    graph: &'a ServiceGraph,
}

impl ResourceProvisioner for ServiceProvisioner<'_> {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Service
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        // Look up the service in the graph
        let service_name = spec.id.as_deref().unwrap_or(name);
        let service = self.graph.get_service(ctx.namespace, service_name)
            .ok_or_else(|| Error::service_not_found(service_name))?;

        // Build FQDN
        let host = format!(
            "{}.{}.svc.{}",
            service_name,
            ctx.namespace,
            ctx.cluster_domain
        );

        // Get port (prefer "http" named port, fall back to first)
        let port = service.ports.get("http")
            .or_else(|| service.ports.values().next())
            .map(|p| p.port)
            .unwrap_or(80);

        // All outputs are non-sensitive for internal services
        Ok(ResourceOutputs {
            outputs: btreemap! {
                "host" => host.clone(),
                "port" => port.to_string(),
                "url" => format!("http://{}:{}", host, port),
                "name" => service_name.to_string(),
            },
            sensitive: BTreeMap::new(),
        })
    }
}
```

**Example usage:**
```yaml
resources:
  api:
    type: service
    direction: outbound
    id: api-gateway

# In variables:
variables:
  API_URL: "${resources.api.url}"  # -> ConfigMap (non-sensitive)
```

#### 3.3 ExternalServiceProvisioner

For `type: external-service` resources - dependencies on LatticeExternalService CRDs:

```rust
pub struct ExternalServiceProvisioner<'a> {
    graph: &'a ServiceGraph,
}

impl ResourceProvisioner for ExternalServiceProvisioner<'_> {
    fn resource_type(&self) -> ResourceType {
        ResourceType::ExternalService
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        let ext_name = spec.id.as_deref().unwrap_or(name);
        let external = self.graph.get_external_service(ctx.namespace, ext_name)
            .ok_or_else(|| Error::external_service_not_found(ext_name))?;

        // Get endpoint (prefer "default", fall back to first)
        let endpoint = external.endpoints.get("default")
            .or_else(|| external.endpoints.values().next())
            .ok_or_else(|| Error::no_endpoints(ext_name))?;

        // Parse URL to extract host/port
        let url = &endpoint.url;
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed.port().unwrap_or(443);

        // External services are non-sensitive (just URLs)
        // If auth is needed, user should use ${secrets.*} namespace
        Ok(ResourceOutputs {
            outputs: btreemap! {
                "host" => host,
                "port" => port.to_string(),
                "url" => url.clone(),
                "name" => ext_name.to_string(),
            },
            sensitive: BTreeMap::new(),
        })
    }
}
```

**Example usage:**
```yaml
resources:
  stripe:
    type: external-service
    direction: outbound
    id: stripe-api

variables:
  STRIPE_URL: "${resources.stripe.url}"  # -> ConfigMap
  # For API key, use future ${secrets.*} namespace or manual Secret
```

#### 3.4 PostgresProvisioner

```rust
pub struct PostgresProvisioner;

impl ResourceProvisioner for PostgresProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Postgres
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        let instance = spec.id.as_deref().unwrap_or(name);
        let service_name = format!("{}-postgres", instance);
        let host = format!("{}.{}.svc.{}", service_name, ctx.namespace, ctx.cluster_domain);

        let port = spec.params
            .as_ref()
            .and_then(|p| p.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(5432);

        let database = spec.params
            .as_ref()
            .and_then(|p| p.get("database"))
            .and_then(|v| v.as_str())
            .unwrap_or(instance);

        let username = spec.params
            .as_ref()
            .and_then(|p| p.get("username"))
            .and_then(|v| v.as_str())
            .unwrap_or("postgres");

        // Look up password from secret store (implementation depends on backend)
        let password = ctx.secret_store.get(&format!("postgres/{}/password", instance))?;

        Ok(ResourceOutputs {
            // Non-sensitive outputs
            outputs: btreemap! {
                "host" => host.clone(),
                "port" => port.to_string(),
                "database" => database.to_string(),
                "url" => format!("postgresql://{}:{}/{}", host, port, database),
            },
            // Sensitive outputs - provisioner explicitly declares these
            sensitive: btreemap! {
                "username" => username.to_string(),
                "password" => password,
                "connection_string" => format!(
                    "postgresql://{}:{}@{}:{}/{}",
                    username, password, host, port, database
                ),
            },
        })
    }
}
```

#### 3.5 RedisProvisioner

```rust
pub struct RedisProvisioner;

impl ResourceProvisioner for RedisProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Redis
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        let instance = spec.id.as_deref().unwrap_or(name);
        let service_name = format!("{}-redis", instance);
        let host = format!("{}.{}.svc.{}", service_name, ctx.namespace, ctx.cluster_domain);

        let port = spec.params
            .as_ref()
            .and_then(|p| p.get("port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(6379);

        // Check if auth is enabled
        let auth_enabled = spec.params
            .as_ref()
            .and_then(|p| p.get("auth"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut outputs = ResourceOutputs {
            outputs: btreemap! {
                "host" => host.clone(),
                "port" => port.to_string(),
            },
            sensitive: BTreeMap::new(),
        };

        if auth_enabled {
            let password = ctx.secret_store.get(&format!("redis/{}/password", instance))?;
            outputs.outputs.insert("url".to_string(), format!("redis://{}:{}", host, port));
            outputs.sensitive.insert("password".to_string(), password.clone());
            outputs.sensitive.insert(
                "url_with_auth".to_string(),
                format!("redis://:{}@{}:{}", password, host, port),
            );
        } else {
            outputs.outputs.insert("url".to_string(), format!("redis://{}:{}", host, port));
        }

        Ok(outputs)
    }
}
```

#### 3.6 RouteProvisioner

```rust
pub struct RouteProvisioner;

impl ResourceProvisioner for RouteProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Route
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        let hostname = spec.params
            .as_ref()
            .and_then(|p| p.get("host"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| format!("{}.{}", name, ctx.ingress_domain));

        let path = spec.params
            .as_ref()
            .and_then(|p| p.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("/");

        // Routes are entirely non-sensitive
        Ok(ResourceOutputs {
            outputs: btreemap! {
                "host" => hostname.clone(),
                "path" => path.to_string(),
                "url" => format!("https://{}{}", hostname, path),
            },
            sensitive: BTreeMap::new(),
        })
    }
}
```

#### 3.7 Register All Provisioners

```rust
impl ProvisionerRegistry {
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(ServiceProvisioner));
        registry.register(Box::new(ExternalServiceProvisioner));
        registry.register(Box::new(PostgresProvisioner));
        registry.register(Box::new(RedisProvisioner));
        registry.register(Box::new(RouteProvisioner));
        registry
    }
}
```

**Files to modify**:
- `src/template/provisioner.rs`

**Tests**:
- ServiceProvisioner resolves to correct FQDN and port from graph
- ServiceProvisioner all outputs are non-sensitive
- ExternalServiceProvisioner resolves URL from LatticeExternalService
- ExternalServiceProvisioner all outputs are non-sensitive
- Postgres `host`, `port`, `database`, `url` in `outputs` (non-sensitive)
- Postgres `username`, `password`, `connection_string` in `sensitive`
- Redis without auth has all fields in `outputs`
- Redis with auth has `password` and `url_with_auth` in `sensitive`
- Route has all fields in `outputs` (entirely non-sensitive)
- Custom params override defaults
- `ResourceOutputs::get()` returns correct sensitivity flag

---

### Phase 4: Volume Mounts to PVC/Volume References

**Goal**: External volume references compile to proper Kubernetes volumes.

#### 4.1 Add Volume Resource Type

```rust
// src/crd/service.rs (modification)

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ResourceType {
    #[default]
    Service,
    ExternalService,
    Route,
    Postgres,
    Redis,
    Volume,  // NEW
}
```

#### 4.2 VolumeProvisioner

```rust
// src/template/provisioner.rs (additions)

pub struct VolumeProvisioner;

impl ResourceProvisioner for VolumeProvisioner {
    fn resource_type(&self) -> ResourceType {
        ResourceType::Volume
    }

    fn resolve(
        &self,
        name: &str,
        spec: &ResourceSpec,
        ctx: &ProvisionerContext,
    ) -> Result<ResourceOutputs, Error> {
        let volume_name = spec.id.as_deref().unwrap_or(name);
        let class = spec.class.as_deref().unwrap_or("pvc");

        // Return volume reference in a structured format
        let volume_ref = match class {
            "pvc" => format!("pvc:{}", volume_name),
            "configmap" => format!("configmap:{}", volume_name),
            "secret" => format!("secret:{}", volume_name),
            "emptydir" => "emptydir:".to_string(),
            _ => format!("pvc:{}", volume_name),  // Default to PVC
        };

        Ok(ResourceOutputs {
            extras: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), volume_name.to_string());
                m.insert("ref".to_string(), volume_ref);
                m.insert("class".to_string(), class.to_string());
                m
            },
            ..Default::default()
        })
    }
}
```

#### 4.3 Volume Compiler

```rust
// src/workload/volumes.rs (new file)

use crate::workload::{Volume, VolumeMount};

pub enum ResolvedVolumeSource {
    PersistentVolumeClaim { claim_name: String },
    ConfigMap { name: String },
    Secret { secret_name: String },
    EmptyDir,
}

pub struct VolumeCompiler;

impl VolumeCompiler {
    /// Compile volume mounts from rendered volume sources
    pub fn compile(
        volumes: &BTreeMap<String, RenderedVolume>,
    ) -> CompiledVolumes {
        let mut pod_volumes = vec![];
        let mut container_mounts = vec![];

        for (mount_path, volume) in volumes {
            let source = Self::parse_source(&volume.source);
            let volume_name = Self::generate_volume_name(mount_path);

            let pod_volume = match &source {
                ResolvedVolumeSource::PersistentVolumeClaim { claim_name } => Volume {
                    name: volume_name.clone(),
                    persistent_volume_claim: Some(PvcVolumeSource {
                        claim_name: claim_name.clone(),
                    }),
                    ..Default::default()
                },
                ResolvedVolumeSource::ConfigMap { name } => Volume {
                    name: volume_name.clone(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: name.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ResolvedVolumeSource::Secret { secret_name } => Volume {
                    name: volume_name.clone(),
                    secret: Some(SecretVolumeSource {
                        secret_name: secret_name.clone(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ResolvedVolumeSource::EmptyDir => Volume {
                    name: volume_name.clone(),
                    empty_dir: Some(EmptyDirVolumeSource {}),
                    ..Default::default()
                },
            };

            pod_volumes.push(pod_volume);

            container_mounts.push(VolumeMount {
                name: volume_name,
                mount_path: mount_path.clone(),
                sub_path: volume.path.clone(),
                read_only: volume.read_only,
            });
        }

        CompiledVolumes {
            volumes: pod_volumes,
            mounts: container_mounts,
        }
    }

    /// Parse volume source string: "pvc:my-claim" -> PVC, "configmap:my-cm" -> ConfigMap
    fn parse_source(source: &str) -> ResolvedVolumeSource {
        if let Some(name) = source.strip_prefix("pvc:") {
            ResolvedVolumeSource::PersistentVolumeClaim {
                claim_name: name.to_string(),
            }
        } else if let Some(name) = source.strip_prefix("configmap:") {
            ResolvedVolumeSource::ConfigMap {
                name: name.to_string(),
            }
        } else if let Some(name) = source.strip_prefix("secret:") {
            ResolvedVolumeSource::Secret {
                secret_name: name.to_string(),
            }
        } else if source.starts_with("emptydir") {
            ResolvedVolumeSource::EmptyDir
        } else {
            // Default: treat as PVC name
            ResolvedVolumeSource::PersistentVolumeClaim {
                claim_name: source.to_string(),
            }
        }
    }

    fn generate_volume_name(path: &str) -> String {
        path.trim_start_matches('/')
            .replace('/', "-")
            .chars()
            .take(63)
            .collect()
    }
}

pub struct CompiledVolumes {
    pub volumes: Vec<Volume>,
    pub mounts: Vec<VolumeMount>,
}

pub struct RenderedVolume {
    pub source: String,      // Rendered template result
    pub path: Option<String>,
    pub read_only: Option<bool>,
}
```

**Files to create/modify**:
- `src/crd/service.rs`
- `src/template/provisioner.rs`
- `src/workload/volumes.rs` (new)
- `src/workload/mod.rs`

**Tests**:
- `pvc:my-claim` creates PVC volume
- `configmap:my-cm` creates ConfigMap volume
- `secret:my-secret` creates Secret volume
- `emptydir:` creates EmptyDir volume
- Sub-path mounts work correctly
- Read-only flag propagates

---

### Phase 5: Canary Deployment to Flagger Resources

**Goal**: Canary strategy generates Flagger Canary resource.

#### 5.1 Add Flagger Types

```rust
// src/workload/canary.rs (new file)

use serde::{Deserialize, Serialize};
use crate::workload::ObjectMeta;

/// Flagger Canary resource
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Canary {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: CanarySpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanarySpec {
    pub target_ref: TargetRef,
    pub service: CanaryService,
    pub analysis: CanaryAnalysis,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TargetRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanaryService {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanaryAnalysis {
    pub interval: String,
    pub threshold: u32,
    pub max_weight: u32,
    pub step_weight: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<CanaryMetric>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanaryMetric {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_range: Option<ThresholdRange>,
    pub interval: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

impl Canary {
    pub fn new(name: &str, namespace: &str) -> Self {
        Self {
            api_version: "flagger.app/v1beta1".to_string(),
            kind: "Canary".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: CanarySpec {
                target_ref: TargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                service: CanaryService {
                    port: 80,
                    target_port: None,
                },
                analysis: CanaryAnalysis {
                    interval: "1m".to_string(),
                    threshold: 5,
                    max_weight: 50,
                    step_weight: 10,
                    metrics: Self::default_metrics(),
                },
            },
        }
    }

    fn default_metrics() -> Vec<CanaryMetric> {
        vec![
            CanaryMetric {
                name: "request-success-rate".to_string(),
                threshold_range: Some(ThresholdRange {
                    min: Some(99.0),
                    max: None,
                }),
                interval: "1m".to_string(),
            },
            CanaryMetric {
                name: "request-duration".to_string(),
                threshold_range: Some(ThresholdRange {
                    min: None,
                    max: Some(500.0),
                }),
                interval: "1m".to_string(),
            },
        ]
    }
}
```

#### 5.2 Integrate into WorkloadCompiler

```rust
// src/workload/mod.rs (additions)

impl WorkloadCompiler {
    fn compile_canary_if_needed(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> Option<Canary> {
        if spec.deploy.strategy != DeployStrategy::Canary {
            return None;
        }

        let mut canary = Canary::new(name, namespace);

        // Apply service port
        if let Some(ref svc) = spec.service {
            if let Some((_, port_spec)) = svc.ports.iter().next() {
                canary.spec.service.port = port_spec.port;
                canary.spec.service.target_port = port_spec.target_port;
            }
        }

        // Apply canary config
        if let Some(ref config) = spec.deploy.canary {
            if let Some(ref interval) = config.interval {
                canary.spec.analysis.interval = interval.clone();
            }
            if let Some(threshold) = config.threshold {
                canary.spec.analysis.threshold = threshold;
            }
            if let Some(max_weight) = config.max_weight {
                canary.spec.analysis.max_weight = max_weight;
            }
            if let Some(step_weight) = config.step_weight {
                canary.spec.analysis.step_weight = step_weight;
            }
        }

        Some(canary)
    }
}
```

**Files to create/modify**:
- `src/workload/canary.rs` (new)
- `src/workload/mod.rs`

**Tests**:
- Canary strategy generates Flagger Canary
- Rolling strategy does not generate Canary
- Service port propagates to Canary
- Canary config values override defaults
- Default metrics included

---

### Phase 6: Controller Integration

**Goal**: Service controller uses full compilation pipeline with proper resource ordering.

#### 6.1 Update ServiceCompiler

```rust
// src/compiler/mod.rs

impl<'a> ServiceCompiler<'a> {
    pub fn compile(&self, service: &LatticeService) -> Result<CompiledService, CompilationError> {
        let name = service.metadata.name.as_deref().unwrap_or("unknown");
        let namespace = &service.spec.environment;

        // 1. Resolve all resources
        let resource_outputs = self.provisioner_registry.resolve_all(
            &service.spec.resources,
            &ProvisionerContext {
                namespace,
                cluster_domain: &self.cluster_domain,
                ingress_domain: &self.ingress_domain,
            },
        )?;

        // 2. Render templates
        let render_config = RenderConfig::new(
            self.graph,
            namespace,
            &self.cluster_domain,
            &resource_outputs,
        );

        let rendered = RenderedService {
            variables: render_config.render_variables(&service.spec)?,
            files: render_config.render_files(&service.spec)?,
            volumes: render_config.render_volumes(&service.spec)?,
        };

        // 3. Compile workloads
        let workloads = WorkloadCompiler::compile(service, namespace, &rendered);

        // 4. Compile policies
        let policies = PolicyCompiler::new(self.graph, &self.trust_domain)
            .compile(name, namespace, namespace);

        // 5. Build resolved dependencies for status
        let resolved_dependencies = resource_outputs
            .iter()
            .filter_map(|(name, outputs)| {
                outputs.url.as_ref().map(|url| (name.clone(), url.clone()))
            })
            .collect();

        Ok(CompiledService {
            workloads,
            policies,
            resolved_dependencies,
        })
    }
}
```

#### 6.2 Update Controller Reconciliation

```rust
// src/controller/service.rs

async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let name = service.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = &service.spec.environment;

    // 1. Validate spec
    if let Err(e) = service.spec.validate() {
        update_status(&ctx.client, &service, ServicePhase::Failed, Some(&e.to_string())).await?;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // 2. Update status to Compiling
    update_status(&ctx.client, &service, ServicePhase::Compiling, None).await?;

    // 3. Compile
    let compiler = ServiceCompiler::new(&ctx.graph, &ctx.trust_domain);
    let compiled = match compiler.compile(&service) {
        Ok(c) => c,
        Err(e) => {
            update_status(&ctx.client, &service, ServicePhase::Failed, Some(&e.to_string())).await?;
            return Ok(Action::requeue(Duration::from_secs(60)));
        }
    };

    // 4. Apply resources in dependency order
    apply_compiled_service(&ctx.client, namespace, &compiled).await?;

    // 5. Update status to Ready
    let status = LatticeServiceStatus::default()
        .phase(ServicePhase::Ready)
        .compiled_at(Utc::now())
        .with_resolved_deps(compiled.resolved_dependencies)
        .condition(Condition::new(
            "Ready",
            ConditionStatus::True,
            "Compiled",
            "All resources compiled and applied",
        ));
    update_full_status(&ctx.client, &service, status).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn apply_compiled_service(
    client: &Client,
    namespace: &str,
    compiled: &CompiledService,
) -> Result<(), ApplyError> {
    // Apply in dependency order:

    // 1. ConfigMaps (env and files depend on nothing)
    if let Some(ref cm) = compiled.workloads.env_config_map {
        apply_resource(client, namespace, cm).await?;
    }
    if let Some(ref cm) = compiled.workloads.files_config_map {
        apply_resource(client, namespace, cm).await?;
    }

    // 2. Secrets
    if let Some(ref secret) = compiled.workloads.secrets {
        apply_resource(client, namespace, secret).await?;
    }
    if let Some(ref secret) = compiled.workloads.files_secret {
        apply_resource(client, namespace, secret).await?;
    }

    // 3. ServiceAccount (Deployment depends on this)
    if let Some(ref sa) = compiled.workloads.service_account {
        apply_resource(client, namespace, sa).await?;
    }

    // 4. Deployment
    if let Some(ref deploy) = compiled.workloads.deployment {
        apply_resource(client, namespace, deploy).await?;
    }

    // 5. Service
    if let Some(ref svc) = compiled.workloads.service {
        apply_resource(client, namespace, svc).await?;
    }

    // 6. HPA
    if let Some(ref hpa) = compiled.workloads.hpa {
        apply_resource(client, namespace, hpa).await?;
    }

    // 7. Canary (depends on Deployment)
    if let Some(ref canary) = compiled.workloads.canary {
        apply_resource(client, namespace, canary).await?;
    }

    // 8. Network Policies
    for policy in &compiled.policies.authorization_policies {
        apply_resource(client, namespace, policy).await?;
    }
    for policy in &compiled.policies.cilium_policies {
        apply_resource(client, namespace, policy).await?;
    }
    for entry in &compiled.policies.service_entries {
        apply_resource(client, namespace, entry).await?;
    }

    Ok(())
}
```

**Files to modify**:
- `src/compiler/mod.rs`
- `src/controller/service.rs`

**Tests**:
- E2E: Service with templates deploys with ConfigMaps
- E2E: Resolved dependencies appear in status
- E2E: Resources applied in correct order
- E2E: Failed compilation updates status

---

### Phase 7: Config Hash for Automatic Rollouts

**Goal**: Changes to ConfigMap/Secret trigger Deployment rollout.

#### 7.1 Compute Config Hash

```rust
// src/workload/mod.rs (additions)

use sha2::{Sha256, Digest};

impl WorkloadCompiler {
    /// Compute hash of all config that should trigger rollout
    fn compute_config_hash(env: &CompiledEnv, files: &CompiledFiles) -> String {
        let mut hasher = Sha256::new();

        // Hash env ConfigMap data
        if let Some(ref cm) = env.config_map {
            for (k, v) in &cm.data {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
        }

        // Hash env Secret data
        if let Some(ref secret) = env.secret {
            for (k, v) in &secret.string_data {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
        }

        // Hash files ConfigMap data
        if let Some(ref cm) = files.config_map {
            for (k, v) in &cm.data {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
        }

        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}
```

#### 7.2 Add Hash to Pod Annotations

```rust
fn compile_deployment(...) -> Deployment {
    let config_hash = Self::compute_config_hash(&env, &files);

    // Add to pod template annotations
    let mut annotations = BTreeMap::new();
    annotations.insert("lattice.dev/config-hash".to_string(), config_hash);

    // ... rest of deployment with annotations in pod template ...
}
```

**Files to modify**:
- `src/workload/mod.rs`

**Tests**:
- Config hash changes when ConfigMap data changes
- Config hash changes when Secret data changes
- Same config produces same hash (deterministic)
- Deployment has config-hash annotation

---

### Phase 8: Error Handling and Status Reporting

**Goal**: Compilation errors are clearly reported in status.

#### 8.1 Structured Compilation Errors

```rust
// src/compiler/error.rs (new file)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompilationError {
    #[error("template error in container '{container}' variable '{variable}': {message}")]
    TemplateVariable {
        container: String,
        variable: String,
        message: String,
    },

    #[error("template error in container '{container}' file '{path}': {message}")]
    TemplateFile {
        container: String,
        path: String,
        message: String,
    },

    #[error("resource '{name}' of type '{type_}' not found")]
    ResourceNotFound { name: String, type_: String },

    #[error("no provisioner registered for resource type '{type_}'")]
    UnsupportedResourceType { type_: String },

    #[error("resource '{name}' provisioner error: {message}")]
    ProvisionerError { name: String, message: String },

    #[error("invalid file mount at '{path}': {message}")]
    InvalidFileMount { path: String, message: String },

    #[error("invalid volume mount at '{path}': {message}")]
    InvalidVolumeMount { path: String, message: String },

    #[error("circular dependency detected: {cycle}")]
    CircularDependency { cycle: String },
}
```

#### 8.2 Status Conditions

```rust
// Standard condition types for LatticeService
pub const CONDITION_TEMPLATES_RESOLVED: &str = "TemplatesResolved";
pub const CONDITION_CONFIG_COMPILED: &str = "ConfigCompiled";
pub const CONDITION_WORKLOADS_READY: &str = "WorkloadsReady";
pub const CONDITION_POLICIES_APPLIED: &str = "PoliciesApplied";

// Example condition updates during reconciliation
status = status
    .condition(Condition::new(
        CONDITION_TEMPLATES_RESOLVED,
        ConditionStatus::True,
        "Resolved",
        format!("Resolved {} template variables", var_count),
    ))
    .condition(Condition::new(
        CONDITION_CONFIG_COMPILED,
        ConditionStatus::True,
        "Compiled",
        format!("Generated {} ConfigMaps, {} Secrets", cm_count, secret_count),
    ));
```

**Files to create/modify**:
- `src/compiler/error.rs` (new)
- `src/crd/service.rs`
- `src/controller/service.rs`

---

## Implementation Order

1. **Phase 1**: ConfigMap/Secret types + environment compilation (foundation)
2. **Phase 2**: File mounts to ConfigMap/Secret (commonly used)
3. **Phase 3**: Additional provisioners - Postgres, Redis, Route (enables real use cases)
4. **Phase 4**: Volume mounts to PVC/Volume (completes Score spec)
5. **Phase 5**: Canary to Flagger (advanced feature)
6. **Phase 6**: Controller integration (ties everything together)
7. **Phase 7**: Config hash for rollouts (operational polish)
8. **Phase 8**: Error handling and status (production readiness)

---

## Test Coverage Requirements

Per CLAUDE.md:
- Target: 90%+ on all code
- Hard stop: 80% minimum
- Critical paths (template rendering, compilation): 95%+

Each phase must include:
1. Unit tests for new functions
2. Integration tests for cross-module behavior
3. E2E test additions to `pivot_e2e.rs` for full flow validation

---

## Summary of Generated Resources

For each LatticeService, the compiler generates:

| Resource | Name Pattern | Condition |
|----------|--------------|-----------|
| ConfigMap | `{name}-env` | Always (if any env vars) |
| Secret | `{name}-secrets` | If sensitive vars exist |
| ConfigMap | `{name}-files` | If text file mounts exist |
| Secret | `{name}-files-secret` | If binary file mounts exist |
| ServiceAccount | `{name}` | Always |
| Deployment | `{name}` | Always |
| Service | `{name}` | If ports defined |
| HPA | `{name}` | If max replicas set |
| Canary | `{name}` | If strategy is canary |
| CiliumNetworkPolicy | `{name}` | If in service graph |
| AuthorizationPolicy | `{name}` | If has allowed callers |
| ServiceEntry | `{name}-{ext}` | If has external deps |

---

## Open Questions

1. **Secret Store Backend**: How does `ctx.secret_store.get()` resolve secrets in provisioners like Postgres/Redis? Options:
   - Kubernetes Secret lookup (simple, but secrets must pre-exist)
   - ESO ExternalSecret generation (deferred resolution at apply time)
   - Vault/AWS Secrets Manager direct lookup (requires backend config)

2. **`${secrets.*}` Namespace**: When implemented, how should manual secret mappings be configured?
   - Per-service in LatticeService spec?
   - Environment-level default mappings?
   - Cluster-level SecretStore references?

3. **Sensitive Output Propagation**: If a template combines sensitive and non-sensitive values (e.g., `"prefix-${resources.db.password}-suffix"`), the entire result is marked sensitive. Is this the right behavior?

4. **Cross-Namespace Service Dependencies**: Should ServiceProvisioner support referencing services in other namespaces? Current design assumes same namespace.
