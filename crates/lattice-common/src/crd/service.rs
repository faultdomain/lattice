//! LatticeService Custom Resource Definition
//!
//! The LatticeService CRD represents a long-running workload deployed by Lattice.
//! Services declare their dependencies and allowed callers for automatic
//! network policy generation.
//!
//! ## Score-Compatible Templating
//!
//! The following fields support `${...}` placeholder syntax per the Score spec:
//! - `containers.*.variables.*` - Environment variable values
//! - `containers.*.files.*.content` - Inline file content
//! - `containers.*.files.*.source` - File source path
//! - `containers.*.volumes.*.source` - Volume source reference
//!
//! Use `$${...}` to escape and produce literal `${...}` in output.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::Condition;
use super::workload::backup::ServiceBackupSpec;
use super::workload::deploy::DeploySpec;
use super::workload::ingress::IngressSpec;
use super::workload::scaling::AutoscalingSpec;
use super::workload::spec::{RuntimeSpec, WorkloadSpec};

// =============================================================================
// Service Phase
// =============================================================================

/// Service lifecycle phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ServicePhase {
    /// Service is waiting for configuration
    #[default]
    Pending,
    /// Service manifests are being compiled
    Compiling,
    /// Service is fully operational
    Ready,
    /// Service has encountered an error
    Failed,
}

impl std::fmt::Display for ServicePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Compiling => write!(f, "Compiling"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// LatticeService CRD
// =============================================================================

/// Specification for a LatticeService
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeService",
    plural = "latticeservices",
    shortname = "ls",
    namespaced,
    status = "LatticeServiceStatus",
    printcolumn = r#"{"name":"Strategy","type":"string","jsonPath":".spec.deploy.strategy"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceSpec {
    /// Score-compatible workload specification (containers, resources, ports)
    pub workload: WorkloadSpec,

    /// Number of pod replicas
    #[serde(default = "default_replicas")]
    pub replicas: u32,

    /// Optional KEDA autoscaling configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<AutoscalingSpec>,

    /// Lattice runtime extensions (sidecars, sysctls, hostNetwork, etc.)
    #[serde(default, flatten)]
    pub runtime: RuntimeSpec,

    /// Backup configuration (Velero hooks and volume policies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<ServiceBackupSpec>,

    /// Deployment strategy configuration
    #[serde(default)]
    pub deploy: DeploySpec,

    /// Ingress configuration for external access via Gateway API
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,
}

fn default_replicas() -> u32 {
    1
}

impl Default for LatticeServiceSpec {
    fn default() -> Self {
        Self {
            workload: WorkloadSpec::default(),
            replicas: default_replicas(),
            autoscaling: None,
            runtime: RuntimeSpec::default(),
            backup: None,
            deploy: DeploySpec::default(),
            ingress: None,
        }
    }
}

impl LatticeServiceSpec {
    /// Validate the service specification (workload + replicas + autoscaling)
    pub fn validate(&self) -> Result<(), crate::Error> {
        self.workload.validate()?;
        self.runtime.validate()?;

        // Validate autoscaling
        if let Some(ref autoscaling) = self.autoscaling {
            if self.replicas > autoscaling.max {
                return Err(crate::Error::validation(
                    "replicas cannot exceed autoscaling max",
                ));
            }
            autoscaling.validate()?;
        }

        Ok(())
    }
}

// =============================================================================
// LatticeService Status
// =============================================================================

/// Status for a LatticeService
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceStatus {
    /// Current phase of the service lifecycle
    #[serde(default)]
    pub phase: ServicePhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Conditions representing the service state
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Last time manifests were compiled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compiled_at: Option<DateTime<Utc>>,

    /// Observed generation for optimistic concurrency
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Resolved dependency URLs
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolved_dependencies: BTreeMap<String, String>,
}

impl LatticeServiceStatus {
    /// Create a new status with the given phase
    pub fn with_phase(phase: ServicePhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set the phase and return self for chaining
    pub fn phase(mut self, phase: ServicePhase) -> Self {
        self.phase = phase;
        self
    }

    /// Set the message and return self for chaining
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Add a condition and return self for chaining
    pub fn condition(mut self, condition: Condition) -> Self {
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
        self
    }

    /// Set the last compiled timestamp
    pub fn compiled_at(mut self, time: DateTime<Utc>) -> Self {
        self.last_compiled_at = Some(time);
        self
    }

    /// Set the observed generation for change detection
    pub fn observed_generation(mut self, gen: Option<i64>) -> Self {
        self.observed_generation = gen;
        self
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::ConditionStatus;
    use crate::crd::workload::backup::{HookErrorAction, VolumeBackupDefault};
    use crate::crd::workload::container::{ContainerSpec, FileMount};
    use crate::crd::workload::deploy::DeployStrategy;
    use crate::crd::workload::resources::{
        DependencyDirection, ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType,
        VolumeAccessMode,
    };
    use crate::template::TemplateString;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: Some(vec!["/usr/sbin/nginx".to_string()]),
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    memory: Some("256Mi".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // =========================================================================
    // Service Phase Tests
    // =========================================================================

    #[test]
    fn test_service_phase_display() {
        assert_eq!(ServicePhase::Pending.to_string(), "Pending");
        assert_eq!(ServicePhase::Compiling.to_string(), "Compiling");
        assert_eq!(ServicePhase::Ready.to_string(), "Ready");
        assert_eq!(ServicePhase::Failed.to_string(), "Failed");
    }

    // =========================================================================
    // Status Builder Stories
    // =========================================================================

    #[test]
    fn controller_builds_status_fluently() {
        let condition = Condition::new(
            "Ready",
            ConditionStatus::True,
            "ServiceReady",
            "All replicas are healthy",
        );

        let status = LatticeServiceStatus::default()
            .phase(ServicePhase::Ready)
            .message("Service is operational")
            .condition(condition)
            .compiled_at(Utc::now());

        assert_eq!(status.phase, ServicePhase::Ready);
        assert_eq!(status.message.as_deref(), Some("Service is operational"));
        assert_eq!(status.conditions.len(), 1);
        assert!(status.last_compiled_at.is_some());
    }

    // =========================================================================
    // YAML Serialization Stories
    // =========================================================================

    #[test]
    fn yaml_simple_service() {
        let yaml = r#"
workload:
  containers:
    main:
      image: nginx:latest
  service:
    ports:
      http:
        port: 80
replicas: 1
autoscaling:
  max: 3
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("simple service YAML should parse successfully");

        assert_eq!(spec.workload.containers.len(), 1);
        assert_eq!(spec.workload.containers["main"].image, "nginx:latest");
        assert_eq!(spec.replicas, 1);
        let autoscaling = spec.autoscaling.expect("autoscaling should be present");
        assert_eq!(autoscaling.max, 3);

        let ports = spec.workload.ports();
        assert_eq!(ports.get("http"), Some(&80));
    }

    #[test]
    fn yaml_service_with_dependencies() {
        let yaml = r#"
workload:
  containers:
    main:
      image: my-api:v1.0
      variables:
        LOG_LEVEL: info
  resources:
    curl-tester:
      type: service
      direction: inbound
    google:
      type: external-service
      direction: outbound
    cache:
      type: service
      direction: both
  service:
    ports:
      http:
        port: 8080
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("service with dependencies YAML should parse successfully");

        let deps = spec.workload.dependencies("test");
        assert!(deps.iter().any(|r| r.name == "google"));
        assert!(deps.iter().any(|r| r.name == "cache"));

        let callers = spec.workload.allowed_callers("test");
        assert!(callers.iter().any(|r| r.name == "curl-tester"));
        assert!(callers.iter().any(|r| r.name == "cache"));

        assert_eq!(
            spec.workload.containers["main"]
                .variables
                .get("LOG_LEVEL")
                .map(|v| v.as_str()),
            Some("info")
        );
    }

    #[test]
    fn yaml_canary_deployment() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:v2.0
deploy:
  strategy: canary
  canary:
    interval: "1m"
    threshold: 5
    maxWeight: 50
    stepWeight: 10
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("canary deployment YAML should parse successfully");

        assert_eq!(spec.deploy.strategy, DeployStrategy::Canary);
        let canary = spec.deploy.canary.expect("canary config should be present");
        assert_eq!(canary.interval, Some("1m".to_string()));
        assert_eq!(canary.threshold, Some(5));
        assert_eq!(canary.max_weight, Some(50));
        assert_eq!(canary.step_weight, Some(10));
    }

    #[test]
    fn spec_survives_yaml_roundtrip() {
        let spec = sample_service_spec();
        let yaml =
            serde_json::to_string(&spec).expect("LatticeServiceSpec serialization should succeed");
        let value = crate::yaml::parse_yaml(&yaml).expect("parse yaml");
        let parsed: LatticeServiceSpec = serde_json::from_value(value)
            .expect("LatticeServiceSpec deserialization should succeed");
        assert_eq!(spec, parsed);
    }

    // =========================================================================
    // Template String Tests
    // =========================================================================

    #[test]
    fn test_variables_support_templates() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      variables:
        DB_HOST: "${resources.postgres.host}"
        DB_PORT: "${resources.postgres.port}"
        STATIC: "plain-value"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("template variables YAML should parse successfully");
        let vars = &spec.workload.containers["main"].variables;

        assert!(vars["DB_HOST"].has_placeholders());
        assert!(vars["DB_PORT"].has_placeholders());
        assert!(!vars["STATIC"].has_placeholders());
    }

    #[test]
    fn test_file_content_supports_templates() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      files:
        /etc/config.yaml:
          content: |
            database:
              host: ${resources.db.host}
              port: ${resources.db.port}
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("file content YAML should parse successfully");
        let file = &spec.workload.containers["main"].files["/etc/config.yaml"];

        assert!(file
            .content
            .as_ref()
            .expect("file content should be present")
            .has_placeholders());
    }

    #[test]
    fn test_volume_source_supports_templates() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      volumes:
        /data:
          source: "${resources.volume.name}"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("volume source YAML should parse successfully");
        let volume = &spec.workload.containers["main"].volumes["/data"];

        assert!(volume.source.as_ref().unwrap().has_placeholders());
    }

    #[test]
    fn test_volume_mount_sourceless_parses() {
        let yaml = r#"
workload:
  containers:
    main:
      image: nginx:latest
      volumes:
        /tmp: {}
        /var/cache/nginx: {}
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("sourceless volume YAML should parse");

        let tmp = &spec.workload.containers["main"].volumes["/tmp"];
        assert!(tmp.source.is_none());
        assert!(tmp.medium.is_none());
        assert!(tmp.size_limit.is_none());

        let cache = &spec.workload.containers["main"].volumes["/var/cache/nginx"];
        assert!(cache.source.is_none());
    }

    #[test]
    fn test_volume_mount_with_medium_and_size_limit_parses() {
        let yaml = r#"
workload:
  containers:
    main:
      image: nginx:latest
      volumes:
        /dev/shm:
          medium: Memory
        /scratch:
          sizeLimit: 5Gi
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("emptyDir with medium/sizeLimit should parse");

        let shm = &spec.workload.containers["main"].volumes["/dev/shm"];
        assert!(shm.source.is_none());
        assert_eq!(shm.medium, Some("Memory".to_string()));

        let scratch = &spec.workload.containers["main"].volumes["/scratch"];
        assert!(scratch.source.is_none());
        assert_eq!(scratch.size_limit, Some("5Gi".to_string()));
    }

    // =========================================================================
    // Probe Tests
    // =========================================================================

    #[test]
    fn test_probe_with_timing_parameters() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("probe YAML should parse successfully");
        let probe = spec.workload.containers["main"]
            .liveness_probe
            .as_ref()
            .expect("liveness probe should be present");

        let http = probe
            .http_get
            .as_ref()
            .expect("HTTP probe should be configured");
        assert_eq!(http.path, "/healthz");
        assert_eq!(http.port, 8080);
    }

    #[test]
    fn test_http_probe_full() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
          scheme: HTTPS
          host: localhost
          httpHeaders:
            - name: X-Custom-Header
              value: test-value
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("probe YAML should parse successfully");
        let probe = spec.workload.containers["main"]
            .readiness_probe
            .as_ref()
            .expect("readiness probe should be present");

        let http = probe
            .http_get
            .as_ref()
            .expect("HTTP probe should be configured");
        assert_eq!(http.path, "/ready");
        assert_eq!(http.port, 8080);
        assert_eq!(http.scheme, Some("HTTPS".to_string()));
        assert_eq!(http.host, Some("localhost".to_string()));
        assert!(http.http_headers.is_some());
    }

    #[test]
    fn test_exec_probe() {
        let yaml = r#"
workload:
  containers:
    main:
      image: app:latest
      livenessProbe:
        exec:
          command:
            - cat
            - /tmp/healthy
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("exec probe YAML should parse successfully");
        let probe = spec.workload.containers["main"]
            .liveness_probe
            .as_ref()
            .expect("liveness probe should be present");

        let exec = probe
            .exec
            .as_ref()
            .expect("exec probe should be configured");
        assert_eq!(exec.command, vec!["cat", "/tmp/healthy"]);
    }

    #[test]
    fn test_image_dot_placeholder_yaml() {
        let yaml = r#"
workload:
  containers:
    main:
      image: "."
      resources:
        limits:
          memory: 256Mi
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("image dot placeholder YAML should parse successfully");
        assert_eq!(spec.workload.containers["main"].image, ".");
        assert!(spec.workload.validate().is_ok());
    }

    // =========================================================================
    // Score Compatibility Tests
    // =========================================================================

    #[test]
    fn test_score_compatible_volume_params() {
        let yaml = r#"
workload:
  containers:
    main:
      image: jellyfin/jellyfin:latest
  resources:
    config:
      type: volume
      params:
        size: 10Gi
        storageClass: local-path
    media:
      type: volume
      id: media-library
      params:
        size: 1Ti
        storageClass: local-path
        accessMode: ReadWriteOnce
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Score-compatible YAML should parse");

        let config = spec
            .workload
            .resources
            .get("config")
            .expect("config should exist");
        assert!(config.is_volume_owner());
        let config_params = config
            .volume_params()
            .expect("config volume params")
            .expect("should have params");
        assert_eq!(config_params.size, Some("10Gi".to_string()));
        assert_eq!(config_params.storage_class, Some("local-path".to_string()));

        let media = spec
            .workload
            .resources
            .get("media")
            .expect("media should exist");
        assert!(media.is_volume_owner());
        assert_eq!(media.id, Some("media-library".to_string()));
        let media_params = media
            .volume_params()
            .expect("media volume params")
            .expect("should have params");
        assert_eq!(media_params.size, Some("1Ti".to_string()));
        assert_eq!(
            media_params.access_mode,
            Some(VolumeAccessMode::ReadWriteOnce)
        );
    }

    #[test]
    fn test_score_compatible_volume_reference() {
        let yaml = r#"
workload:
  containers:
    main:
      image: sonarr:latest
  resources:
    media:
      type: volume
      id: media-library
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Volume reference YAML should parse");

        let media = spec
            .workload
            .resources
            .get("media")
            .expect("media should exist");
        assert!(!media.is_volume_owner());
        assert!(media.is_volume_reference());
        assert_eq!(media.id, Some("media-library".to_string()));
    }

    #[test]
    fn test_lattice_bilateral_agreement_directions() {
        let yaml = r#"
workload:
  containers:
    main:
      image: jellyfin/jellyfin:latest
  resources:
    sonarr:
      type: service
      direction: inbound
    nzbget:
      type: service
      direction: outbound
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Bilateral agreement YAML should parse");

        let sonarr = spec
            .workload
            .resources
            .get("sonarr")
            .expect("sonarr should exist");
        assert_eq!(sonarr.direction, DependencyDirection::Inbound);

        let nzbget = spec
            .workload
            .resources
            .get("nzbget")
            .expect("nzbget should exist");
        assert_eq!(nzbget.direction, DependencyDirection::Outbound);
    }

    #[test]
    fn test_custom_type_in_yaml_spec() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
  resources:
    my-postgres:
      type: postgres
      params:
        size: 10Gi
        version: "15"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Custom resource type in YAML should parse");

        let resource = spec
            .workload
            .resources
            .get("my-postgres")
            .expect("my-postgres should exist");
        assert!(matches!(resource.type_, ResourceType::Custom(ref s) if s == "postgres"));
    }

    // =========================================================================
    // GPU Validation Tests
    // =========================================================================

    #[test]
    fn gpu_resource_validation_in_service_spec() {
        let yaml = r#"
workload:
  containers:
    main:
      image: vllm/vllm-openai:latest
  resources:
    my-gpu:
      type: gpu
      params:
        count: 0
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("gpu resource should parse");

        assert!(spec.workload.validate().is_err());
    }

    // =========================================================================
    // Full Integration Tests
    // =========================================================================

    #[test]
    fn test_media_server_style_spec() {
        let yaml = r#"
workload:
  containers:
    main:
      image: jellyfin/jellyfin:latest
      variables:
        JELLYFIN_PublishedServerUrl: "http://jellyfin.media.svc.cluster.local:8096"
      volumes:
        /config:
          source: ${resources.config}
        /media:
          source: ${resources.media}
      resources:
        requests:
          cpu: 500m
          memory: 1Gi
        limits:
          cpu: 4000m
          memory: 8Gi
      readinessProbe:
        httpGet:
          path: /health
          port: 8096
        initialDelaySeconds: 30
  service:
    ports:
      http:
        port: 8096
        protocol: TCP
  resources:
    config:
      type: volume
      params:
        size: 10Gi
        storageClass: local-path
    media:
      type: volume
      id: media-library
      params:
        size: 1Ti
        storageClass: local-path
        accessMode: ReadWriteOnce
    sonarr:
      type: service
      direction: inbound
replicas: 1
ingress:
  routes:
    public:
      hosts:
        - jellyfin.home.local
      tls:
        issuerRef:
          name: letsencrypt-prod
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Media server YAML should parse");

        assert_eq!(spec.workload.containers.len(), 1);
        let main = spec
            .workload
            .containers
            .get("main")
            .expect("main container");
        assert_eq!(main.image, "jellyfin/jellyfin:latest");
        assert!(!main.volumes.is_empty());

        assert_eq!(spec.workload.resources.len(), 3);
        assert!(spec
            .workload
            .resources
            .get("config")
            .expect("config")
            .is_volume_owner());
        assert!(spec
            .workload
            .resources
            .get("media")
            .expect("media")
            .is_volume_owner());

        let service = spec
            .workload
            .service
            .as_ref()
            .expect("service should exist");
        assert!(service.ports.contains_key("http"));

        let ingress = spec.ingress.as_ref().expect("ingress should exist");
        let public_route = ingress
            .routes
            .get("public")
            .expect("public route should exist");
        assert_eq!(public_route.hosts, vec!["jellyfin.home.local"]);

        spec.workload.validate().expect("spec should be valid");
    }

    // =========================================================================
    // Security Context Tests
    // =========================================================================

    #[test]
    fn security_context_parses() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
      security:
        capabilities: [NET_ADMIN, SYS_MODULE]
        dropCapabilities: [ALL]
        privileged: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        allowPrivilegeEscalation: false
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Security context YAML should parse");

        let security = spec.workload.containers["main"]
            .security
            .as_ref()
            .expect("security should be present");
        assert_eq!(security.capabilities, vec!["NET_ADMIN", "SYS_MODULE"]);
        assert_eq!(security.drop_capabilities, Some(vec!["ALL".to_string()]));
        assert_eq!(security.privileged, Some(false));
        assert_eq!(security.read_only_root_filesystem, Some(true));
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(security.run_as_user, Some(1000));
        assert_eq!(security.run_as_group, Some(1000));
        assert_eq!(security.allow_privilege_escalation, Some(false));
    }

    #[test]
    fn security_context_minimal() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
      security:
        capabilities: [NET_BIND_SERVICE]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Minimal security context should parse");

        let security = spec.workload.containers["main"]
            .security
            .as_ref()
            .expect("security should be present");
        assert_eq!(security.capabilities, vec!["NET_BIND_SERVICE"]);
        assert!(security.drop_capabilities.is_none());
        assert!(security.privileged.is_none());
    }

    // =========================================================================
    // Sidecar Tests
    // =========================================================================

    #[test]
    fn sidecars_parse_with_init_flag() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
sidecars:
  setup:
    image: busybox:latest
    init: true
    command: ["sh", "-c"]
    args: ["chown -R 1000:1000 /data"]
    security:
      runAsUser: 0
  vpn:
    image: wireguard:latest
    init: false
    security:
      capabilities: [NET_ADMIN]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Sidecar YAML should parse");

        assert_eq!(spec.runtime.sidecars.len(), 2);

        let setup = spec
            .runtime
            .sidecars
            .get("setup")
            .expect("setup should exist");
        assert_eq!(setup.image, "busybox:latest");
        assert_eq!(setup.init, Some(true));
        assert_eq!(
            setup.security.as_ref().map(|s| s.run_as_user),
            Some(Some(0))
        );

        let vpn = spec.runtime.sidecars.get("vpn").expect("vpn should exist");
        assert_eq!(vpn.image, "wireguard:latest");
        assert_eq!(vpn.init, Some(false));
        assert_eq!(
            vpn.security.as_ref().map(|s| s.capabilities.clone()),
            Some(vec!["NET_ADMIN".to_string()])
        );
    }

    #[test]
    fn sidecar_full_spec() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
sidecars:
  logging:
    image: fluent-bit:latest
    command: ["/fluent-bit/bin/fluent-bit"]
    args: ["-c", "/config/fluent-bit.conf"]
    variables:
      LOG_LEVEL: info
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
    readinessProbe:
      httpGet:
        path: /health
        port: 2020
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Full sidecar spec should parse");

        let logging = spec
            .runtime
            .sidecars
            .get("logging")
            .expect("logging should exist");
        assert_eq!(logging.image, "fluent-bit:latest");
        assert!(logging.command.is_some());
        assert!(logging.args.is_some());
        assert!(!logging.variables.is_empty());
        assert!(logging.resources.is_some());
        assert!(logging.readiness_probe.is_some());
    }

    // =========================================================================
    // Pod-Level Settings Tests
    // =========================================================================

    #[test]
    fn runtime_settings_parse() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
sysctls:
  net.ipv4.conf.all.src_valid_mark: "1"
  net.core.somaxconn: "65535"
hostNetwork: true
shareProcessNamespace: true
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Runtime settings should parse");

        assert_eq!(spec.runtime.sysctls.len(), 2);
        assert_eq!(
            spec.runtime.sysctls.get("net.ipv4.conf.all.src_valid_mark"),
            Some(&"1".to_string())
        );
        assert_eq!(
            spec.runtime.sysctls.get("net.core.somaxconn"),
            Some(&"65535".to_string())
        );
        assert_eq!(spec.runtime.host_network, Some(true));
        assert_eq!(spec.runtime.share_process_namespace, Some(true));
    }

    #[test]
    fn vpn_killswitch_example() {
        let yaml = r#"
workload:
  containers:
    main:
      image: linuxserver/nzbget:latest
      variables:
        PUID: "1000"
  service:
    ports:
      http:
        port: 6789
sysctls:
  net.ipv4.conf.all.src_valid_mark: "1"
sidecars:
  vpn:
    image: linuxserver/wireguard:latest
    security:
      capabilities: [NET_ADMIN, SYS_MODULE]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("VPN killswitch example should parse");

        assert!(spec.workload.containers.contains_key("main"));
        assert!(spec
            .runtime
            .sysctls
            .contains_key("net.ipv4.conf.all.src_valid_mark"));

        let vpn = spec
            .runtime
            .sidecars
            .get("vpn")
            .expect("vpn sidecar should exist");
        let caps = &vpn
            .security
            .as_ref()
            .expect("security should be set")
            .capabilities;
        assert!(caps.contains(&"NET_ADMIN".to_string()));
        assert!(caps.contains(&"SYS_MODULE".to_string()));
    }

    #[test]
    fn empty_sidecars_and_sysctls() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Spec without sidecars should parse");

        assert!(spec.runtime.sidecars.is_empty());
        assert!(spec.runtime.sysctls.is_empty());
        assert!(spec.runtime.host_network.is_none());
        assert!(spec.runtime.share_process_namespace.is_none());
    }

    // =========================================================================
    // Backup Configuration Tests
    // =========================================================================

    #[test]
    fn test_service_backup_spec_roundtrip() {
        let yaml = r#"
workload:
  containers:
    main:
      image: postgres:16
backup:
  hooks:
    pre:
      - name: freeze-db
        container: main
        command: ["/bin/sh", "-c", "pg_dump -U postgres mydb -Fc -f /backup/dump.sql"]
        timeout: "600s"
        onError: Fail
    post:
      - name: cleanup
        container: main
        command: ["/bin/sh", "-c", "rm -f /backup/dump.sql"]
  volumes:
    include: [data, wal]
    exclude: [tmp]
    defaultPolicy: opt-in
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("should parse spec with backup");
        let backup = spec.backup.expect("should have backup spec");

        let hooks = backup.hooks.expect("should have hooks");
        assert_eq!(hooks.pre.len(), 1);
        assert_eq!(hooks.pre[0].name, "freeze-db");
        assert_eq!(hooks.pre[0].container, "main");
        assert_eq!(hooks.pre[0].timeout, Some("600s".to_string()));
        assert!(matches!(hooks.pre[0].on_error, HookErrorAction::Fail));

        assert_eq!(hooks.post.len(), 1);
        assert_eq!(hooks.post[0].name, "cleanup");

        let volumes = backup.volumes.expect("should have volume spec");
        assert_eq!(volumes.include, vec!["data", "wal"]);
        assert_eq!(volumes.exclude, vec!["tmp"]);
        assert!(matches!(volumes.default_policy, VolumeBackupDefault::OptIn));
    }

    #[test]
    fn test_service_backup_defaults() {
        let yaml = r#"
workload:
  containers:
    main:
      image: nginx:latest
backup:
  hooks:
    pre:
      - name: sync
        container: main
        command: ["/bin/sh", "-c", "sync"]
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("should parse spec");
        let backup = spec.backup.expect("should have backup");
        let hooks = backup.hooks.expect("should have hooks");

        assert!(matches!(hooks.pre[0].on_error, HookErrorAction::Continue));
        assert!(hooks.pre[0].timeout.is_none());
        assert!(hooks.post.is_empty());
        assert!(backup.volumes.is_none());
    }

    #[test]
    fn test_service_without_backup() {
        let yaml = r#"
workload:
  containers:
    main:
      image: nginx:latest
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("should parse spec");
        assert!(spec.backup.is_none());
    }

    // =========================================================================
    // GPU Resource Tests
    // =========================================================================

    #[test]
    fn gpu_resource_yaml_roundtrip() {
        let yaml = r#"
workload:
  containers:
    main:
      image: vllm/vllm:latest
  resources:
    my-gpu:
      type: gpu
      params:
        count: 1
        memory: 8Gi
        compute: 20
        model: L4
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("GPU resource YAML should parse");

        let gpu_resource = spec
            .workload
            .resources
            .get("my-gpu")
            .expect("should have gpu resource");
        assert!(gpu_resource.type_.is_gpu());
        let gpu = gpu_resource
            .gpu_params()
            .expect("parse gpu params")
            .expect("should have params");
        assert_eq!(gpu.count, 1);
        assert_eq!(gpu.memory, Some("8Gi".to_string()));
        assert_eq!(gpu.compute, Some(20));
        assert_eq!(gpu.model, Some("L4".to_string()));
    }

    #[test]
    fn gpu_resource_tolerations_default_none() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
  resources:
    my-gpu:
      type: gpu
      params:
        count: 2
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("parse");
        let gpu = spec.workload.resources["my-gpu"]
            .gpu_params()
            .expect("parse")
            .expect("params");
        assert_eq!(gpu.count, 2);
        assert!(gpu.tolerations.is_none());
    }

    #[test]
    fn gpu_resource_tolerations_explicit_false() {
        let yaml = r#"
workload:
  containers:
    main:
      image: myapp:latest
  resources:
    my-gpu:
      type: gpu
      params:
        count: 1
        tolerations: false
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("parse");
        let gpu = spec.workload.resources["my-gpu"]
            .gpu_params()
            .expect("parse")
            .expect("params");
        assert_eq!(gpu.tolerations, Some(false));
    }

    // =========================================================================
    // Secret Resource Tests
    // =========================================================================

    fn secret_resource(remote_key: &str, provider: &str, keys: Option<&[&str]>) -> ResourceSpec {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!(provider));
        params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
        if let Some(keys) = keys {
            params.insert("keys".to_string(), serde_json::json!(keys));
        }
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some(remote_key.to_string()),
            params: Some(params),
            ..Default::default()
        }
    }

    #[test]
    fn secret_resource_with_explicit_keys() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "db-creds".to_string(),
            secret_resource("path/to/db", "local-test", Some(&["user", "pass"])),
        );

        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: {
                    let mut c = BTreeMap::new();
                    c.insert("main".to_string(), simple_container());
                    c
                },
                resources,
                ..Default::default()
            },
            ..Default::default()
        };

        let db = spec
            .workload
            .resources
            .get("db-creds")
            .expect("db-creds resource");
        assert!(matches!(db.type_, ResourceType::Secret));
        assert_eq!(db.id, Some("path/to/db".to_string()));

        let params = db.params.as_ref().expect("params");
        assert_eq!(params["provider"], serde_json::json!("local-test"));
        assert_eq!(params["keys"], serde_json::json!(["user", "pass"]));
    }

    #[test]
    fn secret_resource_without_keys_omits_keys_param() {
        let res = secret_resource("path/to/all", "local-test", None);
        let params = res.params.as_ref().expect("params");

        assert!(params.get("provider").is_some());
        assert!(params.get("keys").is_none());
    }

    #[test]
    fn service_with_image_pull_secrets() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "ghcr-creds".to_string(),
            secret_resource("local-regcreds", "local-test", None),
        );

        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: {
                    let mut c = BTreeMap::new();
                    c.insert("main".to_string(), simple_container());
                    c
                },
                resources,
                ..Default::default()
            },
            runtime: RuntimeSpec {
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(spec.runtime.image_pull_secrets, vec!["ghcr-creds"]);
        assert!(spec.workload.resources.contains_key("ghcr-creds"));
    }

    #[test]
    fn service_with_secret_env_vars_and_file_mount() {
        let mut variables = BTreeMap::new();
        variables.insert(
            "DB_PASSWORD".to_string(),
            TemplateString::new("${secret.db-creds.password}"),
        );
        variables.insert(
            "DATABASE_URL".to_string(),
            TemplateString::new(
                "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db:5432/mydb",
            ),
        );

        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            FileMount {
                content: Some(TemplateString::new("password: ${secret.db-creds.password}")),
                ..Default::default()
            },
        );

        let container = ContainerSpec {
            image: "busybox:latest".to_string(),
            variables,
            files,
            ..Default::default()
        };

        let mut resources = BTreeMap::new();
        resources.insert(
            "db-creds".to_string(),
            secret_resource(
                "local-db-creds",
                "local-test",
                Some(&["username", "password"]),
            ),
        );

        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: {
                    let mut c = BTreeMap::new();
                    c.insert("main".to_string(), container);
                    c
                },
                resources,
                ..Default::default()
            },
            ..Default::default()
        };

        let main = spec
            .workload
            .containers
            .get("main")
            .expect("main container");
        assert!(main.variables.contains_key("DB_PASSWORD"));
        assert!(main.variables.contains_key("DATABASE_URL"));
        assert!(main.files.contains_key("/etc/app/config.yaml"));
        assert!(spec.workload.resources.contains_key("db-creds"));
    }

    #[test]
    fn sidecar_name_with_underscores_fails() {
        use crate::crd::workload::container::SidecarSpec;

        let mut spec = sample_service_spec();
        spec.runtime.sidecars.insert(
            "my_sidecar".to_string(),
            SidecarSpec {
                image: "fluentbit:latest".to_string(),
                ..Default::default()
            },
        );
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("sidecar name"));
    }
}
