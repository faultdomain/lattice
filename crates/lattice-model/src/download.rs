//! Model download compilation — LatticeJob and pod template injection
//!
//! Pure compilation functions that take a `ModelSourceSpec` and produce:
//! - A LatticeJob CRD that downloads the model through the Lattice compilation pipeline
//! - A ServiceAccount for SPIFFE identity
//! - Volume + volumeMount injection for role pod templates
//! - Scheduling gate injection so pods stay `SchedulingGated` until download completes
//!
//! The download job declares the model cache volume as an **owner** (with size). The job
//! compiler forwards the LatticeJob's ownerReferences (pointing to LatticeModel) to
//! VolumeCompiler, which creates the PVC with proper GC cascading. Serving pods reference
//! the same volume id without size, getting pod affinity for co-location.
//!
//! The LatticeJob goes through the normal compilation pipeline (WorkloadCompiler → mesh
//! member → VCJob). Entity-based egress (`entity:world:443`) is declared as an
//! `external-service` resource, which WorkloadCompiler compiles into a LatticeMeshMember
//! with HTTPS egress. The token secret (when configured) uses the `lattice-local` ESO
//! provider and `env_from` to inject credentials.
//!
//! Uses a single `lattice-downloader` image with all tools pre-installed:
//! - `hf://` → `hf download`
//! - `s3://` → `aws s3 sync`
//! - `gs://` → `gsutil -m rsync -r`

use std::collections::BTreeMap;

use lattice_common::crd::workload::container::VolumeMount;
use lattice_common::crd::{
    ContainerSpec, DependencyDirection, JobTaskSpec, LatticeJob, LatticeJobSpec, ModelSourceSpec,
    ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType, RestartPolicy, RuntimeSpec,
    WorkloadSpec,
};
use lattice_common::kube_utils::OwnerReference;
use lattice_common::template::TemplateString;

use crate::error::ModelError;

/// Scheduling gate name applied to model-serving pods while download is in progress.
/// The controller removes this gate after the download Job succeeds.
pub const SCHEDULING_GATE_MODEL_DOWNLOAD: &str = "lattice.dev/model-download";

/// Maximum Job retry count before the controller treats a download as failed.
/// Used by both the LatticeJob `max_retry` and the controller status check.
pub const DOWNLOAD_BACKOFF_LIMIT: u32 = 3;

const DEFAULT_MOUNT_PATH: &str = "/models";
const VOLUME_NAME: &str = "model-cache";
const DEFAULT_DOWNLOADER_IMAGE: &str = "ghcr.io/evan-hines-js/lattice-downloader:latest";

/// Compiled download resources for a LatticeModel
#[derive(Debug)]
pub struct CompiledDownload {
    /// LatticeJob CRD for the download workload (compiled through the Lattice pipeline)
    pub job: LatticeJob,
    /// ServiceAccount for download pod SPIFFE identity
    pub service_account: serde_json::Value,
    /// PVC name for model artifact cache (VolumeCompiler creates the PVC)
    pvc_name: String,
    /// Mount path for model artifacts in serving containers
    mount_path: String,
}

impl CompiledDownload {
    /// Job name derived from the LatticeJob metadata
    pub fn job_name(&self) -> &str {
        self.job.metadata.name.as_deref().unwrap_or_default()
    }

    /// PVC name for model artifact cache
    pub fn pvc_name(&self) -> &str {
        &self.pvc_name
    }

    /// Mount path for model artifacts in serving containers
    pub fn mount_path(&self) -> &str {
        &self.mount_path
    }
}

/// URI scheme parsed from a model source URI
#[derive(Debug, Clone, PartialEq)]
enum UriScheme {
    HuggingFace,
    S3,
    Gcs,
}

/// Parsed model URI
#[derive(Debug)]
struct ParsedUri {
    scheme: UriScheme,
    /// The path portion after the scheme (e.g. "Qwen/Qwen3-8B" for hf://)
    path: String,
}

fn parse_uri(uri: &str) -> Result<ParsedUri, ModelError> {
    let (scheme, path) = if let Some(p) = uri.strip_prefix("hf://") {
        (UriScheme::HuggingFace, p)
    } else if let Some(p) = uri.strip_prefix("s3://") {
        (UriScheme::S3, p)
    } else if let Some(p) = uri.strip_prefix("gs://") {
        (UriScheme::Gcs, p)
    } else {
        return Err(ModelError::InvalidModelUri(format!(
            "unsupported URI scheme (expected hf://, s3://, or gs://): {uri}"
        )));
    };

    if path.is_empty() {
        return Err(ModelError::InvalidModelUri(format!(
            "empty path in URI: {uri}"
        )));
    }

    Ok(ParsedUri {
        scheme,
        path: path.to_string(),
    })
}

/// Compile model download resources from a ModelSourceSpec.
///
/// Produces a LatticeJob and ServiceAccount ready for apply. The LatticeJob
/// declares the model cache volume as an owner (with size), so the job
/// compiler's VolumeCompiler creates the PVC with proper ownerReferences.
/// This is a pure compilation function — no K8s API calls.
pub fn compile_download(
    model_name: &str,
    namespace: &str,
    uid: &str,
    source: &ModelSourceSpec,
) -> Result<CompiledDownload, ModelError> {
    let parsed = parse_uri(&source.uri)?;
    let mount_path = source
        .mount_path
        .as_deref()
        .unwrap_or(DEFAULT_MOUNT_PATH)
        .to_string();
    let job_name = format!("{}-download", model_name);
    // Volume id for cross-workload PVC sharing. VolumeCompiler generates
    // PVC name as vol-{id}, so serving pods reference the same PVC.
    let volume_id = format!("{}-model-cache", model_name);
    let pvc_name = format!("vol-{}", volume_id);

    let owner_ref = OwnerReference {
        api_version: "lattice.dev/v1alpha1".to_string(),
        kind: "LatticeModel".to_string(),
        name: model_name.to_string(),
        uid: uid.to_string(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    };

    let job = compile_lattice_job(
        &job_name,
        namespace,
        &owner_ref,
        &volume_id,
        &mount_path,
        &parsed,
        source,
    );

    let service_account = compile_service_account(&job_name, namespace, &owner_ref)?;

    Ok(CompiledDownload {
        job,
        service_account,
        pvc_name,
        mount_path,
    })
}

fn compile_lattice_job(
    name: &str,
    namespace: &str,
    owner_ref: &OwnerReference,
    volume_id: &str,
    mount_path: &str,
    parsed: &ParsedUri,
    source: &ModelSourceSpec,
) -> LatticeJob {
    let (image, command) = download_command(parsed, mount_path, source.downloader_image.as_deref());

    let mut resources = BTreeMap::new();

    // Volume owner — VolumeCompiler creates the PVC with ownerReferences
    // forwarded from the LatticeJob (which point to LatticeModel for GC).
    // The volume id enables cross-workload sharing: serving pods declare
    // the same id as a reference and get pod affinity for co-location.
    let mut volume_params: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    volume_params.insert("size".to_string(), serde_json::json!(source.cache_size));
    if let Some(ref sc) = source.storage_class {
        volume_params.insert("storageClass".to_string(), serde_json::json!(sc));
    }
    if let Some(ref am) = source.access_mode {
        volume_params.insert("accessMode".to_string(), serde_json::json!(am));
    }
    resources.insert(
        VOLUME_NAME.to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            id: Some(volume_id.to_string()),
            params: Some(volume_params),
            ..Default::default()
        },
    );

    // Entity-based HTTPS egress — WorkloadCompiler parses entity: prefix and
    // generates a LatticeMeshMember with EgressTarget::Entity.
    resources.insert(
        "internet".to_string(),
        ResourceSpec {
            type_: ResourceType::ExternalService,
            id: Some("entity:world:443".to_string()),
            direction: DependencyDirection::Outbound,
            ..Default::default()
        },
    );

    // Token secret via lattice-local ESO provider (if configured)
    let mut env_from = Vec::new();
    if let Some(ref token_secret) = source.token_secret {
        let mut secret_params: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        secret_params.insert("provider".to_string(), serde_json::json!("lattice-local"));

        resources.insert(
            "token".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(token_secret.name.clone()),
                params: Some(secret_params),
                ..Default::default()
            },
        );
        env_from.push("token".to_string());
    }

    // Container with volume mounts and download command
    let mut volumes = BTreeMap::new();
    volumes.insert(
        mount_path.to_string(),
        VolumeMount {
            source: Some(TemplateString::from(format!(
                "${{resources.{}}}",
                VOLUME_NAME
            ))),
            ..Default::default()
        },
    );
    // Writable /tmp for tool caches (root filesystem is read-only, HOME=/tmp is baked into the image)
    volumes.insert("/tmp".to_string(), VolumeMount::default());

    let mut containers = BTreeMap::new();
    containers.insert(
        "download".to_string(),
        ContainerSpec {
            image: image.clone(),
            command: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                command.clone(),
            ]),
            volumes,
            env_from,
            security: source.security.clone(),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("100m".to_string()),
                    memory: Some("256Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("1".to_string()),
                    memory: Some("1Gi".to_string()),
                }),
            }),
            ..Default::default()
        },
    );

    // Merge any user-provided resources (e.g. ghcr-creds for imagePullSecrets)
    for (key, spec) in &source.resources {
        resources.entry(key.clone()).or_insert_with(|| spec.clone());
    }

    let workload = WorkloadSpec {
        containers,
        resources,
        ..Default::default()
    };

    let runtime = RuntimeSpec {
        image_pull_secrets: source.image_pull_secrets.clone(),
        ..Default::default()
    };

    let mut tasks = BTreeMap::new();
    tasks.insert(
        "download".to_string(),
        JobTaskSpec {
            replicas: Some(1),
            workload,
            runtime,
            restart_policy: Some(RestartPolicy::Never),
            policies: None,
        },
    );

    let spec = LatticeJobSpec {
        max_retry: Some(DOWNLOAD_BACKOFF_LIMIT),
        tasks,
        ..Default::default()
    };

    let mut job = LatticeJob::new(name, spec);
    job.metadata.namespace = Some(namespace.to_string());
    job.metadata.owner_references = Some(vec![owner_ref.into()]);
    job
}

/// Compile a ServiceAccount for download pod SPIFFE identity.
fn compile_service_account(
    name: &str,
    namespace: &str,
    owner_ref: &OwnerReference,
) -> Result<serde_json::Value, ModelError> {
    let mut sa = lattice_common::kube_utils::compile_service_account(name, namespace);
    sa["metadata"]["ownerReferences"] =
        serde_json::to_value([owner_ref]).map_err(ModelError::Serialization)?;
    Ok(sa)
}

/// Returns (image, shell_command) for the download container
fn download_command(
    parsed: &ParsedUri,
    mount_path: &str,
    custom_image: Option<&str>,
) -> (String, String) {
    let image = custom_image.unwrap_or(DEFAULT_DOWNLOADER_IMAGE).to_string();

    // Derive local dir name from the last path segment (e.g. "Qwen/Qwen3-8B" → "Qwen3-8B")
    let local_name = parsed.path.rsplit('/').next().unwrap_or(&parsed.path);
    let dest = format!("{}/{}", mount_path, local_name);

    let cmd = match parsed.scheme {
        UriScheme::HuggingFace => format!("hf download {} --local-dir {dest}", parsed.path),
        UriScheme::S3 => format!("aws s3 sync s3://{} {dest}", parsed.path),
        UriScheme::Gcs => format!("gsutil -m rsync -r gs://{} {dest}", parsed.path),
    };

    (image, cmd)
}

/// Push a value onto a JSON array field, creating the array if absent.
///
/// Uses `get_mut` internally so it never inserts null keys — mutable indexing
/// on `serde_json::Value` silently inserts `Null` for missing keys, which
/// Kubernetes rejects on array-typed fields.
fn json_array_push(object: &mut serde_json::Value, key: &str, value: serde_json::Value) {
    if let Some(obj) = object.as_object_mut() {
        match obj.get_mut(key).and_then(|v| v.as_array_mut()) {
            Some(arr) => arr.push(value),
            None => {
                obj.insert(key.to_string(), serde_json::json!([value]));
            }
        }
    }
}

/// Inject model cache volume + volumeMounts into a JSON pod template.
///
/// Adds a PVC-backed volume to `spec.volumes` and a read-only volumeMount
/// to every container in `spec.containers` and `spec.initContainers`.
pub fn inject_model_volume(pod_template: &mut serde_json::Value, pvc_name: &str, mount_path: &str) {
    let volume = serde_json::json!({
        "name": VOLUME_NAME,
        "persistentVolumeClaim": {
            "claimName": pvc_name,
            "readOnly": true
        }
    });
    let mount = serde_json::json!({
        "name": VOLUME_NAME,
        "mountPath": mount_path,
        "readOnly": true
    });

    let spec = &mut pod_template["spec"];
    json_array_push(spec, "volumes", volume);

    for key in &["containers", "initContainers"] {
        if let Some(containers) = spec.get_mut(*key).and_then(|v| v.as_array_mut()) {
            for container in containers {
                json_array_push(container, "volumeMounts", mount.clone());
            }
        }
    }
}

/// Inject a scheduling gate into a JSON pod template.
///
/// Adds the `lattice.dev/model-download` gate to `spec.schedulingGates` so
/// the pod remains `SchedulingGated` until the controller removes it after
/// the download Job succeeds.
pub fn inject_scheduling_gate(pod_template: &mut serde_json::Value) {
    let gate = serde_json::json!({ "name": SCHEDULING_GATE_MODEL_DOWNLOAD });
    json_array_push(&mut pod_template["spec"], "schedulingGates", gate);
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::SecretKeySelector;

    fn hf_source() -> ModelSourceSpec {
        ModelSourceSpec {
            uri: "hf://Qwen/Qwen3-8B".to_string(),
            cache_size: "50Gi".to_string(),
            storage_class: None,
            mount_path: None,
            token_secret: None,
            downloader_image: None,
            access_mode: None,
            security: None,
            resources: BTreeMap::new(),
            image_pull_secrets: Vec::new(),
        }
    }

    fn sample_pod_template() -> serde_json::Value {
        serde_json::json!({
            "metadata": { "labels": { "app": "test" } },
            "spec": {
                "containers": [{
                    "name": "main",
                    "image": "vllm/vllm-openai:latest"
                }]
            }
        })
    }

    #[test]
    fn parse_hf_uri() {
        let parsed = parse_uri("hf://Qwen/Qwen3-8B").unwrap();
        assert_eq!(parsed.scheme, UriScheme::HuggingFace);
        assert_eq!(parsed.path, "Qwen/Qwen3-8B");
    }

    #[test]
    fn parse_s3_uri() {
        let parsed = parse_uri("s3://my-bucket/models/llama").unwrap();
        assert_eq!(parsed.scheme, UriScheme::S3);
        assert_eq!(parsed.path, "my-bucket/models/llama");
    }

    #[test]
    fn parse_gs_uri() {
        let parsed = parse_uri("gs://my-bucket/models/llama").unwrap();
        assert_eq!(parsed.scheme, UriScheme::Gcs);
        assert_eq!(parsed.path, "my-bucket/models/llama");
    }

    #[test]
    fn parse_unsupported_uri_fails() {
        assert!(parse_uri("http://example.com/model").is_err());
    }

    #[test]
    fn parse_empty_hf_path_fails() {
        assert!(parse_uri("hf://").is_err());
    }

    #[test]
    fn compile_hf_download() {
        let source = hf_source();
        let download = compile_download("llm-serving", "serving", "uid-123", &source).unwrap();

        assert_eq!(download.pvc_name(), "vol-llm-serving-model-cache");
        assert_eq!(download.mount_path(), "/models");
        assert_eq!(download.job_name(), "llm-serving-download");

        // LatticeJob structure
        let job = &download.job;
        assert_eq!(job.metadata.name.as_deref(), Some("llm-serving-download"));
        assert_eq!(job.metadata.namespace.as_deref(), Some("serving"));
        assert_eq!(job.spec.max_retry, Some(DOWNLOAD_BACKOFF_LIMIT));

        // LatticeJob ownerReference to LatticeModel
        let job_owner = &job.metadata.owner_references.as_ref().unwrap()[0];
        assert_eq!(job_owner.kind, "LatticeModel");
        assert_eq!(job_owner.name, "llm-serving");
        assert_eq!(job_owner.uid, "uid-123");
        assert_eq!(job_owner.controller, Some(true));
        assert_eq!(job_owner.block_owner_deletion, Some(true));
        assert_eq!(job.spec.tasks.len(), 1);

        let task = &job.spec.tasks["download"];
        assert_eq!(task.replicas, Some(1));
        assert_eq!(task.restart_policy, Some(RestartPolicy::Never));

        // Container
        let container = &task.workload.containers["download"];
        assert_eq!(container.image, DEFAULT_DOWNLOADER_IMAGE);
        let cmd = container.command.as_ref().unwrap();
        assert_eq!(cmd[0], "/bin/sh");
        assert_eq!(cmd[1], "-c");
        assert_eq!(
            cmd[2],
            "hf download Qwen/Qwen3-8B --local-dir /models/Qwen3-8B"
        );

        // Volume owner (has size — VolumeCompiler creates the PVC)
        let vol_resource = &task.workload.resources[VOLUME_NAME];
        assert_eq!(vol_resource.type_, ResourceType::Volume);
        assert_eq!(vol_resource.id.as_deref(), Some("llm-serving-model-cache"));
        assert!(
            vol_resource.is_volume_owner(),
            "volume should be an owner (has size in params)"
        );
        let vol_params = vol_resource.volume_params().unwrap().unwrap();
        assert_eq!(vol_params.size, Some("50Gi".to_string()));

        // Entity egress resource
        let egress_resource = &task.workload.resources["internet"];
        assert_eq!(egress_resource.type_, ResourceType::ExternalService);
        assert_eq!(egress_resource.id.as_deref(), Some("entity:world:443"));
        assert!(egress_resource.direction.is_outbound());

        // Volume mount on container
        let vol_mount = &container.volumes["/models"];
        assert_eq!(
            vol_mount.source.as_ref().unwrap().as_str(),
            "${resources.model-cache}"
        );

        // No token secret → no secret resource, no env_from
        assert!(container.env_from.is_empty());
        assert!(!task.workload.resources.contains_key("token"));
    }

    #[test]
    fn compile_s3_download() {
        let source = ModelSourceSpec {
            uri: "s3://my-bucket/models/llama".to_string(),
            cache_size: "100Gi".to_string(),
            storage_class: None,
            mount_path: None,
            token_secret: None,
            downloader_image: None,
            access_mode: None,
            security: None,
            resources: BTreeMap::new(),
            image_pull_secrets: Vec::new(),
        };

        let download = compile_download("my-model", "default", "uid-456", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        assert_eq!(container.image, DEFAULT_DOWNLOADER_IMAGE);
        let cmd = &container.command.as_ref().unwrap()[2];
        assert_eq!(cmd, "aws s3 sync s3://my-bucket/models/llama /models/llama");
    }

    #[test]
    fn compile_gs_download() {
        let source = ModelSourceSpec {
            uri: "gs://my-bucket/models/gemma".to_string(),
            cache_size: "80Gi".to_string(),
            storage_class: None,
            mount_path: None,
            token_secret: None,
            downloader_image: None,
            access_mode: None,
            security: None,
            resources: BTreeMap::new(),
            image_pull_secrets: Vec::new(),
        };

        let download = compile_download("my-model", "default", "uid-789", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        assert_eq!(container.image, DEFAULT_DOWNLOADER_IMAGE);
        let cmd = &container.command.as_ref().unwrap()[2];
        assert_eq!(
            cmd,
            "gsutil -m rsync -r gs://my-bucket/models/gemma /models/gemma"
        );
    }

    #[test]
    fn custom_mount_path_propagated() {
        let source = ModelSourceSpec {
            mount_path: Some("/data/weights".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        assert_eq!(download.mount_path(), "/data/weights");

        let cmd = &download.job.spec.tasks["download"].workload.containers["download"]
            .command
            .as_ref()
            .unwrap()[2];
        assert!(cmd.contains("/data/weights/Qwen3-8B"));
    }

    #[test]
    fn custom_downloader_image_overrides_default() {
        let source = ModelSourceSpec {
            downloader_image: Some("my-org/downloader:v2".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        assert_eq!(container.image, "my-org/downloader:v2");
    }

    #[test]
    fn storage_class_set_when_provided() {
        let source = ModelSourceSpec {
            storage_class: Some("fast-nvme".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let vol_resource = &download.job.spec.tasks["download"].workload.resources[VOLUME_NAME];
        let vol_params = vol_resource.volume_params().unwrap().unwrap();
        assert_eq!(vol_params.storage_class, Some("fast-nvme".to_string()));
    }

    #[test]
    fn token_secret_creates_resource_and_env_from() {
        let source = ModelSourceSpec {
            token_secret: Some(SecretKeySelector {
                name: "hf-credentials".to_string(),
            }),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let task = &download.job.spec.tasks["download"];

        // Secret resource declared with lattice-local provider
        let secret_resource = &task.workload.resources["token"];
        assert_eq!(secret_resource.type_, ResourceType::Secret);
        assert_eq!(secret_resource.id.as_deref(), Some("hf-credentials"));
        let params = secret_resource.params.as_ref().unwrap();
        assert_eq!(params["provider"], serde_json::json!("lattice-local"));

        // Container env_from references the secret resource
        let container = &task.workload.containers["download"];
        assert_eq!(container.env_from, vec!["token"]);
    }

    #[test]
    fn s3_token_creates_secret_resource() {
        let source = ModelSourceSpec {
            uri: "s3://bucket/model".to_string(),
            cache_size: "50Gi".to_string(),
            storage_class: None,
            mount_path: None,
            token_secret: Some(SecretKeySelector {
                name: "aws-creds".to_string(),
            }),
            downloader_image: None,
            access_mode: None,
            security: None,
            resources: BTreeMap::new(),
            image_pull_secrets: Vec::new(),
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let secret_resource = &download.job.spec.tasks["download"].workload.resources["token"];
        assert_eq!(secret_resource.id.as_deref(), Some("aws-creds"));
    }

    #[test]
    fn no_token_secret_no_env_from() {
        let source = hf_source();
        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        assert!(container.env_from.is_empty());
        assert!(!download.job.spec.tasks["download"]
            .workload
            .resources
            .contains_key("token"));
    }

    #[test]
    fn service_account_compiled() {
        let source = hf_source();
        let download = compile_download("test", "ns", "uid-sa", &source).unwrap();

        assert_eq!(
            download.service_account["metadata"]["name"],
            "test-download"
        );
        assert_eq!(download.service_account["metadata"]["namespace"], "ns");
        assert_eq!(
            download.service_account["automountServiceAccountToken"],
            false
        );

        // ServiceAccount ownerReference to LatticeModel
        let sa_owner = &download.service_account["metadata"]["ownerReferences"][0];
        assert_eq!(sa_owner["kind"], "LatticeModel");
        assert_eq!(sa_owner["name"], "test");
        assert_eq!(sa_owner["uid"], "uid-sa");
    }

    #[test]
    fn lattice_job_has_max_retry() {
        let source = hf_source();
        let download = compile_download("test", "ns", "uid", &source).unwrap();
        assert_eq!(download.job.spec.max_retry, Some(DOWNLOAD_BACKOFF_LIMIT));
    }

    #[test]
    fn pvc_name_matches_volume_compiler_convention() {
        let source = hf_source();
        let download = compile_download("my-model", "ns", "uid", &source).unwrap();

        // VolumeCompiler uses vol-{id} naming for shared volumes
        let vol_resource = &download.job.spec.tasks["download"].workload.resources[VOLUME_NAME];
        let volume_id = vol_resource.id.as_deref().unwrap();
        let expected_pvc_name = format!("vol-{}", volume_id);
        assert_eq!(download.pvc_name(), expected_pvc_name);
    }

    #[test]
    fn custom_access_mode_propagated() {
        let source = ModelSourceSpec {
            access_mode: Some("ReadWriteMany".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let vol_resource = &download.job.spec.tasks["download"].workload.resources[VOLUME_NAME];
        let vol_params = vol_resource.volume_params().unwrap().unwrap();
        assert_eq!(
            vol_params.access_mode,
            Some(lattice_common::crd::VolumeAccessMode::ReadWriteMany)
        );
    }

    #[test]
    fn security_context_propagated_to_download_container() {
        let source = ModelSourceSpec {
            security: Some(lattice_common::crd::SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["*".to_string()],
                ..Default::default()
            }),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        let security = container.security.as_ref().expect("security should be set");
        assert_eq!(security.apparmor_profile.as_deref(), Some("Unconfined"));
        assert_eq!(security.allowed_binaries, vec!["*"]);
    }

    #[test]
    fn no_security_context_when_omitted() {
        let source = hf_source();
        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let container = &download.job.spec.tasks["download"].workload.containers["download"];
        assert!(container.security.is_none());
    }

    #[test]
    fn image_pull_secrets_propagated_to_runtime() {
        let mut resources = BTreeMap::new();
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("lattice-local"));
        resources.insert(
            "ghcr-creds".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some("local-regcreds".to_string()),
                params: Some(params),
                ..Default::default()
            },
        );

        let source = ModelSourceSpec {
            resources,
            image_pull_secrets: vec!["ghcr-creds".to_string()],
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let task = &download.job.spec.tasks["download"];

        // imagePullSecrets set on runtime
        assert_eq!(task.runtime.image_pull_secrets, vec!["ghcr-creds"]);

        // ghcr-creds resource merged into workload resources
        let creds = &task.workload.resources["ghcr-creds"];
        assert_eq!(creds.type_, ResourceType::Secret);
        assert_eq!(creds.id.as_deref(), Some("local-regcreds"));
    }

    #[test]
    fn inject_model_volume_adds_volume_and_mounts() {
        let mut template = sample_pod_template();
        inject_model_volume(&mut template, "my-model-cache", "/models");

        // Volume added
        let volumes = template["spec"]["volumes"].as_array().unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0]["name"], VOLUME_NAME);
        assert_eq!(
            volumes[0]["persistentVolumeClaim"]["claimName"],
            "my-model-cache"
        );
        assert_eq!(volumes[0]["persistentVolumeClaim"]["readOnly"], true);

        // VolumeMount on container
        let mounts = template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["name"], VOLUME_NAME);
        assert_eq!(mounts[0]["mountPath"], "/models");
        assert_eq!(mounts[0]["readOnly"], true);
    }

    #[test]
    fn inject_volume_preserves_existing_volumes() {
        let mut template = serde_json::json!({
            "metadata": { "labels": {} },
            "spec": {
                "containers": [{
                    "name": "main",
                    "image": "test:latest",
                    "volumeMounts": [{
                        "name": "existing",
                        "mountPath": "/data"
                    }]
                }],
                "volumes": [{
                    "name": "existing",
                    "emptyDir": {}
                }]
            }
        });

        inject_model_volume(&mut template, "pvc-name", "/models");

        let volumes = template["spec"]["volumes"].as_array().unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0]["name"], "existing");
        assert_eq!(volumes[1]["name"], VOLUME_NAME);

        let mounts = template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap();
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0]["name"], "existing");
        assert_eq!(mounts[1]["name"], VOLUME_NAME);
    }

    #[test]
    fn inject_volume_into_all_containers() {
        let mut template = serde_json::json!({
            "metadata": { "labels": {} },
            "spec": {
                "containers": [
                    { "name": "main", "image": "a:latest" },
                    { "name": "sidecar", "image": "b:latest" }
                ]
            }
        });

        inject_model_volume(&mut template, "pvc", "/models");

        for i in 0..2 {
            let mounts = template["spec"]["containers"][i]["volumeMounts"]
                .as_array()
                .unwrap();
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0]["name"], VOLUME_NAME);
        }
    }

    #[test]
    fn inject_volume_no_null_init_containers() {
        let mut template = sample_pod_template();
        assert!(template["spec"]["initContainers"].is_null());

        inject_model_volume(&mut template, "pvc", "/models");

        // initContainers must remain absent — a null value causes K8s API rejection
        assert!(
            !template["spec"]
                .as_object()
                .unwrap()
                .contains_key("initContainers"),
            "initContainers should not be inserted as null"
        );
    }

    #[test]
    fn inject_volume_into_existing_init_containers() {
        let mut template = serde_json::json!({
            "metadata": { "labels": {} },
            "spec": {
                "containers": [{ "name": "main", "image": "a:latest" }],
                "initContainers": [{ "name": "init", "image": "b:latest" }]
            }
        });

        inject_model_volume(&mut template, "pvc", "/models");

        let mounts = template["spec"]["initContainers"][0]["volumeMounts"]
            .as_array()
            .unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["name"], VOLUME_NAME);
    }

    #[test]
    fn inject_scheduling_gate_adds_gate() {
        let mut template = sample_pod_template();
        inject_scheduling_gate(&mut template);

        let gates = template["spec"]["schedulingGates"].as_array().unwrap();
        assert_eq!(gates.len(), 1);
        assert_eq!(gates[0]["name"], SCHEDULING_GATE_MODEL_DOWNLOAD);
    }

    #[test]
    fn inject_scheduling_gate_preserves_existing() {
        let mut template = serde_json::json!({
            "metadata": { "labels": {} },
            "spec": {
                "containers": [],
                "schedulingGates": [{ "name": "other-gate" }]
            }
        });

        inject_scheduling_gate(&mut template);

        let gates = template["spec"]["schedulingGates"].as_array().unwrap();
        assert_eq!(gates.len(), 2);
        assert_eq!(gates[0]["name"], "other-gate");
        assert_eq!(gates[1]["name"], SCHEDULING_GATE_MODEL_DOWNLOAD);
    }
}
