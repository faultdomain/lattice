//! Model download compilation — PVC, Job, and pod template injection
//!
//! Pure compilation functions that take a `ModelSourceSpec` and produce:
//! - A PVC for caching downloaded model artifacts
//! - A K8s batch/v1 Job that downloads the model into the PVC
//! - Volume + volumeMount injection for role pod templates
//! - Scheduling gate injection so pods stay `SchedulingGated` until download completes
//!
//! Uses existing public container images per URI scheme:
//! - `hf://` → `python:3.11-slim` (installs `huggingface-hub`, runs `huggingface-cli download`)
//! - `s3://` → `amazon/aws-cli` (runs `aws s3 sync`)
//! - `gs://` → `google/cloud-sdk:slim` (runs `gsutil -m rsync -r`)

use lattice_common::crd::ModelSourceSpec;

use crate::error::ModelError;

/// Scheduling gate name applied to model-serving pods while download is in progress.
/// The controller removes this gate after the download Job succeeds.
pub const SCHEDULING_GATE_MODEL_DOWNLOAD: &str = "lattice.dev/model-download";

const DEFAULT_MOUNT_PATH: &str = "/models";
const VOLUME_NAME: &str = "model-cache";

/// Compiled download resources for a LatticeModel
#[derive(Debug)]
pub struct CompiledDownload {
    /// PVC for model artifact cache (as JSON for ApplyBatch)
    pub pvc: serde_json::Value,
    /// K8s batch/v1 Job that downloads the model (as JSON for ApplyBatch)
    pub job: serde_json::Value,
    /// PVC name (for volume references in pod templates)
    pub pvc_name: String,
    /// Mount path for model artifacts in serving containers
    pub mount_path: String,
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
    if let Some(path) = uri.strip_prefix("hf://") {
        if path.is_empty() {
            return Err(ModelError::InvalidModelUri(
                "hf:// URI must include a repository path".to_string(),
            ));
        }
        Ok(ParsedUri {
            scheme: UriScheme::HuggingFace,
            path: path.to_string(),
        })
    } else if let Some(path) = uri.strip_prefix("s3://") {
        if path.is_empty() {
            return Err(ModelError::InvalidModelUri(
                "s3:// URI must include a bucket path".to_string(),
            ));
        }
        Ok(ParsedUri {
            scheme: UriScheme::S3,
            path: format!("s3://{}", path),
        })
    } else if let Some(path) = uri.strip_prefix("gs://") {
        if path.is_empty() {
            return Err(ModelError::InvalidModelUri(
                "gs:// URI must include a bucket path".to_string(),
            ));
        }
        Ok(ParsedUri {
            scheme: UriScheme::Gcs,
            path: format!("gs://{}", path),
        })
    } else {
        Err(ModelError::InvalidModelUri(format!(
            "unsupported URI scheme (expected hf://, s3://, or gs://): {}",
            uri
        )))
    }
}

/// Compile model download resources from a ModelSourceSpec.
///
/// Produces a PVC + Job as JSON values ready for ApplyBatch. This is a pure
/// compilation function — no K8s API calls.
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
    let pvc_name = format!("{}-model-cache", model_name);
    let job_name = format!("{}-download", model_name);

    let owner_ref = serde_json::json!([{
        "apiVersion": "lattice.dev/v1alpha1",
        "kind": "LatticeModel",
        "name": model_name,
        "uid": uid,
        "controller": true,
        "blockOwnerDeletion": true
    }]);

    let pvc = compile_pvc(
        &pvc_name,
        namespace,
        &source.cache_size,
        source.storage_class.as_deref(),
        &owner_ref,
    );

    let job = compile_job(
        &job_name,
        namespace,
        &pvc_name,
        &mount_path,
        &parsed,
        source,
        &owner_ref,
    );

    Ok(CompiledDownload {
        pvc,
        job,
        pvc_name,
        mount_path,
    })
}

fn compile_pvc(
    name: &str,
    namespace: &str,
    cache_size: &str,
    storage_class: Option<&str>,
    owner_ref: &serde_json::Value,
) -> serde_json::Value {
    let mut pvc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "ownerReferences": owner_ref,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "app.kubernetes.io/component": "model-cache"
            }
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": cache_size
                }
            }
        }
    });

    if let Some(sc) = storage_class {
        pvc["spec"]["storageClassName"] = serde_json::Value::String(sc.to_string());
    }

    pvc
}

fn compile_job(
    name: &str,
    namespace: &str,
    pvc_name: &str,
    mount_path: &str,
    parsed: &ParsedUri,
    source: &ModelSourceSpec,
    owner_ref: &serde_json::Value,
) -> serde_json::Value {
    let (image, command) = download_command(parsed, mount_path, source.downloader_image.as_deref());

    // Mount entire secret as env vars via envFrom — the secret's keys must match
    // what the download tool expects (e.g. HF_TOKEN, AWS_ACCESS_KEY_ID, etc.)
    let mut env_from: Vec<serde_json::Value> = Vec::new();
    if let Some(ref token_secret) = source.token_secret {
        env_from.push(serde_json::json!({
            "secretRef": { "name": token_secret.name }
        }));
    }

    serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "ownerReferences": owner_ref,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "app.kubernetes.io/component": "model-download"
            }
        },
        "spec": {
            "backoffLimit": 3,
            "template": {
                "spec": {
                    "restartPolicy": "OnFailure",
                    "containers": [{
                        "name": "download",
                        "image": image,
                        "command": ["sh", "-c", command],
                        "envFrom": env_from,
                        "volumeMounts": [{
                            "name": VOLUME_NAME,
                            "mountPath": mount_path
                        }]
                    }],
                    "volumes": [{
                        "name": VOLUME_NAME,
                        "persistentVolumeClaim": {
                            "claimName": pvc_name
                        }
                    }]
                }
            }
        }
    })
}

/// Returns (image, shell_command) for the download container
fn download_command(
    parsed: &ParsedUri,
    mount_path: &str,
    custom_image: Option<&str>,
) -> (String, String) {
    match parsed.scheme {
        UriScheme::HuggingFace => {
            let repo_id = &parsed.path;
            // Derive local dir name from repo_id (e.g. "Qwen/Qwen3-8B" → "Qwen3-8B")
            let local_name = repo_id.rsplit('/').next().unwrap_or(repo_id);
            let image = custom_image
                .unwrap_or("python:3.11-slim")
                .to_string();
            let cmd = format!(
                "pip install -q huggingface-hub && huggingface-cli download {} --local-dir {}/{}",
                repo_id, mount_path, local_name
            );
            (image, cmd)
        }
        UriScheme::S3 => {
            // parsed.path is already "s3://bucket/path"
            let bucket_path = &parsed.path;
            let local_name = bucket_path.rsplit('/').next().unwrap_or("model");
            let image = custom_image
                .unwrap_or("amazon/aws-cli:latest")
                .to_string();
            let cmd = format!(
                "aws s3 sync {} {}/{}",
                bucket_path, mount_path, local_name
            );
            (image, cmd)
        }
        UriScheme::Gcs => {
            let bucket_path = &parsed.path;
            let local_name = bucket_path.rsplit('/').next().unwrap_or("model");
            let image = custom_image
                .unwrap_or("google/cloud-sdk:slim")
                .to_string();
            let cmd = format!(
                "gsutil -m rsync -r {} {}/{}",
                bucket_path, mount_path, local_name
            );
            (image, cmd)
        }
    }
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
pub fn inject_model_volume(
    pod_template: &mut serde_json::Value,
    pvc_name: &str,
    mount_path: &str,
) {
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
        assert_eq!(parsed.path, "s3://my-bucket/models/llama");
    }

    #[test]
    fn parse_gs_uri() {
        let parsed = parse_uri("gs://my-bucket/models/llama").unwrap();
        assert_eq!(parsed.scheme, UriScheme::Gcs);
        assert_eq!(parsed.path, "gs://my-bucket/models/llama");
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

        assert_eq!(download.pvc_name, "llm-serving-model-cache");
        assert_eq!(download.mount_path, "/models");

        // PVC checks
        assert_eq!(download.pvc["metadata"]["name"], "llm-serving-model-cache");
        assert_eq!(download.pvc["metadata"]["namespace"], "serving");
        assert_eq!(
            download.pvc["spec"]["resources"]["requests"]["storage"],
            "50Gi"
        );
        assert_eq!(download.pvc["spec"]["accessModes"][0], "ReadWriteOnce");
        assert!(download.pvc["spec"]["storageClassName"].is_null());

        // PVC owner reference
        let pvc_owner = &download.pvc["metadata"]["ownerReferences"][0];
        assert_eq!(pvc_owner["kind"], "LatticeModel");
        assert_eq!(pvc_owner["name"], "llm-serving");
        assert_eq!(pvc_owner["uid"], "uid-123");

        // Job checks
        assert_eq!(download.job["metadata"]["name"], "llm-serving-download");
        assert_eq!(download.job["metadata"]["namespace"], "serving");
        assert_eq!(download.job["spec"]["backoffLimit"], 3);

        let container = &download.job["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(container["image"], "python:3.11-slim");
        let cmd = container["command"][2].as_str().unwrap();
        assert!(cmd.contains("huggingface-cli download Qwen/Qwen3-8B"));
        assert!(cmd.contains("--local-dir /models/Qwen3-8B"));

        // Job owner reference
        let job_owner = &download.job["metadata"]["ownerReferences"][0];
        assert_eq!(job_owner["kind"], "LatticeModel");
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
        };

        let download = compile_download("my-model", "default", "uid-456", &source).unwrap();

        let container = &download.job["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(container["image"], "amazon/aws-cli:latest");
        let cmd = container["command"][2].as_str().unwrap();
        assert!(cmd.contains("aws s3 sync s3://my-bucket/models/llama /models/llama"));
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
        };

        let download = compile_download("my-model", "default", "uid-789", &source).unwrap();

        let container = &download.job["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(container["image"], "google/cloud-sdk:slim");
        let cmd = container["command"][2].as_str().unwrap();
        assert!(cmd.contains("gsutil -m rsync -r gs://my-bucket/models/gemma /models/gemma"));
    }

    #[test]
    fn custom_mount_path_propagated() {
        let source = ModelSourceSpec {
            mount_path: Some("/data/weights".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        assert_eq!(download.mount_path, "/data/weights");

        let cmd = download.job["spec"]["template"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(cmd.contains("/data/weights/Qwen3-8B"));
    }

    #[test]
    fn custom_downloader_image_overrides_default() {
        let source = ModelSourceSpec {
            downloader_image: Some("my-org/downloader:v2".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let image = download.job["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .unwrap();
        assert_eq!(image, "my-org/downloader:v2");
    }

    #[test]
    fn storage_class_set_when_provided() {
        let source = ModelSourceSpec {
            storage_class: Some("fast-nvme".to_string()),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        assert_eq!(download.pvc["spec"]["storageClassName"], "fast-nvme");
    }

    #[test]
    fn token_secret_uses_env_from() {
        let source = ModelSourceSpec {
            token_secret: Some(SecretKeySelector {
                name: "hf-credentials".to_string(),
            }),
            ..hf_source()
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let container = &download.job["spec"]["template"]["spec"]["containers"][0];

        // envFrom mounts the entire secret
        let env_from = container["envFrom"].as_array().unwrap();
        assert_eq!(env_from.len(), 1);
        assert_eq!(env_from[0]["secretRef"]["name"], "hf-credentials");

        // No individual env vars
        assert!(
            container["envFrom"][0].get("secretKeyRef").is_none(),
            "should use envFrom, not per-key secretKeyRef"
        );
    }

    #[test]
    fn s3_token_uses_env_from() {
        let source = ModelSourceSpec {
            uri: "s3://bucket/model".to_string(),
            cache_size: "50Gi".to_string(),
            storage_class: None,
            mount_path: None,
            token_secret: Some(SecretKeySelector {
                name: "aws-creds".to_string(),
            }),
            downloader_image: None,
        };

        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let env_from = download.job["spec"]["template"]["spec"]["containers"][0]["envFrom"]
            .as_array()
            .unwrap();
        assert_eq!(env_from[0]["secretRef"]["name"], "aws-creds");
    }

    #[test]
    fn no_token_secret_empty_env_from() {
        let source = hf_source();
        let download = compile_download("test", "ns", "uid", &source).unwrap();
        let env_from = download.job["spec"]["template"]["spec"]["containers"][0]["envFrom"]
            .as_array()
            .unwrap();
        assert!(env_from.is_empty());
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
