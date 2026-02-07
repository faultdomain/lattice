//! ModelCache reconciliation controller
//!
//! Watches ModelArtifact CRDs and drives the download lifecycle:
//! - `Pending` → create pre-fetch Job → `Downloading`
//! - `Downloading` → poll Job status → `Ready` or `Failed`
//! - `Ready` → remove scheduling gates, periodic re-check
//! - `Failed` → reset to `Pending` for retry
//!
//! Also provides `discover_models()` for use as a `.watches(LatticeService)` mapper
//! that ensures ModelArtifact CRDs exist for every `type: model` resource.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::batch::v1::Job;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeService, ModelArtifact, ModelArtifactPhase, ModelArtifactSpec, ModelArtifactStatus,
};
use lattice_common::ReconcileError;

use crate::gate;
use crate::job;

/// Default model loader image
const DEFAULT_MODEL_LOADER_IMAGE: &str = "ghcr.io/lattice-cloud/model-loader:v1";

/// Context for the ModelCache controller
pub struct ModelCacheContext {
    /// Kubernetes client
    pub client: Client,
    /// Container image used for the model-loader Job
    pub model_loader_image: String,
}

impl ModelCacheContext {
    /// Create a new context with the default loader image
    pub fn new(client: Client) -> Self {
        Self {
            client,
            model_loader_image: DEFAULT_MODEL_LOADER_IMAGE.to_string(),
        }
    }

    /// Create a new context with a custom loader image
    pub fn with_loader_image(client: Client, image: String) -> Self {
        Self {
            client,
            model_loader_image: image,
        }
    }
}

/// Error policy for the ModelCache controller.
///
/// Logs the error and requeues for retry after 30 seconds.
pub fn error_policy(
    _obj: Arc<ModelArtifact>,
    error: &ReconcileError,
    _ctx: Arc<ModelCacheContext>,
) -> Action {
    warn!(error = %error, "ModelCache reconcile error, will retry");
    Action::requeue(Duration::from_secs(30))
}

/// Reconcile a ModelArtifact through its download lifecycle.
///
/// Phase transitions:
/// - `Pending` → Check for existing Job; if absent, create one. Transition to `Downloading`.
/// - `Downloading` → Check Job status. Complete → `Ready` + remove gates. Failed → `Failed`.
/// - `Ready` → Remove gates for any new Deployments, periodic re-check.
/// - `Failed` → Reset to `Pending` for retry.
/// - `Evicting` → Future: cleanup (no-op for now).
pub async fn reconcile(
    artifact: Arc<ModelArtifact>,
    ctx: Arc<ModelCacheContext>,
) -> Result<Action, ReconcileError> {
    let name = artifact.name_any();
    let namespace = artifact
        .namespace()
        .ok_or_else(|| ReconcileError::Validation("ModelArtifact must be namespaced".into()))?;
    let client = &ctx.client;

    let phase = artifact
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or_default();

    info!(artifact = %name, ?phase, "Reconciling ModelArtifact");

    match phase {
        ModelArtifactPhase::Pending => {
            reconcile_pending(&artifact, &name, &namespace, ctx.as_ref()).await
        }
        ModelArtifactPhase::Downloading => {
            reconcile_downloading(&artifact, &name, &namespace, client).await
        }
        ModelArtifactPhase::Ready => reconcile_ready(&artifact, &name, &namespace, client).await,
        ModelArtifactPhase::Failed => reconcile_failed(&name, &namespace, client).await,
        ModelArtifactPhase::Evicting => {
            debug!(artifact = %name, "Evicting phase - no-op for now");
            Ok(Action::requeue(Duration::from_secs(300)))
        }
    }
}

/// Pending: create a pre-fetch Job if one doesn't exist, transition to Downloading
async fn reconcile_pending(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    ctx: &ModelCacheContext,
) -> Result<Action, ReconcileError> {
    let client = &ctx.client;
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let job_name = format!("model-prefetch-{}", name);

    // Check if a Job already exists (idempotent)
    match jobs.get_opt(&job_name).await {
        Ok(Some(_)) => {
            info!(artifact = %name, "Pre-fetch Job already exists, transitioning to Downloading");
            update_phase(
                client,
                name,
                namespace,
                ModelArtifactPhase::Downloading,
                None,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Ok(None) => {
            let uid = artifact
                .uid()
                .ok_or_else(|| ReconcileError::Internal("ModelArtifact has no UID".into()))?;

            let job = job::build_prefetch_job(
                &artifact.spec,
                name,
                &uid,
                namespace,
                &ctx.model_loader_image,
            );

            info!(artifact = %name, job = %job_name, "Creating pre-fetch Job");
            jobs.create(&PostParams::default(), &job)
                .await
                .map_err(|e| {
                    ReconcileError::Kube(format!("failed to create pre-fetch job: {}", e))
                })?;

            update_phase(
                client,
                name,
                namespace,
                ModelArtifactPhase::Downloading,
                None,
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(10)))
        }
        Err(e) => Err(ReconcileError::Kube(format!(
            "failed to check for existing job: {}",
            e
        ))),
    }
}

/// Downloading: poll Job status, transition to Ready or Failed
async fn reconcile_downloading(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let job_name = format!("model-prefetch-{}", name);

    match jobs.get_opt(&job_name).await {
        Ok(Some(job_obj)) => {
            if job::is_job_complete(&job_obj) {
                info!(artifact = %name, "Pre-fetch Job completed, model is ready");
                update_phase(client, name, namespace, ModelArtifactPhase::Ready, None).await?;

                // Remove scheduling gates for Deployments waiting on this model
                gate::remove_gates_for_pvc(client, namespace, &artifact.spec.pvc_name).await?;

                Ok(Action::requeue(Duration::from_secs(300)))
            } else if job::is_job_failed(&job_obj) {
                let msg = job::job_failure_message(&job_obj)
                    .unwrap_or_else(|| "unknown failure".to_string());
                warn!(artifact = %name, error = %msg, "Pre-fetch Job failed");
                update_phase(
                    client,
                    name,
                    namespace,
                    ModelArtifactPhase::Failed,
                    Some(msg),
                )
                .await?;
                Ok(Action::requeue(Duration::from_secs(30)))
            } else {
                // Still running, poll again
                debug!(artifact = %name, "Pre-fetch Job still running");
                Ok(Action::requeue(Duration::from_secs(15)))
            }
        }
        Ok(None) => {
            // Job disappeared (deleted externally?). Reset to Pending to recreate.
            warn!(artifact = %name, "Pre-fetch Job not found, resetting to Pending");
            update_phase(
                client,
                name,
                namespace,
                ModelArtifactPhase::Pending,
                Some("Pre-fetch Job not found, will retry".to_string()),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        Err(e) => Err(ReconcileError::Kube(format!(
            "failed to get job status: {}",
            e
        ))),
    }
}

/// Ready: remove scheduling gates for any new Deployments, periodic health check
async fn reconcile_ready(
    artifact: &ModelArtifact,
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    debug!(artifact = %name, "Model is Ready, checking for new Deployments needing gate removal");
    gate::remove_gates_for_pvc(client, namespace, &artifact.spec.pvc_name).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Failed: reset to Pending to trigger a retry
async fn reconcile_failed(
    name: &str,
    namespace: &str,
    client: &Client,
) -> Result<Action, ReconcileError> {
    info!(artifact = %name, "Resetting Failed artifact to Pending for retry");
    update_phase(client, name, namespace, ModelArtifactPhase::Pending, None).await?;
    Ok(Action::requeue(Duration::from_secs(5)))
}

/// Update the ModelArtifact status phase
async fn update_phase(
    client: &Client,
    name: &str,
    namespace: &str,
    phase: ModelArtifactPhase,
    error: Option<String>,
) -> Result<(), ReconcileError> {
    let api: Api<ModelArtifact> = Api::namespaced(client.clone(), namespace);

    let mut status = ModelArtifactStatus {
        phase: phase.clone(),
        error,
        ..Default::default()
    };

    if phase == ModelArtifactPhase::Ready {
        status.completed_at = Some(chrono::Utc::now());
    }

    let patch = serde_json::json!({ "status": status });

    api.patch_status(
        name,
        &PatchParams::apply("lattice-model-cache"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to update status: {}", e)))?;

    Ok(())
}

/// Watch mapper: discovers ModelArtifact refs from LatticeService changes.
///
/// For each `type: model` resource in the service spec, ensures a ModelArtifact
/// CRD exists (creates one if missing) and returns its `ObjectRef` so the
/// controller reconciles it.
///
/// Used as the mapper function in `.watches(LatticeService, ...)`.
pub fn discover_models(client: Client) -> impl Fn(LatticeService) -> Vec<ObjectRef<ModelArtifact>> {
    move |service: LatticeService| {
        let namespace = match service.metadata.namespace.as_deref() {
            Some(ns) => ns.to_string(),
            None => return vec![],
        };

        let mut refs = Vec::new();

        for resource in service.spec.resources.values() {
            let params = match resource.model_params() {
                Ok(Some(p)) => p,
                _ => continue,
            };

            let artifact_name = params.cache_pvc_name();

            // Spawn a background task to ensure the ModelArtifact exists.
            // We can't do async work in the mapper directly, so we spawn.
            let client = client.clone();
            let ns = namespace.clone();
            let name = artifact_name.clone();
            let spec = ModelArtifactSpec {
                uri: params.uri.clone(),
                revision: params.revision.clone(),
                pvc_name: artifact_name.clone(),
                size_bytes: None,
            };
            tokio::spawn(async move {
                if let Err(e) = ensure_model_artifact(&client, &name, &ns, spec).await {
                    warn!(
                        artifact = %name,
                        namespace = %ns,
                        error = %e,
                        "Failed to ensure ModelArtifact exists"
                    );
                }
            });

            refs.push(ObjectRef::<ModelArtifact>::new(&artifact_name).within(&namespace));
        }

        refs
    }
}

/// Ensure a ModelArtifact CRD exists for the given model; create if missing.
async fn ensure_model_artifact(
    client: &Client,
    name: &str,
    namespace: &str,
    spec: ModelArtifactSpec,
) -> Result<(), ReconcileError> {
    let api: Api<ModelArtifact> = Api::namespaced(client.clone(), namespace);

    match api.get_opt(name).await {
        Ok(Some(_)) => {
            debug!(artifact = %name, "ModelArtifact already exists");
            Ok(())
        }
        Ok(None) => {
            info!(artifact = %name, namespace = %namespace, "Creating ModelArtifact");
            let artifact = ModelArtifact::new(name, spec);
            api.create(&PostParams::default(), &artifact)
                .await
                .map_err(|e| {
                    ReconcileError::Kube(format!("failed to create ModelArtifact: {}", e))
                })?;
            Ok(())
        }
        Err(e) => Err(ReconcileError::Kube(format!(
            "failed to check ModelArtifact: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::ModelArtifactPhase;

    #[test]
    fn default_phase_is_pending() {
        assert_eq!(ModelArtifactPhase::default(), ModelArtifactPhase::Pending);
    }

    #[test]
    fn default_loader_image() {
        assert_eq!(
            DEFAULT_MODEL_LOADER_IMAGE,
            "ghcr.io/lattice-cloud/model-loader:v1"
        );
    }

    #[test]
    fn job_name_derived_from_artifact() {
        // Verify the job naming convention used throughout the controller
        let artifact_name = "model-cache-meta-llama-abc123";
        let expected = format!("model-prefetch-{}", artifact_name);
        assert_eq!(expected, "model-prefetch-model-cache-meta-llama-abc123");
    }
}
