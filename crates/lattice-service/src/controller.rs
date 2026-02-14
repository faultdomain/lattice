//! LatticeService controller implementation
//!
//! This module implements the reconciliation logic for LatticeService resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.
//!
//! The controller maintains a ServiceGraph for tracking service dependencies
//! and allowed callers for network policy generation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Client, Resource, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use kube::discovery::ApiResource;
use lattice_common::kube_utils::HasApiResource;
use lattice_common::policy::{AuthorizationPolicy, CiliumNetworkPolicy, ServiceEntry};

use lattice_cedar::PolicyEngine;
use lattice_common::events::{actions, reasons, EventPublisher};
use lattice_common::KubeEventPublisher;
#[cfg(test)]
use lattice_common::NoopEventPublisher;

use crate::compiler::{ApplyLayer, CompiledService, CompilerPhase, ServiceCompiler};
use crate::crd::{
    Condition, ConditionStatus, LatticeExternalService, LatticeExternalServiceStatus,
    LatticeService, LatticeServicePolicy, LatticeServiceSpec, LatticeServiceStatus,
    MonitoringConfig, ProviderType, ServiceBackupSpec, ServicePhase,
};
use crate::graph::ServiceGraph;
use crate::ingress::{Certificate, Gateway, GrpcRoute, HttpRoute, TcpRoute};
use crate::workload::backup::merge_backup_specs;
use crate::Error;
use lattice_common::mesh;

// =============================================================================
// Discovered CRD versions
// =============================================================================

/// Cache of discovered API versions for third-party CRDs.
///
/// At operator startup, we discover which CRDs are installed and their API versions
/// via Kubernetes API discovery. This avoids hardcoding versions like `v1beta1` that
/// may differ from what's actually installed (e.g., the cluster has `v1` only).
///
/// If a CRD isn't installed, its field is `None` and resources of that type are
/// skipped with a warning during apply.
pub struct DiscoveredCrds {
    pub external_secret: Option<ApiResource>,
    pub cilium_network_policy: Option<ApiResource>,
    pub authorization_policy: Option<ApiResource>,
    pub service_entry: Option<ApiResource>,
    pub gateway: Option<ApiResource>,
    pub http_route: Option<ApiResource>,
    pub grpc_route: Option<ApiResource>,
    pub tcp_route: Option<ApiResource>,
    pub certificate: Option<ApiResource>,
    pub scaled_object: Option<ApiResource>,
    pub vm_service_scrape: Option<ApiResource>,
}

impl DiscoveredCrds {
    /// Discover installed CRD versions from the API server.
    ///
    /// Runs a single API discovery and looks up each third-party CRD.
    /// Missing CRDs result in `None` (not an error).
    pub async fn discover(client: &Client) -> Self {
        use kube::discovery::Discovery;

        let discovery = match Discovery::new(client.clone()).run().await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "API discovery failed, falling back to hardcoded CRD versions");
                return Self::hardcoded_defaults();
            }
        };

        Self {
            external_secret: Self::find_resource(
                &discovery,
                "external-secrets.io",
                "ExternalSecret",
            ),
            cilium_network_policy: Self::find_resource(
                &discovery,
                "cilium.io",
                "CiliumNetworkPolicy",
            ),
            authorization_policy: Self::find_resource(
                &discovery,
                "security.istio.io",
                "AuthorizationPolicy",
            ),
            service_entry: Self::find_resource(&discovery, "networking.istio.io", "ServiceEntry"),
            gateway: Self::find_resource(&discovery, "gateway.networking.k8s.io", "Gateway"),
            http_route: Self::find_resource(&discovery, "gateway.networking.k8s.io", "HTTPRoute"),
            grpc_route: Self::find_resource(&discovery, "gateway.networking.k8s.io", "GRPCRoute"),
            tcp_route: Self::find_resource(&discovery, "gateway.networking.k8s.io", "TCPRoute"),
            certificate: Self::find_resource(&discovery, "cert-manager.io", "Certificate"),
            scaled_object: Self::find_resource(&discovery, "keda.sh", "ScaledObject"),
            vm_service_scrape: Self::find_resource(
                &discovery,
                "operator.victoriametrics.com",
                "VMServiceScrape",
            ),
        }
    }

    /// Look up a single resource in the discovery results.
    fn find_resource(
        discovery: &kube::discovery::Discovery,
        group: &str,
        kind: &str,
    ) -> Option<ApiResource> {
        for api_group in discovery.groups() {
            if api_group.name() != group {
                continue;
            }
            for (ar, _caps) in api_group.resources_by_stability() {
                if ar.kind == kind {
                    info!(
                        group = %group,
                        kind = %kind,
                        api_version = %ar.api_version,
                        "discovered CRD version"
                    );
                    return Some(ar);
                }
            }
        }
        warn!(group = %group, kind = %kind, "CRD not found in API discovery");
        None
    }

    /// Fall back to hardcoded `HasApiResource` defaults.
    ///
    /// Used when API discovery fails entirely, and in tests.
    pub fn hardcoded_defaults() -> Self {
        use crate::workload::ScaledObject;
        use lattice_secret_provider::ExternalSecret;

        Self {
            external_secret: Some(ExternalSecret::api_resource()),
            cilium_network_policy: Some(CiliumNetworkPolicy::api_resource()),
            authorization_policy: Some(AuthorizationPolicy::api_resource()),
            service_entry: Some(ServiceEntry::api_resource()),
            gateway: Some(Gateway::api_resource()),
            http_route: Some(HttpRoute::api_resource()),
            grpc_route: Some(GrpcRoute::api_resource()),
            tcp_route: Some(TcpRoute::api_resource()),
            certificate: Some(Certificate::api_resource()),
            scaled_object: Some(ScaledObject::api_resource()),
            vm_service_scrape: Some(lattice_common::kube_utils::build_api_resource(
                "operator.victoriametrics.com/v1beta1",
                "VMServiceScrape",
            )),
        }
    }
}

// =============================================================================
// Traits for dependency injection and testability
// =============================================================================

/// Trait abstracting Kubernetes client operations for LatticeService
///
/// This trait allows mocking the Kubernetes client in tests while using
/// the real client in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ServiceKubeClient: Send + Sync {
    /// Patch the status of a LatticeService
    async fn patch_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeServiceStatus,
    ) -> Result<(), Error>;

    /// Patch the status of a LatticeExternalService
    async fn patch_external_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeExternalServiceStatus,
    ) -> Result<(), Error>;

    /// Get a LatticeService by name and namespace
    async fn get_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeService>, Error>;

    /// Get a LatticeExternalService by name and namespace
    async fn get_external_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeExternalService>, Error>;

    /// List all LatticeServices across all namespaces
    async fn list_services(&self) -> Result<Vec<LatticeService>, Error>;

    /// List all LatticeExternalServices across all namespaces
    async fn list_external_services(&self) -> Result<Vec<LatticeExternalService>, Error>;

    /// List all LatticeServicePolicies across all namespaces
    async fn list_policies(&self) -> Result<Vec<LatticeServicePolicy>, Error>;

    /// Get labels for a namespace (returns empty map if namespace not found)
    async fn get_namespace_labels(&self, name: &str) -> Result<BTreeMap<String, String>, Error>;

    /// Apply compiled workloads and policies to the cluster
    async fn apply_compiled_service(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error>;
}

/// Real Kubernetes client implementation
pub struct ServiceKubeClientImpl {
    client: Client,
    crds: Arc<DiscoveredCrds>,
}

/// Fetch labels for a Kubernetes namespace. Returns empty map if not found.
pub(crate) async fn fetch_namespace_labels(
    client: &Client,
    name: &str,
) -> Result<BTreeMap<String, String>, kube::Error> {
    use k8s_openapi::api::core::v1::Namespace;
    let api: Api<Namespace> = Api::all(client.clone());
    Ok(api
        .get_opt(name)
        .await?
        .and_then(|ns| ns.metadata.labels)
        .unwrap_or_default())
}

impl ServiceKubeClientImpl {
    /// Create a new ServiceKubeClientImpl wrapping the given client and discovered CRDs
    pub fn new(client: Client, crds: Arc<DiscoveredCrds>) -> Self {
        Self { client, crds }
    }

    /// Ensure a namespace exists with ambient mode labels for Istio traffic routing.
    ///
    /// Istio ambient mode requires namespaces to have:
    /// - `istio.io/dataplane-mode: ambient` - enrolls pods into ambient mesh (ztunnel intercepts traffic)
    ///
    /// Waypoint routing is per-Service (applied by the service compiler when L7 is needed),
    /// not per-namespace.
    async fn ensure_namespace_with_ambient(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Namespace;

        let api: Api<Namespace> = Api::all(self.client.clone());

        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "labels": {
                    (mesh::DATAPLANE_MODE_LABEL): mesh::DATAPLANE_MODE_AMBIENT
                }
            }
        });

        api.patch(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Apply(&ns),
        )
        .await?;

        debug!(namespace = %name, "ensured namespace with ambient mode labels");
        Ok(())
    }
}

#[async_trait]
impl ServiceKubeClient for ServiceKubeClientImpl {
    async fn patch_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeServiceStatus,
    ) -> Result<(), Error> {
        let api: Api<LatticeService> = Api::namespaced(self.client.clone(), namespace);
        let status_patch = serde_json::json!({ "status": status });

        api.patch_status(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Merge(&status_patch),
        )
        .await?;

        Ok(())
    }

    async fn patch_external_service_status(
        &self,
        name: &str,
        namespace: &str,
        status: &LatticeExternalServiceStatus,
    ) -> Result<(), Error> {
        let api: Api<LatticeExternalService> = Api::namespaced(self.client.clone(), namespace);
        let status_patch = serde_json::json!({ "status": status });

        api.patch_status(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Merge(&status_patch),
        )
        .await?;

        Ok(())
    }

    async fn get_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeService>, Error> {
        let api: Api<LatticeService> = Api::namespaced(self.client.clone(), namespace);
        match api.get(name).await {
            Ok(svc) => Ok(Some(svc)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_external_service(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<LatticeExternalService>, Error> {
        let api: Api<LatticeExternalService> = Api::namespaced(self.client.clone(), namespace);
        match api.get(name).await {
            Ok(svc) => Ok(Some(svc)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_services(&self) -> Result<Vec<LatticeService>, Error> {
        let api: Api<LatticeService> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn list_external_services(&self) -> Result<Vec<LatticeExternalService>, Error> {
        let api: Api<LatticeExternalService> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn list_policies(&self) -> Result<Vec<LatticeServicePolicy>, Error> {
        let api: Api<LatticeServicePolicy> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn get_namespace_labels(&self, name: &str) -> Result<BTreeMap<String, String>, Error> {
        Ok(fetch_namespace_labels(&self.client, name).await?)
    }

    async fn apply_compiled_service(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use k8s_openapi::api::apps::v1::Deployment as K8sDeployment;
        use k8s_openapi::api::core::v1::{
            ConfigMap as K8sCm, PersistentVolumeClaim as K8sPvc, Secret as K8sSecret,
            Service as K8sService, ServiceAccount as K8sSA,
        };

        self.ensure_namespace_with_ambient(namespace).await?;

        let params = PatchParams::apply("lattice-service-controller").force();

        // ApiResources for native K8s types (used by push via DynamicObject)
        let ar_sa = ApiResource::erase::<K8sSA>(&());
        let ar_pvc = ApiResource::erase::<K8sPvc>(&());
        let ar_cm = ApiResource::erase::<K8sCm>(&());
        let ar_secret = ApiResource::erase::<K8sSecret>(&());
        let ar_svc = ApiResource::erase::<K8sService>(&());
        let ar_deploy = ApiResource::erase::<K8sDeployment>(&());
        let ar_pdb =
            lattice_common::kube_utils::build_api_resource("policy/v1", "PodDisruptionBudget");

        // ── Layer 1: Infrastructure ──
        // Everything except the Deployment and ScaledObject. ExternalSecrets
        // trigger ESO to sync K8s Secrets that the Deployment may reference
        // via imagePullSecrets, so they must be applied first.
        let mut layer1 = ApplyBatch::new(self.client.clone(), namespace, &params);

        // Workload infrastructure
        if let Some(sa) = &compiled.workloads.service_account {
            layer1.push("ServiceAccount", &sa.metadata.name, sa, &ar_sa)?;
        }
        for pvc in &compiled.workloads.pvcs {
            layer1.push("PVC", &pvc.metadata.name, pvc, &ar_pvc)?;
        }
        for cm in &compiled.workloads.env_config_maps {
            layer1.push("ConfigMap", &cm.metadata.name, cm, &ar_cm)?;
        }
        for secret in &compiled.workloads.env_secrets {
            layer1.push("Secret", &secret.metadata.name, secret, &ar_secret)?;
        }
        for cm in &compiled.workloads.files_config_maps {
            layer1.push("ConfigMap", &cm.metadata.name, cm, &ar_cm)?;
        }
        for secret in &compiled.workloads.files_secrets {
            layer1.push("Secret", &secret.metadata.name, secret, &ar_secret)?;
        }
        if let Some(svc) = &compiled.workloads.service {
            layer1.push("Service", &svc.metadata.name, svc, &ar_svc)?;
        }
        if let Some(pdb) = &compiled.workloads.pdb {
            layer1.push("PodDisruptionBudget", &pdb.metadata.name, pdb, &ar_pdb)?;
        }

        // ExternalSecrets (ESO syncs secrets from Vault)
        layer1.push_crd(
            "ExternalSecret",
            self.crds.external_secret.as_ref(),
            &compiled.workloads.external_secrets,
            |es| &es.metadata.name,
        )?;

        // Network policies
        layer1.push_crd(
            "CiliumNetworkPolicy",
            self.crds.cilium_network_policy.as_ref(),
            &compiled.policies.cilium_policies,
            |cnp| &cnp.metadata.name,
        )?;
        layer1.push_crd(
            "AuthorizationPolicy",
            self.crds.authorization_policy.as_ref(),
            &compiled.policies.authorization_policies,
            |p| &p.metadata.name,
        )?;
        layer1.push_crd(
            "ServiceEntry",
            self.crds.service_entry.as_ref(),
            &compiled.policies.service_entries,
            |e| &e.metadata.name,
        )?;

        // Ingress — Gateway uses per-service field manager for SSA listener merging.
        // Each service owns its own listeners via a unique field manager, so SSA
        // merges them automatically (Gateway listeners use `name` as merge key).
        if let Some(gw) = &compiled.ingress.gateway {
            if let Some(ar) = &self.crds.gateway {
                let gw_manager = format!("lattice-service-controller/{}", service_name);
                let gw_params = PatchParams::apply(&gw_manager).force();
                let mut gw_batch = ApplyBatch::new(self.client.clone(), namespace, &gw_params);
                gw_batch.push("Gateway", &gw.metadata.name, gw, ar)?;
                gw_batch.run("gateway").await?;
            } else {
                warn!("Gateway CRD not installed, skipping ingress");
            }
        }

        // Ingress routes and certificates
        layer1.push_crd(
            "HTTPRoute",
            self.crds.http_route.as_ref(),
            &compiled.ingress.http_routes,
            |r| &r.metadata.name,
        )?;
        layer1.push_crd(
            "GRPCRoute",
            self.crds.grpc_route.as_ref(),
            &compiled.ingress.grpc_routes,
            |r| &r.metadata.name,
        )?;
        layer1.push_crd(
            "TCPRoute",
            self.crds.tcp_route.as_ref(),
            &compiled.ingress.tcp_routes,
            |r| &r.metadata.name,
        )?;
        layer1.push_crd(
            "Certificate",
            self.crds.certificate.as_ref(),
            &compiled.ingress.certificates,
            |c| &c.metadata.name,
        )?;

        // Waypoint (east-west L7 policies via Istio ambient mesh)
        layer1.push_optional_crd(
            "Gateway",
            self.crds.gateway.as_ref(),
            compiled.waypoint.gateway.as_ref(),
            |gw| &gw.metadata.name,
        )?;
        layer1.push_optional_crd(
            "AuthorizationPolicy",
            self.crds.authorization_policy.as_ref(),
            compiled.waypoint.allow_to_waypoint_policy.as_ref(),
            |p| &p.metadata.name,
        )?;

        // Extension resources — infrastructure layer
        for ext in &compiled.extensions {
            if ext.layer == ApplyLayer::Infrastructure {
                layer1.push_dynamic(ext)?;
            }
        }

        let layer1_count = layer1.run("infrastructure").await?;

        // ── Wait: imagePullSecrets must exist before the Deployment ──
        // ESO syncs K8s Secrets from the ExternalSecrets applied above.
        // On subsequent reconciles the secrets already exist so this is instant.
        self.wait_for_image_pull_secrets(namespace, &compiled.workloads.deployment)
            .await?;

        // ── Layer 2: Deployment + workload extensions ──
        let mut layer2 = ApplyBatch::new(self.client.clone(), namespace, &params);
        if let Some(deployment) = &compiled.workloads.deployment {
            layer2.push(
                "Deployment",
                &deployment.metadata.name,
                deployment,
                &ar_deploy,
            )?;
        }
        for ext in &compiled.extensions {
            if ext.layer == ApplyLayer::Workload {
                layer2.push_dynamic(ext)?;
            }
        }
        let layer2_count = layer2.run("deployment").await?;

        // ── Layer 3: ScaledObject (KEDA) ──
        // Must be applied after the Deployment because KEDA's admission webhook
        // validates that the scaleTargetRef target exists.
        let mut layer3 = ApplyBatch::new(self.client.clone(), namespace, &params);
        layer3.push_optional_crd(
            "ScaledObject",
            self.crds.scaled_object.as_ref(),
            compiled.workloads.scaled_object.as_ref(),
            |so| &so.metadata.name,
        )?;
        let layer3_count = layer3.run("autoscaling").await?;

        info!(
            service = %service_name,
            namespace = %namespace,
            resources = layer1_count + layer2_count + layer3_count,
            "applied compiled resources"
        );
        Ok(())
    }
}

// =============================================================================
// ApplyBatch — parallel server-side-apply for K8s resources
// =============================================================================

/// Type alias for boxed futures used in parallel resource application.
type ApplyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>;

/// Collects server-side-apply operations and runs them in parallel.
///
/// All resources (native K8s types and discovered CRDs) are applied via
/// `DynamicObject` with an explicit `ApiResource`. For native types, construct
/// the `ApiResource` with `ApiResource::erase::<T>(&())`. For discovered CRDs,
/// use the `ApiResource` from `DiscoveredCrds`.
struct ApplyBatch<'a> {
    client: Client,
    futures: Vec<ApplyFuture>,
    namespace: &'a str,
    params: &'a PatchParams,
}

impl<'a> ApplyBatch<'a> {
    fn new(client: Client, namespace: &'a str, params: &'a PatchParams) -> Self {
        Self {
            client,
            futures: Vec::new(),
            namespace,
            params,
        }
    }

    /// Serialize a typed resource and queue a server-side-apply patch.
    fn push(
        &mut self,
        kind: &str,
        name: &str,
        resource: &impl serde::Serialize,
        ar: &ApiResource,
    ) -> Result<(), Error> {
        let json = serde_json::to_value(resource)
            .map_err(|e| Error::serialization(format!("{}: {}", kind, e)))?;
        self.push_json(kind, name, json, ar)
    }

    /// Queue a server-side-apply patch for a `DynamicResource` (pre-serialized JSON).
    fn push_dynamic(&mut self, ext: &crate::compiler::DynamicResource) -> Result<(), Error> {
        self.push_json(&ext.kind, &ext.name, ext.json.clone(), &ext.api_resource)
    }

    /// Queue a server-side-apply patch from raw JSON.
    ///
    /// Overrides `apiVersion` from the `ApiResource` so CRD versions always
    /// match what the server actually serves.
    fn push_json(
        &mut self,
        kind: &str,
        name: &str,
        mut json: serde_json::Value,
        ar: &ApiResource,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        if let Some(obj) = json.as_object_mut() {
            obj.insert(
                "apiVersion".to_string(),
                serde_json::Value::String(ar.api_version.clone()),
            );
        }

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), self.namespace, ar);
        let params = self.params.clone();
        let name = name.to_string();
        let kind = kind.to_string();
        self.futures.push(Box::pin(async move {
            debug!(name = %name, kind = %kind, "applying resource");
            api.patch(&name, &params, &Patch::Apply(&json)).await?;
            Ok(())
        }));
        Ok(())
    }

    /// Push a list of CRD-backed resources if the CRD is discovered, warn if not.
    ///
    /// This is the standard pattern for optional CRDs: apply if installed, warn
    /// if resources were compiled but the CRD is missing.
    fn push_crd<T: serde::Serialize>(
        &mut self,
        kind: &str,
        crd: Option<&ApiResource>,
        resources: &[T],
        name_fn: impl Fn(&T) -> &str,
    ) -> Result<(), Error> {
        if let Some(ar) = crd {
            for resource in resources {
                self.push(kind, name_fn(resource), resource, ar)?;
            }
        } else if !resources.is_empty() {
            warn!(
                count = resources.len(),
                kind = kind,
                "CRD not installed, skipping"
            );
        }
        Ok(())
    }

    /// Push a single optional CRD-backed resource if both it and the CRD exist.
    fn push_optional_crd<T: serde::Serialize>(
        &mut self,
        kind: &str,
        crd: Option<&ApiResource>,
        resource: Option<&T>,
        name_fn: impl Fn(&T) -> &str,
    ) -> Result<(), Error> {
        let Some(resource) = resource else {
            return Ok(());
        };
        if let Some(ar) = crd {
            self.push(kind, name_fn(resource), resource, ar)?;
        } else {
            warn!(kind = kind, "CRD not installed, skipping");
        }
        Ok(())
    }

    /// Execute all queued patches in parallel, returning the count applied.
    async fn run(self, layer: &str) -> Result<usize, Error> {
        use futures::future::join_all;

        let count = self.futures.len();
        if count == 0 {
            return Ok(0);
        }

        debug!(count, layer, "applying resources in parallel");
        let results = join_all(self.futures).await;

        let mut errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();
        if !errors.is_empty() {
            for (i, err) in errors.iter().enumerate() {
                error!(error = %err, index = i, layer, "resource application failed");
            }
            return Err(errors.swap_remove(0));
        }

        Ok(count)
    }
}

impl ServiceKubeClientImpl {
    /// Wait for imagePullSecrets K8s Secrets to exist before applying the Deployment.
    ///
    /// ESO creates K8s Secrets from the ExternalSecrets applied in Layer 1. If the
    /// Deployment references those secrets via `imagePullSecrets` and they don't exist
    /// yet, kubelet enters `ImagePullBackOff` with exponential backoff (up to 5 min).
    /// Polling here is cheap: on subsequent reconciles the secrets already exist so
    /// `get_opt` returns immediately.
    async fn wait_for_image_pull_secrets(
        &self,
        namespace: &str,
        deployment: &Option<crate::workload::Deployment>,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Secret as K8sSecret;

        let deployment = match deployment {
            Some(d) => d,
            None => return Ok(()),
        };

        let secret_names: Vec<&str> = deployment
            .spec
            .template
            .spec
            .image_pull_secrets
            .iter()
            .map(|r| r.name.as_str())
            .collect();

        if secret_names.is_empty() {
            return Ok(());
        }

        let api: Api<K8sSecret> = Api::namespaced(self.client.clone(), namespace);
        let timeout = Duration::from_secs(120);
        let poll_interval = Duration::from_secs(2);

        for secret_name in &secret_names {
            let start = std::time::Instant::now();
            loop {
                match api.get_opt(secret_name).await? {
                    Some(_) => {
                        debug!(secret = %secret_name, "imagePullSecret exists");
                        break;
                    }
                    None => {
                        if start.elapsed() >= timeout {
                            return Err(Error::internal_with_context(
                                "wait_for_image_pull_secrets",
                                format!(
                                    "timed out waiting for imagePullSecret '{}' in namespace '{}'",
                                    secret_name, namespace
                                ),
                            ));
                        }
                        debug!(
                            secret = %secret_name,
                            elapsed = ?start.elapsed(),
                            "waiting for imagePullSecret to be synced by ESO"
                        );
                        tokio::time::sleep(poll_interval).await;
                    }
                }
            }
        }

        info!(
            count = secret_names.len(),
            namespace = %namespace,
            "all imagePullSecrets available"
        );
        Ok(())
    }
}

// =============================================================================
// Controller context
// =============================================================================

/// Controller context containing shared state and clients
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients)
/// and shared state (like the ServiceGraph).
pub struct ServiceContext {
    /// Kubernetes client for API operations
    pub kube: Arc<dyn ServiceKubeClient>,
    /// Service dependency graph (shared across all reconciliations)
    pub graph: Arc<ServiceGraph>,
    /// Cluster name used in trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
    /// Provider type for topology-aware scheduling (zone for cloud, hostname for on-prem)
    pub provider_type: ProviderType,
    /// Cedar policy engine for secret access authorization
    pub cedar: Arc<PolicyEngine>,
    /// Event publisher for emitting Kubernetes Events
    pub events: Arc<dyn EventPublisher>,
    /// Monitoring configuration for this cluster (VictoriaMetrics mode)
    pub monitoring: MonitoringConfig,
    /// Extension phases that run after core compilation
    pub extension_phases: Vec<Arc<dyn CompilerPhase>>,
}

impl ServiceContext {
    /// Create a new ServiceContext with the given dependencies
    pub fn new(
        kube: Arc<dyn ServiceKubeClient>,
        graph: Arc<ServiceGraph>,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        events: Arc<dyn EventPublisher>,
        monitoring: MonitoringConfig,
    ) -> Self {
        Self {
            kube,
            graph,
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            events,
            monitoring,
            extension_phases: Vec::new(),
        }
    }

    /// Create a new ServiceContext from a Kubernetes client with discovered CRDs
    ///
    /// This creates a new ServiceGraph and default-deny PolicyEngine.
    /// For shared state, create dependencies externally and use the constructor.
    pub fn from_client(
        client: Client,
        cluster_name: impl Into<String>,
        provider_type: ProviderType,
        cedar: Arc<PolicyEngine>,
        crds: Arc<DiscoveredCrds>,
        monitoring: MonitoringConfig,
    ) -> Self {
        let events = Arc::new(KubeEventPublisher::new(
            client.clone(),
            "lattice-service-controller",
        ));
        Self {
            kube: Arc::new(ServiceKubeClientImpl::new(client, crds)),
            graph: Arc::new(ServiceGraph::new()),
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            events,
            monitoring,
            extension_phases: Vec::new(),
        }
    }

    /// Create a context for testing with mock clients
    ///
    /// Uses a default-deny PolicyEngine. To test with policies, construct
    /// `ServiceContext` directly with a configured `PolicyEngine`.
    #[cfg(test)]
    pub fn for_testing(kube: Arc<dyn ServiceKubeClient>) -> Self {
        Self {
            kube,
            graph: Arc::new(ServiceGraph::new()),
            cluster_name: "test-cluster".to_string(),
            provider_type: ProviderType::Docker,
            cedar: Arc::new(PolicyEngine::new()),
            events: Arc::new(NoopEventPublisher),
            monitoring: MonitoringConfig::default(),
            extension_phases: Vec::new(),
        }
    }
}

// =============================================================================
// LatticeService reconciliation
// =============================================================================

/// Reconcile a LatticeService resource
///
/// This function is called whenever a LatticeService is created, updated, or deleted.
/// It maintains the service graph and updates the service status.
///
/// # Arguments
///
/// * `service` - The LatticeService to reconcile
/// * `ctx` - Shared controller context
///
/// # Returns
///
/// An `Action` indicating when to requeue, or an `Error` if reconciliation failed.
#[instrument(skip(service, ctx), fields(service = %service.name_any()))]
pub async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<ServiceContext>,
) -> Result<Action, Error> {
    let name = service.name_any();
    info!("reconciling service");

    // Validate the service spec
    if let Err(e) = service.spec.workload.validate() {
        warn!(error = %e, "service validation failed");
        update_service_status(&service, &ctx, ServiceStatusUpdate::failed(&e.to_string())).await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = service
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ServicePhase::Pending);

    debug!(?current_phase, "current service phase");

    // Get namespace from metadata (LatticeService is namespace-scoped)
    let namespace = match service.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            error!("LatticeService is missing namespace - this is a cluster-scoped resource that needs migration");
            update_service_status(
                &service,
                &ctx,
                ServiceStatusUpdate::failed("Resource missing namespace"),
            )
            .await?;
            return Ok(Action::await_change());
        }
    };

    // Always ensure this service is in the graph (crash recovery)
    // This is idempotent - put_service handles updates correctly
    ctx.graph.put_service(namespace, &name, &service.spec);

    // State machine: transition based on current phase
    match current_phase {
        ServicePhase::Pending => {
            update_service_status(&service, &ctx, ServiceStatusUpdate::compiling()).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ServicePhase::Compiling => {
            let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, namespace);
            if !missing_deps.is_empty() {
                debug!(?missing_deps, "waiting for dependencies");
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            let active_in = ctx.graph.get_active_inbound_edges(namespace, &name);
            let active_out = ctx.graph.get_active_outbound_edges(namespace, &name);
            debug!(
                active_inbound = active_in.len(),
                active_outbound = active_out.len(),
                "edge status"
            );

            try_compile(&service, &name, namespace, &ctx).await
        }
        ServicePhase::Ready => {
            let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, namespace);
            if !missing_deps.is_empty() {
                warn!(?missing_deps, "dependencies no longer available");
                update_service_status(&service, &ctx, ServiceStatusUpdate::compiling()).await?;
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            try_compile(&service, &name, namespace, &ctx).await
        }
        ServicePhase::Failed => try_compile(&service, &name, namespace, &ctx).await,
    }
}

/// Error policy for LatticeService and LatticeExternalService controllers (kube-rs callback).
///
/// Retryable errors (transient): requeue after 30 seconds.
/// Non-retryable errors (permanent): await spec change.
pub fn error_policy<T: ResourceExt>(
    resource: Arc<T>,
    error: &Error,
    _ctx: Arc<ServiceContext>,
) -> Action {
    error!(
        ?error,
        resource = %resource.name_any(),
        retryable = error.is_retryable(),
        "reconciliation failed"
    );

    if error.is_retryable() {
        Action::requeue(Duration::from_secs(30))
    } else {
        Action::await_change()
    }
}

/// Check which dependencies are missing from the graph
fn check_missing_dependencies(
    spec: &LatticeServiceSpec,
    graph: &ServiceGraph,
    namespace: &str,
) -> Vec<String> {
    spec.workload
        .internal_dependencies(namespace)
        .into_iter()
        .filter(|dep| {
            // Check if dependency exists (not Unknown type)
            let dep_ns = dep.resolve_namespace(namespace);
            graph
                .get_service(dep_ns, &dep.name)
                .map(|node| node.type_ == crate::graph::ServiceType::Unknown)
                .unwrap_or(true)
        })
        .map(|dep| {
            // Format as "namespace/name" for cross-namespace deps, just "name" for same namespace
            let dep_ns = dep.resolve_namespace(namespace);
            if dep_ns == namespace {
                dep.name
            } else {
                format!("{}/{}", dep_ns, dep.name)
            }
        })
        .collect()
}

/// Resolve policy defaults (backup + ingress) for a service in one pass.
///
/// Reads cached policies and namespace labels from the ServiceGraph.
/// On the first reconcile for a namespace, fetches labels from the API
/// server and caches them in the graph.
///
/// Extracts:
/// - Backup: merged from matching policies (priority-ordered) + inline spec
/// - Ingress: first matching policy with ingress set wins (no deep merge)
async fn resolve_policy_defaults(
    service: &LatticeService,
    namespace: &str,
    ctx: &ServiceContext,
) -> (
    Option<ServiceBackupSpec>,
    Option<crate::crd::IngressPolicySpec>,
) {
    // Ensure namespace labels are cached
    if ctx.graph.get_namespace_labels(namespace).is_none() {
        match ctx.kube.get_namespace_labels(namespace).await {
            Ok(labels) => ctx.graph.put_namespace_labels(namespace, labels),
            Err(e) => {
                debug!(error = %e, "failed to get namespace labels");
            }
        }
    }

    let svc_labels = service.labels();
    let matched = ctx.graph.matching_policies(&svc_labels, namespace);
    if matched.is_empty() {
        return (None, None);
    }

    // Backup: merge matching policy backup specs with inline spec
    let policy_backup_specs: Vec<&ServiceBackupSpec> =
        matched.iter().filter_map(|p| p.backup.as_ref()).collect();
    let effective_backup = if policy_backup_specs.is_empty() {
        None
    } else {
        merge_backup_specs(&policy_backup_specs, service.spec.backup.as_ref())
    };

    // Ingress: first matching policy with ingress wins
    let ingress_defaults = matched.into_iter().find_map(|p| p.ingress);

    (effective_backup, ingress_defaults)
}

/// Try compiling and applying a service. On success, transition to Ready.
/// On failure, compile_and_apply already sets status to Failed; requeue to retry.
///
/// This is the shared compilation path for Compiling, Ready, and Failed phases.
/// Using `match` instead of `?` prevents CompilationError → Error::Validation
/// → error_policy → Action::await_change() from permanently parking the service.
async fn try_compile(
    service: &LatticeService,
    name: &str,
    namespace: &str,
    ctx: &ServiceContext,
) -> Result<Action, Error> {
    match compile_and_apply(service, name, namespace, ctx).await {
        Ok(()) => {
            update_service_status(service, ctx, ServiceStatusUpdate::ready()).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        Err(_) => {
            // compile_and_apply already set status to Failed
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

/// Compile a service and apply the resulting resources to the cluster.
///
/// On compile failure, publishes a warning event and sets the service to Failed.
/// On apply failure, sets the service to Failed and returns the error.
async fn compile_and_apply(
    service: &LatticeService,
    name: &str,
    namespace: &str,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    // Resolve policy defaults (backup + ingress) in one pass
    let (effective_backup, ingress_defaults) =
        resolve_policy_defaults(service, namespace, ctx).await;

    // Apply ingress defaults to service if needed
    let mut service_with_defaults;
    let effective_service = if let (Some(ref ingress_spec), Some(ref defaults)) =
        (&service.spec.ingress, &ingress_defaults)
    {
        let mut ingress = ingress_spec.clone();
        // Apply default gateway class if not set
        if ingress.gateway_class.is_none() {
            ingress.gateway_class.clone_from(&defaults.gateway_class);
        }
        // Apply default TLS to routes that have no TLS
        if let Some(ref default_tls) = defaults.tls {
            for (_route_name, route) in ingress.routes.iter_mut() {
                if route.tls.is_none() {
                    route.tls = Some(default_tls.clone());
                }
            }
        }
        service_with_defaults = service.clone();
        service_with_defaults.spec.ingress = Some(ingress);
        &service_with_defaults
    } else {
        service
    };

    let compiler = ServiceCompiler::new(
        &ctx.graph,
        &ctx.cluster_name,
        ctx.provider_type,
        &ctx.cedar,
        ctx.monitoring.clone(),
    )
    .with_phases(&ctx.extension_phases)
    .with_effective_backup(effective_backup);
    let compiled = match compiler.compile(effective_service).await {
        Ok(compiled) => compiled,
        Err(e) => {
            let msg = e.to_string();

            // Skip redundant events when status hasn't changed (status update
            // itself is guarded by update_service_status's idempotency check).
            if !is_status_unchanged(service, ServicePhase::Failed, &msg) {
                let event_reason = if e.is_policy_denied() {
                    match &e {
                        crate::workload::CompilationError::SecurityOverrideDenied { .. } => {
                            reasons::SECURITY_OVERRIDE_DENIED
                        }
                        crate::workload::CompilationError::VolumeAccessDenied { .. } => {
                            reasons::VOLUME_ACCESS_DENIED
                        }
                        _ => reasons::SECRET_ACCESS_DENIED,
                    }
                } else {
                    reasons::COMPILATION_FAILED
                };
                ctx.events
                    .publish(
                        &service.object_ref(&()),
                        EventType::Warning,
                        event_reason,
                        actions::COMPILE,
                        Some(msg.clone()),
                    )
                    .await;
                warn!(error = %msg, "compilation failed");
            } else {
                debug!(error = %msg, "compilation still failing");
            }

            update_service_status(service, ctx, ServiceStatusUpdate::failed(&msg)).await?;
            return Err(Error::from(e));
        }
    };

    debug!(
        resources = compiled.resource_count(),
        "applying compiled resources"
    );
    if let Err(e) = ctx
        .kube
        .apply_compiled_service(name, namespace, &compiled)
        .await
    {
        let msg = e.to_string();
        if !is_status_unchanged(service, ServicePhase::Failed, &msg) {
            error!(error = %msg, "failed to apply compiled resources");
        } else {
            debug!(error = %msg, "apply still failing");
        }
        update_service_status(service, ctx, ServiceStatusUpdate::failed(&msg)).await?;
        return Err(e);
    }

    Ok(())
}

// =============================================================================
// LatticeExternalService reconciliation
// =============================================================================

/// Reconcile a LatticeExternalService resource
///
/// This function is called whenever a LatticeExternalService is created, updated, or deleted.
/// It maintains the service graph for network policy generation.
#[instrument(skip(external, ctx), fields(external_service = %external.name_any()))]
pub async fn reconcile_external(
    external: Arc<LatticeExternalService>,
    ctx: Arc<ServiceContext>,
) -> Result<Action, Error> {
    let name = external.name_any();
    info!("reconciling external service");

    // Validate the external service spec
    if let Err(e) = external.spec.validate() {
        warn!(error = %e, "external service validation failed");
        update_external_status(
            &external,
            &ctx,
            ExternalStatusUpdate::failed(&e.to_string()),
        )
        .await?;
        return Ok(Action::await_change());
    }

    // Get namespace from metadata (LatticeExternalService is namespace-scoped)
    let namespace = match external.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            error!("LatticeExternalService is missing namespace - this is a cluster-scoped resource that needs migration");
            update_external_status(
                &external,
                &ctx,
                ExternalStatusUpdate::failed("Resource missing namespace"),
            )
            .await?;
            return Ok(Action::await_change());
        }
    };

    // Update graph with this external service
    ctx.graph
        .put_external_service(namespace, &name, &external.spec);

    // update_external_status skips the patch if already Ready with same message
    update_external_status(&external, &ctx, ExternalStatusUpdate::ready()).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

// =============================================================================
// Service cleanup on delete
// =============================================================================

/// Handle service deletion by removing from the graph
///
/// Called when a LatticeService is deleted. Removes the service from the graph
/// and cleans up edges.
pub fn cleanup_service(service: &LatticeService, ctx: &ServiceContext) {
    let name = service.name_any();
    let namespace = match service.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            warn!(service = %name, "LatticeService missing namespace during cleanup, skipping");
            return;
        }
    };

    info!(service = %name, namespace = %namespace, "removing service from graph");
    ctx.graph.delete_service(namespace, &name);
}

/// Handle external service deletion by removing from the graph
pub fn cleanup_external_service(external: &LatticeExternalService, ctx: &ServiceContext) {
    let name = external.name_any();
    let namespace = match external.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            warn!(external_service = %name, "LatticeExternalService missing namespace during cleanup, skipping");
            return;
        }
    };

    info!(external_service = %name, namespace = %namespace, "removing external service from graph");
    ctx.graph.delete_service(namespace, &name);
}

// =============================================================================
// Status update helpers
// =============================================================================

/// Status update configuration for LatticeService
struct ServiceStatusUpdate<'a> {
    phase: ServicePhase,
    message: &'a str,
    condition_type: &'a str,
    condition_status: ConditionStatus,
    reason: &'a str,
    set_compiled_at: bool,
}

impl<'a> ServiceStatusUpdate<'a> {
    fn compiling() -> Self {
        Self {
            phase: ServicePhase::Compiling,
            message: "Compiling service dependencies",
            condition_type: "Compiling",
            condition_status: ConditionStatus::True,
            reason: "DependencyCheck",
            set_compiled_at: false,
        }
    }

    fn ready() -> Self {
        Self {
            phase: ServicePhase::Ready,
            message: "Service is operational",
            condition_type: "Ready",
            condition_status: ConditionStatus::True,
            reason: "ServiceReady",
            set_compiled_at: true,
        }
    }

    fn failed(message: &'a str) -> Self {
        Self {
            phase: ServicePhase::Failed,
            message,
            condition_type: "Ready",
            condition_status: ConditionStatus::False,
            reason: "ValidationFailed",
            set_compiled_at: false,
        }
    }
}

/// Check if the service status already matches — avoids update loop.
///
/// Same pattern as CloudProvider and SecretProvider: skip redundant patches
/// because `Condition::new()` stamps a fresh `lastTransitionTime` on every call,
/// making every merge patch "different" and generating a watch event that triggers
/// another reconcile.
fn is_status_unchanged(service: &LatticeService, phase: ServicePhase, message: &str) -> bool {
    service
        .status
        .as_ref()
        .map(|s| s.phase == phase && s.message.as_deref() == Some(message))
        .unwrap_or(false)
}

/// Update LatticeService status with the given configuration.
///
/// Skips the patch if phase and message already match the current status,
/// preventing a self-triggering reconcile storm.
async fn update_service_status(
    service: &LatticeService,
    ctx: &ServiceContext,
    update: ServiceStatusUpdate<'_>,
) -> Result<(), Error> {
    // Check if status already matches — avoid update loop
    if is_status_unchanged(service, update.phase, update.message) {
        debug!("status unchanged, skipping update");
        return Ok(());
    }

    let name = service.name_any();
    let namespace = service.namespace().unwrap_or_default();

    let mut status = LatticeServiceStatus::with_phase(update.phase)
        .message(update.message)
        .condition(Condition::new(
            update.condition_type,
            update.condition_status,
            update.reason,
            update.message,
        ));

    if update.set_compiled_at {
        status = status.compiled_at(Utc::now());
    }

    ctx.kube
        .patch_service_status(&name, &namespace, &status)
        .await
}

/// Status update configuration for LatticeExternalService
struct ExternalStatusUpdate<'a> {
    phase: crate::crd::ExternalServicePhase,
    message: &'a str,
    condition_type: &'a str,
    condition_status: ConditionStatus,
    reason: &'a str,
}

impl<'a> ExternalStatusUpdate<'a> {
    fn ready() -> Self {
        Self {
            phase: crate::crd::ExternalServicePhase::Ready,
            message: "External service is configured",
            condition_type: "Ready",
            condition_status: ConditionStatus::True,
            reason: "EndpointsConfigured",
        }
    }

    fn failed(message: &'a str) -> Self {
        Self {
            phase: crate::crd::ExternalServicePhase::Failed,
            message,
            condition_type: "Ready",
            condition_status: ConditionStatus::False,
            reason: "ValidationFailed",
        }
    }
}

fn is_external_status_unchanged(
    external: &LatticeExternalService,
    phase: crate::crd::ExternalServicePhase,
    message: &str,
) -> bool {
    external
        .status
        .as_ref()
        .map(|s| s.phase == phase && s.message.as_deref() == Some(message))
        .unwrap_or(false)
}

async fn update_external_status(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
    update: ExternalStatusUpdate<'_>,
) -> Result<(), Error> {
    if is_external_status_unchanged(external, update.phase, update.message) {
        debug!("external service status unchanged, skipping update");
        return Ok(());
    }

    let name = external.name_any();
    let namespace = external.namespace().unwrap_or_default();
    let status = LatticeExternalServiceStatus::with_phase(update.phase)
        .message(update.message)
        .condition(Condition::new(
            update.condition_type,
            update.condition_status,
            update.reason,
            update.message,
        ));

    ctx.kube
        .patch_external_service_status(&name, &namespace, &status)
        .await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        BackupHook, BackupHooksSpec, ContainerSpec, DependencyDirection, HookErrorAction,
        LatticeExternalServiceSpec, LatticeServicePolicySpec, Resolution, ResourceSpec,
        ServiceSelector, VolumeBackupDefault, VolumeBackupSpec, WorkloadSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            resources: Some(lattice_common::crd::ResourceRequirements {
                limits: Some(lattice_common::crd::ResourceQuantity {
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

    fn sample_service(name: &str) -> LatticeService {
        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec: sample_service_spec(),
            status: None,
        }
    }

    fn service_with_deps(name: &str, deps: Vec<&str>) -> LatticeService {
        let mut spec = sample_service_spec();
        for dep in deps {
            spec.workload.resources.insert(
                dep.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn service_with_callers(name: &str, callers: Vec<&str>) -> LatticeService {
        let mut spec = sample_service_spec();
        for caller in callers {
            spec.workload.resources.insert(
                caller.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn sample_external_service(name: &str) -> LatticeExternalService {
        let mut endpoints = BTreeMap::new();
        endpoints.insert("api".to_string(), "https://api.example.com".to_string());

        LatticeExternalService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("test".to_string()),
                ..Default::default()
            },
            spec: LatticeExternalServiceSpec {
                endpoints,
                allowed_requesters: vec!["*".to_string()],
                resolution: Resolution::Dns,
                description: None,
            },
            status: None,
        }
    }

    // =========================================================================
    // Mock Setup
    // =========================================================================

    fn mock_kube_with_policies(policies: Vec<LatticeServicePolicy>) -> MockServiceKubeClient {
        let mut mock = MockServiceKubeClient::new();
        mock.expect_patch_service_status()
            .returning(|_, _, _| Ok(()));
        mock.expect_patch_external_service_status()
            .returning(|_, _, _| Ok(()));
        mock.expect_get_service().returning(|_, _| Ok(None));
        mock.expect_get_external_service()
            .returning(|_, _| Ok(None));
        mock.expect_list_services().returning(|| Ok(vec![]));
        mock.expect_list_external_services()
            .returning(|| Ok(vec![]));
        mock.expect_list_policies()
            .returning(move || Ok(policies.clone()));
        mock.expect_get_namespace_labels()
            .returning(|_| Ok(BTreeMap::new()));
        mock.expect_apply_compiled_service()
            .returning(|_, _, _| Ok(()));
        mock
    }

    /// Helper to populate the graph with policies from LatticeServicePolicy objects
    fn populate_graph_policies(ctx: &ServiceContext, policies: &[LatticeServicePolicy]) {
        for p in policies {
            ctx.graph.put_policy(p.into());
        }
    }

    fn make_hook(name: &str, cmd: &str) -> BackupHook {
        BackupHook {
            name: name.to_string(),
            container: "main".to_string(),
            command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd.to_string()],
            timeout: None,
            on_error: HookErrorAction::Continue,
        }
    }

    // =========================================================================
    // Reconciliation Story Tests
    // =========================================================================

    /// Story: New service transitions from Pending to Compiling
    #[tokio::test]
    async fn new_service_transitions_to_compiling() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx.clone())
            .await
            .expect("reconcile should succeed");

        // Should requeue quickly to check dependencies
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));

        // Service should be in the graph
        let node = ctx.graph.get_service("test", "my-service");
        assert!(node.is_some());
    }

    /// Story: Service with dependencies waits for them
    #[tokio::test]
    async fn service_waits_for_dependencies() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Put the service in the graph first
        ctx.graph.put_service("test", "frontend", &service.spec);

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should requeue to wait for dependencies
        assert_eq!(action, Action::requeue(Duration::from_secs(10)));
    }

    /// Story: Service becomes ready when dependencies exist
    #[tokio::test]
    async fn service_becomes_ready_with_deps() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add both services to graph
        ctx.graph.put_service("test", "frontend", &service.spec);
        ctx.graph
            .put_service("test", "backend", &sample_service_spec());

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should transition to Ready and requeue periodically
        assert_eq!(action, Action::requeue(Duration::from_secs(60)));
    }

    /// Story: Service in Ready state stays ready
    #[tokio::test]
    async fn ready_service_stays_ready() {
        let mut service = sample_service("my-service");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Ready));
        let service = Arc::new(service);

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        ctx.graph.put_service("test", "my-service", &service.spec);

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should requeue for periodic drift check
        assert_eq!(action, Action::requeue(Duration::from_secs(60)));
    }

    /// Story: Invalid service transitions to Failed
    #[tokio::test]
    async fn invalid_service_fails() {
        let mut service = sample_service("bad-service");
        // Make it invalid by removing containers
        service.spec.workload.containers.clear();
        let service = Arc::new(service);

        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should await change (no requeue)
        assert_eq!(action, Action::await_change());
    }

    /// Story: External service reconciles immediately to Ready
    #[tokio::test]
    async fn external_service_becomes_ready() {
        let external = Arc::new(sample_external_service("stripe"));
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile_external(external, ctx.clone())
            .await
            .expect("reconcile_external should succeed");

        // Should requeue periodically
        assert_eq!(action, Action::requeue(Duration::from_secs(60)));

        // External service should be in graph
        let node = ctx.graph.get_service("test", "stripe");
        assert!(node.is_some());
    }

    // =========================================================================
    // Graph Integration Tests
    // =========================================================================

    /// Story: Graph tracks active edges with bilateral agreements
    #[tokio::test]
    async fn graph_tracks_bilateral_agreements() {
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Frontend depends on backend
        let frontend = service_with_deps("frontend", vec!["backend"]);
        ctx.graph.put_service("test", "frontend", &frontend.spec);

        // Backend allows frontend
        let backend = service_with_callers("backend", vec!["frontend"]);
        ctx.graph.put_service("test", "backend", &backend.spec);

        // Should have active edge from frontend to backend
        let active = ctx.graph.get_active_outbound_edges("test", "frontend");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].callee_name, "backend");
    }

    /// Story: Graph handles service deletion
    #[tokio::test]
    async fn graph_handles_deletion() {
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add a service
        ctx.graph
            .put_service("test", "my-service", &sample_service_spec());
        assert!(ctx.graph.get_service("test", "my-service").is_some());

        // Create and cleanup
        let service = sample_service("my-service");
        cleanup_service(&service, &ctx);

        // Should be removed
        assert!(ctx.graph.get_service("test", "my-service").is_none());
    }

    // =========================================================================
    // Error Policy Tests
    // =========================================================================

    /// Story: Error policy distinguishes retryable vs non-retryable errors
    #[test]
    fn error_policy_requeues() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Validation errors are NOT retryable - should await spec change
        let validation_error = Error::validation("test error");
        let action = error_policy(Arc::clone(&service), &validation_error, Arc::clone(&ctx));
        assert_eq!(action, Action::await_change());

        // Bootstrap errors ARE retryable - should requeue with backoff
        let retryable_error = Error::bootstrap("connection timeout");
        let action = error_policy(service, &retryable_error, ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    // =========================================================================
    // Missing Dependency Detection Tests
    // =========================================================================

    /// Story: Detect missing internal dependencies
    #[test]
    fn detect_missing_dependencies() {
        let graph = ServiceGraph::new();
        let spec = service_with_deps("frontend", vec!["backend", "cache"]).spec;

        // Nothing in graph - all deps missing
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"backend".to_string()));
        assert!(missing.contains(&"cache".to_string()));

        // Add backend - now only cache is missing
        graph.put_service("test", "backend", &sample_service_spec());
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&"cache".to_string()));

        // Add cache - no deps missing
        graph.put_service("test", "cache", &sample_service_spec());
        let missing = check_missing_dependencies(&spec, &graph, "test");
        assert!(missing.is_empty());
    }

    // =========================================================================
    // Environment Isolation Tests
    // =========================================================================

    /// Story: Services are isolated by environment
    #[tokio::test]
    async fn services_isolated_by_environment() {
        let mock_kube = mock_kube_with_policies(vec![]);
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        // Add same-named service to different environments
        ctx.graph.put_service("prod", "api", &sample_service_spec());
        ctx.graph
            .put_service("staging", "api", &sample_service_spec());

        // Both should exist independently
        assert!(ctx.graph.get_service("prod", "api").is_some());
        assert!(ctx.graph.get_service("staging", "api").is_some());

        // Deleting one shouldn't affect the other
        ctx.graph.delete_service("prod", "api");
        assert!(ctx.graph.get_service("prod", "api").is_none());
        assert!(ctx.graph.get_service("staging", "api").is_some());
    }

    // =========================================================================
    // Context Builder Tests
    // =========================================================================

    /// Story: Context can share graph across instances
    #[test]
    fn shared_graph_across_contexts() {
        let mock_kube1 = Arc::new(mock_kube_with_policies(vec![]));
        let mock_kube2 = Arc::new(mock_kube_with_policies(vec![]));
        let shared_graph = Arc::new(ServiceGraph::new());
        let cedar = Arc::new(PolicyEngine::new());

        let ctx1 = ServiceContext::new(
            mock_kube1,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            MonitoringConfig::default(),
        );
        let ctx2 = ServiceContext::new(
            mock_kube2,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
            MonitoringConfig::default(),
        );

        // Add service via ctx1
        ctx1.graph
            .put_service("shared", "svc", &sample_service_spec());

        // Should be visible via ctx2
        assert!(ctx2.graph.get_service("shared", "svc").is_some());
    }

    // =========================================================================
    // Story: Policy-based backup merging in compile_and_apply
    // =========================================================================

    fn make_policy(
        name: &str,
        namespace: &str,
        priority: i32,
        backup: Option<ServiceBackupSpec>,
    ) -> LatticeServicePolicy {
        LatticeServicePolicy {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: LatticeServicePolicySpec {
                selector: ServiceSelector::default(), // matches all in same namespace
                description: None,
                priority,
                backup,
                ingress: None,
            },
            status: None,
        }
    }

    /// Story: When policies with backup specs match a service, compile_and_apply
    /// produces backup annotations on the deployment
    #[tokio::test]
    async fn policy_backup_applied_to_service() {
        let policy_backup = ServiceBackupSpec {
            hooks: Some(BackupHooksSpec {
                pre: vec![BackupHook {
                    timeout: Some("60s".to_string()),
                    on_error: HookErrorAction::Fail,
                    ..make_hook("policy-freeze", "sync")
                }],
                post: vec![],
            }),
            volumes: Some(VolumeBackupSpec {
                include: vec!["data".to_string()],
                exclude: vec![],
                default_policy: VolumeBackupDefault::OptIn,
            }),
        };

        let policy = make_policy("db-backup", "test", 100, Some(policy_backup));
        let mock_kube = mock_kube_with_policies(vec![]);

        let mut service = sample_service("my-db");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));

        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &[policy]);
        ctx.graph.put_service("test", "my-db", &service.spec);

        let result = reconcile(Arc::new(service), ctx).await;
        assert!(result.is_ok());
    }

    /// Story: resolve_policy_defaults merges policy + inline correctly
    #[tokio::test]
    async fn resolve_effective_backup_merges_policies() {
        // Low-priority policy: hooks + volumes
        let low_policy = make_policy(
            "low",
            "test",
            10,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("low-hook", "low")],
                    post: vec![],
                }),
                volumes: Some(VolumeBackupSpec {
                    include: vec!["low-vol".to_string()],
                    exclude: vec![],
                    default_policy: VolumeBackupDefault::OptIn,
                }),
            }),
        );

        // High-priority policy: hooks override low, no volumes
        let high_policy = make_policy(
            "high",
            "test",
            100,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("high-hook", "high")],
                    post: vec![],
                }),
                volumes: None,
            }),
        );

        let policies = vec![low_policy, high_policy];
        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &policies);

        let (backup, _ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        let backup = backup.expect("should have merged backup");
        // Hooks from high-priority policy
        assert_eq!(backup.hooks.as_ref().unwrap().pre[0].name, "high-hook");
        // Volumes from low-priority (high didn't set them)
        assert_eq!(backup.volumes.as_ref().unwrap().include, vec!["low-vol"]);
    }

    /// Story: No matching policies returns None
    #[tokio::test]
    async fn resolve_effective_backup_no_policies() {
        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let (backup, ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        assert!(backup.is_none());
        assert!(ingress.is_none());
    }

    /// Story: Policy matches only same namespace when no namespace selector
    #[tokio::test]
    async fn resolve_effective_backup_namespace_scoping() {
        // Policy in "other" namespace — should NOT match service in "test"
        let policy = make_policy(
            "other-ns-policy",
            "other",
            100,
            Some(ServiceBackupSpec {
                hooks: Some(BackupHooksSpec {
                    pre: vec![make_hook("should-not-match", "true")],
                    post: vec![],
                }),
                volumes: None,
            }),
        );

        let mock_kube = mock_kube_with_policies(vec![]);
        let service = sample_service("my-app");
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));
        populate_graph_policies(&ctx, &[policy]);

        let (backup, _ingress) = resolve_policy_defaults(&service, "test", &ctx).await;

        // Policy is in "other" namespace, service is in "test" — no match
        assert!(backup.is_none());
    }
}
