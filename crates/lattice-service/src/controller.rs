//! LatticeService controller implementation
//!
//! This module implements the reconciliation logic for LatticeService resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.
//!
//! The controller maintains a ServiceGraph for tracking service dependencies
//! and allowed callers for network policy generation.

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

use crate::compiler::{CompileError, CompiledService, ServiceCompiler};
use crate::crd::{
    Condition, ConditionStatus, LatticeExternalService, LatticeExternalServiceStatus,
    LatticeService, LatticeServiceSpec, LatticeServiceStatus, ProviderType, ServicePhase,
};
use crate::graph::ServiceGraph;
use crate::ingress::{Certificate, Gateway, HttpRoute};
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
    pub certificate: Option<ApiResource>,
}

impl DiscoveredCrds {
    /// Discover installed CRD versions from the API server.
    ///
    /// Runs a single API discovery and looks up each third-party CRD.
    /// Missing CRDs result in `None` (not an error).
    pub async fn discover(client: &Client) -> Self {
        use kube::discovery::Discovery;

        let discovery = match Discovery::new(client.clone()).run().await {
            Ok(d) => Some(d),
            Err(e) => {
                warn!(error = %e, "API discovery failed, falling back to hardcoded CRD versions");
                return Self::hardcoded_defaults();
            }
        };
        let discovery = discovery.unwrap();

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
            certificate: Self::find_resource(&discovery, "cert-manager.io", "Certificate"),
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
        use lattice_secrets_provider::ExternalSecret;

        Self {
            external_secret: Some(ExternalSecret::api_resource()),
            cilium_network_policy: Some(CiliumNetworkPolicy::api_resource()),
            authorization_policy: Some(AuthorizationPolicy::api_resource()),
            service_entry: Some(ServiceEntry::api_resource()),
            gateway: Some(Gateway::api_resource()),
            http_route: Some(HttpRoute::api_resource()),
            certificate: Some(Certificate::api_resource()),
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

impl ServiceKubeClientImpl {
    /// Create a new ServiceKubeClientImpl wrapping the given client and discovered CRDs
    pub fn new(client: Client, crds: Arc<DiscoveredCrds>) -> Self {
        Self { client, crds }
    }

    /// Ensure a namespace exists with ambient mode labels for Istio traffic routing.
    ///
    /// Istio ambient mode requires namespaces to have:
    /// - `istio.io/dataplane-mode: ambient` - enrolls pods into ambient mesh (ztunnel intercepts traffic)
    /// - `istio.io/use-waypoint: {namespace}-waypoint` - routes all traffic through waypoint for L7 enforcement
    async fn ensure_namespace_with_ambient(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Namespace;

        let api: Api<Namespace> = Api::all(self.client.clone());
        let waypoint = mesh::waypoint_name(name);

        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "labels": {
                    (mesh::DATAPLANE_MODE_LABEL): mesh::DATAPLANE_MODE_AMBIENT,
                    (mesh::USE_WAYPOINT_LABEL): waypoint
                }
            }
        });

        api.patch(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Apply(&ns),
        )
        .await?;

        debug!(namespace = %name, waypoint = %waypoint, "ensured namespace with ambient mode labels");
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

    async fn apply_compiled_service(
        &self,
        service_name: &str,
        namespace: &str,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use futures::future::join_all;

        // Ensure namespace exists with ambient mode label for Istio traffic routing
        self.ensure_namespace_with_ambient(namespace).await?;

        let params = PatchParams::apply("lattice-service-controller").force();

        // Collect all patch operations as futures and run them in parallel
        // This significantly improves performance vs sequential application
        let mut futures: Vec<
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>,
        > = Vec::new();

        // Apply workload resources (ServiceAccount, PVCs, Deployment, Service, HPA)
        self.collect_workload_futures(&mut futures, namespace, &params, compiled)?;

        // Apply ExternalSecrets (ESO syncs secrets from Vault)
        self.collect_secret_futures(&mut futures, namespace, &params, compiled)?;

        // Apply policy resources (Cilium and Istio policies)
        self.collect_policy_futures(&mut futures, namespace, &params, compiled)?;

        // Apply ingress resources (Gateway, HttpRoute, Certificate)
        self.collect_ingress_futures(&mut futures, namespace, &params, compiled)?;

        // Apply waypoint resources (Waypoint gateway and policies)
        self.collect_waypoint_futures(&mut futures, namespace, &params, compiled)?;

        // Execute all patches in parallel and collect all results
        let count = futures.len();
        if count > 0 {
            debug!(count = count, "applying resources in parallel");
            let results = join_all(futures).await;

            // Collect all errors and log them
            let mut errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();

            // Log all failures and return the first error if any
            if !errors.is_empty() {
                for (i, err) in errors.iter().enumerate() {
                    error!(error = %err, index = i, "resource application failed");
                }
                // Use swap_remove to avoid the unwrap - we verified errors is non-empty above
                return Err(errors.swap_remove(0));
            }
        }

        info!(
            service = %service_name,
            namespace = %namespace,
            resources = count,
            "applied compiled resources"
        );
        Ok(())
    }
}

// =============================================================================
// Helper methods for ServiceKubeClientImpl
// =============================================================================

/// Type alias for boxed futures used in parallel resource application.
/// This reduces complexity in function signatures.
type ApplyFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>;

impl ServiceKubeClientImpl {
    /// Collect futures for workload resources (ServiceAccount, PVCs, Deployment, Service, HPA)
    fn collect_workload_futures(
        &self,
        futures: &mut Vec<ApplyFuture>,
        namespace: &str,
        params: &PatchParams,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use k8s_openapi::api::apps::v1::Deployment as K8sDeployment;
        use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler as K8sHpa;
        use k8s_openapi::api::core::v1::{
            PersistentVolumeClaim as K8sPvc, Service as K8sService, ServiceAccount as K8sSA,
        };

        // ServiceAccount
        if let Some(ref sa) = compiled.workloads.service_account {
            let name = sa.metadata.name.clone();
            let json = serialize_resource("ServiceAccount", sa)?;
            let api: Api<K8sSA> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying ServiceAccount");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // PersistentVolumeClaims
        for pvc in &compiled.workloads.pvcs {
            let name = pvc.metadata.name.clone();
            let json = serialize_resource("PersistentVolumeClaim", pvc)?;
            let api: Api<K8sPvc> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying PersistentVolumeClaim");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Deployment
        if let Some(ref deployment) = compiled.workloads.deployment {
            let name = deployment.metadata.name.clone();
            let json = serialize_resource("Deployment", deployment)?;
            let api: Api<K8sDeployment> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying Deployment");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Service
        if let Some(ref service) = compiled.workloads.service {
            let name = service.metadata.name.clone();
            let json = serialize_resource("Service", service)?;
            let api: Api<K8sService> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying Service");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // HPA
        if let Some(ref hpa) = compiled.workloads.hpa {
            let name = hpa.metadata.name.clone();
            let json = serialize_resource("HPA", hpa)?;
            let api: Api<K8sHpa> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying HPA");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        Ok(())
    }

    /// Collect futures for ExternalSecret resources (ESO syncs secrets from Vault)
    fn collect_secret_futures(
        &self,
        futures: &mut Vec<ApplyFuture>,
        namespace: &str,
        params: &PatchParams,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        if compiled.workloads.external_secrets.is_empty() {
            return Ok(());
        }

        let es_ar = match &self.crds.external_secret {
            Some(ar) => ar.clone(),
            None => {
                warn!(
                    "ExternalSecret CRD not installed, skipping {} ExternalSecret resource(s)",
                    compiled.workloads.external_secrets.len()
                );
                return Ok(());
            }
        };

        for external_secret in &compiled.workloads.external_secrets {
            let name = external_secret.metadata.name.clone();
            let json = serialize_resource("ExternalSecret", external_secret)?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &es_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying ExternalSecret");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        Ok(())
    }

    /// Collect futures for policy resources (Cilium and Istio policies)
    fn collect_policy_futures(
        &self,
        futures: &mut Vec<ApplyFuture>,
        namespace: &str,
        params: &PatchParams,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        // CiliumNetworkPolicies
        if !compiled.policies.cilium_policies.is_empty() {
            match &self.crds.cilium_network_policy {
                Some(cnp_ar) => {
                    for cnp in &compiled.policies.cilium_policies {
                        let name = cnp.metadata.name.clone();
                        let json = serialize_resource("CiliumNetworkPolicy", cnp)?;
                        let api: Api<DynamicObject> =
                            Api::namespaced_with(self.client.clone(), namespace, cnp_ar);
                        let params = params.clone();
                        futures.push(Box::pin(async move {
                            debug!(name = %name, "applying CiliumNetworkPolicy");
                            api.patch(&name, &params, &Patch::Apply(&json)).await?;
                            Ok(())
                        }));
                    }
                }
                None => {
                    warn!(
                        "CiliumNetworkPolicy CRD not installed, skipping {} policy resource(s)",
                        compiled.policies.cilium_policies.len()
                    );
                }
            }
        }

        // AuthorizationPolicies
        if !compiled.policies.authorization_policies.is_empty() {
            match &self.crds.authorization_policy {
                Some(authz_ar) => {
                    for authz in &compiled.policies.authorization_policies {
                        let name = authz.metadata.name.clone();
                        let json = serialize_resource("AuthorizationPolicy", authz)?;
                        let api: Api<DynamicObject> =
                            Api::namespaced_with(self.client.clone(), namespace, authz_ar);
                        let params = params.clone();
                        futures.push(Box::pin(async move {
                            debug!(name = %name, "applying AuthorizationPolicy");
                            api.patch(&name, &params, &Patch::Apply(&json)).await?;
                            Ok(())
                        }));
                    }
                }
                None => {
                    warn!(
                        "AuthorizationPolicy CRD not installed, skipping {} policy resource(s)",
                        compiled.policies.authorization_policies.len()
                    );
                }
            }
        }

        // ServiceEntries
        if !compiled.policies.service_entries.is_empty() {
            match &self.crds.service_entry {
                Some(se_ar) => {
                    for entry in &compiled.policies.service_entries {
                        let name = entry.metadata.name.clone();
                        let json = serialize_resource("ServiceEntry", entry)?;
                        let api: Api<DynamicObject> =
                            Api::namespaced_with(self.client.clone(), namespace, se_ar);
                        let params = params.clone();
                        futures.push(Box::pin(async move {
                            debug!(name = %name, "applying ServiceEntry");
                            api.patch(&name, &params, &Patch::Apply(&json)).await?;
                            Ok(())
                        }));
                    }
                }
                None => {
                    warn!(
                        "ServiceEntry CRD not installed, skipping {} service entry resource(s)",
                        compiled.policies.service_entries.len()
                    );
                }
            }
        }

        Ok(())
    }

    /// Collect futures for ingress resources (Gateway, HttpRoute, Certificate)
    fn collect_ingress_futures(
        &self,
        futures: &mut Vec<ApplyFuture>,
        namespace: &str,
        params: &PatchParams,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        // Gateway
        if let Some(ref gateway) = compiled.ingress.gateway {
            match &self.crds.gateway {
                Some(gw_ar) => {
                    let name = gateway.metadata.name.clone();
                    let json = serialize_resource("Gateway", gateway)?;
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(self.client.clone(), namespace, gw_ar);
                    let params = params.clone();
                    futures.push(Box::pin(async move {
                        debug!(name = %name, "applying Gateway");
                        api.patch(&name, &params, &Patch::Apply(&json)).await?;
                        Ok(())
                    }));
                }
                None => {
                    warn!("Gateway CRD not installed, skipping ingress Gateway");
                }
            }
        }

        // HTTPRoute
        if let Some(ref route) = compiled.ingress.http_route {
            match &self.crds.http_route {
                Some(route_ar) => {
                    let name = route.metadata.name.clone();
                    let json = serialize_resource("HTTPRoute", route)?;
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(self.client.clone(), namespace, route_ar);
                    let params = params.clone();
                    futures.push(Box::pin(async move {
                        debug!(name = %name, "applying HTTPRoute");
                        api.patch(&name, &params, &Patch::Apply(&json)).await?;
                        Ok(())
                    }));
                }
                None => {
                    warn!("HTTPRoute CRD not installed, skipping ingress HTTPRoute");
                }
            }
        }

        // Certificate
        if let Some(ref cert) = compiled.ingress.certificate {
            match &self.crds.certificate {
                Some(cert_ar) => {
                    let name = cert.metadata.name.clone();
                    let json = serialize_resource("Certificate", cert)?;
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(self.client.clone(), namespace, cert_ar);
                    let params = params.clone();
                    futures.push(Box::pin(async move {
                        debug!(name = %name, "applying Certificate");
                        api.patch(&name, &params, &Patch::Apply(&json)).await?;
                        Ok(())
                    }));
                }
                None => {
                    warn!("Certificate CRD not installed, skipping ingress Certificate");
                }
            }
        }

        Ok(())
    }

    /// Collect futures for waypoint resources (Waypoint gateway and policies)
    fn collect_waypoint_futures(
        &self,
        futures: &mut Vec<ApplyFuture>,
        namespace: &str,
        params: &PatchParams,
        compiled: &CompiledService,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        // Waypoint Gateway (for east-west L7 policies via Istio ambient mesh)
        if let Some(ref gateway) = compiled.waypoint.gateway {
            match &self.crds.gateway {
                Some(gw_ar) => {
                    let name = gateway.metadata.name.clone();
                    let json = serialize_resource("Waypoint Gateway", gateway)?;
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(self.client.clone(), namespace, gw_ar);
                    let params = params.clone();
                    futures.push(Box::pin(async move {
                        debug!(name = %name, "applying waypoint Gateway");
                        api.patch(&name, &params, &Patch::Apply(&json)).await?;
                        Ok(())
                    }));
                }
                None => {
                    warn!("Gateway CRD not installed, skipping waypoint Gateway");
                }
            }
        }

        // Waypoint allow-to-waypoint AuthorizationPolicy
        // This allows any authenticated traffic to reach the waypoint on port 15008 (HBONE)
        // Without this, mesh-default-deny blocks traffic before it reaches the waypoint
        if let Some(ref policy) = compiled.waypoint.allow_to_waypoint_policy {
            match &self.crds.authorization_policy {
                Some(authz_ar) => {
                    let name = policy.metadata.name.clone();
                    let json = serialize_resource("Waypoint AuthorizationPolicy", policy)?;
                    let api: Api<DynamicObject> =
                        Api::namespaced_with(self.client.clone(), namespace, authz_ar);
                    let params = params.clone();
                    futures.push(Box::pin(async move {
                        debug!(name = %name, "applying waypoint AuthorizationPolicy");
                        api.patch(&name, &params, &Patch::Apply(&json)).await?;
                        Ok(())
                    }));
                }
                None => {
                    warn!("AuthorizationPolicy CRD not installed, skipping waypoint AuthorizationPolicy");
                }
            }
        }

        Ok(())
    }
}

/// Serialize a Kubernetes resource to JSON Value for patching
///
/// This helper reduces repetitive serialization error handling throughout
/// the apply_compiled_service function.
fn serialize_resource<T: serde::Serialize>(
    name: &str,
    resource: &T,
) -> Result<serde_json::Value, Error> {
    serde_json::to_value(resource).map_err(|e| Error::serialization(format!("{}: {}", name, e)))
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
    ) -> Self {
        Self {
            kube,
            graph,
            cluster_name: cluster_name.into(),
            provider_type,
            cedar,
            events,
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
    if let Err(e) = service.spec.validate() {
        warn!(error = %e, "service validation failed");
        update_service_status_failed(&service, &ctx, &e.to_string()).await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = service
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ServicePhase::Pending);

    debug!(?current_phase, "current service phase");

    // Get namespace from metadata (LatticeService is namespace-scoped)
    let namespace = match service.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            error!("LatticeService is missing namespace - this is a cluster-scoped resource that needs migration");
            update_service_status_failed(&service, &ctx, "Resource missing namespace").await?;
            return Ok(Action::await_change());
        }
    };

    // Always ensure this service is in the graph (crash recovery)
    // This is idempotent - put_service handles updates correctly
    ctx.graph.put_service(namespace, &name, &service.spec);

    // State machine: transition based on current phase
    match current_phase {
        ServicePhase::Pending => {
            // Transition to Compiling
            update_service_status_compiling(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ServicePhase::Compiling => {
            // Verify dependencies exist in the graph
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

            compile_and_apply(&service, &name, namespace, &ctx).await?;
            info!("service ready");
            update_service_status_ready(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ServicePhase::Ready => {
            let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, namespace);
            if !missing_deps.is_empty() {
                warn!(?missing_deps, "dependencies no longer available");
                update_service_status_compiling(&service, &ctx).await?;
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            compile_and_apply(&service, &name, namespace, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ServicePhase::Failed => {
            // Re-attempt compilation without changing phase.
            // If it succeeds, transition to Ready. If it still fails, stay Failed.
            match compile_and_apply(&service, &name, namespace, &ctx).await {
                Ok(()) => {
                    info!("previously failed service now compiles");
                    update_service_status_ready(&service, &ctx).await?;
                    Ok(Action::requeue(Duration::from_secs(60)))
                }
                Err(_) => {
                    debug!("service still failing, will retry");
                    Ok(Action::requeue(Duration::from_secs(30)))
                }
            }
        }
    }
}

/// Error policy for the service controller
///
/// This function is called when reconciliation fails. It determines
/// the requeue strategy based on error type:
/// - Retryable errors (transient): exponential backoff starting at 30 seconds
/// - Non-retryable errors (permanent): await spec change, don't retry
pub fn error_policy(
    service: Arc<LatticeService>,
    error: &Error,
    _ctx: Arc<ServiceContext>,
) -> Action {
    error!(
        ?error,
        service = %service.name_any(),
        retryable = error.is_retryable(),
        "reconciliation failed"
    );

    if error.is_retryable() {
        // Transient error - retry with backoff
        Action::requeue(Duration::from_secs(30))
    } else {
        // Permanent error - requires spec change to fix
        Action::await_change()
    }
}

/// Check which dependencies are missing from the graph
fn check_missing_dependencies(
    spec: &LatticeServiceSpec,
    graph: &ServiceGraph,
    namespace: &str,
) -> Vec<String> {
    spec.internal_dependencies(namespace)
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
    let compiler =
        ServiceCompiler::new(&ctx.graph, &ctx.cluster_name, ctx.provider_type, &ctx.cedar);
    let compiled = match compiler.compile(service).await {
        Ok(compiled) => compiled,
        Err(e) => {
            let event_reason = match &e {
                CompileError::SecretAccessDenied(_) => reasons::SECRET_ACCESS_DENIED,
                _ => reasons::COMPILATION_FAILED,
            };
            let msg = e.to_string();
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
            update_service_status_failed(service, ctx, &msg).await?;
            return Err(Error::internal_with_context("compiler", msg));
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
        error!(error = %e, "failed to apply compiled resources");
        update_service_status_failed(service, ctx, &e.to_string()).await?;
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
        update_external_status_failed(&external, &ctx, &e.to_string()).await?;
        return Ok(Action::await_change());
    }

    // Get namespace from metadata (LatticeExternalService is namespace-scoped)
    let namespace = match external.metadata.namespace.as_deref() {
        Some(ns) => ns,
        None => {
            error!("LatticeExternalService is missing namespace - this is a cluster-scoped resource that needs migration");
            update_external_status_failed(&external, &ctx, "Resource missing namespace").await?;
            return Ok(Action::await_change());
        }
    };

    // Update graph with this external service
    ctx.graph
        .put_external_service(namespace, &name, &external.spec);

    // Only update status if not already Ready (avoid reconcile loop)
    let is_ready = external
        .status
        .as_ref()
        .map(|s| s.phase == crate::crd::ExternalServicePhase::Ready)
        .unwrap_or(false);

    if !is_ready {
        info!(namespace = %namespace, "external service transitioning to Ready");
        update_external_status_ready(&external, &ctx).await?;
    }

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Error policy for the external service controller
///
/// Uses the same retry logic as the service controller:
/// - Retryable errors: 30 second backoff
/// - Non-retryable errors: await spec change
pub fn error_policy_external(
    external: Arc<LatticeExternalService>,
    error: &Error,
    _ctx: Arc<ServiceContext>,
) -> Action {
    error!(
        ?error,
        external_service = %external.name_any(),
        retryable = error.is_retryable(),
        "reconciliation failed"
    );

    if error.is_retryable() {
        Action::requeue(Duration::from_secs(30))
    } else {
        Action::await_change()
    }
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

/// Update LatticeService status with the given configuration
async fn update_service_status(
    service: &LatticeService,
    ctx: &ServiceContext,
    update: ServiceStatusUpdate<'_>,
) -> Result<(), Error> {
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

/// Convenience wrapper for compiling status
async fn update_service_status_compiling(
    service: &LatticeService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    update_service_status(service, ctx, ServiceStatusUpdate::compiling()).await
}

/// Convenience wrapper for ready status
async fn update_service_status_ready(
    service: &LatticeService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    update_service_status(service, ctx, ServiceStatusUpdate::ready()).await
}

/// Convenience wrapper for failed status
async fn update_service_status_failed(
    service: &LatticeService,
    ctx: &ServiceContext,
    message: &str,
) -> Result<(), Error> {
    update_service_status(service, ctx, ServiceStatusUpdate::failed(message)).await
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

/// Update LatticeExternalService status with the given configuration
async fn update_external_status(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
    update: ExternalStatusUpdate<'_>,
) -> Result<(), Error> {
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

/// Convenience wrapper for external ready status
async fn update_external_status_ready(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    update_external_status(external, ctx, ExternalStatusUpdate::ready()).await
}

/// Convenience wrapper for external failed status
async fn update_external_status_failed(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
    message: &str,
) -> Result<(), Error> {
    update_external_status(external, ctx, ExternalStatusUpdate::failed(message)).await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DependencyDirection, DeploySpec, LatticeExternalServiceSpec, ReplicaSpec,
        Resolution, ResourceSpec, ResourceType,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            resources: None,
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
            security: None,
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
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
            spec.resources.insert(
                dep.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: None,
                    inbound: None,
                    outbound: None,
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
            spec.resources.insert(
                caller.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Inbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: None,
                    inbound: None,
                    outbound: None,
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

    fn mock_kube_success() -> MockServiceKubeClient {
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
        mock.expect_apply_compiled_service()
            .returning(|_, _, _| Ok(()));
        mock
    }

    // =========================================================================
    // Reconciliation Story Tests
    // =========================================================================

    /// Story: New service transitions from Pending to Compiling
    #[tokio::test]
    async fn story_new_service_transitions_to_compiling() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube_success();
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
    async fn story_service_waits_for_dependencies() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mock_kube = mock_kube_success();
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
    async fn story_service_becomes_ready_with_deps() {
        let mut service = service_with_deps("frontend", vec!["backend"]);
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Compiling));
        let service = Arc::new(service);

        let mock_kube = mock_kube_success();
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
    async fn story_ready_service_stays_ready() {
        let mut service = sample_service("my-service");
        service.status = Some(LatticeServiceStatus::with_phase(ServicePhase::Ready));
        let service = Arc::new(service);

        let mock_kube = mock_kube_success();
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
    async fn story_invalid_service_fails() {
        let mut service = sample_service("bad-service");
        // Make it invalid by removing containers
        service.spec.containers.clear();
        let service = Arc::new(service);

        let mock_kube = mock_kube_success();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile(service, ctx)
            .await
            .expect("reconcile should succeed");

        // Should await change (no requeue)
        assert_eq!(action, Action::await_change());
    }

    /// Story: External service reconciles immediately to Ready
    #[tokio::test]
    async fn story_external_service_becomes_ready() {
        let external = Arc::new(sample_external_service("stripe"));
        let mock_kube = mock_kube_success();
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
    async fn story_graph_tracks_bilateral_agreements() {
        let mock_kube = mock_kube_success();
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
    async fn story_graph_handles_deletion() {
        let mock_kube = mock_kube_success();
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
    fn story_error_policy_requeues() {
        let service = Arc::new(sample_service("my-service"));
        let mock_kube = mock_kube_success();
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
    fn story_detect_missing_dependencies() {
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
    async fn story_services_isolated_by_environment() {
        let mock_kube = mock_kube_success();
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
    fn story_shared_graph_across_contexts() {
        let mock_kube1 = Arc::new(mock_kube_success());
        let mock_kube2 = Arc::new(mock_kube_success());
        let shared_graph = Arc::new(ServiceGraph::new());
        let cedar = Arc::new(PolicyEngine::new());

        let ctx1 = ServiceContext::new(
            mock_kube1,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
        );
        let ctx2 = ServiceContext::new(
            mock_kube2,
            Arc::clone(&shared_graph),
            "test-cluster",
            ProviderType::Docker,
            Arc::clone(&cedar),
            Arc::new(NoopEventPublisher),
        );

        // Add service via ctx1
        ctx1.graph
            .put_service("shared", "svc", &sample_service_spec());

        // Should be visible via ctx2
        assert!(ctx2.graph.get_service("shared", "svc").is_some());
    }
}
