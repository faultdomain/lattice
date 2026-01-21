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
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use crate::compiler::{CompiledService, ServiceCompiler};
use crate::crd::{
    Condition, ConditionStatus, LatticeExternalService, LatticeExternalServiceStatus,
    LatticeService, LatticeServiceSpec, LatticeServiceStatus, ServicePhase,
};
use crate::graph::ServiceGraph;
use crate::Error;

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
        status: &LatticeServiceStatus,
    ) -> Result<(), Error>;

    /// Patch the status of a LatticeExternalService
    async fn patch_external_service_status(
        &self,
        name: &str,
        status: &LatticeExternalServiceStatus,
    ) -> Result<(), Error>;

    /// Get a LatticeService by name
    async fn get_service(&self, name: &str) -> Result<Option<LatticeService>, Error>;

    /// Get a LatticeExternalService by name
    async fn get_external_service(
        &self,
        name: &str,
    ) -> Result<Option<LatticeExternalService>, Error>;

    /// List all LatticeServices
    async fn list_services(&self) -> Result<Vec<LatticeService>, Error>;

    /// List all LatticeExternalServices
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
}

impl ServiceKubeClientImpl {
    /// Create a new ServiceKubeClientImpl wrapping the given client
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Ensure a namespace exists with the ambient mode label for Istio traffic routing.
    ///
    /// Istio ambient mode requires namespaces to have `istio.io/dataplane-mode: ambient`
    /// for ztunnel to intercept traffic and route it through waypoint proxies for L7 enforcement.
    async fn ensure_namespace_with_ambient(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Namespace;

        let api: Api<Namespace> = Api::all(self.client.clone());

        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "labels": {
                    "istio.io/dataplane-mode": "ambient"
                }
            }
        });

        api.patch(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Apply(&ns),
        )
        .await?;

        debug!(namespace = %name, "ensured namespace with ambient mode label");
        Ok(())
    }
}

#[async_trait]
impl ServiceKubeClient for ServiceKubeClientImpl {
    async fn patch_service_status(
        &self,
        name: &str,
        status: &LatticeServiceStatus,
    ) -> Result<(), Error> {
        let api: Api<LatticeService> = Api::all(self.client.clone());
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
        status: &LatticeExternalServiceStatus,
    ) -> Result<(), Error> {
        let api: Api<LatticeExternalService> = Api::all(self.client.clone());
        let status_patch = serde_json::json!({ "status": status });

        api.patch_status(
            name,
            &PatchParams::apply("lattice-service-controller"),
            &Patch::Merge(&status_patch),
        )
        .await?;

        Ok(())
    }

    async fn get_service(&self, name: &str) -> Result<Option<LatticeService>, Error> {
        let api: Api<LatticeService> = Api::all(self.client.clone());
        match api.get(name).await {
            Ok(svc) => Ok(Some(svc)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_external_service(
        &self,
        name: &str,
    ) -> Result<Option<LatticeExternalService>, Error> {
        let api: Api<LatticeExternalService> = Api::all(self.client.clone());
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
        use futures::future::try_join_all;
        use k8s_openapi::api::apps::v1::Deployment as K8sDeployment;
        use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler as K8sHpa;
        use k8s_openapi::api::core::v1::{Service as K8sService, ServiceAccount as K8sSA};
        use kube::api::DynamicObject;
        use kube::discovery::ApiResource;

        // Ensure namespace exists with ambient mode label for Istio traffic routing
        self.ensure_namespace_with_ambient(namespace).await?;

        let params = PatchParams::apply("lattice-service-controller").force();

        // Collect all patch operations as futures and run them in parallel
        // This significantly improves performance vs sequential application
        let mut futures: Vec<
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send>>,
        > = Vec::new();

        // ServiceAccount
        if let Some(ref sa) = compiled.workloads.service_account {
            let name = sa.metadata.name.clone();
            let json = serde_json::to_value(sa)
                .map_err(|e| Error::serialization(format!("ServiceAccount: {}", e)))?;
            let api: Api<K8sSA> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying ServiceAccount");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Deployment
        if let Some(ref deployment) = compiled.workloads.deployment {
            let name = deployment.metadata.name.clone();
            let json = serde_json::to_value(deployment)
                .map_err(|e| Error::serialization(format!("Deployment: {}", e)))?;
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
            let json = serde_json::to_value(service)
                .map_err(|e| Error::serialization(format!("Service: {}", e)))?;
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
            let json = serde_json::to_value(hpa)
                .map_err(|e| Error::serialization(format!("HPA: {}", e)))?;
            let api: Api<K8sHpa> = Api::namespaced(self.client.clone(), namespace);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying HPA");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // CiliumNetworkPolicies
        let cnp_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "cilium.io".to_string(),
            version: "v2".to_string(),
            kind: "CiliumNetworkPolicy".to_string(),
        });
        for cnp in &compiled.policies.cilium_policies {
            let name = cnp.metadata.name.clone();
            let json = serde_json::to_value(cnp)
                .map_err(|e| Error::serialization(format!("CiliumNetworkPolicy: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &cnp_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying CiliumNetworkPolicy");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // AuthorizationPolicies
        let authz_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "security.istio.io".to_string(),
            version: "v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
        });
        for authz in &compiled.policies.authorization_policies {
            let name = authz.metadata.name.clone();
            let json = serde_json::to_value(authz)
                .map_err(|e| Error::serialization(format!("AuthorizationPolicy: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &authz_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying AuthorizationPolicy");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // ServiceEntries
        let se_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "networking.istio.io".to_string(),
            version: "v1beta1".to_string(),
            kind: "ServiceEntry".to_string(),
        });
        for entry in &compiled.policies.service_entries {
            let name = entry.metadata.name.clone();
            let json = serde_json::to_value(entry)
                .map_err(|e| Error::serialization(format!("ServiceEntry: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &se_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying ServiceEntry");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Gateway
        let gw_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "gateway.networking.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "Gateway".to_string(),
        });
        if let Some(ref gateway) = compiled.ingress.gateway {
            let name = gateway.metadata.name.clone();
            let json = serde_json::to_value(gateway)
                .map_err(|e| Error::serialization(format!("Gateway: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &gw_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying Gateway");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // HTTPRoute
        let route_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "gateway.networking.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "HTTPRoute".to_string(),
        });
        if let Some(ref route) = compiled.ingress.http_route {
            let name = route.metadata.name.clone();
            let json = serde_json::to_value(route)
                .map_err(|e| Error::serialization(format!("HTTPRoute: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &route_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying HTTPRoute");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Certificate
        let cert_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "cert-manager.io".to_string(),
            version: "v1".to_string(),
            kind: "Certificate".to_string(),
        });
        if let Some(ref cert) = compiled.ingress.certificate {
            let name = cert.metadata.name.clone();
            let json = serde_json::to_value(cert)
                .map_err(|e| Error::serialization(format!("Certificate: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &cert_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying Certificate");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Waypoint EnvoyProxy (configures HBONE port on waypoint Service)
        let envoy_proxy_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "gateway.envoyproxy.io".to_string(),
            version: "v1alpha1".to_string(),
            kind: "EnvoyProxy".to_string(),
        });
        if let Some(ref envoy_proxy) = compiled.waypoint.envoy_proxy {
            let name = envoy_proxy.metadata.name.clone();
            let json = serde_json::to_value(envoy_proxy)
                .map_err(|e| Error::serialization(format!("EnvoyProxy: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &envoy_proxy_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying waypoint EnvoyProxy");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Waypoint GatewayClass (references namespace-local EnvoyProxy)
        let gateway_class_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "gateway.networking.k8s.io".to_string(),
            version: "v1".to_string(),
            kind: "GatewayClass".to_string(),
        });
        if let Some(ref gateway_class) = compiled.waypoint.gateway_class {
            let name = gateway_class.metadata.name.clone();
            let json = serde_json::to_value(gateway_class)
                .map_err(|e| Error::serialization(format!("GatewayClass: {}", e)))?;
            // GatewayClass is cluster-scoped
            let api: Api<DynamicObject> =
                Api::all_with(self.client.clone(), &gateway_class_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying waypoint GatewayClass");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Waypoint Gateway (for east-west L7 policies via Envoy Gateway)
        if let Some(ref gateway) = compiled.waypoint.gateway {
            let name = gateway.metadata.name.clone();
            let json = serde_json::to_value(gateway)
                .map_err(|e| Error::serialization(format!("Waypoint Gateway: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &gw_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying waypoint Gateway");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Waypoint HTTPRoute (routes mesh traffic through waypoint)
        if let Some(ref route) = compiled.waypoint.http_route {
            let name = route.metadata.name.clone();
            let json = serde_json::to_value(route)
                .map_err(|e| Error::serialization(format!("Waypoint HTTPRoute: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &route_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying waypoint HTTPRoute");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // BackendTrafficPolicy (Envoy Gateway traffic shaping)
        let btp_ar = ApiResource::from_gvk(&kube::api::GroupVersionKind {
            group: "gateway.envoyproxy.io".to_string(),
            version: "v1alpha1".to_string(),
            kind: "BackendTrafficPolicy".to_string(),
        });
        for policy in compiled
            .traffic_policies
            .outbound
            .iter()
            .chain(compiled.traffic_policies.inbound.iter())
        {
            let name = policy.metadata.name.clone();
            let json = serde_json::to_value(policy)
                .map_err(|e| Error::serialization(format!("BackendTrafficPolicy: {}", e)))?;
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace, &btp_ar);
            let params = params.clone();
            futures.push(Box::pin(async move {
                debug!(name = %name, "applying BackendTrafficPolicy");
                api.patch(&name, &params, &Patch::Apply(&json)).await?;
                Ok(())
            }));
        }

        // Execute all patches in parallel
        let count = futures.len();
        if count > 0 {
            debug!(count = count, "applying resources in parallel");
            try_join_all(futures).await?;
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
    /// SPIFFE trust domain for policy generation
    pub trust_domain: String,
}

impl ServiceContext {
    /// Create a new ServiceContext with the given dependencies
    pub fn new(
        kube: Arc<dyn ServiceKubeClient>,
        graph: Arc<ServiceGraph>,
        trust_domain: impl Into<String>,
    ) -> Self {
        Self {
            kube,
            graph,
            trust_domain: trust_domain.into(),
        }
    }

    /// Create a new ServiceContext from a Kubernetes client
    ///
    /// This creates a new ServiceGraph. For shared state, create the graph
    /// externally and pass it to the constructor.
    pub fn from_client(client: Client, trust_domain: impl Into<String>) -> Self {
        Self {
            kube: Arc::new(ServiceKubeClientImpl::new(client)),
            graph: Arc::new(ServiceGraph::new()),
            trust_domain: trust_domain.into(),
        }
    }

    /// Create a context for testing with mock clients
    #[cfg(test)]
    pub fn for_testing(kube: Arc<dyn ServiceKubeClient>) -> Self {
        Self {
            kube,
            graph: Arc::new(ServiceGraph::new()),
            trust_domain: "test.local".to_string(),
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

    // Get environment from spec (determines namespace)
    let env = &service.spec.environment;

    // State machine: transition based on current phase
    match current_phase {
        ServicePhase::Pending => {
            // Update graph with this service's dependencies
            info!(env = %env, "adding service to graph");
            ctx.graph.put_service(env, &name, &service.spec);

            // Transition to Compiling
            update_service_status_compiling(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ServicePhase::Compiling => {
            // Verify dependencies exist in the graph
            let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, env);

            if !missing_deps.is_empty() {
                debug!(?missing_deps, "waiting for dependencies");
                // Dependencies not yet available, requeue
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            // All dependencies exist, check for bilateral agreements (active edges)
            let active_in = ctx.graph.get_active_inbound_edges(env, &name);
            let active_out = ctx.graph.get_active_outbound_edges(env, &name);

            debug!(
                active_inbound = active_in.len(),
                active_outbound = active_out.len(),
                "edge status"
            );

            // Compile workloads and policies
            let compiler = ServiceCompiler::new(&ctx.graph, &ctx.trust_domain);
            let compiled = compiler.compile(&service);

            // Use environment as namespace (LatticeService is cluster-scoped, so metadata.namespace is always None)
            let namespace = env;

            // Apply compiled resources to the cluster
            info!(
                resources = compiled.resource_count(),
                "applying compiled resources"
            );
            if let Err(e) = ctx
                .kube
                .apply_compiled_service(&name, namespace, &compiled)
                .await
            {
                error!(error = %e, "failed to apply compiled resources");
                update_service_status_failed(&service, &ctx, &e.to_string()).await?;
                return Err(e);
            }

            // Transition to Ready
            info!("service ready");
            update_service_status_ready(&service, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ServicePhase::Ready => {
            // Service is ready, ensure graph is up to date
            ctx.graph.put_service(env, &name, &service.spec);

            // Check for any issues that would cause degradation
            let missing_deps = check_missing_dependencies(&service.spec, &ctx.graph, env);
            if !missing_deps.is_empty() {
                warn!(?missing_deps, "dependencies no longer available");
                // Transition back to Compiling to wait for deps
                update_service_status_compiling(&service, &ctx).await?;
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            // Recompile and apply policies to handle changes in dependent services
            // This is necessary because when a new service is added that depends on us,
            // or when a service we depend on changes its allowed callers, we need to
            // update our ingress/egress policies to reflect the new bilateral agreements.
            let compiler = ServiceCompiler::new(&ctx.graph, &ctx.trust_domain);
            let compiled = compiler.compile(&service);

            let namespace = env;
            debug!(
                resources = compiled.resource_count(),
                "reapplying compiled resources for policy drift"
            );
            if let Err(e) = ctx
                .kube
                .apply_compiled_service(&name, namespace, &compiled)
                .await
            {
                error!(error = %e, "failed to reapply compiled resources");
                update_service_status_failed(&service, &ctx, &e.to_string()).await?;
                return Err(e);
            }

            // Steady state - requeue periodically to check for drift
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ServicePhase::Failed => {
            // Retry failed services periodically - failure may have been transient
            // (e.g., webhook not ready yet, temporary network issue)
            warn!("service is in Failed state, will retry");
            Ok(Action::requeue(Duration::from_secs(30)))
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
    env: &str,
) -> Vec<String> {
    spec.internal_dependencies()
        .into_iter()
        .filter(|dep| {
            // Check if dependency exists (not Unknown type)
            graph
                .get_service(env, dep)
                .map(|node| node.type_ == crate::graph::ServiceType::Unknown)
                .unwrap_or(true)
        })
        .map(String::from)
        .collect()
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

    // Get environment from spec
    let env = &external.spec.environment;

    // Update graph with this external service
    ctx.graph.put_external_service(env, &name, &external.spec);

    // Only update status if not already Ready (avoid reconcile loop)
    let is_ready = external
        .status
        .as_ref()
        .map(|s| s.phase == crate::crd::ExternalServicePhase::Ready)
        .unwrap_or(false);

    if !is_ready {
        info!(env = %env, "external service transitioning to Ready");
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
    let env = &service.spec.environment;

    info!(service = %name, env = %env, "removing service from graph");
    ctx.graph.delete_service(env, &name);
}

/// Handle external service deletion by removing from the graph
pub fn cleanup_external_service(external: &LatticeExternalService, ctx: &ServiceContext) {
    let name = external.name_any();
    let env = &external.spec.environment;

    info!(external_service = %name, env = %env, "removing external service from graph");
    ctx.graph.delete_service(env, &name);
}

// =============================================================================
// Status update helpers
// =============================================================================

async fn update_service_status_compiling(
    service: &LatticeService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    let name = service.name_any();
    let status = LatticeServiceStatus::with_phase(ServicePhase::Compiling)
        .message("Compiling service dependencies")
        .condition(Condition::new(
            "Compiling",
            ConditionStatus::True,
            "DependencyCheck",
            "Checking service dependencies",
        ));

    ctx.kube.patch_service_status(&name, &status).await
}

async fn update_service_status_ready(
    service: &LatticeService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    let name = service.name_any();
    let status = LatticeServiceStatus::with_phase(ServicePhase::Ready)
        .message("Service is operational")
        .compiled_at(Utc::now())
        .condition(Condition::new(
            "Ready",
            ConditionStatus::True,
            "ServiceReady",
            "All dependencies resolved",
        ));

    ctx.kube.patch_service_status(&name, &status).await
}

async fn update_service_status_failed(
    service: &LatticeService,
    ctx: &ServiceContext,
    message: &str,
) -> Result<(), Error> {
    let name = service.name_any();
    let status = LatticeServiceStatus::with_phase(ServicePhase::Failed)
        .message(message)
        .condition(Condition::new(
            "Ready",
            ConditionStatus::False,
            "ValidationFailed",
            message,
        ));

    ctx.kube.patch_service_status(&name, &status).await
}

async fn update_external_status_ready(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
) -> Result<(), Error> {
    use crate::crd::ExternalServicePhase;

    let name = external.name_any();
    let status = LatticeExternalServiceStatus::with_phase(ExternalServicePhase::Ready)
        .message("External service is configured")
        .condition(Condition::new(
            "Ready",
            ConditionStatus::True,
            "EndpointsConfigured",
            "All endpoints are configured",
        ));

    ctx.kube.patch_external_service_status(&name, &status).await
}

async fn update_external_status_failed(
    external: &LatticeExternalService,
    ctx: &ServiceContext,
    message: &str,
) -> Result<(), Error> {
    use crate::crd::ExternalServicePhase;

    let name = external.name_any();
    let status = LatticeExternalServiceStatus::with_phase(ExternalServicePhase::Failed)
        .message(message)
        .condition(Condition::new(
            "Ready",
            ConditionStatus::False,
            "ValidationFailed",
            message,
        ));

    ctx.kube.patch_external_service_status(&name, &status).await
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
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            environment: "test".to_string(),
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
        }
    }

    fn sample_service(name: &str) -> LatticeService {
        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
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
                    outbound: None,
                    inbound: None,
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
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
                    outbound: None,
                    inbound: None,
                },
            );
        }

        LatticeService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
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
                ..Default::default()
            },
            spec: LatticeExternalServiceSpec {
                environment: "test".to_string(),
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
        mock.expect_patch_service_status().returning(|_, _| Ok(()));
        mock.expect_patch_external_service_status()
            .returning(|_, _| Ok(()));
        mock.expect_get_service().returning(|_| Ok(None));
        mock.expect_get_external_service().returning(|_| Ok(None));
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

        let action = reconcile(service, ctx.clone()).await.unwrap();

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

        let action = reconcile(service, ctx).await.unwrap();

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

        let action = reconcile(service, ctx).await.unwrap();

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

        let action = reconcile(service, ctx).await.unwrap();

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

        let action = reconcile(service, ctx).await.unwrap();

        // Should await change (no requeue)
        assert_eq!(action, Action::await_change());
    }

    /// Story: External service reconciles immediately to Ready
    #[tokio::test]
    async fn story_external_service_becomes_ready() {
        let external = Arc::new(sample_external_service("stripe"));
        let mock_kube = mock_kube_success();
        let ctx = Arc::new(ServiceContext::for_testing(Arc::new(mock_kube)));

        let action = reconcile_external(external, ctx.clone()).await.unwrap();

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
        assert_eq!(active[0].callee, "backend");
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

        let ctx1 = ServiceContext::new(mock_kube1, Arc::clone(&shared_graph), "test.local");
        let ctx2 = ServiceContext::new(mock_kube2, Arc::clone(&shared_graph), "test.local");

        // Add service via ctx1
        ctx1.graph
            .put_service("shared", "svc", &sample_service_spec());

        // Should be visible via ctx2
        assert!(ctx2.graph.get_service("shared", "svc").is_some());
    }
}
