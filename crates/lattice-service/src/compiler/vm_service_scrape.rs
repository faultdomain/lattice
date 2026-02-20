//! VMServiceScrape compiler phase
//!
//! Generates a VictoriaMetrics `VMServiceScrape` for LatticeServices that
//! declare a port named `metrics`, plus an AuthorizationPolicy allowing VMAgent
//! to scrape through the Istio waypoint. This opt-in approach avoids scrape
//! errors on ports that don't serve Prometheus metrics (HTTP APIs returning HTML,
//! gRPC ports, etc.).

use async_trait::async_trait;
use kube::discovery::ApiResource;
use kube::Client;
use lattice_common::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE, LABEL_NAME};

use super::{ApplyLayer, CompiledService, DynamicResource};
use crate::compiler::phase::{CompilationContext, CompilerPhase};

/// Compiler phase that emits a `operator.victoriametrics.com/v1beta1` `VMServiceScrape`
/// and an Istio `AuthorizationPolicy` allowing VMAgent to scrape through the waypoint.
///
/// The phase no-ops when:
/// - Monitoring is disabled on the cluster
/// - The service has no port named `metrics`
///
/// If the VMServiceScrape CRD was not discovered at startup (e.g. the VictoriaMetrics
/// operator is installed in the background), the phase discovers it on demand from
/// the API server. If the CRD is still not installed, the phase returns an error
/// so the service retries until it becomes available.
pub struct VMServiceScrapePhase {
    /// Cached ApiResource. Written once when first discovered.
    api_resource: std::sync::RwLock<Option<ApiResource>>,
    /// Client for on-demand CRD discovery. None in tests.
    client: Option<Client>,
}

impl VMServiceScrapePhase {
    /// Create a new `VMServiceScrapePhase`.
    ///
    /// If the VMServiceScrape CRD was discovered at startup, pass `Some(ar)`.
    /// If not, pass `None` — the phase will discover it on demand when a service
    /// needs it.
    pub fn new(api_resource: Option<ApiResource>, client: Option<Client>) -> Self {
        Self {
            api_resource: std::sync::RwLock::new(api_resource),
            client,
        }
    }

    /// Resolve the ApiResource, discovering from the API server if not cached.
    ///
    /// Returns `None` only when the CRD is genuinely not installed and there's
    /// no client to attempt discovery.
    async fn resolve_api_resource(&self) -> Option<ApiResource> {
        // Fast path: already resolved
        {
            let guard = self.api_resource.read().unwrap();
            if let Some(ar) = guard.as_ref() {
                return Some(ar.clone());
            }
        }

        // Slow path: discover from API server
        let client = self.client.as_ref()?;
        let discovery = kube::discovery::Discovery::new(client.clone())
            .run()
            .await
            .ok()?;
        let discovered = lattice_common::kube_utils::find_discovered_resource(
            &discovery,
            "operator.victoriametrics.com",
            "VMServiceScrape",
        );

        if let Some(ref ar) = discovered {
            tracing::info!("discovered VMServiceScrape CRD on demand");
            *self.api_resource.write().unwrap() = Some(ar.clone());
        }
        discovered
    }
}

#[async_trait]
impl CompilerPhase for VMServiceScrapePhase {
    fn name(&self) -> &str {
        "vm-service-scrape"
    }

    async fn compile(
        &self,
        ctx: &CompilationContext<'_>,
        output: &mut CompiledService,
    ) -> Result<(), String> {
        if !ctx.monitoring.enabled {
            return Ok(());
        }

        // Only generate a scrape config for services that explicitly declare
        // a port named "metrics". Many services expose HTTP/gRPC ports where
        // they don't serve Prometheus metrics. Requiring an explicit "metrics"
        // port is opt-in: zero config for those who add it, zero noise for
        // those who don't.
        let has_metrics_port = ctx
            .service
            .spec
            .workload
            .service
            .as_ref()
            .and_then(|svc| svc.ports.get("metrics"))
            .is_some();
        if !has_metrics_port {
            return Ok(());
        }

        let ar = self.resolve_api_resource().await.ok_or_else(|| {
            "VMServiceScrape CRD not installed (operator.victoriametrics.com); \
             the VictoriaMetrics operator may still be installing"
                .to_string()
        })?;

        // Emit VMServiceScrape
        let scrape_name = format!("{}-scrape", ctx.name);
        let json = serde_json::json!({
            "apiVersion": "operator.victoriametrics.com/v1beta1",
            "kind": "VMServiceScrape",
            "metadata": {
                "name": scrape_name,
                "namespace": ctx.namespace,
                "labels": {
                    LABEL_NAME: ctx.name,
                    LABEL_MANAGED_BY: LABEL_MANAGED_BY_LATTICE
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        LABEL_NAME: ctx.name
                    }
                },
                "endpoints": [{
                    "port": "metrics",
                    "path": "/metrics",
                    "interval": "30s"
                }]
            }
        });

        output.extensions.push(DynamicResource {
            kind: "VMServiceScrape".to_string(),
            name: scrape_name,
            json,
            api_resource: ar,
            layer: ApplyLayer::Infrastructure,
        });

        // vmagent reaches metrics ports via depends_all + implicit metrics
        // port allow in the service graph — no explicit allowed_callers needed.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, LatticeService, LatticeServiceSpec, PortSpec, ServicePortsSpec, WorkloadSpec,
    };
    use std::collections::BTreeMap;

    /// Build a fake ApiResource for VMServiceScrape
    fn fake_ar() -> ApiResource {
        lattice_common::kube_utils::build_api_resource(
            "operator.victoriametrics.com/v1beta1",
            "VMServiceScrape",
        )
    }

    /// Build a minimal LatticeService with given ports
    fn make_service_with_ports(
        name: &str,
        namespace: &str,
        port_names: &[(&str, u16)],
    ) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                ..Default::default()
            },
        );

        let mut ports = BTreeMap::new();
        for (pname, pport) in port_names {
            ports.insert(
                pname.to_string(),
                PortSpec {
                    port: *pport,
                    target_port: None,
                    protocol: None,
                },
            );
        }

        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    service: if ports.is_empty() {
                        None
                    } else {
                        Some(ServicePortsSpec { ports })
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        }
    }

    fn make_ctx<'a>(
        service: &'a LatticeService,
        monitoring_enabled: bool,
    ) -> CompilationContext<'a> {
        use crate::crd::{MonitoringConfig, ProviderType};
        use crate::graph::ServiceGraph;

        let graph: &'static ServiceGraph = Box::leak(Box::new(ServiceGraph::new()));

        CompilationContext {
            service,
            name: service.metadata.name.as_deref().unwrap(),
            namespace: service.metadata.namespace.as_deref().unwrap(),
            graph,
            cluster_name: "test-cluster",
            provider_type: ProviderType::Docker,
            monitoring: MonitoringConfig {
                enabled: monitoring_enabled,
                ha: true,
            },
        }
    }

    // =========================================================================
    // No-op cases
    // =========================================================================

    #[tokio::test]
    async fn monitoring_disabled_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, false);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.mesh_member.is_none());
    }

    #[tokio::test]
    async fn no_ports_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.mesh_member.is_none());
    }

    #[tokio::test]
    async fn no_metrics_port_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80), ("grpc", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.mesh_member.is_none());
    }

    #[tokio::test]
    async fn crd_not_installed_no_metrics_port_is_noop() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(None, None);
        let mut compiled = CompiledService::default();

        // No metrics port → no-op, even without CRD
        phase.compile(&ctx, &mut compiled).await.unwrap();
        assert!(compiled.extensions.is_empty());
    }

    #[tokio::test]
    async fn crd_not_installed_with_metrics_port_returns_error() {
        let svc = make_service_with_ports("my-app", "default", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        // No CRD, no client → cannot discover
        let phase = VMServiceScrapePhase::new(None, None);
        let mut compiled = CompiledService::default();

        let err = phase.compile(&ctx, &mut compiled).await.unwrap_err();
        assert!(err.contains("VMServiceScrape CRD not installed"));
    }

    // =========================================================================
    // Happy-path cases
    // =========================================================================

    #[tokio::test]
    async fn metrics_port_produces_vm_service_scrape() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();

        assert_eq!(compiled.extensions.len(), 1);
        let ext = &compiled.extensions[0];
        assert_eq!(ext.kind, "VMServiceScrape");
        assert_eq!(ext.name, "my-app-scrape");
        assert_eq!(ext.layer, ApplyLayer::Infrastructure);

        let endpoints = ext.json["spec"]["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["port"], "metrics");
        assert_eq!(endpoints[0]["path"], "/metrics");
        assert_eq!(endpoints[0]["interval"], "30s");
    }

    #[tokio::test]
    async fn metrics_port_adds_vmagent_caller_to_mesh_member() {
        use lattice_common::crd::{LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget};

        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService {
            mesh_member: Some(LatticeMeshMember {
                metadata: kube::api::ObjectMeta {
                    name: Some("my-app".to_string()),
                    namespace: Some("prod".to_string()),
                    ..Default::default()
                },
                spec: LatticeMeshMemberSpec {
                    target: MeshMemberTarget::Selector(BTreeMap::from([(
                        "app.kubernetes.io/name".to_string(),
                        "my-app".to_string(),
                    )])),
                    ports: vec![],
                    allowed_callers: vec![],
                    dependencies: vec![],
                    egress: vec![],
                    allow_peer_traffic: false,
                    ingress: None,
                    service_account: None,
                    depends_all: false,
                },
                status: None,
            }),
            ..Default::default()
        };

        phase.compile(&ctx, &mut compiled).await.unwrap();

        // vmagent reaches metrics ports via depends_all + implicit graph
        // allow — no explicit allowed_callers entry needed
        let mm = compiled.mesh_member.unwrap();
        assert!(mm.spec.allowed_callers.is_empty());
    }

    #[tokio::test]
    async fn metrics_port_among_others_only_scrapes_metrics() {
        let svc = make_service_with_ports(
            "my-app",
            "default",
            &[("http", 80), ("metrics", 9090), ("grpc", 9000)],
        );
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();

        let endpoints = compiled.extensions[0].json["spec"]["endpoints"]
            .as_array()
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["port"], "metrics");
    }

    #[tokio::test]
    async fn labels_and_selector_match_workload_compiler() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();

        let json = &compiled.extensions[0].json;
        let labels = &json["metadata"]["labels"];
        assert_eq!(labels[LABEL_NAME], "my-app");
        assert_eq!(labels[LABEL_MANAGED_BY], LABEL_MANAGED_BY_LATTICE);

        let selector = &json["spec"]["selector"]["matchLabels"];
        assert_eq!(selector[LABEL_NAME], "my-app");
    }

    #[tokio::test]
    async fn correct_namespace_and_api_version() {
        let svc = make_service_with_ports("my-app", "staging", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();

        let json = &compiled.extensions[0].json;
        assert_eq!(json["apiVersion"], "operator.victoriametrics.com/v1beta1");
        assert_eq!(json["kind"], "VMServiceScrape");
        assert_eq!(json["metadata"]["namespace"], "staging");
    }

    #[tokio::test]
    async fn layer_is_infrastructure() {
        let svc = make_service_with_ports("my-app", "default", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()), None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).await.unwrap();

        assert_eq!(compiled.extensions[0].layer, ApplyLayer::Infrastructure);
    }
}
