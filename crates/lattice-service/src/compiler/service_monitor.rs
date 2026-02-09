//! ServiceMonitor compiler phase
//!
//! Generates a Prometheus-compatible `ServiceMonitor` for LatticeServices that
//! declare a port named `metrics`. This opt-in approach avoids scrape errors
//! on ports that don't serve Prometheus metrics (HTTP APIs returning HTML,
//! gRPC ports, etc.).

use kube::discovery::ApiResource;
use lattice_common::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE, LABEL_NAME};

use super::{ApplyLayer, CompiledService, DynamicResource};
use crate::compiler::phase::{CompilationContext, CompilerPhase};

/// Compiler phase that emits a `monitoring.coreos.com/v1` `ServiceMonitor`.
///
/// The phase no-ops when:
/// - Monitoring is disabled on the cluster
/// - The ServiceMonitor CRD is not installed (`api_resource` is `None`)
/// - The service has no port named `metrics`
pub struct ServiceMonitorPhase {
    api_resource: Option<ApiResource>,
}

impl ServiceMonitorPhase {
    /// Create a new `ServiceMonitorPhase`.
    ///
    /// Pass `None` if the ServiceMonitor CRD is not installed — the phase
    /// will gracefully no-op.
    pub fn new(api_resource: Option<ApiResource>) -> Self {
        Self { api_resource }
    }
}

impl CompilerPhase for ServiceMonitorPhase {
    fn name(&self) -> &str {
        "service-monitor"
    }

    fn compile(
        &self,
        ctx: &CompilationContext<'_>,
        output: &mut CompiledService,
    ) -> Result<(), String> {
        // Gate 1: monitoring must be enabled
        if !ctx.monitoring_enabled {
            return Ok(());
        }

        // Gate 2: CRD must be installed
        let ar = match &self.api_resource {
            Some(ar) => ar.clone(),
            None => return Ok(()),
        };

        // Gate 3: service must have a port named "metrics".
        // Scraping arbitrary ports (http, grpc) produces noisy errors because
        // they don't serve Prometheus metrics. Requiring an explicit "metrics"
        // port is opt-in: zero config for those who add it, zero noise for
        // those who don't.
        let has_metrics_port = ctx
            .service
            .spec
            .service
            .as_ref()
            .map(|svc| svc.ports.contains_key("metrics"))
            .unwrap_or(false);
        if !has_metrics_port {
            return Ok(());
        }

        let endpoints = vec![serde_json::json!({
            "port": "metrics",
            "path": "/metrics",
            "interval": "30s"
        })];

        let monitor_name = format!("{}-monitor", ctx.name);

        let json = serde_json::json!({
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "ServiceMonitor",
            "metadata": {
                "name": monitor_name,
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
                "endpoints": endpoints
            }
        });

        output.extensions.push(DynamicResource {
            kind: "ServiceMonitor".to_string(),
            name: monitor_name,
            json,
            api_resource: ar,
            layer: ApplyLayer::Infrastructure,
        });

        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, LatticeService, LatticeServiceSpec, PortSpec, ServicePortsSpec,
    };
    use std::collections::BTreeMap;

    /// Build a fake ApiResource for ServiceMonitor
    fn fake_ar() -> ApiResource {
        lattice_common::kube_utils::build_api_resource("monitoring.coreos.com/v1", "ServiceMonitor")
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
                containers,
                service: if ports.is_empty() {
                    None
                } else {
                    Some(ServicePortsSpec { ports })
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
        // We need a graph but ServiceMonitorPhase doesn't use it
        use crate::crd::ProviderType;
        use crate::graph::ServiceGraph;

        // Leak a ServiceGraph so the reference lives long enough for tests.
        // In tests this is fine — each test is short-lived.
        let graph: &'static ServiceGraph = Box::leak(Box::new(ServiceGraph::new()));

        CompilationContext {
            service,
            name: service.metadata.name.as_deref().unwrap(),
            namespace: service.metadata.namespace.as_deref().unwrap(),
            graph,
            cluster_name: "test-cluster",
            provider_type: ProviderType::Docker,
            monitoring_enabled,
        }
    }

    // =========================================================================
    // Gate tests
    // =========================================================================

    #[test]
    fn monitoring_disabled_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, false);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
    }

    #[test]
    fn crd_not_installed_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(None);
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
    }

    #[test]
    fn no_ports_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
    }

    #[test]
    fn no_metrics_port_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80), ("grpc", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
    }

    // =========================================================================
    // Happy path tests
    // =========================================================================

    #[test]
    fn metrics_port_produces_service_monitor() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();

        assert_eq!(compiled.extensions.len(), 1);
        let ext = &compiled.extensions[0];
        assert_eq!(ext.kind, "ServiceMonitor");
        assert_eq!(ext.name, "my-app-monitor");
        assert_eq!(ext.layer, ApplyLayer::Infrastructure);

        let endpoints = ext.json["spec"]["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["port"], "metrics");
        assert_eq!(endpoints[0]["path"], "/metrics");
        assert_eq!(endpoints[0]["interval"], "30s");
    }

    #[test]
    fn metrics_port_among_others_only_scrapes_metrics() {
        let svc = make_service_with_ports(
            "my-app",
            "prod",
            &[("http", 80), ("metrics", 9090), ("grpc", 9000)],
        );
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();

        assert_eq!(compiled.extensions.len(), 1);
        let endpoints = compiled.extensions[0].json["spec"]["endpoints"]
            .as_array()
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["port"], "metrics");
    }

    #[test]
    fn labels_and_selector_match_workload_compiler() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();

        let json = &compiled.extensions[0].json;

        // Metadata labels
        let labels = &json["metadata"]["labels"];
        assert_eq!(labels[LABEL_NAME], "my-app");
        assert_eq!(labels[LABEL_MANAGED_BY], LABEL_MANAGED_BY_LATTICE);

        // Selector must match what WorkloadCompiler puts on the K8s Service
        let selector = &json["spec"]["selector"]["matchLabels"];
        assert_eq!(selector[LABEL_NAME], "my-app");
    }

    #[test]
    fn correct_namespace_and_api_version() {
        let svc = make_service_with_ports("my-app", "staging", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();

        let json = &compiled.extensions[0].json;
        assert_eq!(json["apiVersion"], "monitoring.coreos.com/v1");
        assert_eq!(json["kind"], "ServiceMonitor");
        assert_eq!(json["metadata"]["namespace"], "staging");
    }

    #[test]
    fn layer_is_infrastructure() {
        let svc = make_service_with_ports("my-app", "default", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = ServiceMonitorPhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::new();

        phase.compile(&ctx, &mut compiled).unwrap();

        assert_eq!(compiled.extensions[0].layer, ApplyLayer::Infrastructure);
    }
}
