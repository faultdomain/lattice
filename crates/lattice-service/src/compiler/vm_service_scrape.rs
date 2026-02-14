//! VMServiceScrape compiler phase
//!
//! Generates a VictoriaMetrics `VMServiceScrape` for LatticeServices that
//! declare a port named `metrics`, plus an AuthorizationPolicy allowing VMAgent
//! to scrape through the Istio waypoint. This opt-in approach avoids scrape
//! errors on ports that don't serve Prometheus metrics (HTTP APIs returning HTML,
//! gRPC ports, etc.).

use std::collections::BTreeMap;

use kube::discovery::ApiResource;
use lattice_common::mesh;
use lattice_common::policy::AuthorizationPolicy;
use lattice_common::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE, LABEL_NAME};
use lattice_infra::bootstrap::prometheus::{MONITORING_NAMESPACE, VMAGENT_SERVICE_ACCOUNT};

use super::{ApplyLayer, CompiledService, DynamicResource};
use crate::compiler::phase::{CompilationContext, CompilerPhase};

/// Compiler phase that emits a `operator.victoriametrics.com/v1beta1` `VMServiceScrape`
/// and an Istio `AuthorizationPolicy` allowing VMAgent to scrape through the waypoint.
///
/// The phase no-ops when:
/// - Monitoring is disabled on the cluster
/// - The VMServiceScrape CRD is not installed (`api_resource` is `None`)
/// - The service has no port named `metrics`
pub struct VMServiceScrapePhase {
    api_resource: Option<ApiResource>,
}

impl VMServiceScrapePhase {
    /// Create a new `VMServiceScrapePhase`.
    ///
    /// Pass `None` if the VMServiceScrape CRD is not installed — the phase
    /// will gracefully no-op.
    pub fn new(api_resource: Option<ApiResource>) -> Self {
        Self { api_resource }
    }
}

impl CompilerPhase for VMServiceScrapePhase {
    fn name(&self) -> &str {
        "vm-service-scrape"
    }

    fn compile(
        &self,
        ctx: &CompilationContext<'_>,
        output: &mut CompiledService,
    ) -> Result<(), String> {
        if !ctx.monitoring.enabled {
            return Ok(());
        }

        let ar = match &self.api_resource {
            Some(ar) => ar.clone(),
            None => return Ok(()),
        };

        // Only generate a scrape config for services that explicitly declare
        // a port named "metrics". Many services expose HTTP/gRPC ports where
        // they don't serve Prometheus metrics. Requiring an explicit "metrics"
        // port is opt-in: zero config for those who add it, zero noise for
        // those who don't.
        let metrics_port = ctx
            .service
            .spec
            .workload
            .service
            .as_ref()
            .and_then(|svc| svc.ports.get("metrics"));
        let metrics_port = match metrics_port {
            Some(p) => p,
            None => return Ok(()),
        };

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

        // Emit AuthorizationPolicy allowing VMAgent to scrape through the waypoint.
        // Without this, the waypoint's default-deny blocks VMAgent's scrape requests.
        let vmagent_principal = mesh::trust_domain::principal(
            ctx.cluster_name,
            MONITORING_NAMESPACE,
            VMAGENT_SERVICE_ACCOUNT,
        );

        // VMAgent scrape traffic goes directly through ztunnel (no waypoint),
        // so use selector-based enforcement.
        let match_labels = BTreeMap::from([(LABEL_NAME.to_string(), ctx.name.to_string())]);
        output
            .policies
            .authorization_policies
            .push(AuthorizationPolicy::allow_to_workload(
                format!("allow-vm-scrape-{}", ctx.name),
                ctx.namespace,
                match_labels,
                vec![vmagent_principal],
                vec![metrics_port.port.to_string()],
            ));

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

    #[test]
    fn monitoring_disabled_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, false);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.policies.authorization_policies.is_empty());
    }

    #[test]
    fn crd_not_installed_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(None);
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.policies.authorization_policies.is_empty());
    }

    #[test]
    fn no_ports_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.policies.authorization_policies.is_empty());
    }

    #[test]
    fn no_metrics_port_produces_no_extensions() {
        let svc = make_service_with_ports("my-app", "default", &[("http", 80), ("grpc", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();
        assert!(compiled.extensions.is_empty());
        assert!(compiled.policies.authorization_policies.is_empty());
    }

    // =========================================================================
    // Happy-path cases
    // =========================================================================

    #[test]
    fn metrics_port_produces_vm_service_scrape() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

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

    #[test]
    fn metrics_port_produces_scrape_auth_policy() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

        assert_eq!(compiled.policies.authorization_policies.len(), 1);
        let policy = &compiled.policies.authorization_policies[0];
        assert_eq!(policy.metadata.name, "allow-vm-scrape-my-app");
        assert_eq!(policy.metadata.namespace, "prod");
        assert_eq!(policy.spec.action, "ALLOW");

        // Ztunnel-enforced via selector (no waypoint in scrape path)
        assert!(policy.spec.target_refs.is_empty());
        let selector = policy.spec.selector.as_ref().unwrap();
        assert_eq!(
            selector.match_labels.get("app.kubernetes.io/name"),
            Some(&"my-app".to_string())
        );

        // Allows VMAgent's SPIFFE identity
        let principal = &policy.spec.rules[0].from[0].source.principals[0];
        assert!(principal.contains("monitoring"));
        assert!(principal.contains("vmagent-lattice-metrics"));

        // On the metrics port
        let ports = &policy.spec.rules[0].to[0].operation.ports;
        assert_eq!(ports, &["9090"]);
    }

    #[test]
    fn metrics_port_among_others_only_scrapes_metrics() {
        let svc = make_service_with_ports(
            "my-app",
            "default",
            &[("http", 80), ("metrics", 9090), ("grpc", 9000)],
        );
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

        let endpoints = compiled.extensions[0].json["spec"]["endpoints"]
            .as_array()
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["port"], "metrics");

        // Auth policy only allows the metrics port
        let ports = &compiled.policies.authorization_policies[0].spec.rules[0].to[0]
            .operation
            .ports;
        assert_eq!(ports, &["9090"]);
    }

    #[test]
    fn labels_and_selector_match_workload_compiler() {
        let svc = make_service_with_ports("my-app", "prod", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

        let json = &compiled.extensions[0].json;
        let labels = &json["metadata"]["labels"];
        assert_eq!(labels[LABEL_NAME], "my-app");
        assert_eq!(labels[LABEL_MANAGED_BY], LABEL_MANAGED_BY_LATTICE);

        let selector = &json["spec"]["selector"]["matchLabels"];
        assert_eq!(selector[LABEL_NAME], "my-app");
    }

    #[test]
    fn correct_namespace_and_api_version() {
        let svc = make_service_with_ports("my-app", "staging", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

        let json = &compiled.extensions[0].json;
        assert_eq!(json["apiVersion"], "operator.victoriametrics.com/v1beta1");
        assert_eq!(json["kind"], "VMServiceScrape");
        assert_eq!(json["metadata"]["namespace"], "staging");
    }

    #[test]
    fn layer_is_infrastructure() {
        let svc = make_service_with_ports("my-app", "default", &[("metrics", 9090)]);
        let ctx = make_ctx(&svc, true);
        let phase = VMServiceScrapePhase::new(Some(fake_ar()));
        let mut compiled = CompiledService::default();

        phase.compile(&ctx, &mut compiled).unwrap();

        assert_eq!(compiled.extensions[0].layer, ApplyLayer::Infrastructure);
    }
}
