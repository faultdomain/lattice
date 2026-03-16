//! Phased infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests.
//! Generates a sequence of [`InfraPhase`]s, each containing one or more
//! [`InfraComponent`]s with an optional health gate (namespace whose
//! deployments must be ready before the next phase starts).
//!
//! Used by:
//! - Operator startup: applies phases sequentially with health gates
//! - Cluster controller reconciliation: applies all manifests at once (infra already exists)
//!
//! All Helm charts are pre-rendered at build time and embedded into the binary.

pub mod cert_manager;
pub mod cilium;
pub mod eastwest;
pub mod eso;
pub mod gpu;
pub mod istio;
pub mod keda;
pub mod kthena;
pub mod metrics_server;
pub mod prometheus;
pub mod tetragon;
pub mod velero;
pub mod volcano;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use kube::ResourceExt;
use tracing::debug;

use lattice_common::crd::{
    BackupsConfig, BootstrapProvider, CedarPolicy, CedarPolicySpec, EgressRule, EgressTarget,
    InfraComponentStatus, LatticeCluster, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberPort,
    MeshMemberTarget, MonitoringConfig, NetworkTopologyConfig, PeerAuth, ProviderType, ServiceRef,
};
use lattice_common::{
    DEFAULT_AUTH_PROXY_PORT, DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT, DEFAULT_PROXY_PORT,
    DEFAULT_WEBHOOK_PORT, LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_PORT, MONITORING_NAMESPACE,
    OPERATOR_NAME, VMAGENT_SA_NAME,
};

/// A single infrastructure component with its name, version, and manifests.
#[derive(Debug, Clone)]
pub struct InfraComponent {
    /// Human-readable name (e.g., "istio", "cilium", "cert-manager").
    pub name: &'static str,
    /// Pinned version from versions.toml (embedded at build time).
    pub version: &'static str,
    /// YAML/JSON manifests to apply via server-side apply.
    pub manifests: Vec<String>,
    /// Namespace to health-gate on after apply.
    /// When set, the phase runner waits for all Deployments in this namespace
    /// to be available before moving to the next phase.
    pub health_namespace: Option<&'static str>,
}

impl InfraComponent {
    /// Convert to the CRD status representation.
    pub fn to_status(&self) -> InfraComponentStatus {
        InfraComponentStatus {
            name: self.name.to_string(),
            desired_version: self.version.to_string(),
            current_version: None,
            phase: Default::default(),
        }
    }
}

/// A group of components applied together.
///
/// All components in a phase are applied (manifests sent to the API server),
/// then all health gates are checked before the next phase begins.
#[derive(Debug, Clone)]
pub struct InfraPhase {
    /// Phase name for logging and status reporting.
    pub name: &'static str,
    /// Components in this phase.
    pub components: Vec<InfraComponent>,
}

impl InfraPhase {
    /// Collect all manifests across all components in this phase.
    pub fn all_manifests(&self) -> Vec<String> {
        self.components
            .iter()
            .flat_map(|c| c.manifests.iter().cloned())
            .collect()
    }

    /// Collect the unique namespaces that need health-gating in this phase.
    pub fn health_namespaces(&self) -> Vec<&'static str> {
        let mut ns: Vec<&'static str> = self
            .components
            .iter()
            .filter_map(|c| c.health_namespace)
            .collect();
        ns.dedup();
        ns
    }
}

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Cluster name for trust domain (lattice.{cluster}.local)
    pub cluster_name: String,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
    /// Skip Istio, Gateway API CRDs, and mesh-related Cilium policies
    pub skip_service_mesh: bool,
    /// Parent cell hostname (None for root/management clusters)
    pub parent_host: Option<String>,
    /// Parent cell gRPC port (used with parent_host)
    pub parent_grpc_port: u16,
    /// Enable GPU infrastructure (NFD + NVIDIA device plugin)
    pub gpu: bool,
    /// Monitoring infrastructure configuration (VictoriaMetrics + KEDA for autoscaling).
    pub monitoring: MonitoringConfig,
    /// Backup infrastructure configuration (Velero).
    pub backups: BackupsConfig,
    /// Network topology configuration for topology-aware scheduling.
    pub network_topology: Option<NetworkTopologyConfig>,
    /// Lattice root CA for generating Istio intermediate CA (cacerts Secret).
    /// When set, a per-cluster intermediate CA is generated and installed as
    /// the `cacerts` Secret before istiod starts, enabling cross-cluster mTLS.
    pub root_ca: Option<crate::pki::CertificateAuthority>,
}

impl Default for InfrastructureConfig {
    fn default() -> Self {
        Self {
            provider: ProviderType::default(),
            bootstrap: BootstrapProvider::default(),
            cluster_name: String::new(),
            skip_cilium_policies: false,
            skip_service_mesh: false,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            root_ca: None,
        }
    }
}

impl From<&LatticeCluster> for InfrastructureConfig {
    /// Create an InfrastructureConfig from a LatticeCluster
    ///
    /// Extracts provider, bootstrap, and cluster name.
    /// NOTE: Does NOT set parent_host - that must come from the `lattice-parent-config`
    /// secret (the upstream parent this cluster connects to), not from parent_config
    /// (which is for this cluster's own cell server endpoints).
    fn from(cluster: &LatticeCluster) -> Self {
        Self {
            provider: cluster.spec.provider.provider_type(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            cluster_name: cluster.name_any(),
            skip_cilium_policies: false,
            skip_service_mesh: !cluster.spec.services,
            parent_host: None,
            parent_grpc_port: DEFAULT_GRPC_PORT,
            gpu: cluster.spec.gpu,
            monitoring: cluster.spec.monitoring.clone(),
            backups: cluster.spec.backups.clone(),
            network_topology: cluster.spec.network_topology.clone(),
            root_ca: None, // Set by caller when CA is available
        }
    }
}

/// Generate infrastructure as a sequence of phases.
///
/// Each phase contains components that can be applied together, with health
/// gates checked between phases. The ordering ensures dependencies are met:
///
/// - Phase 0 "cert-manager": must be ready before CAPI and webhook-dependent components
/// - Phase 1 "service-mesh": Istio + Cilium + Gateway API CRDs
/// - Phase 2 "core": ESO, Volcano, Kthena, Tetragon (always installed)
/// - Phase 3 "monitoring": VictoriaMetrics + KEDA + metrics-server (conditional)
/// - Phase 4 "gpu": GPU operator (conditional)
/// - Phase 5 "backup": Velero (conditional)
pub fn generate_phases(config: &InfrastructureConfig) -> Result<Vec<InfraPhase>, String> {
    let mut phases = Vec::new();

    // Phase 0: cert-manager (must be ready before anything with webhooks)
    phases.push(InfraPhase {
        name: "cert-manager",
        components: vec![InfraComponent {
            name: "cert-manager",
            version: cert_manager::cert_manager_version(),
            manifests: cert_manager::generate_cert_manager().to_vec(),
            health_namespace: Some("cert-manager"),
        }],
    });

    // Phase 1: service mesh (Istio + Cilium policies + Gateway API CRDs)
    if !config.skip_service_mesh {
        let mut components = Vec::new();

        // Gateway API CRDs first (Istio depends on them)
        let gw_api = generate_gateway_api_crds();
        debug!(count = gw_api.len(), "generated Gateway API CRDs");
        components.push(InfraComponent {
            name: "gateway-api",
            version: env!("GATEWAY_API_VERSION"),
            manifests: gw_api.to_vec(),
            health_namespace: None, // CRDs only, no deployments
        });

        // Istio ambient mesh + policies
        components.push(InfraComponent {
            name: "istio",
            version: env!("ISTIO_VERSION"),
            manifests: generate_istio_manifests(config)?,
            health_namespace: Some("istio-system"),
        });

        // East-west gateway + istiod proxy RBAC for multi-cluster
        let mut ew_manifests = vec![eastwest::generate_eastwest_gateway(&config.cluster_name)];
        ew_manifests.extend(eastwest::generate_istiod_proxy_rbac());
        components.push(InfraComponent {
            name: "eastwest-gateway",
            version: env!("ISTIO_VERSION"),
            manifests: ew_manifests,
            health_namespace: None, // Gateway controller creates deployment async
        });

        // Cilium network policies
        if !config.skip_cilium_policies {
            components.push(InfraComponent {
                name: "cilium-policies",
                version: env!("CILIUM_VERSION"),
                manifests: generate_cilium_policy_manifests()?,
                health_namespace: None, // Policy objects, no deployments
            });
        }

        // Enroll lattice-system in ambient mesh so ESO can reach the operator's
        // local-secrets webhook via HBONE/mTLS. Applied in Phase 1 so the
        // namespace label and MeshMember CRD are present before ESO starts in
        // Phase 2. The static operator-allow AuthorizationPolicy (above) covers
        // the bootstrap window before the MeshMember controller processes this.
        let mut operator_manifests = vec![namespace_yaml_ambient(LATTICE_SYSTEM_NAMESPACE)];
        operator_manifests.extend(serialize_lmms(vec![generate_operator_mesh_member()])?);
        components.push(InfraComponent {
            name: "operator-mesh-enrollment",
            version: "1",
            manifests: operator_manifests,
            health_namespace: None,
        });

        phases.push(InfraPhase {
            name: "service-mesh",
            components,
        });
    }

    // Phase 2: core services (always installed)
    {
        let mut components = vec![
            InfraComponent {
                name: "eso",
                version: eso::eso_version(),
                manifests: eso::generate_eso().to_vec(),
                health_namespace: Some("external-secrets"),
            },
            InfraComponent {
                name: "volcano",
                version: volcano::volcano_version(),
                manifests: generate_volcano_manifests(config),
                health_namespace: Some("volcano-system"),
            },
            InfraComponent {
                name: "kthena",
                version: kthena::kthena_version(),
                manifests: kthena::generate_kthena().to_vec(),
                health_namespace: Some("kthena-system"),
            },
        ];

        // Tetragon (DaemonSet in kube-system, no namespace health gate)
        let mut tetragon_manifests = tetragon::generate_tetragon().to_vec();
        tetragon_manifests.push(
            serde_json::to_string_pretty(&tetragon::generate_baseline_tracing_policy())
                .map_err(|e| format!("Failed to serialize baseline TracingPolicy: {e}"))?,
        );
        components.push(InfraComponent {
            name: "tetragon",
            version: tetragon::tetragon_version(),
            manifests: tetragon_manifests,
            health_namespace: None, // DaemonSet, not deployments
        });

        // Mesh policies for core components (ESO, Volcano, Kthena)
        // These must be in Phase 2 because these namespaces are subject to
        // default-deny after Phase 1 (service-mesh) completes.
        if !config.skip_service_mesh {
            let mut mesh_manifests = Vec::new();
            mesh_manifests.extend(serialize_lmms(eso::generate_eso_mesh_members())?);
            mesh_manifests.extend(serialize_lmms(volcano::generate_volcano_mesh_members())?);
            mesh_manifests.extend(serialize_lmms(kthena::generate_kthena_mesh_members())?);
            mesh_manifests.push(
                serde_json::to_string_pretty(&generate_kthena_router_cedar_policy())
                    .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?,
            );
            mesh_manifests.push(
                serde_json::to_string_pretty(&generate_kthena_autoscaler_cedar_policy())
                    .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?,
            );
            components.push(InfraComponent {
                name: "core-mesh-policies",
                version: "1",
                manifests: mesh_manifests,
                health_namespace: None,
            });
        }

        phases.push(InfraPhase {
            name: "core",
            components,
        });
    }

    // Phase 3: monitoring (conditional)
    if config.monitoring.enabled {
        let mut components = vec![
            InfraComponent {
                name: "victoria-metrics",
                version: prometheus::victoria_metrics_version(),
                manifests: prometheus::generate_prometheus(config.monitoring.ha).to_vec(),
                health_namespace: Some("monitoring"),
            },
            InfraComponent {
                name: "keda",
                version: keda::keda_version(),
                manifests: keda::generate_keda().to_vec(),
                health_namespace: Some("keda"),
            },
            InfraComponent {
                name: "metrics-server",
                version: metrics_server::metrics_server_version(),
                manifests: metrics_server::generate_metrics_server().to_vec(),
                health_namespace: None, // Deploys into kube-system
            },
        ];

        // Mesh policies for monitoring components (keda + monitoring only)
        if !config.skip_service_mesh {
            let mut mesh_manifests = Vec::new();
            mesh_manifests.extend(serialize_lmms(keda::generate_keda_mesh_members())?);
            mesh_manifests.extend(serialize_lmms(
                prometheus::generate_monitoring_mesh_members(config.monitoring.ha),
            )?);
            mesh_manifests.push(
                serde_json::to_string_pretty(&generate_vmagent_cedar_policy())
                    .map_err(|e| format!("Failed to serialize CedarPolicy: {e}"))?,
            );

            components.push(InfraComponent {
                name: "monitoring-mesh-policies",
                version: prometheus::victoria_metrics_version(),
                manifests: mesh_manifests,
                health_namespace: None,
            });
        }

        phases.push(InfraPhase {
            name: "monitoring",
            components,
        });
    }

    // Phase 4: GPU (conditional)
    if config.gpu {
        let mut components = vec![InfraComponent {
            name: "gpu-operator",
            version: gpu::gpu_operator_version(),
            manifests: gpu::generate_gpu_stack().to_vec(),
            health_namespace: Some("gpu-operator"),
        }];

        if !config.skip_service_mesh {
            components.push(InfraComponent {
                name: "gpu-mesh-policies",
                version: "1",
                manifests: serialize_lmms(gpu::generate_gpu_mesh_members())?,
                health_namespace: None,
            });
        }

        phases.push(InfraPhase {
            name: "gpu",
            components,
        });
    }

    // Phase 5: backup (conditional)
    if config.backups.enabled {
        let mut components = vec![InfraComponent {
            name: "velero",
            version: velero::velero_version(),
            manifests: velero::generate_velero().to_vec(),
            health_namespace: Some("velero"),
        }];

        if !config.skip_service_mesh {
            components.push(InfraComponent {
                name: "velero-mesh-policies",
                version: "1",
                manifests: serialize_lmms(velero::generate_velero_mesh_members())?,
                health_namespace: None,
            });
        }

        phases.push(InfraPhase {
            name: "backup",
            components,
        });
    }

    Ok(phases)
}

/// Flatten all phases into a single manifest list.
///
/// Used by the cluster controller for reconciliation (infra already exists,
/// just ensuring desired state — no need for phased application).
pub fn flatten_manifests(phases: &[InfraPhase]) -> Vec<String> {
    phases.iter().flat_map(|p| p.all_manifests()).collect()
}

/// Generate all infrastructure manifests as a flat list.
///
/// Convenience wrapper around [`generate_phases`] + [`flatten_manifests`]
/// for call sites that don't need phased application.
pub fn generate_all_manifests(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    let phases = generate_phases(config)?;
    Ok(flatten_manifests(&phases))
}

// ---- Phase application ----

/// Timeout for deployment health gates between phases.
const HEALTH_GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Apply a single phase: send manifests to the API server, then wait for health gates.
///
/// Returns the list of `InfraComponentStatus` entries for this phase.
pub async fn apply_phase(
    client: &kube::Client,
    phase: &InfraPhase,
) -> anyhow::Result<Vec<InfraComponentStatus>> {
    use lattice_common::crd::InfraComponentPhase;
    use lattice_common::kube_utils;
    use lattice_common::retry::{retry_with_backoff, RetryConfig};
    use lattice_common::{apply_manifests, ApplyOptions};

    let manifests = phase.all_manifests();
    tracing::info!(
        phase = phase.name,
        components = phase.components.len(),
        manifests = manifests.len(),
        "Applying infrastructure phase"
    );

    // Apply manifests with retry
    let retry = RetryConfig {
        initial_delay: std::time::Duration::from_secs(2),
        ..RetryConfig::default()
    };
    retry_with_backoff(&retry, phase.name, || {
        let client = client.clone();
        let manifests = manifests.clone();
        async move { apply_manifests(&client, &manifests, &ApplyOptions::default()).await }
    })
    .await?;

    // Wait for health gates
    let health_namespaces = phase.health_namespaces();
    for ns in &health_namespaces {
        tracing::info!(
            phase = phase.name,
            namespace = ns,
            "Waiting for deployments"
        );
        kube_utils::wait_for_all_deployments(client, ns, HEALTH_GATE_TIMEOUT)
            .await
            .map_err(|e| anyhow::anyhow!("{} health gate failed ({}): {}", phase.name, ns, e))?;
    }

    // Build status entries
    let statuses = phase
        .components
        .iter()
        .map(|c| InfraComponentStatus {
            name: c.name.to_string(),
            desired_version: c.version.to_string(),
            current_version: Some(c.version.to_string()),
            phase: InfraComponentPhase::UpToDate,
        })
        .collect();

    tracing::info!(phase = phase.name, "Phase complete");
    Ok(statuses)
}

/// Apply all phases sequentially, waiting for health gates between each phase.
///
/// Returns the combined `InfraComponentStatus` entries for all components.
/// If `skip_first_n` is set, skips that many phases (useful when cert-manager
/// was already applied in the blocking path).
pub async fn apply_all_phases(
    client: &kube::Client,
    phases: &[InfraPhase],
    skip_first_n: usize,
) -> anyhow::Result<Vec<InfraComponentStatus>> {
    let mut statuses = Vec::new();

    for phase in phases.iter().skip(skip_first_n) {
        statuses.extend(apply_phase(client, phase).await?);
    }

    Ok(statuses)
}

// ---- Internal manifest generators ----

/// Generate Istio manifests (namespace + charts + cacerts + policies).
///
/// The cacerts Secret MUST be created before istiod starts. When istiod finds
/// a `cacerts` Secret in `istio-system`, it uses the intermediate CA from that
/// Secret to sign workload certificates instead of generating a self-signed CA.
/// This enables cross-cluster mTLS when all clusters share the same root CA.
fn generate_istio_manifests(config: &InfrastructureConfig) -> Result<Vec<String>, String> {
    // istio-system needs topology.istio.io/network label for multi-cluster
    let mut manifests = vec![namespace_yaml_with_network(
        "istio-system",
        &config.cluster_name,
    )];

    // cacerts Secret with per-cluster intermediate CA (must be before istiod).
    // Only included when root_ca is Some — the caller is responsible for
    // checking whether cacerts already exists to avoid regenerating the
    // intermediate CA on every reconcile (which would break in-flight mTLS).
    if let Some(ref root_ca) = config.root_ca {
        manifests.push(
            generate_cacerts_manifest(root_ca, &config.cluster_name)
                .map_err(|e| format!("Failed to generate cacerts: {e}"))?,
        );
    }

    let reconciler = istio::IstioReconciler::new(&config.cluster_name);
    manifests.extend(reconciler.manifests().iter().cloned());

    for policy in [
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_peer_authentication()),
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_default_deny()),
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_waypoint_default_deny()),
        serde_json::to_string_pretty(&istio::IstioReconciler::generate_operator_allow_policy()),
    ] {
        manifests.push(policy.map_err(|e| format!("Failed to serialize Istio policy: {e}"))?);
    }

    Ok(manifests)
}

/// Generate the `cacerts` Secret for Istio's intermediate CA.
///
/// Istio expects four PEM files in a `cacerts` Secret in `istio-system`:
/// - `ca-cert.pem`: per-cluster intermediate CA (signed by root)
/// - `ca-key.pem`: intermediate CA private key
/// - `root-cert.pem`: shared root CA
/// - `cert-chain.pem`: intermediate + root concatenated
fn generate_cacerts_manifest(
    root_ca: &crate::pki::CertificateAuthority,
    cluster_name: &str,
) -> Result<String, crate::pki::PkiError> {
    use base64::Engine;

    let intermediate = root_ca.generate_istio_intermediate_ca(cluster_name)?;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());

    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "cacerts",
            "namespace": "istio-system",
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "data": {
            "ca-cert.pem": b64(&intermediate.ca_cert_pem),
            "ca-key.pem": b64(&intermediate.ca_key_pem),
            "root-cert.pem": b64(&intermediate.root_cert_pem),
            "cert-chain.pem": b64(&intermediate.cert_chain_pem)
        }
    });

    Ok(serde_json::to_string_pretty(&secret).expect("serialize cacerts"))
}

/// Generate Cilium network policy manifests.
fn generate_cilium_policy_manifests() -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();

    for policy in [
        serde_json::to_string_pretty(&cilium::generate_ztunnel_allowlist()),
        serde_json::to_string_pretty(&cilium::generate_default_deny()),
        serde_json::to_string_pretty(&cilium::generate_mesh_proxy_egress_policy()),
        serde_json::to_string_pretty(&cilium::generate_eastwest_gateway_policy()),
    ] {
        manifests
            .push(policy.map_err(|e| format!("Failed to serialize CiliumNetworkPolicy: {e}"))?);
    }

    Ok(manifests)
}

/// Generate Volcano manifests including optional topology discovery ConfigMap.
fn generate_volcano_manifests(config: &InfrastructureConfig) -> Vec<String> {
    let mut manifests = volcano::generate_volcano().to_vec();

    if let Some(ref topo) = config.network_topology {
        if let Some(cm) = volcano::generate_topology_discovery_configmap(topo, config.provider) {
            manifests.push(cm);
        }
    }

    manifests
}

// ---- Helpers ----

/// Pre-rendered Gateway API CRDs embedded at build time.
static GATEWAY_API_CRDS: LazyLock<Vec<String>> = LazyLock::new(|| {
    split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gateway-api-crds.yaml"
    )))
});

/// Generate Gateway API CRDs
pub fn generate_gateway_api_crds() -> &'static [String] {
    &GATEWAY_API_CRDS
}

pub(crate) fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

/// Create a namespace YAML with Istio multi-cluster network label.
///
/// The `topology.istio.io/network` label tells istiod which network this
/// namespace belongs to, required for cross-network traffic routing.
pub(crate) fn namespace_yaml_with_network(name: &str, network: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n  labels:\n    topology.istio.io/network: {}",
        name, network
    )
}

/// Egress rule allowing traffic to the kube-apiserver.
///
/// Required for system components (KEDA, VM operator, etc.) that need to
/// reach the Kubernetes API from within the ambient mesh.
/// Port 6443 is the actual endpoint port after DNAT from the ClusterIP (443).
pub(crate) fn kube_apiserver_egress() -> EgressRule {
    EgressRule {
        target: EgressTarget::Entity("kube-apiserver".to_string()),
        ports: vec![6443],
    }
}

/// Generate a LatticeMeshMember for the lattice-operator itself.
///
/// Enrolls the operator in the ambient mesh so ESO (also ambient) can reach
/// the local-secrets webhook via proper HBONE/mTLS instead of an FQDN egress
/// hack. Ports 8443 (bootstrap webhook) and 50051 (agent gRPC) use Webhook
/// PeerAuth because their callers lack mesh identity.
pub fn generate_operator_mesh_member() -> LatticeMeshMember {
    lmm(
        OPERATOR_NAME,
        LATTICE_SYSTEM_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                OPERATOR_NAME.to_string(),
            )])),
            ports: vec![
                MeshMemberPort {
                    port: DEFAULT_WEBHOOK_PORT,
                    service_port: None,
                    name: "validation-webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_BOOTSTRAP_PORT,
                    service_port: None,
                    name: "webhook".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_GRPC_PORT,
                    service_port: None,
                    name: "grpc".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_PROXY_PORT,
                    service_port: None,
                    name: "proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: DEFAULT_AUTH_PROXY_PORT,
                    service_port: None,
                    name: "auth-proxy".to_string(),
                    peer_auth: PeerAuth::Webhook,
                },
                MeshMemberPort {
                    port: LOCAL_SECRETS_PORT,
                    service_port: None,
                    name: "local-secrets".to_string(),
                    peer_auth: PeerAuth::Strict,
                },
            ],
            allowed_callers: vec![ServiceRef::new("external-secrets", "external-secrets")],
            dependencies: vec![ServiceRef::new(MONITORING_NAMESPACE, "vm-read-target")],
            egress: vec![
                kube_apiserver_egress(),
                // Agent connects outbound to parent cell's gRPC and bootstrap ports
                EgressRule {
                    target: EgressTarget::Entity("world".to_string()),
                    ports: vec![DEFAULT_GRPC_PORT, DEFAULT_BOOTSTRAP_PORT],
                },
            ],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true,
        },
    )
}

/// Create a namespaced LatticeMeshMember.
pub(crate) fn lmm(name: &str, namespace: &str, spec: LatticeMeshMemberSpec) -> LatticeMeshMember {
    let mut member = LatticeMeshMember::new(name, spec);
    member.metadata.namespace = Some(namespace.to_string());
    member
}

/// Generate the CedarPolicy that permits vmagent's wildcard outbound.
///
/// vmagent uses `depends_all: true` to scrape metrics from any service that
/// exposes a "metrics" port. This Cedar policy authorizes that wildcard.
fn generate_vmagent_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "vmagent-wildcard-outbound",
        CedarPolicySpec {
            description: Some("Allow vmagent wildcard outbound for metrics scraping".to_string()),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{}/{}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);"#,
                MONITORING_NAMESPACE, VMAGENT_SA_NAME,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Generate the CedarPolicy that permits kthena-router's wildcard traffic.
///
/// kthena-router uses `depends_all: true` to reach any model service that
/// declares it as an allowed caller (outbound), and `allowed_callers: [*]`
/// so any service can send inference requests through it (inbound).
fn generate_kthena_router_cedar_policy() -> CedarPolicy {
    let principal = format!(
        "{}/{}",
        lattice_common::KTHENA_NAMESPACE,
        lattice_common::KTHENA_ROUTER_SA,
    );
    let mut policy = CedarPolicy::new(
        "kthena-router-wildcard",
        CedarPolicySpec {
            description: Some(
                "Allow kthena-router wildcard outbound (model routing) and inbound (inference requests)".to_string(),
            ),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{principal}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);

permit(
    principal == Lattice::Service::"{principal}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"inbound"
);"#,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Generate the CedarPolicy that permits kthena-autoscaler's wildcard outbound.
///
/// kthena-autoscaler uses `depends_all: true` to scrape metrics from model
/// services for autoscaling decisions. This Cedar policy authorizes that wildcard.
fn generate_kthena_autoscaler_cedar_policy() -> CedarPolicy {
    let mut policy = CedarPolicy::new(
        "kthena-autoscaler-wildcard-outbound",
        CedarPolicySpec {
            description: Some(
                "Allow kthena-autoscaler wildcard outbound for model metrics scraping".to_string(),
            ),
            policies: format!(
                r#"permit(
    principal == Lattice::Service::"{}/{}",
    action == Lattice::Action::"AllowWildcard",
    resource == Lattice::Mesh::"outbound"
);"#,
                lattice_common::KTHENA_NAMESPACE,
                lattice_common::KTHENA_AUTOSCALER_SA,
            ),
            priority: 0,
            enabled: true,
            propagate: true,
        },
    );
    policy.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    policy
}

/// Serialize a vec of LMMs to JSON manifests.
fn serialize_lmms(members: Vec<LatticeMeshMember>) -> Result<Vec<String>, String> {
    members
        .iter()
        .map(|m| {
            serde_json::to_string_pretty(m)
                .map_err(|e| format!("Failed to serialize LatticeMeshMember: {e}"))
        })
        .collect()
}

/// Create a namespace YAML with Istio ambient mesh enrollment.
///
/// Used for infrastructure namespaces (e.g. monitoring) whose pods need
/// mTLS communication with workload pods enrolled in the ambient mesh.
pub(crate) fn namespace_yaml_ambient(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n  labels:\n    istio.io/dataplane-mode: ambient",
        name
    )
}

/// Split a multi-document YAML string into individual documents.
///
/// Only used for parsing external YAML sources (helm output, CRD files).
/// Filters out empty documents and comment-only blocks.
/// Normalizes output to always have `---` prefix for kubectl apply compatibility.
///
/// Helm hooks: `pre-install` and `pre-upgrade` hooks are kept because they
/// contain setup resources (e.g. cert-generation Jobs) that work fine when
/// applied as regular resources — the retry loop handles ordering. Test and
/// delete hooks are filtered since they don't make sense outside `helm install`.
///
/// Note: JSON policies from our typed generators are added directly to manifest
/// lists and never go through this function.
pub fn split_yaml_documents(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|doc| doc.trim())
        .filter(|doc| {
            let keep = !doc.is_empty() && doc.contains("kind:") && !is_filtered_helm_hook(doc);
            if !keep && !doc.is_empty() {
                tracing::debug!(
                    doc_preview = &doc[..doc.len().min(100)],
                    "Filtered out YAML document"
                );
            }
            keep
        })
        .map(|doc| {
            if doc.starts_with("---") {
                doc.to_string()
            } else {
                format!("---\n{}", doc)
            }
        })
        .collect()
}

/// Returns true if a YAML document is a Helm hook that should be filtered out.
///
/// We keep pre-install/pre-upgrade hooks (setup resources like cert-generation Jobs)
/// and filter test/delete hooks that only make sense during `helm install/delete`.
fn is_filtered_helm_hook(doc: &str) -> bool {
    if !doc.contains("helm.sh/hook") {
        return false;
    }
    // Keep pre-install and pre-upgrade hooks — they set up prerequisites
    // and work fine as regular resources applied alongside everything else
    if doc.contains("pre-install") || doc.contains("pre-upgrade") {
        return false;
    }
    // Filter test hooks, delete hooks, and any other hook types
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_yaml_documents() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_namespace_yaml() {
        let ns = namespace_yaml("test");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: test"));
    }

    #[test]
    fn test_gateway_api_crds() {
        let crds = generate_gateway_api_crds();
        assert!(!crds.is_empty());
        assert!(crds.iter().any(|c| c.contains("CustomResourceDefinition")));
    }

    #[test]
    fn helm_hooks_pre_install_kept() {
        let yaml = "kind: Job\nmetadata:\n  annotations:\n    helm.sh/hook: pre-install\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 2, "pre-install hooks should be kept");
    }

    #[test]
    fn helm_hooks_test_filtered() {
        let yaml =
            "kind: Pod\nmetadata:\n  annotations:\n    helm.sh/hook: test\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1, "test hooks should be filtered");
    }

    #[test]
    fn helm_hooks_pre_delete_filtered() {
        let yaml = "kind: Job\nmetadata:\n  annotations:\n    helm.sh/hook: pre-delete\n---\nkind: Deployment\n";
        let docs = split_yaml_documents(yaml);
        assert_eq!(docs.len(), 1, "pre-delete hooks should be filtered");
    }

    #[test]
    fn generate_phases_default_config() {
        let config = InfrastructureConfig::default();
        let phases = generate_phases(&config).expect("should generate phases");

        // cert-manager is always phase 0
        assert_eq!(phases[0].name, "cert-manager");
        assert_eq!(phases[0].components[0].name, "cert-manager");
        assert_eq!(
            phases[0].components[0].health_namespace,
            Some("cert-manager")
        );

        // All phases should have at least one component
        for phase in &phases {
            assert!(
                !phase.components.is_empty(),
                "phase {} is empty",
                phase.name
            );
            for comp in &phase.components {
                assert!(
                    !comp.manifests.is_empty(),
                    "component {} has no manifests",
                    comp.name
                );
                assert!(
                    !comp.version.is_empty(),
                    "component {} has no version",
                    comp.name
                );
            }
        }
    }

    #[test]
    fn generate_phases_with_monitoring() {
        let config = InfrastructureConfig {
            monitoring: MonitoringConfig {
                enabled: true,
                ha: false,
            },
            ..Default::default()
        };
        let phases = generate_phases(&config).expect("should generate phases");
        assert!(
            phases.iter().any(|p| p.name == "monitoring"),
            "should include monitoring phase"
        );
    }

    #[test]
    fn generate_phases_without_monitoring() {
        let config = InfrastructureConfig {
            monitoring: MonitoringConfig {
                enabled: false,
                ha: false,
            },
            ..Default::default()
        };
        let phases = generate_phases(&config).expect("should generate phases");
        assert!(
            !phases.iter().any(|p| p.name == "monitoring"),
            "should not include monitoring phase"
        );
    }

    #[test]
    fn generate_all_manifests_matches_flatten() {
        let config = InfrastructureConfig::default();
        let all = generate_all_manifests(&config).expect("should generate");
        let phases = generate_phases(&config).expect("should generate");
        let flattened = flatten_manifests(&phases);
        assert_eq!(all.len(), flattened.len());
    }

    #[test]
    fn component_to_status() {
        let comp = InfraComponent {
            name: "test",
            version: "1.0.0",
            manifests: vec![],
            health_namespace: None,
        };
        let status = comp.to_status();
        assert_eq!(status.name, "test");
        assert_eq!(status.desired_version, "1.0.0");
        assert!(status.current_version.is_none());
    }

    #[test]
    fn operator_mesh_member_generated() {
        let member = generate_operator_mesh_member();
        assert_eq!(member.metadata.name.as_deref(), Some("lattice-operator"));
        assert_eq!(
            member.metadata.namespace.as_deref(),
            Some(LATTICE_SYSTEM_NAMESPACE)
        );
        assert!(member.spec.validate().is_ok());
        assert!(member.spec.ambient);

        // 6 ports: validation-webhook (9443), webhook (8443), grpc (50051), proxy (8081), auth-proxy (8082), local-secrets (8787)
        assert_eq!(member.spec.ports.len(), 6);

        let webhook = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "webhook")
            .expect("webhook port");
        assert_eq!(webhook.port, DEFAULT_BOOTSTRAP_PORT);
        assert_eq!(webhook.peer_auth, PeerAuth::Webhook);

        let grpc = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "grpc")
            .expect("grpc port");
        assert_eq!(grpc.port, DEFAULT_GRPC_PORT);
        assert_eq!(grpc.peer_auth, PeerAuth::Webhook);

        let proxy = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "proxy")
            .expect("proxy port");
        assert_eq!(proxy.port, DEFAULT_PROXY_PORT);
        assert_eq!(proxy.peer_auth, PeerAuth::Webhook);

        let auth_proxy = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "auth-proxy")
            .expect("auth-proxy port");
        assert_eq!(auth_proxy.port, DEFAULT_AUTH_PROXY_PORT);
        assert_eq!(auth_proxy.peer_auth, PeerAuth::Webhook);

        let secrets = member
            .spec
            .ports
            .iter()
            .find(|p| p.name == "local-secrets")
            .expect("local-secrets port");
        assert_eq!(secrets.port, LOCAL_SECRETS_PORT);
        assert_eq!(secrets.peer_auth, PeerAuth::Strict);

        // ESO is the only allowed caller
        assert_eq!(member.spec.allowed_callers.len(), 1);
        assert_eq!(member.spec.allowed_callers[0].name, "external-secrets");
        assert_eq!(
            member.spec.allowed_callers[0].namespace.as_deref(),
            Some("external-secrets")
        );
    }

    #[test]
    fn service_mesh_phase_includes_operator_enrollment() {
        let config = InfrastructureConfig::default();
        let phases = generate_phases(&config).expect("should generate phases");

        let mesh_phase = phases
            .iter()
            .find(|p| p.name == "service-mesh")
            .expect("service-mesh phase should exist");
        assert!(
            mesh_phase
                .components
                .iter()
                .any(|c| c.name == "operator-mesh-enrollment"),
            "service-mesh phase should include operator mesh enrollment"
        );
    }
}
