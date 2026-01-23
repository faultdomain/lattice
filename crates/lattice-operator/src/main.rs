//! Lattice Operator - Kubernetes multi-cluster lifecycle management

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, CustomResourceExt};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use lattice_operator::agent::client::{AgentClient, AgentClientConfig, AgentCredentials};
use lattice_operator::capi::{ensure_capi_installed, CapiProviderConfig, ClusterctlInstaller};
use lattice_operator::controller::{
    error_policy, error_policy_external, reconcile, reconcile_external, service_error_policy,
    service_reconcile, Context, ServiceContext,
};
use lattice_operator::crd::{LatticeCluster, LatticeExternalService, LatticeService, ProviderType};
use lattice_operator::parent::{ParentConfig, ParentServers};

/// Lattice - CRD-driven Kubernetes operator for multi-cluster lifecycle management
#[derive(Parser, Debug)]
#[command(name = "lattice", version, about, long_about = None)]
struct Cli {
    /// Generate CRD manifests and exit
    #[arg(long)]
    crd: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Controller mode selection
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ControllerMode {
    /// Run all controllers (cluster + service)
    #[default]
    All,
    /// Run only cluster controller (LatticeCluster management)
    Cluster,
    /// Run only service controller (LatticeService/ExternalService management)
    Service,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as controller (default mode)
    ///
    /// Every Lattice instance runs as a controller that:
    /// - Watches LatticeCluster CRDs and reconciles them
    /// - If this cluster has a cellRef (parent), also connects as an agent
    /// - If this cluster has a cell spec, starts cell servers for child clusters
    ///
    /// This unified mode means every cluster is self-managing.
    Controller {
        /// Which controllers to run
        #[arg(long, short, value_enum, default_value = "all")]
        mode: ControllerMode,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install crypto provider - FIPS-validated aws-lc-rs
    // This MUST succeed for the application to operate securely.
    // Failure here indicates a serious system configuration issue.
    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        eprintln!(
            "CRITICAL: Failed to install FIPS-validated crypto provider: {:?}. \
             The application cannot operate securely without a working TLS implementation. \
             This may indicate aws-lc-rs was not compiled correctly or there is a \
             conflict with another crypto provider.",
            e
        );
        std::process::exit(1);
    }

    // When compiled with FIPS feature, verify FIPS mode is actually active
    #[cfg(feature = "fips")]
    {
        if let Err(e) = aws_lc_rs::try_fips_mode() {
            eprintln!(
                "CRITICAL: FIPS feature is enabled but FIPS mode failed to initialize: {}. \
                 This may indicate the aws-lc-rs FIPS module was not compiled correctly. \
                 Ensure you're building with the correct toolchain and FIPS prerequisites.",
                e
            );
            std::process::exit(1);
        }
        // Log FIPS status on startup
        eprintln!("FIPS mode: ENABLED (aws-lc-rs FIPS 140-3 validated module)");
    }

    #[cfg(not(feature = "fips"))]
    {
        eprintln!("WARNING: Running without FIPS mode. For production, build with --features fips");
    }

    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.crd {
        // Generate CRD YAML
        let crd = serde_yaml::to_string(&LatticeCluster::crd())
            .map_err(|e| anyhow::anyhow!("Failed to serialize CRD: {}", e))?;
        println!("{crd}");
        return Ok(());
    }

    match cli.command {
        Some(Commands::Controller { mode }) => run_controller(mode).await,
        None => run_controller(ControllerMode::All).await,
    }
}

/// Ensure all Lattice CRDs are installed
///
/// The operator installs its own CRDs on startup using server-side apply.
/// This ensures the CRD versions always match the operator version.
async fn ensure_crds_installed(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::{Patch, PatchParams};

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-controller").force();

    // Install LatticeCluster CRD
    tracing::info!("Installing LatticeCluster CRD...");
    crds.patch(
        "latticeclusters.lattice.dev",
        &params,
        &Patch::Apply(&LatticeCluster::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeCluster CRD: {}", e))?;

    // Install LatticeService CRD
    tracing::info!("Installing LatticeService CRD...");
    crds.patch(
        "latticeservices.lattice.dev",
        &params,
        &Patch::Apply(&LatticeService::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeService CRD: {}", e))?;

    // Install LatticeExternalService CRD
    tracing::info!("Installing LatticeExternalService CRD...");
    crds.patch(
        "latticeexternalservices.lattice.dev",
        &params,
        &Patch::Apply(&LatticeExternalService::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeExternalService CRD: {}", e))?;

    tracing::info!("All Lattice CRDs installed/updated");
    Ok(())
}

/// Ensure the MutatingWebhookConfiguration for Deployment injection is installed
///
/// This creates a webhook that intercepts Deployment CREATE/UPDATE and injects
/// container specs from LatticeService CRDs. Only Deployments with the
/// `lattice.dev/service` label are intercepted.
async fn ensure_webhook_config(
    client: &Client,
    ca: &std::sync::Arc<lattice_operator::pki::CertificateAuthority>,
) -> anyhow::Result<()> {
    use k8s_openapi::api::admissionregistration::v1::{
        MutatingWebhook, MutatingWebhookConfiguration, RuleWithOperations, ServiceReference,
        WebhookClientConfig,
    };
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
    use kube::api::{Api, Patch, PatchParams};

    let params = PatchParams::apply("lattice-controller").force();

    // 1. Create ClusterIP Service for the webhook
    // This exposes the operator's webhook endpoint internally
    let webhook_service = Service {
        metadata: kube::api::ObjectMeta {
            name: Some("lattice-webhook".to_string()),
            namespace: Some("lattice-system".to_string()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(std::collections::BTreeMap::from([(
                "app".to_string(),
                "lattice-operator".to_string(),
            )])),
            ports: Some(vec![ServicePort {
                name: Some("https".to_string()),
                port: 443,
                target_port: Some(
                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(
                        lattice_operator::DEFAULT_BOOTSTRAP_PORT as i32,
                    ),
                ),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let services: Api<Service> = Api::namespaced(client.clone(), "lattice-system");
    services
        .patch("lattice-webhook", &params, &Patch::Apply(&webhook_service))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create webhook Service: {}", e))?;

    // 2. Create MutatingWebhookConfiguration
    // This tells K8s to send Deployment admission requests to our webhook
    let ca_bundle = ca.ca_cert_pem().as_bytes().to_vec();

    let webhook_config = MutatingWebhookConfiguration {
        metadata: kube::api::ObjectMeta {
            name: Some("lattice-deployment-mutator".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![MutatingWebhook {
            name: "deployments.lattice.dev".to_string(),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: "None".to_string(),
            failure_policy: Some("Fail".to_string()),
            match_policy: Some("Equivalent".to_string()),
            rules: Some(vec![RuleWithOperations {
                operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                api_groups: Some(vec!["apps".to_string()]),
                api_versions: Some(vec!["v1".to_string()]),
                resources: Some(vec!["deployments".to_string()]),
                scope: Some("Namespaced".to_string()),
            }]),
            client_config: WebhookClientConfig {
                service: Some(ServiceReference {
                    name: "lattice-webhook".to_string(),
                    namespace: "lattice-system".to_string(),
                    path: Some("/mutate/deployments".to_string()),
                    port: Some(443),
                }),
                ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                ..Default::default()
            },
            // Only intercept Deployments with lattice.dev/service label
            object_selector: Some(LabelSelector {
                match_expressions: Some(vec![LabelSelectorRequirement {
                    key: "lattice.dev/service".to_string(),
                    operator: "Exists".to_string(),
                    values: None,
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }]),
    };

    let webhooks: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    webhooks
        .patch(
            "lattice-deployment-mutator",
            &params,
            &Patch::Apply(&webhook_config),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create MutatingWebhookConfiguration: {}", e))?;

    tracing::info!("Webhook configuration installed");
    Ok(())
}

/// Reconcile infrastructure components
///
/// Ensures all infrastructure is installed. Server-side apply handles idempotency.
/// This runs on every controller startup, applying the latest manifests.
///
/// IMPORTANT: Uses the SAME generate_all() function as the bootstrap webhook.
/// This guarantees upgrades work by changing Lattice version - on restart,
/// the operator re-applies identical infrastructure manifests.
async fn ensure_infrastructure(client: &Client) -> anyhow::Result<()> {
    use kube::api::ListParams;
    use lattice_operator::crd::LatticeCluster;
    use lattice_operator::infra::bootstrap::{self, InfrastructureConfig};

    let is_bootstrap_cluster = std::env::var("LATTICE_ROOT_INSTALL").is_ok()
        || std::env::var("LATTICE_BOOTSTRAP_CLUSTER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

    tracing::info!("Applying infrastructure manifests (server-side apply)...");

    if is_bootstrap_cluster {
        // Bootstrap cluster (KIND): Use generate_core() + clusterctl init
        // This is a temporary cluster that doesn't need full self-management infra
        let manifests = bootstrap::generate_core(true);
        tracing::info!(count = manifests.len(), "applying core infrastructure");
        apply_manifests(client, &manifests).await?;

        tracing::info!("Installing CAPI on bootstrap cluster...");
        ensure_capi_on_bootstrap().await?;
    } else {
        // Workload cluster: Read provider/bootstrap from LatticeCluster CRD
        // This is the source of truth - same values used by bootstrap webhook
        let clusters: kube::Api<LatticeCluster> = kube::Api::all(client.clone());
        let list = clusters.list(&ListParams::default()).await?;

        let (provider, bootstrap) = if let Some(cluster) = list.items.first() {
            let p = cluster.spec.provider.provider_type().to_string();
            let b = cluster.spec.provider.kubernetes.bootstrap.clone();
            tracing::info!(provider = %p, bootstrap = ?b, "read config from LatticeCluster CRD");
            (p, b)
        } else {
            // No LatticeCluster yet - use defaults (shouldn't happen on real clusters)
            tracing::warn!("no LatticeCluster found, using defaults");
            (
                "docker".to_string(),
                lattice_operator::crd::BootstrapProvider::Kubeadm,
            )
        };

        let config = InfrastructureConfig {
            provider,
            bootstrap,
            skip_cilium_policies: false,
        };

        let manifests = bootstrap::generate_all(&config);
        tracing::info!(
            count = manifests.len(),
            "applying all infrastructure (same as bootstrap webhook)"
        );
        apply_manifests(client, &manifests).await?;
    }

    tracing::info!("Infrastructure installation complete");
    Ok(())
}

/// Install CAPI on the bootstrap cluster.
///
/// The bootstrap cluster needs CAPI installed BEFORE a LatticeCluster is created,
/// because the installer waits for CAPI CRDs to be available. Without this, the
/// installer hangs in Phase 2 waiting for CRDs that would only be installed when
/// a LatticeCluster is reconciled (Phase 3).
///
/// Uses LATTICE_PROVIDER env var to determine which infrastructure provider to install.
async fn ensure_capi_on_bootstrap() -> anyhow::Result<()> {
    let provider_str = std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());

    let infrastructure = match provider_str.to_lowercase().as_str() {
        "docker" => ProviderType::Docker,
        "proxmox" => ProviderType::Proxmox,
        "openstack" => ProviderType::OpenStack,
        "aws" => ProviderType::Aws,
        "gcp" => ProviderType::Gcp,
        "azure" => ProviderType::Azure,
        other => return Err(anyhow::anyhow!("unknown LATTICE_PROVIDER: {}", other)),
    };

    tracing::info!(infrastructure = %provider_str, "Installing CAPI providers for bootstrap cluster");

    let config = CapiProviderConfig::new(infrastructure)
        .map_err(|e| anyhow::anyhow!("Failed to create CAPI config: {}", e))?;
    ensure_capi_installed(&ClusterctlInstaller::new(), &config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = %provider_str, "CAPI providers installed successfully");
    Ok(())
}

/// Get priority for a Kubernetes resource kind (lower = apply first)
fn kind_priority(kind: &str) -> u8 {
    match kind {
        "Namespace" => 0,
        "CustomResourceDefinition" => 1,
        "ServiceAccount" => 2,
        "ClusterRole" | "Role" => 3,
        "ClusterRoleBinding" | "RoleBinding" => 4,
        "ConfigMap" | "Secret" => 5,
        "Service" => 6,
        "Deployment" | "DaemonSet" | "StatefulSet" => 7,
        "HorizontalPodAutoscaler" => 8,
        _ => 10, // webhooks, policies, etc. come last
    }
}

/// Extract kind from a YAML manifest
fn extract_kind(manifest: &str) -> &str {
    manifest
        .lines()
        .find(|line| line.starts_with("kind:"))
        .and_then(|line| line.strip_prefix("kind:"))
        .map(|k| k.trim())
        .unwrap_or("")
}

/// Apply multiple YAML manifests to the cluster
///
/// Applies in two phases:
/// 1. Namespaces and CRDs (foundational resources)
/// 2. Re-run discovery to learn new CRD types
/// 3. Everything else (sorted by kind priority)
async fn apply_manifests(client: &Client, manifests: &[impl AsRef<str>]) -> anyhow::Result<()> {
    use kube::api::PatchParams;
    use kube::discovery::Discovery;

    if manifests.is_empty() {
        return Ok(());
    }

    // Split into foundational (Namespace, CRD) and rest
    let (mut foundational, mut rest): (Vec<&str>, Vec<&str>) =
        manifests.iter().map(|m| m.as_ref()).partition(|m| {
            let kind = extract_kind(m);
            kind == "Namespace" || kind == "CustomResourceDefinition"
        });

    // Sort each group by priority
    foundational.sort_by_key(|m| kind_priority(extract_kind(m)));
    rest.sort_by_key(|m| kind_priority(extract_kind(m)));

    let params = PatchParams::apply("lattice").force();

    // Phase 1: Apply foundational resources (Namespaces, CRDs)
    if !foundational.is_empty() {
        let discovery = Discovery::new(client.clone())
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to run API discovery: {}", e))?;

        for manifest in &foundational {
            apply_single_manifest(client, &discovery, manifest, &params).await?;
        }
    }

    // Phase 2: Re-run discovery to learn new CRD types, then apply rest
    if !rest.is_empty() {
        let discovery = Discovery::new(client.clone())
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to refresh API discovery: {}", e))?;

        for manifest in &rest {
            apply_single_manifest(client, &discovery, manifest, &params).await?;
        }
    }

    Ok(())
}

/// Apply a single manifest using the provided discovery cache
async fn apply_single_manifest(
    client: &Client,
    discovery: &kube::discovery::Discovery,
    manifest: &str,
    params: &kube::api::PatchParams,
) -> anyhow::Result<()> {
    use kube::api::{Api, DynamicObject, Patch};

    let obj: serde_json::Value =
        serde_yaml::from_str(manifest).map_err(|e| anyhow::anyhow!("Invalid YAML: {}", e))?;

    let kind = obj
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing kind"))?;
    let api_version = obj
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing apiVersion"))?;
    let name = obj
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing metadata.name"))?;
    let namespace = obj.pointer("/metadata/namespace").and_then(|v| v.as_str());

    // Parse apiVersion into group/version
    let (group, version) = if let Some((g, v)) = api_version.split_once('/') {
        (g, v)
    } else {
        ("", api_version)
    };

    let gvk = kube::api::GroupVersionKind {
        group: group.to_string(),
        version: version.to_string(),
        kind: kind.to_string(),
    };

    let (api_resource, _) = discovery
        .resolve_gvk(&gvk)
        .ok_or_else(|| anyhow::anyhow!("Unknown resource type: {}/{}", api_version, kind))?;

    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
        None => Api::all_with(client.clone(), &api_resource),
    };

    api.patch(name, params, &Patch::Apply(&obj))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply {}/{}: {}", kind, name, e))?;

    tracing::debug!(kind = %kind, name = %name, namespace = ?namespace, "Applied manifest");
    Ok(())
}

/// Re-register clusters that completed bootstrap before operator restart
///
/// BootstrapState is in-memory and lost on restart. This reads status.bootstrap_complete
/// from the CRD and re-registers clusters so CSR signing works immediately.
async fn re_register_existing_clusters<G: lattice_operator::bootstrap::ManifestGenerator>(
    client: &Client,
    bootstrap_state: &std::sync::Arc<lattice_operator::bootstrap::BootstrapState<G>>,
    self_cluster_name: &Option<String>,
    parent_servers: &std::sync::Arc<lattice_operator::parent::ParentServers<G>>,
) {
    use kube::api::ListParams;

    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let list = match clusters.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list clusters for re-registration");
            return;
        }
    };

    for cluster in list.items {
        let name = match cluster.metadata.name.as_ref() {
            Some(n) => n,
            None => continue,
        };

        // Skip self-cluster
        if self_cluster_name.as_ref() == Some(name) {
            continue;
        }

        // Re-register clusters that need bootstrap (Provisioning, Pivoting, or bootstrap_complete)
        // BootstrapState is in-memory, so we must re-register on operator restart
        let phase = cluster
            .status
            .as_ref()
            .map(|s| &s.phase)
            .cloned()
            .unwrap_or_default();

        let needs_registration = matches!(
            phase,
            lattice_operator::crd::ClusterPhase::Provisioning
                | lattice_operator::crd::ClusterPhase::Pivoting
        ) || cluster
            .status
            .as_ref()
            .map(|s| s.bootstrap_complete)
            .unwrap_or(false);

        if !needs_registration {
            tracing::debug!(cluster = %name, phase = ?phase, "Skipping re-registration (not in Provisioning/Pivoting)");
            continue;
        }

        // Skip if already registered
        if bootstrap_state.is_cluster_registered(name) {
            continue;
        }

        // Get self cluster for endpoints
        let self_name = match self_cluster_name {
            Some(n) => n,
            None => {
                tracing::warn!(cluster = %name, "Cannot re-register cluster: no self_cluster_name");
                continue;
            }
        };

        let self_cluster = match clusters.get(self_name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to get self cluster for re-registration");
                continue;
            }
        };

        let endpoints = match self_cluster.spec.parent_config.as_ref() {
            Some(e) => e,
            None => {
                tracing::warn!("Self cluster has no endpoints, cannot re-register");
                continue;
            }
        };

        let ca_cert = parent_servers.ca().ca_cert_pem().to_string();

        // Get the cell host from the LoadBalancer Service
        let cell_host = match discover_cell_host(client).await {
            Some(h) => h,
            None => {
                tracing::warn!(cluster = %name, "Cell host not available from Service, cannot re-register");
                continue;
            }
        };
        let cell_endpoint = format!(
            "{}:{}:{}",
            cell_host, endpoints.bootstrap_port, endpoints.grpc_port
        );

        // Serialize cluster manifest for export
        let cluster_manifest = match serde_json::to_string(&cluster.for_export()) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, cluster = %name, "Failed to serialize cluster for re-registration");
                continue;
            }
        };

        let registration = lattice_operator::bootstrap::ClusterRegistration {
            cluster_id: name.clone(),
            cell_endpoint,
            ca_certificate: ca_cert,
            cluster_manifest,
            networking: cluster.spec.networking.clone(),
            proxmox_ipv4_pool: cluster
                .spec
                .provider
                .config
                .proxmox
                .as_ref()
                .map(|p| p.ipv4_pool.clone()),
            provider: cluster.spec.provider.provider_type().to_string(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
        };

        bootstrap_state.register_cluster(registration, true);
        tracing::info!(cluster = %name, "re-registered cluster after operator restart");
    }
}

/// Ensure the cell LoadBalancer Service exists.
///
/// Creates the lattice-cell Service if it doesn't exist. This must be called
/// during startup BEFORE waiting for the cell endpoint, otherwise we have a
/// chicken-and-egg problem (controllers create Service, but controllers wait for endpoint).
///
/// - Cloud providers: `load_balancer_ip` is None, cloud assigns address
/// - On-prem: `load_balancer_ip` is set from parent_config.host, Cilium L2 announces it
async fn ensure_cell_service_exists(
    client: &Client,
    load_balancer_ip: Option<String>,
    bootstrap_port: u16,
    grpc_port: u16,
) -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use kube::api::PostParams;

    let api: Api<Service> = Api::namespaced(client.clone(), "lattice-system");

    // Check if it already exists
    if api.get("lattice-cell").await.is_ok() {
        tracing::debug!("lattice-cell Service already exists");
        return Ok(());
    }

    let mut labels = std::collections::BTreeMap::new();
    labels.insert("app".to_string(), "lattice-operator".to_string());

    let service = Service {
        metadata: ObjectMeta {
            name: Some("lattice-cell".to_string()),
            namespace: Some("lattice-system".to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("LoadBalancer".to_string()),
            selector: Some(labels),
            load_balancer_ip: load_balancer_ip.clone(),
            ports: Some(vec![
                ServicePort {
                    name: Some("bootstrap".to_string()),
                    port: bootstrap_port as i32,
                    target_port: Some(IntOrString::Int(bootstrap_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("grpc".to_string()),
                    port: grpc_port as i32,
                    target_port: Some(IntOrString::Int(grpc_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    api.create(&PostParams::default(), &service).await?;
    tracing::info!(
        load_balancer_ip = ?load_balancer_ip,
        bootstrap_port,
        grpc_port,
        "Created lattice-cell LoadBalancer Service"
    );

    Ok(())
}

/// Discover the cell service host from the LoadBalancer Service.
///
/// The cell service is the LoadBalancer that exposes the Lattice operator's
/// gRPC and bootstrap endpoints. Child clusters connect to this endpoint.
///
/// Returns the host (hostname or IP) from the Service's LoadBalancer status,
/// or None if not yet assigned by the cloud provider.
async fn discover_cell_host(client: &Client) -> Option<String> {
    use k8s_openapi::api::core::v1::Service;

    let services: Api<Service> = Api::namespaced(client.clone(), "lattice-system");
    let svc = services.get("lattice-cell").await.ok()?;
    let ingress = svc.status?.load_balancer?.ingress?;
    let first = ingress.first()?;

    // Prefer hostname (AWS ELB) over IP
    first.hostname.clone().or_else(|| first.ip.clone())
}

/// Run in controller mode - manages clusters and/or services
///
/// Cell servers (gRPC + bootstrap HTTP) start automatically when needed.
/// Cell endpoint configuration is read from the local LatticeCluster CRD's spec.parent_config.
///
/// If this cluster has a cellRef (parent), the controller also connects as an agent
/// to the parent cell for pivot coordination and health reporting.
async fn run_controller(mode: ControllerMode) -> anyhow::Result<()> {
    tracing::info!(mode = ?mode, "Lattice controller starting...");

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}", e))?;

    // Operator installs its own CRDs on startup
    ensure_crds_installed(&client).await?;

    // Ensure infrastructure components are installed (Istio)
    // This enables day-2 upgrades: new Lattice version has new component versions
    // Infrastructure is required for service mesh - fail startup if it can't be installed
    ensure_infrastructure(&client).await?;

    // Create cell servers (but don't start them yet - wait for LatticeCluster to get SANs)
    // The webhook is always needed for LatticeService → Deployment mutation
    // External exposure (LoadBalancer) is configured per-cluster based on spec.parent_config
    // CA is loaded from Secret (or created and persisted) to survive operator restarts
    let parent_servers = Arc::new(
        ParentServers::new(ParentConfig::default(), &client)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create cell servers: {}", e))?,
    );

    // Install MutatingWebhookConfiguration for Deployment injection
    // CA is available immediately from parent_servers (created in ParentServers::new)
    ensure_webhook_config(&client, parent_servers.ca()).await?;

    // Start cell servers BEFORE controllers - webhook must be ready for deployment creation
    // This ensures TLS certificate has correct SANs (spec.parent_config.host) before serving
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    {
        let manifest_generator = lattice_operator::bootstrap::DefaultManifestGenerator::new();

        // Get extra SANs from LatticeCluster - MUST wait for it to exist with parent_config
        // The server certificate needs the correct SANs for workload clusters to connect
        //
        // Skip waiting for:
        // - Bootstrap clusters (LATTICE_BOOTSTRAP_CLUSTER=true): temporary kind cluster
        // - Child clusters (have lattice-parent-config secret): LatticeCluster comes via pivot
        //
        // Only wait for root/management clusters that provision children.
        let is_bootstrap_cluster = std::env::var("LATTICE_BOOTSTRAP_CLUSTER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        // Check if this is a child cluster (has parent config secret)
        // Child clusters get their LatticeCluster via pivot, so we can't wait for it
        let is_child_cluster = {
            use k8s_openapi::api::core::v1::Secret;
            let secrets: kube::Api<Secret> =
                kube::Api::namespaced(client.clone(), "lattice-system");
            secrets.get("lattice-parent-config").await.is_ok()
        };

        let extra_sans: Vec<String> = if is_bootstrap_cluster {
            tracing::info!("Bootstrap cluster, using default SANs");
            vec![]
        } else if let Some(ref cluster_name) = self_cluster_name {
            // Try to discover cell endpoint for TLS SANs
            // - Child clusters: don't block (endpoint may not exist yet)
            // - Management clusters: wait for endpoint to be discovered
            if is_child_cluster {
                // Child clusters can't block - check once and continue
                if let Some(host) = discover_cell_host(&client).await {
                    tracing::info!(host = %host, "Cell host found");
                    vec![host]
                } else {
                    tracing::info!("Cell host not yet available, using default SANs");
                    vec![]
                }
            } else {
                // Management cluster - wait for LatticeCluster, create cell Service, wait for endpoint
                let lattice_clusters: Api<LatticeCluster> = Api::all(client.clone());

                // Step 1: Wait for LatticeCluster to exist (arrives via pivot)
                tracing::info!(cluster = %cluster_name, "Waiting for LatticeCluster...");
                let cluster = loop {
                    match lattice_clusters.get(cluster_name).await {
                        Ok(c) => break c,
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                    }
                };

                // Step 2: Create cell Service if parent_config exists
                if let Some(ref parent_config) = cluster.spec.parent_config {
                    tracing::info!("Creating cell Service");
                    if let Err(e) = ensure_cell_service_exists(
                        &client,
                        parent_config.host.clone(),
                        parent_config.bootstrap_port,
                        parent_config.grpc_port,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "Failed to create cell Service");
                    }
                }

                // Step 3: Wait for cell host from LoadBalancer
                tracing::info!(cluster = %cluster_name, "Waiting for cell host...");
                loop {
                    if let Some(host) = discover_cell_host(&client).await {
                        tracing::info!(host = %host, "Cell host discovered");
                        break vec![host];
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        } else {
            vec![]
        };

        // Start cell servers - MUST complete before controllers start
        // If running in service mode, also add the webhook router for Deployment injection
        let run_service = matches!(mode, ControllerMode::All | ControllerMode::Service);
        let webhook_router = if run_service {
            let webhook_state =
                std::sync::Arc::new(lattice_service::webhook::WebhookState::new(client.clone()));
            Some(lattice_service::webhook::webhook_router(webhook_state))
        } else {
            None
        };

        parent_servers
            .ensure_running_with(
                manifest_generator,
                &extra_sans,
                client.clone(),
                webhook_router,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start cell servers: {}", e))?;

        tracing::info!("Cell servers started (bootstrap + gRPC + optional webhook)");

        // Re-register any clusters that are past Pending phase
        // This handles operator restarts where BootstrapState was lost but clusters are mid-provisioning
        if let Some(bootstrap_state) = parent_servers.bootstrap_state().await {
            re_register_existing_clusters(
                &client,
                &bootstrap_state,
                &self_cluster_name,
                &parent_servers,
            )
            .await;
        }
    }

    // Create unpivot channel for controller -> agent communication
    let (unpivot_tx, unpivot_rx) = tokio::sync::mpsc::channel(10);

    // Create controller context with cell servers
    // LATTICE_CLUSTER_NAME tells the controller which cluster it's running on (to avoid self-provisioning)
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    let mut ctx_builder = Context::builder(client.clone())
        .parent_servers(parent_servers.clone())
        .unpivot_channel(unpivot_tx);
    if let Some(ref name) = self_cluster_name {
        tracing::info!(cluster = %name, "Running as self-managed cluster");
        ctx_builder = ctx_builder.self_cluster_name(name.clone());
    }
    let ctx = Arc::new(ctx_builder.build());

    // Check if we need to connect as an agent to a parent cell
    // This happens when the cluster has a cellRef (was provisioned by a parent)
    // Connection happens in background with retries - don't block controller startup
    // Agent task is cancelled when parent_servers shuts down
    let agent_cancel_token = tokio_util::sync::CancellationToken::new();
    if let Some(ref cluster_name) = self_cluster_name {
        let client_clone = client.clone();
        let cluster_name_clone = cluster_name.clone();
        let token = agent_cancel_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("Agent connection loop cancelled during shutdown");
                }
                _ = start_agent_with_retry(&client_clone, &cluster_name_clone, unpivot_rx) => {}
            }
        });
    }

    // Create APIs for all CRDs (cluster-scoped)
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client.clone());

    // Create service context for service controllers
    let service_ctx = Arc::new(ServiceContext::from_client(client, "cluster.local"));

    // Log which controllers will be started
    tracing::info!("Starting Lattice controllers...");
    let run_cluster = matches!(mode, ControllerMode::All | ControllerMode::Cluster);
    let run_service = matches!(mode, ControllerMode::All | ControllerMode::Service);

    if run_cluster {
        tracing::info!("  - LatticeCluster controller");
    }
    if run_service {
        tracing::info!("  - LatticeService controller");
        tracing::info!("  - LatticeExternalService controller");
    }

    // Create cluster controller if needed
    let cluster_controller = if run_cluster {
        Some(
            Controller::new(clusters, WatcherConfig::default())
                .shutdown_on_signal()
                .run(reconcile, error_policy, ctx.clone())
                .for_each(|result| async move {
                    match result {
                        Ok(action) => {
                            tracing::debug!(?action, "Cluster reconciliation completed");
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Cluster reconciliation error");
                        }
                    }
                }),
        )
    } else {
        None
    };

    // Create service controllers if needed
    let (service_controller, external_service_controller) = if run_service {
        // Clone graph for the watch mapper closure
        let graph_for_watch = service_ctx.graph.clone();

        let svc_ctrl = Controller::new(services.clone(), WatcherConfig::default())
            // Watch all LatticeService changes and trigger re-reconciliation of dependent services
            // This enables eventual consistency: when service B is created, services that
            // depend on B get re-reconciled to update their egress policies. When service A
            // is created with deps, services that A depends on get re-reconciled to update
            // their ingress policies (if they allow A).
            .watches(services, WatcherConfig::default(), move |service| {
                let graph = graph_for_watch.clone();
                let env = &service.spec.environment;
                let name = service.metadata.name.as_deref().unwrap_or_default();

                // Get services that this service depends on (they need to update ingress)
                let dependencies = graph.get_dependencies(env, name);
                // Get services that depend on this service (they need to update egress)
                let dependents = graph.get_dependents(env, name);

                // Combine and deduplicate
                let mut affected: Vec<String> = dependencies;
                affected.extend(dependents);
                affected.sort();
                affected.dedup();

                tracing::debug!(
                    service = %name,
                    env = %env,
                    affected_count = affected.len(),
                    "Service changed, triggering re-reconciliation of affected services"
                );

                affected
                    .into_iter()
                    .map(|dep_name| ObjectRef::<LatticeService>::new(&dep_name))
            })
            .shutdown_on_signal()
            .run(service_reconcile, service_error_policy, service_ctx.clone())
            .for_each(|result| async move {
                match result {
                    Ok(action) => {
                        tracing::debug!(?action, "Service reconciliation completed");
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "Service reconciliation error");
                    }
                }
            });

        let ext_ctrl = Controller::new(external_services, WatcherConfig::default())
            .shutdown_on_signal()
            .run(
                reconcile_external,
                error_policy_external,
                service_ctx.clone(),
            )
            .for_each(|result| async move {
                match result {
                    Ok(action) => {
                        tracing::debug!(?action, "External service reconciliation completed");
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "External service reconciliation error");
                    }
                }
            });

        (Some(svc_ctrl), Some(ext_ctrl))
    } else {
        (None, None)
    };

    // Run selected controllers concurrently
    match (
        cluster_controller,
        service_controller,
        external_service_controller,
    ) {
        (Some(cluster), Some(service), Some(external)) => {
            tokio::select! {
                _ = cluster => tracing::info!("Cluster controller completed"),
                _ = service => tracing::info!("Service controller completed"),
                _ = external => tracing::info!("External service controller completed"),
            }
        }
        (Some(cluster), None, None) => {
            cluster.await;
            tracing::info!("Cluster controller completed");
        }
        (None, Some(service), Some(external)) => {
            tokio::select! {
                _ = service => tracing::info!("Service controller completed"),
                _ = external => tracing::info!("External service controller completed"),
            }
        }
        _ => {
            tracing::warn!("No controllers to run");
        }
    }

    // Cancel agent background task and shutdown cell servers
    agent_cancel_token.cancel();
    parent_servers.shutdown().await;

    tracing::info!("Lattice controller shutting down");
    Ok(())
}

/// Supervise agent connection with automatic reconnection.
/// If a parent cell is configured, maintains connection indefinitely with retries.
/// Also handles unpivot requests from the controller.
/// Runs in background - does not block.
async fn start_agent_with_retry(
    client: &Client,
    cluster_name: &str,
    mut unpivot_rx: tokio::sync::mpsc::Receiver<lattice_operator::controller::UnpivotRequest>,
) {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(30);

    loop {
        match start_agent_if_needed(client, cluster_name).await {
            Ok(Some(agent)) => {
                tracing::info!("Agent connection to parent cell established");
                // Reset retry delay on successful connection
                retry_delay = Duration::from_secs(1);

                // Monitor connection and handle unpivot requests
                loop {
                    tokio::select! {
                        // Check for unpivot requests
                        Some(request) = unpivot_rx.recv() => {
                            tracing::info!(
                                cluster = %request.cluster_name,
                                namespace = %request.namespace,
                                "Received unpivot request"
                            );
                            let result = handle_unpivot_request(&agent, &request).await;
                            if request.completion_tx.send(result).is_err() {
                                tracing::warn!(
                                    cluster = %request.cluster_name,
                                    "Unpivot completion receiver dropped - requester may have timed out"
                                );
                            }
                        }
                        // Periodic connection check
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {
                            let state = agent.state().await;
                            if state == lattice_operator::agent::client::ClientState::Disconnected
                                || state == lattice_operator::agent::client::ClientState::Failed
                            {
                                tracing::warn!(
                                    state = ?state,
                                    "Agent disconnected from parent cell, will reconnect..."
                                );
                                break;
                            }
                        }
                    }
                }
                // Fall through to retry connection
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
                // Still need to drain unpivot requests even if no parent
                while let Some(request) = unpivot_rx.recv().await {
                    if request
                        .completion_tx
                        .send(Err("No parent cell configured".to_string()))
                        .is_err()
                    {
                        tracing::warn!(
                            cluster = %request.cluster_name,
                            "Unpivot completion receiver dropped while draining requests"
                        );
                    }
                }
                return;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    retry_in = ?retry_delay,
                    "Failed to connect to parent cell, retrying..."
                );
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

/// Handle an unpivot request by notifying the parent to clean up CAPI resources
///
/// With --to-directory pivot, parent keeps paused CAPI resources.
/// Child just needs to notify parent to unpause and delete.
async fn handle_unpivot_request(
    agent: &AgentClient,
    request: &lattice_operator::controller::UnpivotRequest,
) -> Result<(), String> {
    tracing::info!(
        cluster = %request.cluster_name,
        namespace = %request.namespace,
        "Notifying parent of cluster deletion"
    );

    // Notify parent that this cluster is being deleted
    // Parent will unpause CAPI resources and trigger infrastructure cleanup
    agent
        .send_cluster_deleting(&request.namespace)
        .await
        .map_err(|e| format!("Failed to send cluster deleting: {}", e))?;

    tracing::info!(
        cluster = %request.cluster_name,
        "Parent notified of cluster deletion"
    );

    Ok(())
}

async fn start_agent_if_needed(
    client: &Client,
    cluster_name: &str,
) -> anyhow::Result<Option<AgentClient>> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::Api;

    // Check for lattice-parent-config secret - this is set by the bootstrap process
    // and indicates we were provisioned by a parent cell and need to connect back.
    // If a cluster has a cellRef, this secret will ALWAYS exist (created during bootstrap).
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "lattice-system");
    let parent_config = match secrets.get("lattice-parent-config").await {
        Ok(config) => config,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            tracing::debug!("No parent config secret, this is a root cluster");
            return Ok(None);
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to get parent config secret: {}", e)),
    };

    tracing::info!(
        cluster = %cluster_name,
        "Found parent config secret, starting agent connection to parent cell"
    );

    let data = parent_config
        .data
        .ok_or_else(|| anyhow::anyhow!("Parent config secret has no data"))?;

    // Parse cell endpoint (format: "host:http_port:grpc_port")
    let cell_endpoint = data
        .get("cell_endpoint")
        .ok_or_else(|| anyhow::anyhow!("Missing cell_endpoint in parent config"))?;
    let cell_endpoint = String::from_utf8(cell_endpoint.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid cell_endpoint encoding: {}", e))?;

    let ca_cert = data
        .get("ca.crt")
        .ok_or_else(|| anyhow::anyhow!("Missing ca.crt in parent config"))?;
    let ca_cert_pem = String::from_utf8(ca_cert.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid CA cert encoding: {}", e))?;

    // Parse endpoint parts
    let parts: Vec<&str> = cell_endpoint.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "Invalid cell_endpoint format, expected host:http_port:grpc_port"
        ));
    }
    let host = parts[0];
    let http_port: u16 = parts[1]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid HTTP port: {}", e))?;
    let grpc_port: u16 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid gRPC port: {}", e))?;

    let http_endpoint = format!("https://{}:{}", host, http_port);
    let grpc_endpoint = format!("https://{}:{}", host, grpc_port);

    tracing::info!(
        http_endpoint = %http_endpoint,
        grpc_endpoint = %grpc_endpoint,
        "Connecting to parent cell"
    );

    // Try to load existing credentials from secret, or request new ones
    let credentials = match load_agent_credentials(&secrets).await {
        Ok(creds) => {
            tracing::info!("Using existing agent credentials from secret");
            creds
        }
        Err(_) => {
            tracing::info!("No existing credentials, requesting new certificate from cell");
            let creds =
                AgentClient::request_certificate(&http_endpoint, cluster_name, &ca_cert_pem)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get certificate: {}", e))?;

            // Store credentials for future restarts
            if let Err(e) = save_agent_credentials(&secrets, &creds).await {
                tracing::warn!(error = %e, "Failed to save agent credentials to secret");
            }
            creds
        }
    };

    // Create agent client config
    let config = AgentClientConfig {
        cluster_name: cluster_name.to_string(),
        cell_grpc_endpoint: grpc_endpoint,
        cell_http_endpoint: http_endpoint,
        ca_cert_pem: Some(ca_cert_pem),
        heartbeat_interval: Duration::from_secs(30),
        ..Default::default()
    };

    // Create and connect agent
    let mut agent = AgentClient::new(config);
    agent
        .connect_with_mtls(&credentials)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to cell: {}", e))?;

    tracing::info!("Agent connected to parent cell");
    Ok(Some(agent))
}

const AGENT_CREDENTIALS_SECRET: &str = "lattice-agent-credentials";

/// Load agent credentials from Kubernetes secret
async fn load_agent_credentials(
    secrets: &Api<k8s_openapi::api::core::v1::Secret>,
) -> anyhow::Result<AgentCredentials> {
    let secret = secrets.get(AGENT_CREDENTIALS_SECRET).await?;
    let data = secret
        .data
        .ok_or_else(|| anyhow::anyhow!("credentials secret has no data"))?;

    let cert_pem = data
        .get("tls.crt")
        .ok_or_else(|| anyhow::anyhow!("missing tls.crt"))?;
    let key_pem = data
        .get("tls.key")
        .ok_or_else(|| anyhow::anyhow!("missing tls.key"))?;
    let ca_pem = data
        .get("ca.crt")
        .ok_or_else(|| anyhow::anyhow!("missing ca.crt"))?;

    Ok(AgentCredentials {
        cert_pem: String::from_utf8(cert_pem.0.clone())?,
        key_pem: String::from_utf8(key_pem.0.clone())?,
        ca_cert_pem: String::from_utf8(ca_pem.0.clone())?,
    })
}

/// Save agent credentials to Kubernetes secret
async fn save_agent_credentials(
    secrets: &Api<k8s_openapi::api::core::v1::Secret>,
    credentials: &AgentCredentials,
) -> anyhow::Result<()> {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::ByteString;
    use kube::api::{ObjectMeta, PostParams};
    use std::collections::BTreeMap;

    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        ByteString(credentials.cert_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_string(),
        ByteString(credentials.key_pem.as_bytes().to_vec()),
    );
    data.insert(
        "ca.crt".to_string(),
        ByteString(credentials.ca_cert_pem.as_bytes().to_vec()),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(AGENT_CREDENTIALS_SECRET.to_string()),
            namespace: Some("lattice-system".to_string()),
            ..Default::default()
        },
        data: Some(data),
        type_: Some("kubernetes.io/tls".to_string()),
        ..Default::default()
    };

    // Try to create, if exists then replace
    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            tracing::info!("Created agent credentials secret");
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            // Already exists, replace it
            secrets
                .replace(AGENT_CREDENTIALS_SECRET, &PostParams::default(), &secret)
                .await?;
            tracing::info!("Updated agent credentials secret");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
