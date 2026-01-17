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

use lattice_operator::agent::client::{AgentClient, AgentClientConfig};
use lattice_operator::capi::{ensure_capi_installed, CapiProviderConfig, ClusterctlInstaller};
use lattice_operator::controller::{
    error_policy, error_policy_external, reconcile, reconcile_external, service_error_policy,
    service_reconcile, Context, ServiceContext,
};
use lattice_operator::crd::{LatticeCluster, LatticeExternalService, LatticeService, ProviderType};
use lattice_operator::infra::{FluxReconciler, IstioReconciler};
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
    Controller,
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
        Some(Commands::Controller) | None => run_controller().await,
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
/// Ensures Istio is installed at the correct version. Cilium is deployed at bootstrap.
/// This runs on every controller startup, enabling version upgrades when
/// Lattice is upgraded (new binary has new component versions).
async fn ensure_infrastructure(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
    use kube::api::{Api, Patch, PatchParams};

    let reconciler = IstioReconciler::new();
    let expected_version = reconciler.version();

    // Check ALL required Istio components, not just istiod
    // All three must exist at expected version to skip installation
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "istio-system");
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), "istio-system");

    let istiod_version = get_deployment_version(&deployments, "istiod").await;
    let cni_version = get_daemonset_version(&daemonsets, "istio-cni-node").await;
    let ztunnel_version = get_daemonset_version(&daemonsets, "ztunnel").await;

    // All components must be at expected version to skip
    let all_at_expected = istiod_version.as_deref() == Some(expected_version)
        && cni_version.as_deref() == Some(expected_version)
        && ztunnel_version.as_deref() == Some(expected_version);

    if all_at_expected {
        tracing::debug!(version = %expected_version, "Istio components at expected version, skipping");
        return Ok(());
    }

    // Log what we're doing
    tracing::info!(
        expected = %expected_version,
        istiod = ?istiod_version,
        cni = ?cni_version,
        ztunnel = ?ztunnel_version,
        "Installing/upgrading Istio components"
    );

    // Get manifests and apply them
    let manifests = reconciler
        .manifests()
        .map_err(|e| anyhow::anyhow!("Failed to generate Istio manifests: {}", e))?;

    tracing::info!(count = manifests.len(), "Applying Istio manifests");

    // Ensure istio-system namespace exists
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": "istio-system" }
    });
    let params = PatchParams::apply("lattice").force();
    namespaces
        .patch("istio-system", &params, &Patch::Apply(&ns))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create istio-system namespace: {}", e))?;

    // Build all Istio manifests to apply
    let mut all_manifests: Vec<String> = manifests.to_vec();
    all_manifests.push(IstioReconciler::generate_peer_authentication());
    all_manifests.push(IstioReconciler::generate_default_deny());
    all_manifests.push(IstioReconciler::generate_operator_allow_policy());

    // Add Cilium policies only if not on bootstrap cluster (kind uses default CNI, not Cilium)
    let is_bootstrap_cluster = std::env::var("LATTICE_ROOT_INSTALL").is_ok();
    if !is_bootstrap_cluster {
        all_manifests.push(lattice_operator::infra::generate_ztunnel_allowlist());
        all_manifests.push(lattice_operator::infra::generate_default_deny());
    } else {
        tracing::debug!("Skipping Cilium policies on bootstrap cluster (no Cilium CRDs)");
    }

    // Apply all manifests in one batch (single discovery call)
    // Istio helm template includes namespace in manifests, so no default needed
    apply_manifests(client, &all_manifests, None).await?;

    tracing::info!(version = %expected_version, "Istio reconciliation complete");

    // Install Flux for GitOps support
    tracing::info!("Installing Flux...");
    ensure_flux(client).await?;
    tracing::info!("Flux installation complete");

    // Install CAPI on bootstrap cluster to allow installer to provision clusters
    // The bootstrap cluster is a temporary kind cluster that provisions the management cluster.
    // CAPI must be installed before the LatticeCluster CRD is created, otherwise the installer
    // will hang waiting for CAPI CRDs that never appear.
    let is_bootstrap_cluster = std::env::var("LATTICE_BOOTSTRAP_CLUSTER")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if is_bootstrap_cluster {
        tracing::info!("Installing CAPI on bootstrap cluster...");
        ensure_capi_on_bootstrap().await?;
        tracing::info!("CAPI installation complete on bootstrap cluster");
    }

    Ok(())
}

/// Ensures Flux is installed at the correct version for GitOps support.
/// Flux enables clusters to watch git repositories and apply changes automatically.
async fn ensure_flux(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::api::apps::v1::Deployment;
    use kube::api::{Api, Patch, PatchParams};

    tracing::debug!("Creating FluxReconciler...");
    let reconciler = FluxReconciler::new()
        .map_err(|e| anyhow::anyhow!("Failed to create Flux reconciler: {}", e))?;
    tracing::debug!("FluxReconciler created successfully");
    let expected_version = reconciler.version();

    // Check source-controller deployment version
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "flux-system");
    let source_version = get_deployment_version(&deployments, "source-controller").await;

    if source_version.as_deref() == Some(expected_version) {
        tracing::debug!(version = %expected_version, "Flux at expected version, skipping");
        return Ok(());
    }

    tracing::info!(
        expected = %expected_version,
        current = ?source_version,
        "Installing/upgrading Flux"
    );

    // Ensure flux-system namespace exists
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": "flux-system" }
    });
    let params = PatchParams::apply("lattice").force();
    namespaces
        .patch("flux-system", &params, &Patch::Apply(&ns))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create flux-system namespace: {}", e))?;

    // Build all Flux manifests including the Istio allow policy
    let mut all_manifests: Vec<String> = reconciler.manifests().to_vec();
    all_manifests.push(IstioReconciler::generate_flux_allow_policy());

    tracing::info!(count = all_manifests.len(), "Applying Flux manifests");

    // Flux helm template doesn't embed namespace in manifests, so we provide flux-system as default
    apply_manifests(client, &all_manifests, Some("flux-system")).await?;

    tracing::info!(version = %expected_version, "Flux installation complete");
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

    let config = CapiProviderConfig::new(infrastructure);
    ensure_capi_installed(&ClusterctlInstaller::new(), &config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = %provider_str, "CAPI providers installed successfully");
    Ok(())
}

/// Get version from a Deployment's container image tag
async fn get_deployment_version(
    api: &kube::Api<k8s_openapi::api::apps::v1::Deployment>,
    name: &str,
) -> Option<String> {
    api.get(name).await.ok().and_then(|deploy| {
        deploy
            .spec
            .and_then(|s| s.template.spec)
            .and_then(|s| s.containers.into_iter().next())
            .and_then(|c| c.image)
            .and_then(|img| img.split(':').next_back().map(String::from))
    })
}

/// Get version from a DaemonSet's container image tag
async fn get_daemonset_version(
    api: &kube::Api<k8s_openapi::api::apps::v1::DaemonSet>,
    name: &str,
) -> Option<String> {
    api.get(name).await.ok().and_then(|ds| {
        ds.spec
            .and_then(|s| s.template.spec)
            .and_then(|s| s.containers.into_iter().next())
            .and_then(|c| c.image)
            .and_then(|img| img.split(':').next_back().map(String::from))
    })
}

/// Apply multiple YAML manifests to the cluster
///
/// If a manifest doesn't specify a namespace and default_ns is provided,
/// the default namespace will be injected for namespaced resources.
/// Uses the discovery API (cached) to determine resource scope.
async fn apply_manifests(
    client: &Client,
    manifests: &[impl AsRef<str>],
    default_ns: Option<&str>,
) -> anyhow::Result<()> {
    use kube::api::{Api, DynamicObject, Patch, PatchParams};
    use kube::discovery::{Discovery, Scope};

    if manifests.is_empty() {
        return Ok(());
    }

    // Run discovery once to cache all API resources
    let discovery = Discovery::new(client.clone())
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run API discovery: {}", e))?;

    let params = PatchParams::apply("lattice").force();

    for manifest in manifests {
        let manifest = manifest.as_ref();

        let mut obj: serde_json::Value =
            serde_yaml::from_str(manifest).map_err(|e| anyhow::anyhow!("Invalid YAML: {}", e))?;

        let kind = obj
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing kind"))?
            .to_string();
        let api_version = obj
            .get("apiVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing apiVersion"))?
            .to_string();
        let name = obj
            .pointer("/metadata/name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing metadata.name"))?
            .to_string();

        // Parse apiVersion into group/version
        let (group, version) = if api_version.contains('/') {
            let parts: Vec<&str> = api_version.splitn(2, '/').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (String::new(), api_version.clone())
        };

        // Look up resource in cached discovery
        let gvk = kube::api::GroupVersionKind {
            group: group.clone(),
            version: version.clone(),
            kind: kind.clone(),
        };

        let (api_resource, capabilities) = discovery
            .resolve_gvk(&gvk)
            .ok_or_else(|| anyhow::anyhow!("Unknown resource type: {}/{}", api_version, kind))?;

        // Determine namespace: use manifest's namespace, or inject default for namespaced resources
        let manifest_ns = obj
            .pointer("/metadata/namespace")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let namespace: Option<String> = if manifest_ns.is_some() {
            manifest_ns
        } else if capabilities.scope == Scope::Namespaced {
            // Inject default namespace into manifest for namespaced resources
            if let Some(ns) = default_ns {
                if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                    metadata.insert("namespace".to_string(), serde_json::Value::String(ns.to_string()));
                }
                Some(ns.to_string())
            } else {
                None
            }
        } else {
            None
        };

        let api: Api<DynamicObject> = match &namespace {
            Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
            None => Api::all_with(client.clone(), &api_resource),
        };

        api.patch(&name, &params, &Patch::Apply(&obj))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to apply {}/{}: {}", kind, name, e))?;

        tracing::debug!(kind = %kind, name = %name, namespace = ?namespace, "Applied manifest");
    }

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

        // Only re-register clusters that completed bootstrap
        let bootstrap_complete = cluster
            .status
            .as_ref()
            .map(|s| s.bootstrap_complete)
            .unwrap_or(false);

        if !bootstrap_complete {
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

        let endpoints = match self_cluster.spec.endpoints.as_ref() {
            Some(e) => e,
            None => {
                tracing::warn!("Self cluster has no endpoints, cannot re-register");
                continue;
            }
        };

        let ca_cert = parent_servers.ca().ca_cert_pem().to_string();
        let cell_endpoint = endpoints.endpoint();

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
            provider: cluster.spec.provider.provider_type().to_string(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
        };

        bootstrap_state.register_cluster(registration, true);
        tracing::info!(cluster = %name, "re-registered cluster after operator restart");
    }
}

/// Run in controller mode - manages clusters
///
/// Cell servers (gRPC + bootstrap HTTP) start automatically when needed.
/// Cell endpoint configuration is read from the local LatticeCluster CRD's spec.endpoints.
///
/// If this cluster has a cellRef (parent), the controller also connects as an agent
/// to the parent cell for pivot coordination and health reporting.
async fn run_controller() -> anyhow::Result<()> {
    tracing::info!("Lattice controller starting...");

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
    // External exposure (LoadBalancer) is configured per-cluster based on spec.endpoints
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
    // This ensures TLS certificate has correct SANs (spec.endpoints.host) before serving
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    {
        let manifest_generator = lattice_operator::bootstrap::DefaultManifestGenerator::new();

        // Get extra SANs from LatticeCluster - MUST wait for it to exist with endpoints
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
            tracing::info!("Running as bootstrap cluster, using default SANs");
            vec![]
        } else if is_child_cluster {
            tracing::info!(
                "Running as child cluster (has parent config), skipping LatticeCluster wait"
            );
            vec![]
        } else if let Some(ref cluster_name) = self_cluster_name {
            let clusters: kube::Api<lattice_operator::crd::LatticeCluster> =
                kube::Api::all(client.clone());

            tracing::info!(cluster = %cluster_name, "Waiting for LatticeCluster with endpoints...");
            let mut retry_delay = std::time::Duration::from_secs(1);
            let max_retry_delay = std::time::Duration::from_secs(10);

            loop {
                match clusters.get(cluster_name).await {
                    Ok(cluster) => {
                        if let Some(ref endpoints) = cluster.spec.endpoints {
                            tracing::info!(host = %endpoints.host, "Adding cell host to server certificate SANs");
                            break vec![endpoints.host.clone()];
                        } else {
                            tracing::info!(
                                cluster = %cluster_name,
                                retry_in = ?retry_delay,
                                "LatticeCluster exists but has no endpoints, waiting..."
                            );
                        }
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => {
                        tracing::info!(
                            cluster = %cluster_name,
                            retry_in = ?retry_delay,
                            "LatticeCluster not found yet, waiting..."
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            retry_in = ?retry_delay,
                            "Failed to read LatticeCluster, retrying..."
                        );
                    }
                }
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
            }
        } else {
            vec![]
        };

        // Start cell servers - MUST complete before controllers start
        parent_servers
            .ensure_running_with(manifest_generator, &extra_sans, client.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start cell servers: {}", e))?;

        tracing::info!("Cell servers started (webhook + bootstrap + gRPC)");

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

    // Create controller context with cell servers
    // LATTICE_CLUSTER_NAME tells the controller which cluster it's running on (to avoid self-provisioning)
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    let mut ctx_builder = Context::builder(client.clone()).parent_servers(parent_servers.clone());
    if let Some(ref name) = self_cluster_name {
        tracing::info!(cluster = %name, "Running as self-managed cluster");
        ctx_builder = ctx_builder.self_cluster_name(name.clone());
    }
    let ctx = Arc::new(ctx_builder.build());

    // Check if we need to connect as an agent to a parent cell
    // This happens when the cluster has a cellRef (was provisioned by a parent)
    // Connection happens in background with retries - don't block controller startup
    if let Some(ref cluster_name) = self_cluster_name {
        let client_clone = client.clone();
        let cluster_name_clone = cluster_name.clone();
        tokio::spawn(async move {
            start_agent_with_retry(&client_clone, &cluster_name_clone).await;
        });
    }

    // Create APIs for all CRDs (cluster-scoped)
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client.clone());

    // Create service context for service controllers
    let service_ctx = Arc::new(ServiceContext::from_client(client, "cluster.local"));

    tracing::info!("Starting Lattice controllers...");
    tracing::info!("  - LatticeCluster controller");
    tracing::info!("  - LatticeService controller");
    tracing::info!("  - LatticeExternalService controller");

    // Create all controllers
    let cluster_controller = Controller::new(clusters, WatcherConfig::default())
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
        });

    // Clone graph for the watch mapper closure
    let graph_for_watch = service_ctx.graph.clone();

    let service_controller = Controller::new(services.clone(), WatcherConfig::default())
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

    let external_service_controller = Controller::new(external_services, WatcherConfig::default())
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

    // Run all controllers concurrently
    tokio::select! {
        _ = cluster_controller => {
            tracing::info!("Cluster controller completed");
        }
        _ = service_controller => {
            tracing::info!("Service controller completed");
        }
        _ = external_service_controller => {
            tracing::info!("External service controller completed");
        }
    }

    // Shutdown cell servers (agent background task cancelled automatically)
    parent_servers.shutdown().await;

    tracing::info!("Lattice controller shutting down");
    Ok(())
}

/// Supervise agent connection with automatic reconnection.
/// If a parent cell is configured, maintains connection indefinitely with retries.
/// Runs in background - does not block.
async fn start_agent_with_retry(client: &Client, cluster_name: &str) {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(30);

    loop {
        match start_agent_if_needed(client, cluster_name).await {
            Ok(Some(agent)) => {
                tracing::info!("Agent connection to parent cell established");
                // Reset retry delay on successful connection
                retry_delay = Duration::from_secs(1);

                // Monitor connection - wait until disconnected, then reconnect
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
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
                // Fall through to retry connection
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
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

    // Request certificate from cell
    let credentials = AgentClient::request_certificate(&http_endpoint, cluster_name, &ca_cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get certificate: {}", e))?;

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
