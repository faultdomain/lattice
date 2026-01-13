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
use lattice_operator::controller::{
    error_policy, error_policy_external, reconcile, reconcile_external, service_error_policy,
    service_reconcile, Context, ServiceContext,
};
use lattice_operator::crd::{LatticeCluster, LatticeExternalService, LatticeService};
use lattice_operator::infra::IstioReconciler;
use lattice_operator::install::{InstallConfig, Installer};
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

    /// Install Lattice - bootstrap a new management cluster
    ///
    /// Creates a temporary kind cluster, provisions the management cluster,
    /// pivots CAPI resources, and deletes the bootstrap cluster.
    Install(InstallArgs),
}

/// Install mode arguments
#[derive(Parser, Debug)]
struct InstallArgs {
    /// Path to the LatticeCluster YAML configuration file
    ///
    /// This file defines the management cluster spec and is applied as-is.
    /// The same file is used for both provisioning and the self-referential
    /// CRD on the management cluster, making it GitOps-friendly.
    #[arg(short = 'f', long = "config")]
    config_file: std::path::PathBuf,

    /// Lattice container image
    #[arg(
        long,
        env = "LATTICE_IMAGE",
        default_value = "ghcr.io/evan-hines-js/lattice:latest"
    )]
    image: String,

    /// Path to registry credentials file (dockerconfigjson format)
    #[arg(long, env = "REGISTRY_CREDENTIALS_FILE")]
    registry_credentials_file: Option<std::path::PathBuf>,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    keep_bootstrap_on_failure: bool,

    /// Timeout for the entire installation in seconds
    #[arg(long, default_value = "1200")]
    timeout_secs: u64,

    /// Kubernetes bootstrap provider (overrides config file if set)
    ///
    /// RKE2 is FIPS-compliant out of the box and is the recommended default.
    /// Kubeadm requires FIPS relaxation to communicate with its API server.
    #[arg(long, default_value = "rke2", value_parser = parse_bootstrap_provider)]
    bootstrap: lattice_operator::crd::BootstrapProvider,
}

/// Parse bootstrap provider from CLI argument
fn parse_bootstrap_provider(s: &str) -> Result<lattice_operator::crd::BootstrapProvider, String> {
    match s.to_lowercase().as_str() {
        "rke2" => Ok(lattice_operator::crd::BootstrapProvider::Rke2),
        "kubeadm" => Ok(lattice_operator::crd::BootstrapProvider::Kubeadm),
        _ => Err(format!(
            "invalid bootstrap provider '{}', must be 'rke2' or 'kubeadm'",
            s
        )),
    }
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
        Some(Commands::Install(args)) => run_install(args).await,
        Some(Commands::Controller) | None => run_controller().await,
    }
}

/// Run the installer - bootstrap a new management cluster
async fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    // Read and validate the cluster config file
    let config_content = tokio::fs::read_to_string(&args.config_file)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read config file {:?}: {}", args.config_file, e))?;

    // Parse the YAML to validate it's a valid LatticeCluster
    let cluster: LatticeCluster = serde_yaml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse LatticeCluster config: {}", e))?;

    let cluster_name = cluster
        .metadata
        .name
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("LatticeCluster must have metadata.name"))?;

    let provider = &cluster.spec.provider.type_;

    println!("=== Lattice Installer ===");
    println!("Config file: {:?}", args.config_file);
    println!("Management cluster: {}", cluster_name);
    println!("Provider: {}", provider);
    println!(
        "Kubernetes version: {}",
        cluster.spec.provider.kubernetes.version
    );
    println!("Bootstrap: {}", args.bootstrap);
    println!();

    // Read registry credentials if provided
    let registry_credentials = if let Some(creds_path) = &args.registry_credentials_file {
        Some(
            tokio::fs::read_to_string(creds_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read registry credentials: {}", e))?,
        )
    } else {
        None
    };

    let config = InstallConfig {
        cluster_config_path: args.config_file,
        cluster_config_content: config_content,
        image: args.image,
        keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        timeout: Duration::from_secs(args.timeout_secs),
        registry_credentials,
        bootstrap_override: Some(args.bootstrap),
    };

    let installer = Installer::new(config).map_err(|e| anyhow::anyhow!("{}", e))?;
    installer.run().await.map_err(|e| anyhow::anyhow!("{}", e))
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

    // Apply manifests (server-side apply handles create or update)
    for manifest in manifests {
        apply_manifest(client, manifest).await?;
    }

    // Apply PeerAuthentication for STRICT mTLS
    let peer_auth = IstioReconciler::generate_peer_authentication();
    apply_manifest(client, &peer_auth).await?;

    // Apply mesh-wide default-deny AuthorizationPolicy
    // This is the security baseline - all traffic denied unless explicitly allowed
    let default_deny = IstioReconciler::generate_default_deny();
    apply_manifest(client, &default_deny).await?;

    // Apply allow policy for lattice-operator (webhook + gRPC from workload clusters)
    let operator_allow = IstioReconciler::generate_operator_allow_policy();
    apply_manifest(client, &operator_allow).await?;

    // Apply Cilium policies only if Cilium is installed (skip on bootstrap cluster)
    // Bootstrap kind cluster uses default CNI, not Cilium, so these CRDs don't exist
    let is_bootstrap_cluster = std::env::var("LATTICE_ROOT_INSTALL").is_ok();
    if !is_bootstrap_cluster {
        // Apply Cilium policy for Istio ambient mode compatibility
        // This allows ztunnel's SNAT-ed health probes (from 169.254.7.127) to reach pods
        // Required when using default-deny network policies with Istio ambient
        let ztunnel_allow = lattice_operator::infra::generate_ztunnel_allowlist();
        apply_manifest(client, &ztunnel_allow).await?;

        // Apply Cilium default-deny policy for L4 defense-in-depth
        // This complements Istio's L7 AuthorizationPolicy - traffic must pass both layers
        let cilium_default_deny = lattice_operator::infra::generate_default_deny();
        apply_manifest(client, &cilium_default_deny).await?;
    } else {
        tracing::debug!("Skipping Cilium policies on bootstrap cluster (no Cilium CRDs)");
    }

    tracing::info!(version = %expected_version, "Istio reconciliation complete");
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

/// Apply a single YAML manifest to the cluster
async fn apply_manifest(client: &Client, manifest: &str) -> anyhow::Result<()> {
    use kube::api::{Api, DynamicObject, Patch, PatchParams};
    use kube::discovery::ApiResource;

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
    let (group, version) = if api_version.contains('/') {
        let parts: Vec<&str> = api_version.splitn(2, '/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    };

    let gvk = kube::api::GroupVersionKind {
        group,
        version,
        kind: kind.to_string(),
    };
    let api_resource = ApiResource::from_gvk(&gvk);

    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
        None => Api::all_with(client.clone(), &api_resource),
    };

    let params = PatchParams::apply("lattice").force();
    api.patch(name, &params, &Patch::Apply(&obj))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply {}/{}: {}", kind, name, e))?;

    tracing::debug!(kind = kind, name = name, "Applied manifest");
    Ok(())
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
    let parent_servers = Arc::new(
        ParentServers::new(ParentConfig::default())
            .map_err(|e| anyhow::anyhow!("Failed to create cell servers: {}", e))?,
    );

    // Install MutatingWebhookConfiguration for Deployment injection
    // CA is available immediately from parent_servers (created in ParentServers::new)
    ensure_webhook_config(&client, parent_servers.ca()).await?;

    // Spawn background task to start cell servers once LatticeCluster is available
    // This ensures TLS certificate has correct SANs (spec.endpoints.host) before serving manifests
    // Controllers start immediately - they check parent_servers.is_running() before provisioning
    let parent_servers_clone = parent_servers.clone();
    let client_clone = client.clone();
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    tokio::spawn(async move {
        let manifest_generator = match lattice_operator::bootstrap::DefaultManifestGenerator::new()
        {
            Ok(gen) => gen,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create manifest generator");
                return;
            }
        };

        // Wait for LatticeCluster to get extra SANs (cell host IP)
        let extra_sans: Vec<String> = if let Some(ref cluster_name) = self_cluster_name {
            let clusters: kube::Api<lattice_operator::crd::LatticeCluster> =
                kube::Api::all(client_clone.clone());

            tracing::info!(cluster = %cluster_name, "Waiting for LatticeCluster before starting cell servers...");
            loop {
                match clusters.get(cluster_name).await {
                    Ok(cluster) => {
                        if let Some(ref cell) = cluster.spec.endpoints {
                            tracing::info!(host = %cell.host, "Adding cell host to server certificate SANs");
                            break vec![cell.host.clone()];
                        } else {
                            tracing::debug!(
                                "LatticeCluster has no cell spec, no extra SANs needed"
                            );
                            break vec![];
                        }
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => {
                        tracing::debug!(
                            cluster = %cluster_name,
                            "LatticeCluster not found yet, waiting..."
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to read LatticeCluster, retrying...");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        } else {
            vec![]
        };

        // Now start cell servers with correct SANs
        if let Err(e) = parent_servers_clone
            .ensure_running_with(manifest_generator, &extra_sans, client_clone)
            .await
        {
            tracing::error!(error = %e, "Failed to start cell servers");
        } else {
            tracing::info!("Cell servers started (webhook + bootstrap + gRPC)");
        }
    });

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
    let agent_handle = if let Some(ref cluster_name) = self_cluster_name {
        match start_agent_if_needed(&client, cluster_name).await {
            Ok(Some(handle)) => {
                tracing::info!("Agent connection to parent cell started");
                Some(handle)
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start agent connection, continuing without");
                None
            }
        }
    } else {
        None
    };

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

    // Shutdown agent if running
    if let Some(mut agent) = agent_handle {
        agent.shutdown().await;
    }

    // Shutdown cell servers
    parent_servers.shutdown().await;

    tracing::info!("Lattice controller shutting down");
    Ok(())
}

/// Check if this cluster has a parent cell and start agent connection if so
///
/// Returns Ok(Some(client)) if agent started, Ok(None) if no parent, Err on failure
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
