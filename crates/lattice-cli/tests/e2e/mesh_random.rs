//! Randomized large-scale mesh test (10-20 services)
//!
//! Generates a random service mesh topology with configurable layers,
//! outbound/inbound probabilities, external services, and wildcard inbound.
//! Deploys traffic generators that continuously test all expected connections,
//! then verifies actual results match expected bilateral agreements.

#![cfg(feature = "provider-e2e")]

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use kube::api::Api;
use rand::prelude::*;
use tokio::time::sleep;
use tracing::info;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use lattice_common::crd::{
    LatticeExternalService, LatticeExternalServiceSpec, LatticeService, Resolution,
};

use super::helpers::{
    apply_mesh_wildcard_inbound_policy, client_from_kubeconfig, create_with_retry,
    delete_namespace, ensure_fresh_namespace, run_kubectl, setup_regcreds_infrastructure,
};
use super::mesh_fixtures::{
    build_lattice_service, curl_container, external_outbound_dep, inbound_allow, inbound_allow_all,
    nginx_container, outbound_dep,
};
use super::mesh_helpers::{
    generate_test_script, parse_traffic_result, retry_verification, wait_for_pods_running,
    wait_for_services_ready, TestTarget,
};

// =============================================================================
// Constants
// =============================================================================

pub const RANDOM_MESH_NAMESPACE: &str = "random-mesh";

// =============================================================================
// Configuration
// =============================================================================

#[derive(Debug, Clone)]
pub struct RandomMeshConfig {
    pub min_services: usize,
    pub max_services: usize,
    pub num_layers: usize,
    pub outbound_probability: f64,
    pub bilateral_probability: f64,
    pub seed: Option<u64>,
    pub num_external_services: usize,
    pub external_outbound_probability: f64,
    pub external_allow_probability: f64,
    /// Probability that a non-frontend service uses wildcard "allow all inbound"
    pub wildcard_probability: f64,
}

impl Default for RandomMeshConfig {
    fn default() -> Self {
        Self {
            min_services: 10,
            max_services: 20,
            num_layers: 3,
            outbound_probability: 0.3,
            bilateral_probability: 0.6,
            seed: None,
            num_external_services: 10,
            external_outbound_probability: 0.3,
            external_allow_probability: 0.6,
            wildcard_probability: 0.15,
        }
    }
}

// =============================================================================
// Service Models
// =============================================================================

#[derive(Debug, Clone)]
struct RandomExternalService {
    url: String,
    allowed_requesters: HashSet<String>,
    resolution: Resolution,
}

#[derive(Debug, Clone)]
struct RandomService {
    name: String,
    outbound: HashSet<String>,
    external_outbound: HashSet<String>,
    inbound: HashSet<String>,
    is_traffic_generator: bool,
    /// If true, this service allows ALL inbound via wildcard (only caller needs outbound)
    allows_all_inbound: bool,
}

// =============================================================================
// Random Mesh Generator
// =============================================================================

#[derive(Debug)]
pub struct RandomMesh {
    services: BTreeMap<String, RandomService>,
    layers: Vec<Vec<String>>,
    external_services: BTreeMap<String, RandomExternalService>,
    /// (source, target, expected_allowed, is_external)
    expected_connections: Vec<(String, String, bool, bool)>,
}

impl RandomMesh {
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    pub fn has_external_services(&self) -> bool {
        !self.external_services.is_empty()
    }

    pub fn generate(config: &RandomMeshConfig) -> Self {
        let mut rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        let num_services = rng.gen_range(config.min_services..=config.max_services);
        info!(
            "[Random Mesh] Generating {} services across {} layers...",
            num_services, config.num_layers
        );

        let layers = Self::generate_layers(num_services, config.num_layers, &mut rng);
        let mut services = Self::create_services(&layers, config, &mut rng);
        let mut expected_connections = Vec::new();

        Self::wire_outbound_connections(
            &layers,
            &mut services,
            &mut expected_connections,
            config,
            &mut rng,
        );
        Self::add_peer_denial_tests(&layers, &services, &mut expected_connections, &mut rng);

        let mut external_services = Self::generate_external_services(config);
        Self::wire_external_connections(
            &mut services,
            &mut external_services,
            &mut expected_connections,
            config,
            &mut rng,
        );

        Self {
            services,
            layers,
            external_services,
            expected_connections,
        }
    }

    fn generate_layers(
        num_services: usize,
        num_layers: usize,
        rng: &mut StdRng,
    ) -> Vec<Vec<String>> {
        let mut layer_sizes = Vec::with_capacity(num_layers);
        let base_size = num_services / num_layers;
        let mut remaining = num_services;

        for i in 0..num_layers {
            let size = if i == num_layers - 1 {
                remaining
            } else {
                let variance = if i == 0 || i == num_layers - 1 {
                    base_size / 2
                } else {
                    base_size / 3
                };
                let remaining_layers = num_layers - i - 1;
                let max_size = remaining.saturating_sub(remaining_layers);
                let size = (base_size + rng.gen_range(0..=variance)).min(max_size);
                remaining -= size;
                size
            };
            layer_sizes.push(size);
        }

        let layer_prefixes = ["frontend", "gateway", "api", "backend", "data"];
        let mut layers = Vec::with_capacity(num_layers);

        for (layer_idx, &size) in layer_sizes.iter().enumerate() {
            let prefix = layer_prefixes.get(layer_idx).unwrap_or(&"svc");
            let layer_services: Vec<String> =
                (0..size).map(|i| format!("{}-{}", prefix, i)).collect();
            layers.push(layer_services);
        }

        layers
    }

    fn create_services(
        layers: &[Vec<String>],
        config: &RandomMeshConfig,
        rng: &mut StdRng,
    ) -> BTreeMap<String, RandomService> {
        let mut services = BTreeMap::new();

        for (layer_idx, layer) in layers.iter().enumerate() {
            let is_traffic_generator = layer_idx == 0;
            for name in layer {
                let allows_all_inbound =
                    !is_traffic_generator && rng.gen::<f64>() < config.wildcard_probability;
                services.insert(
                    name.clone(),
                    RandomService {
                        name: name.clone(),
                        outbound: HashSet::new(),
                        external_outbound: HashSet::new(),
                        inbound: HashSet::new(),
                        is_traffic_generator,
                        allows_all_inbound,
                    },
                );
            }
        }

        services
    }

    fn wire_outbound_connections(
        layers: &[Vec<String>],
        services: &mut BTreeMap<String, RandomService>,
        expected_connections: &mut Vec<(String, String, bool, bool)>,
        config: &RandomMeshConfig,
        rng: &mut StdRng,
    ) {
        let num_layers = layers.len();
        for layer_idx in 0..num_layers.saturating_sub(1) {
            for source_name in &layers[layer_idx] {
                for target_layer in layers.iter().skip(layer_idx + 1) {
                    for target_name in target_layer {
                        if rng.gen::<f64>() < config.outbound_probability {
                            services
                                .get_mut(source_name)
                                .expect("source service should exist")
                                .outbound
                                .insert(target_name.clone());

                            let target_allows_all = services[target_name].allows_all_inbound;
                            let is_bilateral = if target_allows_all {
                                true
                            } else {
                                let bilateral = rng.gen::<f64>() < config.bilateral_probability;
                                if bilateral {
                                    services
                                        .get_mut(target_name)
                                        .expect("target service should exist")
                                        .inbound
                                        .insert(source_name.clone());
                                }
                                bilateral
                            };

                            if services[source_name].is_traffic_generator {
                                expected_connections.push((
                                    source_name.clone(),
                                    target_name.clone(),
                                    is_bilateral,
                                    false,
                                ));
                            }
                        }
                    }
                }

                // Add negative tests: sample non-dependent targets
                if services[source_name].is_traffic_generator {
                    for target_layer in layers.iter().skip(layer_idx + 1) {
                        let not_dependent: Vec<_> = target_layer
                            .iter()
                            .filter(|t| !services[source_name].outbound.contains(*t))
                            .collect();
                        let sample_size = not_dependent.len().min(3);
                        for target_name in not_dependent.choose_multiple(rng, sample_size) {
                            expected_connections.push((
                                source_name.clone(),
                                (*target_name).clone(),
                                false,
                                false,
                            ));
                        }
                    }
                }
            }
        }
    }

    fn add_peer_denial_tests(
        layers: &[Vec<String>],
        services: &BTreeMap<String, RandomService>,
        expected_connections: &mut Vec<(String, String, bool, bool)>,
        rng: &mut StdRng,
    ) {
        for layer in layers {
            if layer.len() < 2 {
                continue;
            }
            let traffic_generators: Vec<_> = layer
                .iter()
                .filter(|s| services[*s].is_traffic_generator)
                .collect();
            for source in &traffic_generators {
                let peers: Vec<_> = layer.iter().filter(|s| *s != *source).collect();
                if let Some(peer) = peers.choose(rng) {
                    expected_connections.push(((*source).clone(), (*peer).clone(), false, false));
                }
            }
        }
    }

    fn generate_external_services(
        config: &RandomMeshConfig,
    ) -> BTreeMap<String, RandomExternalService> {
        let external_urls = [
            ("httpbin", "https://httpbin.org/status/200"),
            ("example", "https://example.com"),
            ("google", "https://www.google.com"),
            ("cloudflare", "https://one.one.one.one"),
            ("github", "https://github.com"),
        ];

        let num_external = config.num_external_services.min(external_urls.len());
        let mut external_services = BTreeMap::new();

        for (name, url) in external_urls.iter().take(num_external) {
            let resolution = if Self::is_ip_based_url(url) {
                Resolution::Static
            } else {
                Resolution::Dns
            };
            external_services.insert(
                name.to_string(),
                RandomExternalService {
                    url: url.to_string(),
                    allowed_requesters: HashSet::new(),
                    resolution,
                },
            );
        }

        external_services
    }

    fn wire_external_connections(
        services: &mut BTreeMap<String, RandomService>,
        external_services: &mut BTreeMap<String, RandomExternalService>,
        expected_connections: &mut Vec<(String, String, bool, bool)>,
        config: &RandomMeshConfig,
        rng: &mut StdRng,
    ) {
        let traffic_generators: Vec<String> = services
            .values()
            .filter(|s| s.is_traffic_generator)
            .map(|s| s.name.clone())
            .collect();
        let ext_names: Vec<String> = external_services.keys().cloned().collect();

        for source_name in &traffic_generators {
            for ext_name in &ext_names {
                if rng.gen::<f64>() < config.external_outbound_probability {
                    services
                        .get_mut(source_name)
                        .expect("source service should exist")
                        .external_outbound
                        .insert(ext_name.clone());
                    let is_allowed = rng.gen::<f64>() < config.external_allow_probability;
                    if is_allowed {
                        external_services
                            .get_mut(ext_name)
                            .expect("external service should exist")
                            .allowed_requesters
                            .insert(source_name.clone());
                    }
                    expected_connections.push((
                        source_name.clone(),
                        ext_name.clone(),
                        is_allowed,
                        true,
                    ));
                }
            }

            // Negative tests for externals
            let not_dependent: Vec<_> = ext_names
                .iter()
                .filter(|e| !services[source_name].external_outbound.contains(*e))
                .cloned()
                .collect();
            for ext_name in not_dependent
                .choose_multiple(rng, not_dependent.len().min(2))
                .cloned()
            {
                expected_connections.push((source_name.clone(), ext_name, false, true));
            }
        }
    }

    fn is_ip_based_url(url: &str) -> bool {
        use std::net::IpAddr;
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host = host.split(':').next().unwrap_or(host);
        let host = host.split('/').next().unwrap_or(host);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<IpAddr>().is_ok()
    }

    fn stats(&self) -> String {
        let total_tests = self.expected_connections.len();
        let expected_allowed = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| *a)
            .count();
        let external_tests = self
            .expected_connections
            .iter()
            .filter(|(_, _, _, e)| *e)
            .count();
        let wildcard_services = self
            .services
            .values()
            .filter(|s| s.allows_all_inbound)
            .count();
        format!(
            "[Random Mesh] Services: {} across {} layers ({} wildcard)\n\
             [Random Mesh]   Tests: {} ({} allowed, {} blocked)\n\
             [Random Mesh]   External: {} services, {} tests",
            self.services.len(),
            self.layers.len(),
            wildcard_services,
            total_tests,
            expected_allowed,
            total_tests - expected_allowed,
            self.external_services.len(),
            external_tests
        )
    }

    fn print_manifest(&self) {
        let allowed: Vec<_> = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| *a)
            .collect();
        let blocked: Vec<_> = self
            .expected_connections
            .iter()
            .filter(|(_, _, a, _)| !*a)
            .collect();

        info!("[Random Mesh] === EXPECTED ALLOWED ({}) ===", allowed.len());
        for (src, tgt, _, is_ext) in allowed.iter().take(20) {
            info!(
                "[Random Mesh]   {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if allowed.len() > 20 {
            info!("[Random Mesh] ... and {} more", allowed.len() - 20);
        }

        info!("[Random Mesh] === EXPECTED BLOCKED ({}) ===", blocked.len());
        for (src, tgt, _, is_ext) in blocked.iter().take(20) {
            info!(
                "[Random Mesh]   {} -> {}{}",
                src,
                tgt,
                if *is_ext { " [EXT]" } else { "" }
            );
        }
        if blocked.len() > 20 {
            info!("[Random Mesh] ... and {} more", blocked.len() - 20);
        }
    }

    fn create_lattice_service(&self, name: &str, namespace: &str) -> LatticeService {
        let svc = &self.services[name];
        let mut resources: BTreeMap<String, _> = BTreeMap::new();

        // Outbound service dependencies
        for dep in &svc.outbound {
            let (key, spec) = outbound_dep(dep);
            resources.insert(key, spec);
        }

        // Inbound: wildcard or explicit
        if svc.allows_all_inbound {
            let (key, spec) = inbound_allow_all();
            resources.insert(key, spec);
        } else {
            for allow in &svc.inbound {
                let (key, spec) = inbound_allow(allow);
                resources.insert(key, spec);
            }
        }

        // External outbound dependencies
        for ext_name in &svc.external_outbound {
            let (key, spec) = external_outbound_dep(ext_name);
            resources.insert(key, spec);
        }

        let container = if svc.is_traffic_generator {
            let targets = self.build_test_targets(name, namespace);
            let script = generate_test_script(name, targets);
            curl_container(script)
        } else {
            nginx_container()
        };

        let has_port = !svc.is_traffic_generator;
        build_lattice_service(name, namespace, resources, has_port, container)
    }

    fn create_external_service(&self, name: &str, namespace: &str) -> LatticeExternalService {
        let ext_svc = &self.external_services[name];
        let mut endpoints = BTreeMap::new();
        endpoints.insert("default".to_string(), ext_svc.url.clone());

        LatticeExternalService {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: LatticeExternalServiceSpec {
                endpoints,
                allowed_requesters: ext_svc.allowed_requesters.iter().cloned().collect(),
                resolution: ext_svc.resolution.clone(),
                description: Some(format!("External service: {}", ext_svc.url)),
            },
            status: None,
        }
    }

    fn build_test_targets(&self, source_name: &str, namespace: &str) -> Vec<TestTarget> {
        self.expected_connections
            .iter()
            .filter(|(src, _, _, _)| src == source_name)
            .map(|(_, target, expected_allowed, is_external)| {
                if *is_external {
                    let url = &self.external_services[target].url;
                    TestTarget::with_url(source_name, target, url, *expected_allowed)
                } else {
                    let url = format!("http://{}.{}.svc.cluster.local/", target, namespace);
                    TestTarget::with_url(source_name, target, &url, *expected_allowed)
                }
            })
            .collect()
    }
}

// =============================================================================
// Deployment & Verification
// =============================================================================

async fn deploy_random_mesh(mesh: &RandomMesh, kubeconfig_path: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig_path, RANDOM_MESH_NAMESPACE).await?;

    // Set up regcreds infrastructure — all services need ghcr-creds for image pulls
    info!("[Random Mesh] Setting up regcreds infrastructure...");
    setup_regcreds_infrastructure(kubeconfig_path).await?;

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    if !mesh.external_services.is_empty() {
        info!(
            "[Random Mesh] Deploying {} external services...",
            mesh.external_services.len()
        );
        let ext_api: Api<LatticeExternalService> =
            Api::namespaced(client.clone(), RANDOM_MESH_NAMESPACE);
        for name in mesh.external_services.keys() {
            let ext_svc = mesh.create_external_service(name, RANDOM_MESH_NAMESPACE);
            create_with_retry(&ext_api, &ext_svc, name).await?;
        }
    }

    // Apply Cedar policies for wildcard inbound services
    for svc in mesh.services.values() {
        if svc.allows_all_inbound {
            apply_mesh_wildcard_inbound_policy(kubeconfig_path, RANDOM_MESH_NAMESPACE, &svc.name)
                .await?;
        }
    }

    let api: Api<LatticeService> = Api::namespaced(client, RANDOM_MESH_NAMESPACE);

    for (layer_idx, layer) in mesh.layers.iter().enumerate().rev() {
        info!(
            "[Random Mesh] [Layer {}] Deploying {} services...",
            layer_idx,
            layer.len()
        );
        for name in layer {
            let svc = mesh.create_lattice_service(name, RANDOM_MESH_NAMESPACE);
            create_with_retry(&api, &svc, name).await?;
        }
        sleep(Duration::from_secs(2)).await;
    }

    info!(
        "[Random Mesh] All {} services deployed!",
        mesh.services.len()
    );
    Ok(())
}

async fn verify_random_mesh_traffic(
    mesh: &RandomMesh,
    kubeconfig_path: &str,
) -> Result<(), String> {
    let mut results: BTreeMap<(String, String), (bool, bool, Option<bool>)> = BTreeMap::new();
    for (src, tgt, expected, is_external) in &mesh.expected_connections {
        results.insert((src.clone(), tgt.clone()), (*expected, *is_external, None));
    }

    let traffic_generators: Vec<_> = mesh
        .services
        .values()
        .filter(|s| s.is_traffic_generator)
        .map(|s| s.name.clone())
        .collect();

    info!(
        "[Random Mesh] Checking logs from {} traffic generators...",
        traffic_generators.len()
    );

    for source in &traffic_generators {
        let logs = run_kubectl(&[
            "--kubeconfig",
            kubeconfig_path,
            "logs",
            "-n",
            RANDOM_MESH_NAMESPACE,
            "-l",
            &format!("{}={}", lattice_common::LABEL_NAME, source),
            "--tail",
            "1000",
        ])
        .await
        .unwrap_or_default();

        for ((src, tgt), (_, _, actual)) in results.iter_mut() {
            if src != source {
                continue;
            }
            let allowed_pattern = format!("{}->{}:ALLOWED", src, tgt);
            let blocked_pattern = format!("{}->{}:BLOCKED", src, tgt);
            *actual = parse_traffic_result(&logs, &allowed_pattern, &blocked_pattern);
        }
    }

    let mut mismatches: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for ((src, tgt), (expected, is_external, actual)) in &results {
        let marker = if *is_external { " [EXT]" } else { "" };
        match actual {
            None => missing.push(format!("{} -> {}{}", src, tgt, marker)),
            Some(got) => {
                if got != expected {
                    mismatches.push(format!(
                        "{} -> {}{}: expected {}, got {}",
                        src,
                        tgt,
                        marker,
                        if *expected { "ALLOWED" } else { "BLOCKED" },
                        if *got { "ALLOWED" } else { "BLOCKED" }
                    ));
                }
            }
        }
    }

    let total = results.len();
    let passed = total - mismatches.len() - missing.len();

    info!("[Random Mesh] ========================================");
    info!("[Random Mesh] RANDOMIZED MESH VERIFICATION");
    info!("[Random Mesh] ========================================");
    info!(
        "[Random Mesh] Total: {}, Passed: {}, Mismatches: {}, Missing: {}",
        total,
        passed,
        mismatches.len(),
        missing.len()
    );

    if !mismatches.is_empty() || !missing.is_empty() {
        if !mismatches.is_empty() {
            info!("[Random Mesh] MISMATCHES:");
            for m in mismatches.iter().take(20) {
                info!("[Random Mesh] {}", m);
            }
            if mismatches.len() > 20 {
                info!("[Random Mesh] ... and {} more", mismatches.len() - 20);
            }
        }
        if !missing.is_empty() {
            info!("[Random Mesh] MISSING:");
            for m in missing.iter().take(20) {
                info!("[Random Mesh] {}", m);
            }
            if missing.len() > 20 {
                info!("[Random Mesh] ... and {} more", missing.len() - 20);
            }
        }
        return Err(format!(
            "[Random Mesh] Random mesh failed: {} mismatches, {} missing",
            mismatches.len(),
            missing.len()
        ));
    }

    info!("[Random Mesh] SUCCESS: All {} tests passed!", total);
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

/// Run the randomized 10-20 service mesh test end-to-end.
///
/// Deploys a random mesh topology, waits for pods, then retries verification
/// every 15s for up to 5 minutes to handle slow policy propagation.
pub async fn run_random_mesh_test(kubeconfig_path: &str) -> Result<(), String> {
    info!("[Random Mesh] Starting randomized large-scale mesh test (10-20 services)...");

    let mesh = RandomMesh::generate(&RandomMeshConfig::default());
    info!("{}", mesh.stats());
    mesh.print_manifest();

    deploy_random_mesh(&mesh, kubeconfig_path).await?;
    wait_for_services_ready(kubeconfig_path, RANDOM_MESH_NAMESPACE, mesh.service_count()).await?;

    let expected_pods = mesh.service_count() + if mesh.has_external_services() { 1 } else { 0 };
    wait_for_pods_running(
        kubeconfig_path,
        RANDOM_MESH_NAMESPACE,
        expected_pods,
        "Random Mesh",
        Duration::from_secs(1200),
        Duration::from_secs(15),
    )
    .await?;

    let kc = kubeconfig_path.to_string();
    let result = retry_verification("Random Mesh", || verify_random_mesh_traffic(&mesh, &kc)).await;

    if result.is_ok() {
        delete_namespace(kubeconfig_path, RANDOM_MESH_NAMESPACE).await;
    } else {
        info!(
            "[Random Mesh] Leaving namespace {} for debugging (test failed)",
            RANDOM_MESH_NAMESPACE
        );
    }

    result
}
