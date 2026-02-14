//! Build script for lattice-infra
//!
//! Pre-renders all Helm charts at build time and embeds the output into the binary.
//! Sets compile-time environment variables for chart versions.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Deserialize)]
struct Versions {
    charts: HashMap<String, Chart>,
    resources: HashMap<String, Resource>,
}

#[derive(Debug, Deserialize)]
struct Chart {
    version: String,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    chart: Option<String>,
    #[serde(default)]
    filename: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Resource {
    version: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    filename: Option<String>,
}

/// Run `helm template` and return the rendered YAML as a String.
fn run_helm_template(
    release_name: &str,
    chart_path: &Path,
    namespace: &str,
    extra_args: &[&str],
) -> String {
    let output = Command::new("helm")
        .args([
            "template",
            release_name,
            &chart_path.to_string_lossy(),
            "--namespace",
            namespace,
            "--include-crds",
        ])
        .args(extra_args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run `helm template {}`: {}. Is helm installed?",
                release_name, e
            )
        });

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("helm template {} failed: {}", release_name, stderr);
    }

    String::from_utf8(output.stdout).unwrap_or_else(|e| {
        panic!(
            "helm template {} produced invalid UTF-8: {}",
            release_name, e
        )
    })
}

/// Ensure all helm charts and resource files are downloaded to `charts_dir`.
///
/// For each chart in `versions.toml` that has `repo`, `chart`, and `filename` fields,
/// runs `helm pull` if the tgz doesn't exist. For resources with `url` and `filename`,
/// downloads via curl.
fn ensure_charts_downloaded(charts_dir: &Path, versions: &Versions) {
    // Track which repos we've already added
    let mut repos_added = std::collections::HashSet::new();

    for (name, chart) in &versions.charts {
        let (Some(repo), Some(chart_name), Some(filename_pattern)) =
            (&chart.repo, &chart.chart, &chart.filename)
        else {
            continue;
        };

        let filename = filename_pattern.replace("{version}", &chart.version);
        let path = charts_dir.join(&filename);
        if path.exists() {
            continue;
        }

        eprintln!("cargo:warning=Downloading missing chart: {}", filename);

        // Add helm repo if we haven't yet
        let repo_alias = chart_name.split('/').next().unwrap_or(name.as_str());
        if repos_added.insert(repo_alias.to_string()) {
            let output = Command::new("helm")
                .args(["repo", "add", repo_alias, repo, "--force-update"])
                .output()
                .expect("helm repo add");
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                panic!("helm repo add {} failed: {}", repo_alias, stderr);
            }
        }

        // Pull the chart
        let output = Command::new("helm")
            .args([
                "pull",
                chart_name,
                "--version",
                &chart.version,
                "--destination",
                &charts_dir.to_string_lossy(),
            ])
            .output()
            .unwrap_or_else(|e| panic!("helm pull {} failed: {}", chart_name, e));

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "helm pull {} --version {} failed: {}",
                chart_name, chart.version, stderr
            );
        }

        assert!(
            path.exists(),
            "helm pull succeeded but {} not found (expected at {})",
            filename,
            path.display()
        );
    }

    // Download resource files (e.g., gateway-api CRDs)
    for resource in versions.resources.values() {
        let (Some(url_pattern), Some(filename_pattern)) = (&resource.url, &resource.filename)
        else {
            continue;
        };

        let filename = filename_pattern.replace("{version}", &resource.version);
        let url = url_pattern.replace("{version}", &resource.version);
        let path = charts_dir.join(&filename);
        if path.exists() {
            continue;
        }

        eprintln!("cargo:warning=Downloading missing resource: {}", filename);

        let output = Command::new("curl")
            .args(["-sL", "-o", &path.to_string_lossy(), &url])
            .output()
            .unwrap_or_else(|e| panic!("curl {} failed: {}", url, e));

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("curl {} failed: {}", url, stderr);
        }
    }
}

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set");
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("crate should have parent")
        .parent()
        .expect("crates dir should have parent");

    let versions_path = workspace_root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let charts_dir = workspace_root.join("test-charts");
    println!("cargo:rerun-if-changed={}", charts_dir.display());

    let content = std::fs::read_to_string(&versions_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", versions_path.display(), e));

    let versions: Versions = toml::from_str(&content).expect("versions.toml should be valid TOML");

    // --- Set version environment variables ---

    println!(
        "cargo:rustc-env=CILIUM_VERSION={}",
        versions.charts["cilium"].version
    );
    println!(
        "cargo:rustc-env=ISTIO_VERSION={}",
        versions.charts["istio-base"].version
    );
    println!(
        "cargo:rustc-env=GATEWAY_API_VERSION={}",
        versions.resources["gateway-api"].version
    );
    println!(
        "cargo:rustc-env=EXTERNAL_SECRETS_VERSION={}",
        versions.charts["external-secrets"].version
    );
    println!(
        "cargo:rustc-env=VELERO_VERSION={}",
        versions.charts["velero"].version
    );
    println!(
        "cargo:rustc-env=GPU_OPERATOR_VERSION={}",
        versions.charts["gpu-operator"].version
    );
    println!(
        "cargo:rustc-env=HAMI_VERSION={}",
        versions.charts["hami"].version
    );
    println!(
        "cargo:rustc-env=KEDA_VERSION={}",
        versions.charts["keda"].version
    );
    println!(
        "cargo:rustc-env=VICTORIA_METRICS_VERSION={}",
        versions.charts["victoria-metrics-k8s-stack"].version
    );
    println!(
        "cargo:rustc-env=METRICS_SERVER_VERSION={}",
        versions.charts["metrics-server"].version
    );

    // --- Auto-download missing charts ---

    std::fs::create_dir_all(&charts_dir).expect("create test-charts dir");
    ensure_charts_downloaded(&charts_dir, &versions);

    // --- Pre-render all Helm charts at build time ---

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR should be set"));

    // Helper to build chart path
    let chart = |filename: &str| charts_dir.join(filename);

    let istio_ver = &versions.charts["istio-base"].version;

    // 1. Cilium
    let yaml = run_helm_template(
        "cilium",
        &chart(&format!("cilium-{}.tgz", versions.charts["cilium"].version)),
        "kube-system",
        &[
            "--set",
            "hubble.enabled=false",
            "--set",
            "hubble.relay.enabled=false",
            "--set",
            "hubble.ui.enabled=false",
            "--set",
            "prometheus.enabled=false",
            "--set",
            "operator.prometheus.enabled=false",
            "--set",
            "cni.exclusive=false",
            "--set",
            "kubeProxyReplacement=false",
            "--set",
            "l2announcements.enabled=true",
            "--set",
            "externalIPs.enabled=true",
            "--set",
            "hostFirewall.enabled=false",
            "--set",
            "routingMode=tunnel",
            "--set",
            "tunnelProtocol=vxlan",
            "--set",
            "mtu=1450",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "bpf.masquerade=false",
            "--set",
            "bpf.hostLegacyRouting=true",
        ],
    );
    std::fs::write(out_dir.join("cilium.yaml"), yaml).expect("write cilium.yaml");

    // 2. Istio Base
    let yaml = run_helm_template(
        "istio-base",
        &chart(&format!("base-{}.tgz", istio_ver)),
        "istio-system",
        &[],
    );
    std::fs::write(out_dir.join("istio-base.yaml"), yaml).expect("write istio-base.yaml");

    // 3. Istio CNI
    let yaml = run_helm_template(
        "istio-cni",
        &chart(&format!("cni-{}.tgz", istio_ver)),
        "istio-system",
        &[
            "--set",
            "profile=ambient",
            "--set",
            "cni.cniConfFileName=05-cilium.conflist",
        ],
    );
    std::fs::write(out_dir.join("istio-cni.yaml"), yaml).expect("write istio-cni.yaml");

    // 4. Istiod (uses placeholder for cluster name)
    let yaml = run_helm_template(
        "istiod",
        &chart(&format!("istiod-{}.tgz", istio_ver)),
        "istio-system",
        &[
            "--set",
            "profile=ambient",
            "--set",
            "meshConfig.trustDomain=lattice.__LATTICE_CLUSTER_NAME__.local",
            "--set",
            "pilot.resources.requests.cpu=100m",
            "--set",
            "pilot.resources.requests.memory=128Mi",
        ],
    );
    std::fs::write(out_dir.join("istiod.yaml"), yaml).expect("write istiod.yaml");

    // 5. Ztunnel
    let yaml = run_helm_template(
        "ztunnel",
        &chart(&format!("ztunnel-{}.tgz", istio_ver)),
        "istio-system",
        &[],
    );
    std::fs::write(out_dir.join("ztunnel.yaml"), yaml).expect("write ztunnel.yaml");

    // 6. External Secrets
    let yaml = run_helm_template(
        "external-secrets",
        &chart(&format!(
            "external-secrets-{}.tgz",
            versions.charts["external-secrets"].version
        )),
        "external-secrets",
        &["--set", "installCRDs=true"],
    );
    std::fs::write(out_dir.join("external-secrets.yaml"), yaml)
        .expect("write external-secrets.yaml");

    // 7. Velero
    let yaml = run_helm_template(
        "velero",
        &chart(&format!("velero-{}.tgz", versions.charts["velero"].version)),
        "velero",
        &[
            "--set",
            "deployNodeAgent=true",
            "--set",
            "snapshotsEnabled=true",
            "--set",
            "initContainers=null",
            "--set-json",
            "configuration.backupStorageLocation=[]",
            "--set-json",
            "configuration.volumeSnapshotLocation=[]",
        ],
    );
    std::fs::write(out_dir.join("velero.yaml"), yaml).expect("write velero.yaml");

    // 8. GPU Operator
    let yaml = run_helm_template(
        "gpu-operator",
        &chart(&format!(
            "gpu-operator-v{}.tgz",
            versions.charts["gpu-operator"].version
        )),
        "gpu-operator",
        &[
            "--set",
            "driver.enabled=false",
            "--set",
            "toolkit.enabled=true",
            "--set",
            "devicePlugin.enabled=true",
            "--set",
            "nfd.enabled=true",
            "--set",
            "dcgmExporter.enabled=true",
            "--set",
            "migManager.enabled=false",
            "--set",
            "gfd.enabled=true",
        ],
    );
    std::fs::write(out_dir.join("gpu-operator.yaml"), yaml).expect("write gpu-operator.yaml");

    // 9. HAMi
    let yaml = run_helm_template(
        "hami",
        &chart(&format!("hami-{}.tgz", versions.charts["hami"].version)),
        "hami-system",
        &["--set", "scheduler.enabled=true"],
    );
    std::fs::write(out_dir.join("hami.yaml"), yaml).expect("write hami.yaml");

    // 10a. VictoriaMetrics K8s Stack — HA mode (VMCluster with 2 replicas each)
    let yaml = run_helm_template(
        "vm",
        &chart(&format!(
            "victoria-metrics-k8s-stack-{}.tgz",
            versions.charts["victoria-metrics-k8s-stack"].version
        )),
        "monitoring",
        &[
            "--set",
            "fullnameOverride=lattice-metrics",
            "--set",
            "vmcluster.enabled=true",
            "--set",
            "vmcluster.spec.retentionPeriod=24h",
            "--set",
            "vmcluster.spec.vmstorage.replicaCount=2",
            "--set",
            "vmcluster.spec.vmselect.replicaCount=2",
            "--set",
            "vmcluster.spec.vminsert.replicaCount=2",
            "--set",
            "vmcluster.spec.replicationFactor=2",
            "--set",
            "vmsingle.enabled=false",
            "--set",
            "grafana.enabled=false",
            "--set",
            "alertmanager.enabled=false",
            "--set",
            "vmalert.enabled=false",
        ],
    );
    std::fs::write(out_dir.join("victoria-metrics-ha.yaml"), yaml)
        .expect("write victoria-metrics-ha.yaml");

    // 10b. VictoriaMetrics K8s Stack — Single-node mode (VMSingle)
    let yaml = run_helm_template(
        "vm",
        &chart(&format!(
            "victoria-metrics-k8s-stack-{}.tgz",
            versions.charts["victoria-metrics-k8s-stack"].version
        )),
        "monitoring",
        &[
            "--set",
            "fullnameOverride=lattice-metrics",
            "--set",
            "vmcluster.enabled=false",
            "--set",
            "vmsingle.enabled=true",
            "--set",
            "vmsingle.spec.retentionPeriod=24h",
            "--set",
            "grafana.enabled=false",
            "--set",
            "alertmanager.enabled=false",
            "--set",
            "vmalert.enabled=false",
        ],
    );
    std::fs::write(out_dir.join("victoria-metrics-single.yaml"), yaml)
        .expect("write victoria-metrics-single.yaml");

    // 11. KEDA (event-driven autoscaler)
    let yaml = run_helm_template(
        "keda",
        &chart(&format!("keda-{}.tgz", versions.charts["keda"].version)),
        "keda",
        &[],
    );
    std::fs::write(out_dir.join("keda.yaml"), yaml).expect("write keda.yaml");

    // 12. cert-manager (with control-plane tolerations so it schedules on tainted CP nodes)
    let yaml = run_helm_template(
        "cert-manager",
        &chart(&format!(
            "cert-manager-v{}.tgz",
            versions.charts["cert-manager"].version
        )),
        "cert-manager",
        &[
            "--set",
            "crds.enabled=true",
            "--set",
            "tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "tolerations[0].operator=Exists",
            "--set",
            "tolerations[0].effect=NoSchedule",
            "--set",
            "webhook.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "webhook.tolerations[0].operator=Exists",
            "--set",
            "webhook.tolerations[0].effect=NoSchedule",
            "--set",
            "cainjector.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "cainjector.tolerations[0].operator=Exists",
            "--set",
            "cainjector.tolerations[0].effect=NoSchedule",
            "--set",
            "startupapicheck.tolerations[0].key=node-role.kubernetes.io/control-plane",
            "--set",
            "startupapicheck.tolerations[0].operator=Exists",
            "--set",
            "startupapicheck.tolerations[0].effect=NoSchedule",
        ],
    );
    std::fs::write(out_dir.join("cert-manager.yaml"), yaml).expect("write cert-manager.yaml");

    // Set cert-manager version env var
    println!(
        "cargo:rustc-env=CERT_MANAGER_VERSION={}",
        versions.charts["cert-manager"].version
    );

    // 13. metrics-server (required for HPA / KEDA CPU triggers)
    let yaml = run_helm_template(
        "metrics-server",
        &chart(&format!(
            "metrics-server-{}.tgz",
            versions.charts["metrics-server"].version
        )),
        "kube-system",
        &["--set", "args={--kubelet-insecure-tls}"],
    );
    std::fs::write(out_dir.join("metrics-server.yaml"), yaml).expect("write metrics-server.yaml");

    // 13. Gateway API CRDs (just copy, not helm)
    let gw_ver = &versions.resources["gateway-api"].version;
    let gw_src = charts_dir.join(format!("gateway-api-crds-v{}.yaml", gw_ver));
    let gw_content = std::fs::read_to_string(&gw_src)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", gw_src.display(), e));
    std::fs::write(out_dir.join("gateway-api-crds.yaml"), gw_content)
        .expect("write gateway-api-crds.yaml");
}
