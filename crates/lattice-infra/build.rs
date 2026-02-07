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
}

#[derive(Debug, Deserialize)]
struct Resource {
    version: String,
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

    // 10. VictoriaMetrics K8s Stack
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
    std::fs::write(out_dir.join("victoria-metrics.yaml"), yaml)
        .expect("write victoria-metrics.yaml");

    // 11. KEDA (event-driven autoscaler)
    let yaml = run_helm_template(
        "keda",
        &chart(&format!("keda-{}.tgz", versions.charts["keda"].version)),
        "keda",
        &[],
    );
    std::fs::write(out_dir.join("keda.yaml"), yaml).expect("write keda.yaml");

    // 12. Gateway API CRDs (just copy, not helm)
    let gw_ver = &versions.resources["gateway-api"].version;
    let gw_src = charts_dir.join(format!("gateway-api-crds-v{}.yaml", gw_ver));
    let gw_content = std::fs::read_to_string(&gw_src)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", gw_src.display(), e));
    std::fs::write(out_dir.join("gateway-api-crds.yaml"), gw_content)
        .expect("write gateway-api-crds.yaml");
}
