//! Cilium CNI manifest generation
//!
//! Generates Cilium manifests using `helm template` for consistent deployment.
//! The same generator is used by bootstrap and day-2 reconciliation.
//!
//! Also provides CiliumNetworkPolicy generation for Lattice components.

use std::process::Command;
use tracing::info;

use crate::agent::CENTRAL_PROXY_PORT;
use crate::{DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT};

/// Default charts directory (set by LATTICE_CHARTS_DIR env var in container)
const DEFAULT_CHARTS_DIR: &str = "/charts";

/// Get charts directory - checks runtime env var first, then compile-time, then default
fn get_charts_dir() -> String {
    // Runtime env var takes precedence (for container override)
    if let Ok(dir) = std::env::var("LATTICE_CHARTS_DIR") {
        return dir;
    }
    // Compile-time env var set by build.rs (for local development)
    if let Some(dir) = option_env!("LATTICE_CHARTS_DIR") {
        return dir.to_string();
    }
    // Default for container
    DEFAULT_CHARTS_DIR.to_string()
}

/// Generate Cilium manifests for a cluster
///
/// Renders via `helm template` on-demand. Provider is passed for future
/// provider-specific configuration if needed.
pub fn generate_cilium_manifests(provider: Option<&str>) -> Result<Vec<String>, String> {
    let charts_dir = get_charts_dir();
    let version = env!("CILIUM_VERSION");
    let chart_path = format!("{}/cilium-{}.tgz", charts_dir, version);

    let values = vec![
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
        // Don't replace kube-proxy - less invasive
        "--set",
        "kubeProxyReplacement=false",
        // Enable L2 announcements for LoadBalancer IPs (required for VIP reachability)
        "--set",
        "l2announcements.enabled=true",
        "--set",
        "externalIPs.enabled=true",
        // Disable host firewall - prevents blocking bridge traffic
        "--set",
        "hostFirewall.enabled=false",
        // VXLAN tunnel mode with reduced MTU (tunnelProtocol replaces deprecated tunnel option)
        "--set",
        "routingMode=tunnel",
        "--set",
        "tunnelProtocol=vxlan",
        "--set",
        "mtu=1450",
        // Use Kubernetes IPAM - gets pod CIDR from kubeadm (192.168.0.0/16)
        // Default cluster-pool mode uses 10.0.0.0/8 which conflicts with common LANs
        "--set",
        "ipam.mode=kubernetes",
        // Disable BPF-based masquerading - use iptables instead (less invasive)
        "--set",
        "bpf.masquerade=false",
        // Disable host routing via BPF - use kernel routing
        "--set",
        "bpf.hostLegacyRouting=true",
    ];

    info!(provider = ?provider, "Rendering Cilium manifests");

    let output = Command::new("helm")
        .args(["template", "cilium", &chart_path, "--namespace", "kube-system"])
        .args(&values)
        .output()
        .map_err(|e| format!("failed to run helm: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("helm template failed: {}", stderr));
    }

    let yaml_str = String::from_utf8_lossy(&output.stdout);

    let manifests: Vec<String> = yaml_str
        .split("\n---")
        .map(|doc| doc.trim())
        .filter(|doc| !doc.is_empty() && doc.contains("kind:"))
        .map(|doc| {
            if doc.starts_with("---") {
                doc.to_string()
            } else {
                format!("---\n{}", doc)
            }
        })
        .collect();

    info!(count = manifests.len(), version, "Rendered Cilium manifests");
    Ok(manifests)
}

/// Get Cilium version
pub fn cilium_version() -> &'static str {
    env!("CILIUM_VERSION")
}

/// Generate a CiliumClusterwideNetworkPolicy to allow ztunnel/ambient traffic.
///
/// This is required for Istio ambient mode when using default-deny policies.
/// The ztunnel uses link-local address 169.254.7.127 for SNAT-ed kubelet health probes.
/// See: https://istio.io/latest/docs/ambient/install/platform-prerequisites/
///
/// Key fields:
/// - enableDefaultDeny: false for both egress/ingress to not interfere with other policies
/// - endpointSelector: {} selects all pods
/// - fromCIDR: allows health probes from ztunnel's link-local address
pub fn generate_ztunnel_allowlist() -> String {
    r#"---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: allow-ambient-hostprobes
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  description: "Allows SNAT-ed kubelet health check probes into ambient pods"
  enableDefaultDeny:
    egress: false
    ingress: false
  endpointSelector: {}
  ingress:
    - fromCIDR:
        - 169.254.7.127/32
"#
    .to_string()
}

/// Generate a CiliumClusterwideNetworkPolicy for mesh-wide default-deny.
///
/// This provides L4 defense-in-depth alongside Istio's L7 AuthorizationPolicy.
/// Traffic not explicitly allowed by service-specific policies is denied.
///
/// Per Cilium docs: https://docs.cilium.io/en/latest/network/servicemesh/default-deny-ingress-policy/
/// - No ingress rules = deny all ingress
/// - Only allow DNS egress to kube-dns
/// - Exclude kube-system namespace from policy
pub fn generate_default_deny() -> String {
    r#"---
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: default-deny
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  description: "Block all ingress traffic by default, allow DNS and K8s API egress"
  endpointSelector:
    matchExpressions:
      - key: k8s:io.kubernetes.pod.namespace
        operator: NotIn
        values:
          - kube-system
          - cilium-system
          - istio-system
          - lattice-system
          - flux-system
          - cert-manager
          - capi-system
          - capi-kubeadm-bootstrap-system
          - capi-kubeadm-control-plane-system
          - rke2-bootstrap-system
          - rke2-control-plane-system
          - capd-system
          - capo-system
          - capmox-system
          - capi-ipam-in-cluster-system
  egress:
    # Allow DNS to kube-dns
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
            dns:
              - matchPattern: "*"
    # Allow access to Kubernetes API server (required for all controllers)
    - toEntities:
        - kube-apiserver
"#
    .to_string()
}

/// Generate a CiliumNetworkPolicy for the Lattice operator/agent.
///
/// This policy restricts the operator to only communicate with:
/// - DNS (kube-dns in kube-system)
/// - Kubernetes API server
/// - Parent cell (if parent_host is provided)
///
/// This follows the principle of least privilege - the agent should only
/// be able to reach what it needs for normal operation.
pub fn generate_operator_network_policy(parent_host: Option<&str>, parent_port: u16) -> String {
    let mut egress_rules = vec![
        // DNS to kube-dns
        r#"    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP"#
            .to_string(),
        // K8s API server
        r#"    - toEntities:
        - kube-apiserver"#
            .to_string(),
    ];

    // Add parent cell if specified
    if let Some(host) = parent_host {
        // Check if host is an IP address or hostname
        let is_ip = host.parse::<std::net::IpAddr>().is_ok();

        if is_ip {
            // Use toCIDR for IP addresses
            egress_rules.push(format!(
                r#"    - toCIDR:
        - {}/32
      toPorts:
        - ports:
            - port: "{}"
              protocol: TCP
            - port: "{}"
              protocol: TCP"#,
                host, DEFAULT_BOOTSTRAP_PORT, parent_port
            ));
        } else {
            // Use toFQDNs for hostnames
            egress_rules.push(format!(
                r#"    - toFQDNs:
        - matchName: {}
      toPorts:
        - ports:
            - port: "{}"
              protocol: TCP
            - port: "{}"
              protocol: TCP"#,
                host, DEFAULT_BOOTSTRAP_PORT, parent_port
            ));
        }
    }

    format!(
        r#"---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: lattice-operator
  namespace: lattice-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  endpointSelector:
    matchLabels:
      app: lattice-operator
  egress:
{egress}
  ingress:
    # Allow ingress for bootstrap webhook, gRPC, and central K8s API proxy
    - toPorts:
        - ports:
            - port: "{bootstrap_port}"
              protocol: TCP
            - port: "{grpc_port}"
              protocol: TCP
            - port: "{proxy_port}"
              protocol: TCP
"#,
        egress = egress_rules.join("\n"),
        bootstrap_port = DEFAULT_BOOTSTRAP_PORT,
        grpc_port = DEFAULT_GRPC_PORT,
        proxy_port = CENTRAL_PROXY_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cilium_manifests() {
        // Only runs if helm is available
        if let Ok(manifests) = generate_cilium_manifests(Some("docker")) {
            assert!(!manifests.is_empty());
            let combined = manifests.join("\n");
            // Check for core Cilium components
            assert!(combined.contains("kind: DaemonSet"));
            assert!(combined.contains("cilium-agent"));
        }
    }

    #[test]
    fn test_cilium_version() {
        assert_eq!(cilium_version(), env!("CILIUM_VERSION"));
    }

    #[test]
    fn test_operator_network_policy_without_parent() {
        let policy = generate_operator_network_policy(None, 50051);

        // Should be valid YAML
        assert!(policy.contains("apiVersion: cilium.io/v2"));
        assert!(policy.contains("kind: CiliumNetworkPolicy"));
        assert!(policy.contains("name: lattice-operator"));
        assert!(policy.contains("namespace: lattice-system"));

        // Should have DNS egress
        assert!(policy.contains("kube-dns"));
        assert!(policy.contains("port: \"53\""));

        // Should have API server egress
        assert!(policy.contains("kube-apiserver"));

        // Should NOT have parent rules
        assert!(!policy.contains("toFQDNs"));
        assert!(!policy.contains("toCIDR"));

        // Should have ingress for cell ports
        assert!(policy.contains("port: \"8443\""));
        assert!(policy.contains("port: \"50051\""));
    }

    #[test]
    fn test_operator_network_policy_with_parent_hostname() {
        let policy = generate_operator_network_policy(Some("cell.example.com"), 50051);

        // Should have parent FQDN rule for hostname
        assert!(policy.contains("toFQDNs"));
        assert!(policy.contains("matchName: cell.example.com"));
        // Should allow both bootstrap and gRPC ports
        assert!(policy.contains("port: \"8443\""));
        assert!(policy.contains("port: \"50051\""));

        // Should NOT use toCIDR for hostname
        assert!(!policy.contains("toCIDR"));

        // Should still have DNS and API server
        assert!(policy.contains("kube-dns"));
        assert!(policy.contains("kube-apiserver"));
    }

    #[test]
    fn test_operator_network_policy_with_parent_ip() {
        let policy = generate_operator_network_policy(Some("172.18.255.10"), 50051);

        // Should have parent CIDR rule for IP address
        assert!(policy.contains("toCIDR"));
        assert!(policy.contains("172.18.255.10/32"));
        // Should allow both bootstrap and gRPC ports
        assert!(policy.contains("port: \"8443\""));
        assert!(policy.contains("port: \"50051\""));

        // Should NOT use toFQDNs for IP
        assert!(!policy.contains("toFQDNs"));

        // Should still have DNS and API server
        assert!(policy.contains("kube-dns"));
        assert!(policy.contains("kube-apiserver"));
    }

    #[test]
    fn test_operator_network_policy_custom_port() {
        let policy = generate_operator_network_policy(Some("parent.local"), 4001);

        // Should use custom gRPC port and default bootstrap port
        assert!(policy.contains("port: \"4001\""));
        assert!(policy.contains("port: \"8443\""));
        assert!(policy.contains("matchName: parent.local"));
    }

    #[test]
    fn test_ztunnel_allowlist() {
        let policy = generate_ztunnel_allowlist();

        // Should be a CiliumClusterwideNetworkPolicy
        assert!(policy.contains("apiVersion: cilium.io/v2"));
        assert!(policy.contains("kind: CiliumClusterwideNetworkPolicy"));
        assert!(policy.contains("name: allow-ambient-hostprobes"));

        // Should allow ztunnel link-local address for health probes
        assert!(policy.contains("169.254.7.127/32"));

        // Should have enableDefaultDeny set to false (per Istio docs)
        assert!(policy.contains("enableDefaultDeny:"));
        assert!(policy.contains("egress: false"));
        assert!(policy.contains("ingress: false"));

        // Should have ingress rule
        assert!(policy.contains("ingress:"));
        assert!(policy.contains("fromCIDR:"));
    }

    #[test]
    fn test_default_deny() {
        let policy = generate_default_deny();

        // Should be a CiliumClusterwideNetworkPolicy
        assert!(policy.contains("apiVersion: cilium.io/v2"));
        assert!(policy.contains("kind: CiliumClusterwideNetworkPolicy"));
        assert!(policy.contains("name: default-deny"));

        // Should exclude system namespaces via matchExpressions
        assert!(policy.contains("matchExpressions:"));
        assert!(policy.contains("k8s:io.kubernetes.pod.namespace"));
        assert!(policy.contains("operator: NotIn"));
        assert!(policy.contains("kube-system"));
        assert!(policy.contains("cert-manager"));
        assert!(policy.contains("capi-system"));

        // Should allow DNS and K8s API egress, NO ingress (implicit deny)
        assert!(policy.contains("egress:"));
        assert!(policy.contains("k8s:k8s-app: kube-dns"));
        assert!(policy.contains("kube-apiserver")); // Allow K8s API access
        assert!(!policy.contains("ingress:")); // No ingress = deny all
        assert!(!policy.contains("fromEntities:")); // No fromEntities allow-all
    }
}
