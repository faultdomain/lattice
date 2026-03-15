//! GPU stack manifest generation
//!
//! Embeds pre-rendered NVIDIA GPU Operator manifests from build time.
//! GPU scheduling uses Volcano's native vGPU device plugin (deployed alongside Volcano).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::crd::{LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget};
use lattice_common::LABEL_NAME;

use super::{kube_apiserver_egress, lmm, namespace_yaml_ambient, split_yaml_documents};

/// Pre-rendered GPU stack manifests (GPU Operator) with namespaces.
static GPU_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = Vec::new();

    // GPU Operator
    manifests.push(namespace_yaml_ambient("gpu-operator"));
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gpu-operator.yaml"
    ))));

    manifests
});

/// NVIDIA GPU Operator version (pinned at build time)
pub fn gpu_operator_version() -> &'static str {
    env!("GPU_OPERATOR_VERSION")
}

/// Generate GPU stack manifests (GPU Operator)
///
/// Returns pre-rendered manifests embedded at build time.
/// The Volcano vGPU device plugin is deployed as part of the Volcano stack,
/// not here, since it's a Volcano scheduler component.
pub fn generate_gpu_stack() -> &'static [String] {
    &GPU_MANIFESTS
}

/// Generate LatticeMeshMembers for GPU Operator components.
///
/// - **gpu-operator**: main operator pod, egress-only (K8s API for CRD reconciliation)
///
/// NFD master, GC, and worker DaemonSets are internal to the operator and run
/// in kube-system (already excluded from mesh policies).
pub fn generate_gpu_mesh_members() -> Vec<LatticeMeshMember> {
    vec![lmm(
        "gpu-operator",
        "gpu-operator",
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "gpu-operator".to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("gpu-operator".to_string()),
            depends_all: false,
            ambient: true,
        },
    )]
}

/// Generate DaemonSet YAML for lattice-gpu-monitor.
///
/// Creates a DaemonSet that runs on GPU nodes, scraping DCGM metrics and
/// annotating nodes with GPU health status for the cluster controller.
///
/// Includes:
/// - DaemonSet with GPU node selector
/// - ServiceAccount + ClusterRole + ClusterRoleBinding
/// - NODE_NAME env from Downward API
pub fn generate_gpu_monitor_daemonset(image: &str) -> Vec<String> {
    let mut rbac = super::split_yaml_documents(include_str!("../../manifests/gpu-monitor-sa.yaml"));
    rbac.extend(super::split_yaml_documents(include_str!(
        "../../manifests/gpu-monitor-rbac.yaml"
    )));

    let daemonset = format!(
        r#"apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: lattice-gpu-monitor
  namespace: lattice-system
  labels:
    app.kubernetes.io/name: lattice-gpu-monitor
    app.kubernetes.io/component: gpu-monitor
    app.kubernetes.io/managed-by: lattice
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: lattice-gpu-monitor
  template:
    metadata:
      labels:
        app.kubernetes.io/name: lattice-gpu-monitor
        app.kubernetes.io/component: gpu-monitor
    spec:
      serviceAccountName: lattice-gpu-monitor
      nodeSelector:
        nvidia.com/gpu.present: "true"
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      initContainers:
      - name: init-checkpoint-dir
        image: busybox:1.37
        command: ["sh", "-c", "chown 65534:65534 /var/lib/lattice/gpu-monitor"]
        volumeMounts:
        - name: checkpoint
          mountPath: /var/lib/lattice/gpu-monitor
        securityContext:
          runAsUser: 0
      containers:
      - name: gpu-monitor
        image: {image}
        command: ["lattice-daemonset", "monitor", "--mode", "gpu"]
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        ports:
        - name: health
          containerPort: 8080
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /healthz
            port: health
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: health
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 200m
            memory: 256Mi
        securityContext:
          runAsUser: 65534
        volumeMounts:
        - name: checkpoint
          mountPath: /var/lib/lattice/gpu-monitor
      volumes:
      - name: checkpoint
        hostPath:
          path: /var/lib/lattice/gpu-monitor
          type: DirectoryOrCreate"#
    );

    rbac.push(daemonset);
    rbac
}

/// Generate LatticeMeshMember for the GPU monitor DaemonSet.
pub fn generate_gpu_monitor_mesh_member() -> LatticeMeshMember {
    lmm(
        "lattice-gpu-monitor",
        lattice_common::LATTICE_SYSTEM_NAMESPACE,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "lattice-gpu-monitor".to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![kube_apiserver_egress()],
            allow_peer_traffic: false,
            ingress: None,
            service_account: Some("lattice-gpu-monitor".to_string()),
            depends_all: false,
            ambient: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_operator_version_is_set() {
        let version = gpu_operator_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn gpu_namespace_is_correct() {
        let ns = namespace_yaml_ambient("gpu-operator");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: gpu-operator"));
        assert!(
            ns.contains("istio.io/dataplane-mode: ambient"),
            "GPU namespace must be enrolled in ambient mesh"
        );
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_gpu_stack();
        assert!(!manifests.is_empty());
    }

    #[test]
    fn gpu_monitor_daemonset_generated() {
        let manifests = generate_gpu_monitor_daemonset("ghcr.io/test/lattice:latest");
        assert_eq!(
            manifests.len(),
            4,
            "should have SA + ClusterRole + CRB + DaemonSet"
        );
        assert!(manifests[0].contains("ServiceAccount"));
        assert!(manifests[1].contains("ClusterRole"));
        assert!(manifests[2].contains("ClusterRoleBinding"));
        assert!(manifests[3].contains("DaemonSet"));
        assert!(manifests[3].contains("nvidia.com/gpu.present"));
        assert!(manifests[3].contains("NODE_NAME"));
        assert!(manifests[3].contains("lattice-daemonset"));
    }

    #[test]
    fn gpu_monitor_mesh_member_generated() {
        let member = generate_gpu_monitor_mesh_member();
        assert_eq!(member.metadata.name.as_deref(), Some("lattice-gpu-monitor"));
        assert_eq!(member.metadata.namespace.as_deref(), Some("lattice-system"));
        assert!(member.spec.ambient);
        assert!(member.spec.ports.is_empty(), "gpu-monitor is egress-only");
    }

    #[test]
    fn gpu_mesh_members_generated() {
        let members = generate_gpu_mesh_members();
        assert_eq!(members.len(), 1, "should have gpu-operator only");

        let op = &members[0];
        assert_eq!(op.metadata.name.as_deref(), Some("gpu-operator"));
        assert_eq!(op.metadata.namespace.as_deref(), Some("gpu-operator"));
        assert!(op.spec.validate().is_ok());
        assert!(op.spec.ambient, "gpu-operator should be ambient");
        assert!(op.spec.ports.is_empty(), "gpu-operator is egress-only");
        assert_eq!(op.spec.service_account.as_deref(), Some("gpu-operator"));
    }
}
