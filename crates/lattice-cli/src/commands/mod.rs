//! CLI commands

pub mod install;
pub mod uninstall;

/// Kind cluster config with Docker socket mount for CAPD (Cluster API Provider Docker)
pub const KIND_CONFIG_WITH_DOCKER: &str = r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /var/run/docker.sock
    containerPath: /var/run/docker.sock
"#;
