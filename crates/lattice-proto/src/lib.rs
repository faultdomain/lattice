//! Protocol buffer definitions for Lattice agent-cell communication.
//!
//! This crate provides the gRPC service and message definitions for communication
//! between Lattice workload cluster agents and their parent cell (management cluster).
//!
//! # Architecture
//!
//! All connections are initiated **outbound** from workload clusters - cells never
//! connect directly to agents. This outbound-only architecture provides several benefits:
//!
//! - **Firewall friendly**: No inbound ports required on workload clusters
//! - **No attack surface**: Workload clusters don't expose network services
//! - **NAT traversal**: Works behind NAT without port forwarding
//!
//! # Communication Flow
//!
//! ```text
//! ┌─────────────────────────┐
//! │     Parent Cell         │
//! │  (Management Cluster)   │
//! │                         │
//! │  ┌─────────────────┐    │
//! │  │  gRPC Server    │◄───┼──── Agent connects outbound
//! │  └─────────────────┘    │
//! └─────────────────────────┘
//!            ▲
//!            │ Bidirectional stream
//!            │ (AgentMessage ↔ CellCommand)
//!            │
//! ┌──────────┴──────────────┐
//! │    Workload Cluster     │
//! │                         │
//! │  ┌─────────────────┐    │
//! │  │  Lattice Agent  │────┼──── Initiates outbound connection
//! │  └─────────────────┘    │
//! └─────────────────────────┘
//! ```
//!
//! # Key Message Types
//!
//! ## Agent to Cell (AgentMessage)
//!
//! - [`AgentReady`]: Sent when agent first connects, includes version info
//! - [`BootstrapComplete`]: Confirms CAPI providers are installed
//! - [`Heartbeat`]: Periodic health check with agent state
//! - [`ClusterHealth`]: Node counts and Kubernetes conditions
//! - [`ClusterDeleting`]: Initiates unpivot (moving resources back to parent)
//! - [`MoveObjectAck`]: Acknowledges receipt of CAPI resources during pivot
//! - [`SubtreeState`]: Reports cluster hierarchy for routing
//! - [`StatusResponse`]: Response to status request with agent state and health
//!
//! ## Cell to Agent (CellCommand)
//!
//! - [`ApplyManifestsCommand`]: Apply Kubernetes manifests on the child cluster
//! - [`StatusRequest`]: Request current cluster status from agent
//! - [`SyncDistributedResourcesCommand`]: Sync CloudProviders, SecretProviders, policies
//! - [`MoveObjectBatch`]: Batch of CAPI resources during pivot
//! - [`MoveComplete`]: Signals all resources sent, agent should unpause CAPI
//! - [`KubernetesRequest`]: Proxy Kubernetes API requests through the agent
//!
//! # Pivot Protocol
//!
//! The pivot process transfers CAPI ownership from parent to child:
//!
//! 1. Cell discovers CAPI CRDs and builds ownership graph
//! 2. Cell pauses Cluster/ClusterClass resources on source
//! 3. Cell sends [`MoveObjectBatch`] messages in topological order
//! 4. Agent creates resources and responds with [`MoveObjectAck`] (UID mappings)
//! 5. Cell sends [`MoveComplete`] with distributable resources
//! 6. Agent unpauses CAPI and becomes self-managing
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use lattice_proto::{AgentMessage, CellCommand, AgentReady, AgentState};
//!
//! // Create an agent ready message
//! let ready = AgentReady {
//!     agent_version: "0.1.0".to_string(),
//!     kubernetes_version: "1.29.0".to_string(),
//!     state: AgentState::Provisioning as i32,
//!     api_server_endpoint: "https://10.0.0.1:6443".to_string(),
//! };
//!
//! let msg = AgentMessage {
//!     cluster_name: "my-cluster".to_string(),
//!     payload: Some(agent_message::Payload::Ready(ready)),
//! };
//! ```

// Generated protobuf code doesn't have docs
#![allow(missing_docs)]

/// Generated protobuf types from agent.proto
pub mod agent {
    /// Version 1 of the agent protocol
    pub mod v1 {
        tonic::include_proto!("lattice.agent.v1");
    }
}

pub mod tracing;

pub use agent::v1::*;

/// Check if a query string indicates a streaming request.
///
/// Streaming requests include:
/// - `watch=true` or `watch=1` for K8s watch API
/// - `follow=true` or `follow=1` for streaming pod logs
///
/// # Examples
///
/// ```
/// use lattice_proto::is_watch_query;
///
/// assert!(is_watch_query("watch=true"));
/// assert!(is_watch_query("labelSelector=app&watch=true"));
/// assert!(is_watch_query("follow=true"));
/// assert!(!is_watch_query("watch=false"));
/// assert!(!is_watch_query(""));
/// ```
pub fn is_watch_query(query: &str) -> bool {
    query.contains("watch=true")
        || query.contains("watch=1")
        || query.contains("follow=true")
        || query.contains("follow=1")
}

/// Check if a path is an exec/attach/portforward request.
///
/// These requests require HTTP upgrade (SPDY/WebSocket) and bidirectional
/// streaming, which is fundamentally different from watch requests that
/// use standard HTTP chunked transfer encoding.
///
/// # Examples
///
/// ```
/// use lattice_proto::is_exec_path;
///
/// assert!(is_exec_path("/api/v1/namespaces/default/pods/nginx/exec"));
/// assert!(is_exec_path("/api/v1/namespaces/default/pods/nginx/attach"));
/// assert!(is_exec_path("/api/v1/namespaces/default/pods/nginx/portforward"));
/// assert!(!is_exec_path("/api/v1/namespaces/default/pods/nginx"));
/// assert!(!is_exec_path("/api/v1/pods"));
/// ```
pub fn is_exec_path(path: &str) -> bool {
    path.ends_with("/exec") || path.ends_with("/attach") || path.ends_with("/portforward")
}

/// SPDY stream IDs following Kubernetes conventions
pub mod stream_id {
    /// Standard input stream
    pub const STDIN: u32 = 0;
    /// Standard output stream
    pub const STDOUT: u32 = 1;
    /// Standard error stream
    pub const STDERR: u32 = 2;
    /// Error/status stream
    pub const ERROR: u32 = 3;
}

/// Parse exec request path to extract namespace, pod name, and subresource.
///
/// Returns (namespace, pod_name, subresource) where subresource is "exec", "attach", or "portforward".
pub fn parse_exec_path(path: &str) -> Option<(&str, &str, &str)> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 8 && parts[1] == "api" && parts[3] == "namespaces" && parts[5] == "pods" {
        Some((parts[4], parts[6], parts[7]))
    } else {
        None
    }
}

/// Parsed exec/attach parameters from query string.
#[derive(Debug, Default, Clone)]
pub struct ExecParams {
    /// Enable stdin
    pub stdin: bool,
    /// Enable stdout
    pub stdout: bool,
    /// Enable stderr
    pub stderr: bool,
    /// Allocate TTY
    pub tty: bool,
    /// Target container name
    pub container: Option<String>,
}

/// Parse query string to extract exec/attach parameters.
pub fn parse_exec_params(query: &str) -> ExecParams {
    let mut params = ExecParams::default();

    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "stdin" => params.stdin = value == "true" || value == "1",
                "stdout" => params.stdout = value == "true" || value == "1",
                "stderr" => params.stderr = value == "true" || value == "1",
                "tty" => params.tty = value == "true" || value == "1",
                "container" if !value.is_empty() => params.container = Some(value.to_string()),
                _ => {}
            }
        }
    }

    params
}

/// Parse query string to extract command for exec.
pub fn parse_exec_command(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .filter(|(key, _)| *key == "command")
        .map(|(_, value)| percent_decode(value))
        .collect()
}

/// Parse query string to extract port numbers for portforward.
///
/// Supports both `ports=8080` and `ports=8080,9090` formats.
///
/// # Examples
///
/// ```
/// use lattice_proto::parse_portforward_ports;
///
/// assert_eq!(parse_portforward_ports("ports=8080"), vec![8080]);
/// assert_eq!(parse_portforward_ports("ports=8080,9090"), vec![8080, 9090]);
/// assert_eq!(parse_portforward_ports("ports=8080&ports=9090"), vec![8080, 9090]);
/// assert!(parse_portforward_ports("").is_empty());
/// ```
pub fn parse_portforward_ports(query: &str) -> Vec<u16> {
    query
        .split('&')
        .filter_map(|part| part.strip_prefix("ports="))
        .flat_map(|v| v.split(','))
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// Simple percent-decoding for URL query parameters.
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_watch_query() {
        // Watch queries
        assert!(is_watch_query("watch=true"));
        assert!(is_watch_query("watch=1"));
        assert!(is_watch_query("labelSelector=app&watch=true"));
        assert!(is_watch_query("watch=true&resourceVersion=100"));
        // Follow queries (for logs)
        assert!(is_watch_query("follow=true"));
        assert!(is_watch_query("follow=1"));
        assert!(is_watch_query("container=main&follow=true"));
        // Non-streaming
        assert!(!is_watch_query("watch=false"));
        assert!(!is_watch_query("follow=false"));
        assert!(!is_watch_query("labelSelector=app"));
        assert!(!is_watch_query(""));
    }

    #[test]
    fn test_is_exec_path() {
        // Exec paths
        assert!(is_exec_path("/api/v1/namespaces/default/pods/nginx/exec"));
        assert!(is_exec_path(
            "/api/v1/namespaces/kube-system/pods/coredns-abc/exec"
        ));
        // Attach paths
        assert!(is_exec_path("/api/v1/namespaces/default/pods/nginx/attach"));
        // Portforward paths
        assert!(is_exec_path(
            "/api/v1/namespaces/default/pods/nginx/portforward"
        ));
        // Non-exec paths
        assert!(!is_exec_path("/api/v1/namespaces/default/pods/nginx"));
        assert!(!is_exec_path("/api/v1/namespaces/default/pods/nginx/log"));
        assert!(!is_exec_path(
            "/api/v1/namespaces/default/pods/nginx/status"
        ));
        assert!(!is_exec_path("/api/v1/pods"));
        assert!(!is_exec_path("/apis/apps/v1/deployments"));
        assert!(!is_exec_path("")); // Empty path
                                    // Edge cases - substring shouldn't match
        assert!(!is_exec_path("/api/v1/namespaces/default/pods/exec-pod"));
        assert!(!is_exec_path("/api/v1/namespaces/exec/pods/nginx"));
    }

    #[test]
    fn test_parse_exec_path() {
        let (ns, pod, sub) = parse_exec_path("/api/v1/namespaces/default/pods/nginx/exec").unwrap();
        assert_eq!(ns, "default");
        assert_eq!(pod, "nginx");
        assert_eq!(sub, "exec");

        let (ns, pod, sub) =
            parse_exec_path("/api/v1/namespaces/kube-system/pods/coredns-abc/attach").unwrap();
        assert_eq!(ns, "kube-system");
        assert_eq!(pod, "coredns-abc");
        assert_eq!(sub, "attach");

        assert!(parse_exec_path("/api/v1/pods").is_none());
        assert!(parse_exec_path("/apis/apps/v1/deployments").is_none());
    }

    #[test]
    fn test_parse_exec_params() {
        let params = parse_exec_params("stdin=true&stdout=true&stderr=true&tty=true");
        assert!(params.stdin);
        assert!(params.stdout);
        assert!(params.stderr);
        assert!(params.tty);

        let params = parse_exec_params("stdin=1&stdout=1&container=main");
        assert!(params.stdin);
        assert!(params.stdout);
        assert_eq!(params.container, Some("main".to_string()));

        let params = parse_exec_params("");
        assert!(!params.stdin);
        assert!(!params.stdout);
    }

    #[test]
    fn test_parse_exec_command() {
        let cmds = parse_exec_command("command=sh&command=-c&command=echo%20hello");
        assert_eq!(cmds, vec!["sh", "-c", "echo hello"]);

        let cmds = parse_exec_command("stdin=true&command=ls");
        assert_eq!(cmds, vec!["ls"]);

        assert!(parse_exec_command("").is_empty());
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("echo+hello"), "echo hello");
        assert_eq!(percent_decode("normal"), "normal");
        assert_eq!(percent_decode("%2Fbin%2Fsh"), "/bin/sh");
    }

    #[test]
    fn test_parse_portforward_ports() {
        assert_eq!(parse_portforward_ports("ports=8080"), vec![8080]);
        assert_eq!(parse_portforward_ports("ports=8080,9090"), vec![8080, 9090]);
        assert_eq!(
            parse_portforward_ports("ports=8080&ports=9090"),
            vec![8080, 9090]
        );
        assert_eq!(
            parse_portforward_ports("ports=8080,9090&foo=bar"),
            vec![8080, 9090]
        );
        assert!(parse_portforward_ports("").is_empty());
        assert!(parse_portforward_ports("foo=bar").is_empty());
        // Invalid port numbers are filtered out
        assert_eq!(
            parse_portforward_ports("ports=8080,invalid,9090"),
            vec![8080, 9090]
        );
    }
}
