//! Watch execution for K8s API proxy
//!
//! Handles streaming watch requests from the parent cell by using
//! kube-rs to watch resources and streaming events back via gRPC.

use std::sync::Arc;

use dashmap::DashMap;
use kube::api::DynamicObject;
use kube::discovery::{ApiCapabilities, ApiResource, Scope};
use kube::{Api, Client, Discovery};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use lattice_proto::{agent_message::Payload, AgentMessage, KubernetesRequest, KubernetesResponse};

/// Parsed watch query parameters
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WatchQueryParams {
    /// Label selector filter
    pub label_selector: Option<String>,
    /// Field selector filter
    pub field_selector: Option<String>,
    /// Resource version to start from
    pub resource_version: Option<String>,
}

/// Parse query string into watch parameters (pure function)
pub fn parse_watch_query(query: &str) -> WatchQueryParams {
    let mut params = WatchQueryParams::default();

    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "labelSelector" => params.label_selector = Some(value.to_string()),
                "fieldSelector" => params.field_selector = Some(value.to_string()),
                "resourceVersion" => params.resource_version = Some(value.to_string()),
                _ => {}
            }
        }
    }

    params
}

/// Build a watch event JSON response (pure function)
pub fn build_watch_event_response(
    request_id: &str,
    event_type: &str,
    object: &serde_json::Value,
) -> KubernetesResponse {
    let event_json = serde_json::json!({
        "type": event_type,
        "object": object
    });
    let body = serde_json::to_vec(&event_json).unwrap_or_default();

    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code: 200,
        body,
        content_type: "application/json".to_string(),
        streaming: true,
        stream_end: false,
        error: String::new(),
    }
}

/// Build an error response for watch failures (pure function)
pub fn build_watch_error_response(
    request_id: &str,
    status_code: u32,
    error: &str,
) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code,
        error: error.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    }
}

/// Build a stream end response (pure function)
pub fn build_stream_end_response(request_id: &str) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    }
}

/// Registry for tracking active watches on the agent
#[derive(Default)]
pub struct WatchRegistry {
    active: DashMap<String, CancellationToken>,
}

impl WatchRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            active: DashMap::new(),
        }
    }

    /// Register a watch and return its cancellation token
    pub fn register(&self, request_id: String) -> CancellationToken {
        let token = CancellationToken::new();
        debug!(request_id = %request_id, "Registering watch");
        self.active.insert(request_id, token.clone());
        token
    }

    /// Cancel an active watch
    pub fn cancel(&self, request_id: &str) -> bool {
        if let Some((_, token)) = self.active.remove(request_id) {
            info!(request_id = %request_id, "Cancelling watch");
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Unregister a watch after completion
    pub fn unregister(&self, request_id: &str) {
        self.active.remove(request_id);
    }

    /// Cancel all active watches
    pub fn cancel_all(&self) {
        let count = self.active.len();
        if count > 0 {
            info!(count = count, "Cancelling all active watches");
            for entry in self.active.iter() {
                entry.value().cancel();
            }
            self.active.clear();
        }
    }
}

/// Execute a watch request and stream events back
pub async fn execute_watch(
    client: Client,
    req: KubernetesRequest,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    registry: Arc<WatchRegistry>,
) {
    let request_id = req.request_id.clone();
    let cancel_token = registry.register(request_id.clone());

    // Parse the path to determine resource type
    let (api_resource, namespace) = match parse_api_path(&req.path) {
        Ok(parsed) => parsed,
        Err(e) => {
            send_error_response(&message_tx, &cluster_name, &request_id, 400, &e).await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Discover the API resource
    let discovery = match Discovery::new(client.clone()).run().await {
        Ok(d) => d,
        Err(e) => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                500,
                &format!("Discovery failed: {}", e),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Find the API resource in discovery
    let (ar, caps) = match find_api_resource(&discovery, &api_resource) {
        Some(found) => found,
        None => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                404,
                &format!("Resource not found: {}", api_resource),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Create the API based on scope
    let api: Api<DynamicObject> = if caps.scope == Scope::Cluster {
        Api::all_with(client.clone(), &ar)
    } else if let Some(ns) = &namespace {
        Api::namespaced_with(client.clone(), ns, &ar)
    } else {
        Api::all_with(client.clone(), &ar)
    };

    // Parse query params for watch options (pure logic)
    let query_params = parse_watch_query(&req.query);

    debug!(
        request_id = %request_id,
        resource = %api_resource,
        namespace = ?namespace,
        label_selector = ?query_params.label_selector,
        field_selector = ?query_params.field_selector,
        "Starting watch"
    );

    // Use kube-rs watcher
    use futures::StreamExt;
    use kube::runtime::{watcher, WatchStreamExt};

    // Build watcher config with selectors
    let mut watcher_config = watcher::Config::default().any_semantic();
    if let Some(labels) = &query_params.label_selector {
        watcher_config = watcher_config.labels(labels);
    }
    if let Some(fields) = &query_params.field_selector {
        watcher_config = watcher_config.fields(fields);
    }

    let watcher = watcher(api, watcher_config)
        .default_backoff()
        .applied_objects();

    tokio::pin!(watcher);

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!(request_id = %request_id, "Watch cancelled");
                send_stream_end(&message_tx, &cluster_name, &request_id).await;
                break;
            }
            event = watcher.next() => {
                match event {
                    Some(Ok(obj)) => {
                        // Convert to watch event format (pure logic)
                        let obj_json = serde_json::to_value(&obj).unwrap_or_default();
                        let response = build_watch_event_response(&request_id, "ADDED", &obj_json);

                        if send_response(&message_tx, &cluster_name, response).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!(request_id = %request_id, error = %e, "Watch error");
                        send_error_response(
                            &message_tx,
                            &cluster_name,
                            &request_id,
                            500,
                            &e.to_string(),
                        ).await;
                        break;
                    }
                    None => {
                        // Stream ended
                        send_stream_end(&message_tx, &cluster_name, &request_id).await;
                        break;
                    }
                }
            }
        }
    }

    registry.unregister(&request_id);
}

/// Parse an API path to extract resource type and namespace
fn parse_api_path(path: &str) -> Result<(String, Option<String>), String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Handle different path formats:
    // /api/v1/pods -> core pods
    // /api/v1/namespaces/default/pods -> namespaced pods
    // /apis/apps/v1/deployments -> apps deployments
    // /apis/apps/v1/namespaces/default/deployments -> namespaced deployments

    if parts.is_empty() {
        return Err("Empty path".to_string());
    }

    let (resource, namespace) = if parts[0] == "api" {
        // Core API
        if parts.len() >= 4 && parts[2] == "namespaces" {
            // /api/v1/namespaces/{ns}/{resource}
            let ns = parts[3].to_string();
            let resource = parts.get(4).unwrap_or(&"").to_string();
            (resource, Some(ns))
        } else if parts.len() >= 3 {
            // /api/v1/{resource}
            (parts[2].to_string(), None)
        } else {
            return Err("Invalid core API path".to_string());
        }
    } else if parts[0] == "apis" {
        // Extended APIs
        if parts.len() >= 5 && parts[3] == "namespaces" {
            // /apis/{group}/{version}/namespaces/{ns}/{resource}
            let ns = parts[4].to_string();
            let resource = parts.get(5).unwrap_or(&"").to_string();
            (resource, Some(ns))
        } else if parts.len() >= 4 {
            // /apis/{group}/{version}/{resource}
            (parts[3].to_string(), None)
        } else {
            return Err("Invalid extended API path".to_string());
        }
    } else {
        return Err(format!("Unknown API prefix: {}", parts[0]));
    };

    if resource.is_empty() {
        return Err("Could not determine resource type".to_string());
    }

    Ok((resource, namespace))
}

/// Find an API resource in discovery results
fn find_api_resource(
    discovery: &Discovery,
    resource_name: &str,
) -> Option<(ApiResource, ApiCapabilities)> {
    for group in discovery.groups() {
        for (ar, caps) in group.recommended_resources() {
            if ar.plural == resource_name || ar.kind.to_lowercase() == resource_name.to_lowercase()
            {
                return Some((ar, caps));
            }
        }
    }
    None
}

async fn send_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    response: KubernetesResponse,
) -> Result<(), ()> {
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::KubernetesResponse(response)),
    };
    tx.send(msg).await.map_err(|_| ())
}

async fn send_error_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    status_code: u32,
    error: &str,
) {
    let response = build_watch_error_response(request_id, status_code, error);
    let _ = send_response(tx, cluster_name, response).await;
}

async fn send_stream_end(tx: &mpsc::Sender<AgentMessage>, cluster_name: &str, request_id: &str) {
    let response = build_stream_end_response(request_id);
    let _ = send_response(tx, cluster_name, response).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_path_core_cluster_scoped() {
        let (resource, ns) = parse_api_path("/api/v1/nodes").unwrap();
        assert_eq!(resource, "nodes");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_core_namespaced() {
        let (resource, ns) = parse_api_path("/api/v1/namespaces/default/pods").unwrap();
        assert_eq!(resource, "pods");
        assert_eq!(ns, Some("default".to_string()));
    }

    #[test]
    fn test_parse_api_path_extended_cluster_scoped() {
        let (resource, ns) = parse_api_path("/apis/apps/v1/deployments").unwrap();
        assert_eq!(resource, "deployments");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_extended_namespaced() {
        let (resource, ns) =
            parse_api_path("/apis/apps/v1/namespaces/kube-system/deployments").unwrap();
        assert_eq!(resource, "deployments");
        assert_eq!(ns, Some("kube-system".to_string()));
    }

    #[test]
    fn test_parse_api_path_invalid() {
        assert!(parse_api_path("").is_err());
        assert!(parse_api_path("/unknown/v1/pods").is_err());
    }

    #[test]
    fn test_watch_registry() {
        let registry = WatchRegistry::new();

        let token = registry.register("watch-1".to_string());
        assert!(!token.is_cancelled());

        registry.cancel("watch-1");
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_watch_registry_cancel_all() {
        let registry = WatchRegistry::new();

        let t1 = registry.register("w1".to_string());
        let t2 = registry.register("w2".to_string());

        registry.cancel_all();

        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }

    #[test]
    fn test_watch_registry_cancel_nonexistent() {
        let registry = WatchRegistry::new();
        // Should return false when cancelling non-existent watch
        assert!(!registry.cancel("nonexistent"));
    }

    #[test]
    fn test_watch_registry_unregister() {
        let registry = WatchRegistry::new();
        let token = registry.register("watch-1".to_string());

        // Unregister should remove without cancelling
        registry.unregister("watch-1");

        // Token should NOT be cancelled by unregister
        assert!(!token.is_cancelled());

        // But now cancel should return false since it's gone
        assert!(!registry.cancel("watch-1"));
    }

    #[test]
    fn test_watch_registry_cancel_all_empty() {
        let registry = WatchRegistry::new();
        // Should not panic on empty registry
        registry.cancel_all();
    }

    #[test]
    fn test_watch_registry_multiple_operations() {
        let registry = WatchRegistry::new();

        let t1 = registry.register("w1".to_string());
        let _t2 = registry.register("w2".to_string());
        let t3 = registry.register("w3".to_string());

        // Cancel one
        assert!(registry.cancel("w2"));

        // Unregister another
        registry.unregister("w3");

        // Cancel all remaining
        registry.cancel_all();

        assert!(t1.is_cancelled());
        // t3 was unregistered, so it won't be cancelled by cancel_all
        assert!(!t3.is_cancelled());
    }

    // =========================================================================
    // Parse API Path Edge Cases
    // =========================================================================

    #[test]
    fn test_parse_api_path_pods_all_namespaces() {
        let (resource, ns) = parse_api_path("/api/v1/pods").unwrap();
        assert_eq!(resource, "pods");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_configmaps() {
        let (resource, ns) = parse_api_path("/api/v1/namespaces/kube-system/configmaps").unwrap();
        assert_eq!(resource, "configmaps");
        assert_eq!(ns, Some("kube-system".to_string()));
    }

    #[test]
    fn test_parse_api_path_statefulsets() {
        let (resource, ns) =
            parse_api_path("/apis/apps/v1/namespaces/default/statefulsets").unwrap();
        assert_eq!(resource, "statefulsets");
        assert_eq!(ns, Some("default".to_string()));
    }

    #[test]
    fn test_parse_api_path_crds() {
        let (resource, ns) =
            parse_api_path("/apis/apiextensions.k8s.io/v1/customresourcedefinitions").unwrap();
        assert_eq!(resource, "customresourcedefinitions");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_lattice_cluster() {
        let (resource, ns) =
            parse_api_path("/apis/lattice.dev/v1alpha1/latticeclusters").unwrap();
        assert_eq!(resource, "latticeclusters");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_namespaced_crd() {
        let (resource, ns) =
            parse_api_path("/apis/lattice.dev/v1alpha1/namespaces/prod/latticeservices").unwrap();
        assert_eq!(resource, "latticeservices");
        assert_eq!(ns, Some("prod".to_string()));
    }

    #[test]
    fn test_parse_api_path_short_api() {
        // /api/v1 is too short - no resource
        let result = parse_api_path("/api/v1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_api_path_short_apis() {
        // /apis/group/v1 is too short - no resource
        let result = parse_api_path("/apis/apps/v1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_api_path_events() {
        let (resource, ns) = parse_api_path("/api/v1/namespaces/default/events").unwrap();
        assert_eq!(resource, "events");
        assert_eq!(ns, Some("default".to_string()));
    }

    #[test]
    fn test_parse_api_path_services() {
        let (resource, ns) = parse_api_path("/api/v1/services").unwrap();
        assert_eq!(resource, "services");
        assert!(ns.is_none());
    }

    #[test]
    fn test_parse_api_path_leading_slash_stripped() {
        let (resource, _) = parse_api_path("api/v1/pods").unwrap();
        assert_eq!(resource, "pods");
    }

    // =========================================================================
    // parse_watch_query Tests
    // =========================================================================

    #[test]
    fn test_parse_watch_query_empty() {
        let params = parse_watch_query("");
        assert_eq!(params, WatchQueryParams::default());
    }

    #[test]
    fn test_parse_watch_query_label_selector() {
        let params = parse_watch_query("labelSelector=app%3Dtest");
        assert_eq!(params.label_selector, Some("app%3Dtest".to_string()));
        assert_eq!(params.field_selector, None);
        assert_eq!(params.resource_version, None);
    }

    #[test]
    fn test_parse_watch_query_field_selector() {
        let params = parse_watch_query("fieldSelector=status.phase%3DRunning");
        assert_eq!(params.label_selector, None);
        assert_eq!(params.field_selector, Some("status.phase%3DRunning".to_string()));
        assert_eq!(params.resource_version, None);
    }

    #[test]
    fn test_parse_watch_query_resource_version() {
        let params = parse_watch_query("resourceVersion=12345");
        assert_eq!(params.resource_version, Some("12345".to_string()));
    }

    #[test]
    fn test_parse_watch_query_multiple() {
        let params = parse_watch_query("watch=true&labelSelector=app%3Dtest&resourceVersion=100");
        assert_eq!(params.label_selector, Some("app%3Dtest".to_string()));
        assert_eq!(params.resource_version, Some("100".to_string()));
    }

    #[test]
    fn test_parse_watch_query_all_params() {
        let params = parse_watch_query(
            "labelSelector=app%3Dtest&fieldSelector=status.phase%3DRunning&resourceVersion=999"
        );
        assert_eq!(params.label_selector, Some("app%3Dtest".to_string()));
        assert_eq!(params.field_selector, Some("status.phase%3DRunning".to_string()));
        assert_eq!(params.resource_version, Some("999".to_string()));
    }

    #[test]
    fn test_parse_watch_query_ignores_unknown() {
        let params = parse_watch_query("unknown=value&labelSelector=app");
        assert_eq!(params.label_selector, Some("app".to_string()));
        assert_eq!(params.field_selector, None);
    }

    // =========================================================================
    // build_watch_event_response Tests
    // =========================================================================

    #[test]
    fn test_build_watch_event_response() {
        let obj = serde_json::json!({"kind": "Pod", "metadata": {"name": "test"}});
        let resp = build_watch_event_response("req-123", "ADDED", &obj);

        assert_eq!(resp.request_id, "req-123");
        assert_eq!(resp.status_code, 200);
        assert!(resp.streaming);
        assert!(!resp.stream_end);
        assert_eq!(resp.content_type, "application/json");

        // Verify the body structure
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["type"], "ADDED");
        assert_eq!(body["object"]["kind"], "Pod");
    }

    #[test]
    fn test_build_watch_event_response_modified() {
        let obj = serde_json::json!({"kind": "Deployment"});
        let resp = build_watch_event_response("req-456", "MODIFIED", &obj);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["type"], "MODIFIED");
    }

    #[test]
    fn test_build_watch_event_response_deleted() {
        let obj = serde_json::json!({"kind": "Service"});
        let resp = build_watch_event_response("req-789", "DELETED", &obj);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["type"], "DELETED");
    }

    // =========================================================================
    // build_watch_error_response Tests
    // =========================================================================

    #[test]
    fn test_build_watch_error_response() {
        let resp = build_watch_error_response("req-err", 500, "Internal error");

        assert_eq!(resp.request_id, "req-err");
        assert_eq!(resp.status_code, 500);
        assert_eq!(resp.error, "Internal error");
        assert!(resp.streaming);
        assert!(resp.stream_end);
    }

    #[test]
    fn test_build_watch_error_response_not_found() {
        let resp = build_watch_error_response("req-404", 404, "Resource not found");

        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.error, "Resource not found");
    }

    // =========================================================================
    // build_stream_end_response Tests
    // =========================================================================

    #[test]
    fn test_build_stream_end_response() {
        let resp = build_stream_end_response("req-end");

        assert_eq!(resp.request_id, "req-end");
        assert!(resp.streaming);
        assert!(resp.stream_end);
        assert_eq!(resp.status_code, 0);
        assert!(resp.error.is_empty());
    }

    // =========================================================================
    // WatchQueryParams Tests
    // =========================================================================

    #[test]
    fn test_watch_query_params_default() {
        let params = WatchQueryParams::default();
        assert!(params.label_selector.is_none());
        assert!(params.field_selector.is_none());
        assert!(params.resource_version.is_none());
    }
}
