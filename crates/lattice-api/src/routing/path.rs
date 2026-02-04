//! Path utilities for K8s API proxy
//!
//! Single source of truth for path manipulation functions used across
//! the proxy, router, and exec handlers.

use axum::http::Method;

/// Strip /clusters/{cluster_name} prefix from a path to get the K8s API path.
///
/// # Examples
///
/// ```
/// use lattice_api::routing::strip_cluster_prefix;
///
/// assert_eq!(
///     strip_cluster_prefix("/clusters/my-cluster/api/v1/pods", "my-cluster"),
///     "/api/v1/pods"
/// );
/// ```
pub fn strip_cluster_prefix<'a>(full_path: &'a str, cluster_name: &str) -> &'a str {
    let prefix = format!("/clusters/{}", cluster_name);
    full_path.strip_prefix(&prefix).unwrap_or(full_path)
}

/// Extract cluster name from a path that starts with /clusters/{name}/...
///
/// # Examples
///
/// ```
/// use lattice_api::routing::extract_cluster_from_path;
///
/// assert_eq!(
///     extract_cluster_from_path("/clusters/my-cluster/api/v1/pods"),
///     Some("my-cluster")
/// );
/// assert_eq!(extract_cluster_from_path("/api/v1/pods"), None);
/// ```
pub fn extract_cluster_from_path(path: &str) -> Option<&str> {
    let path = path.strip_prefix("/clusters/")?;
    let cluster = path.split('/').next()?;
    if cluster.is_empty() {
        None
    } else {
        Some(cluster)
    }
}

/// Map HTTP method to Kubernetes verb for authorization.
///
/// # Examples
///
/// ```
/// use axum::http::Method;
/// use lattice_api::routing::method_to_k8s_verb;
///
/// assert_eq!(method_to_k8s_verb(&Method::GET), "get");
/// assert_eq!(method_to_k8s_verb(&Method::POST), "create");
/// ```
pub fn method_to_k8s_verb(method: &Method) -> &'static str {
    match *method {
        Method::GET => "get", // Could also be "list" or "watch" depending on path
        Method::POST => "create",
        Method::PUT => "update",
        Method::PATCH => "patch",
        Method::DELETE => "delete",
        Method::HEAD => "get",
        Method::OPTIONS => "get",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_cluster_prefix() {
        assert_eq!(
            strip_cluster_prefix("/clusters/my-cluster/api/v1/pods", "my-cluster"),
            "/api/v1/pods"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_apis() {
        assert_eq!(
            strip_cluster_prefix("/clusters/e2e-mgmt/apis/apps/v1/deployments", "e2e-mgmt"),
            "/apis/apps/v1/deployments"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_exec() {
        assert_eq!(
            strip_cluster_prefix(
                "/clusters/workload-1/api/v1/namespaces/default/pods/nginx/exec",
                "workload-1"
            ),
            "/api/v1/namespaces/default/pods/nginx/exec"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_no_match() {
        assert_eq!(
            strip_cluster_prefix("/api/v1/pods", "my-cluster"),
            "/api/v1/pods"
        );
    }

    #[test]
    fn test_strip_cluster_prefix_root_path() {
        assert_eq!(
            strip_cluster_prefix("/clusters/test-cluster", "test-cluster"),
            ""
        );
    }

    #[test]
    fn test_extract_cluster_from_path() {
        assert_eq!(
            extract_cluster_from_path("/clusters/my-cluster/api/v1/pods"),
            Some("my-cluster")
        );
    }

    #[test]
    fn test_extract_cluster_from_path_exec() {
        assert_eq!(
            extract_cluster_from_path(
                "/clusters/workload-1/api/v1/namespaces/default/pods/nginx/exec"
            ),
            Some("workload-1")
        );
    }

    #[test]
    fn test_extract_cluster_from_path_no_prefix() {
        assert_eq!(extract_cluster_from_path("/api/v1/pods"), None);
    }

    #[test]
    fn test_extract_cluster_from_path_incomplete() {
        assert_eq!(extract_cluster_from_path("/clusters/"), None);
    }

    #[test]
    fn test_method_to_k8s_verb() {
        assert_eq!(method_to_k8s_verb(&Method::GET), "get");
        assert_eq!(method_to_k8s_verb(&Method::POST), "create");
        assert_eq!(method_to_k8s_verb(&Method::PUT), "update");
        assert_eq!(method_to_k8s_verb(&Method::PATCH), "patch");
        assert_eq!(method_to_k8s_verb(&Method::DELETE), "delete");
        assert_eq!(method_to_k8s_verb(&Method::HEAD), "get");
        assert_eq!(method_to_k8s_verb(&Method::OPTIONS), "get");
    }
}
