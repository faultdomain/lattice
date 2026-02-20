//! Path utilities for K8s API proxy
//!
//! Single source of truth for path manipulation functions used across
//! the proxy, router, and exec handlers.

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
}
