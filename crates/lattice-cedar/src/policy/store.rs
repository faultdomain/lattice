//! Cedar policy store
//!
//! Concurrent policy storage using DashMap for fast, lock-free reads.

use std::sync::Arc;

use cedar_policy::PolicySet;
use dashmap::DashMap;
use tracing::{debug, info};

use super::PolicyCompiler;
use crate::error::{CedarError, Result};

/// Key for policy lookup: (namespace, service_name)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    /// Service namespace
    pub namespace: String,
    /// Service name
    pub name: String,
}

impl PolicyKey {
    /// Create a new policy key
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for PolicyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// Cached policy entry with metadata
#[derive(Debug, Clone)]
pub struct PolicyEntry {
    /// Compiled policy set
    pub policy_set: Arc<PolicySet>,
    /// Original policy text (for debugging/display)
    #[allow(dead_code)]
    pub source: String,
    /// Resource version for change detection
    pub resource_version: String,
}

/// Concurrent policy store backed by DashMap
///
/// Provides thread-safe access to compiled Cedar policies with:
/// - Lock-free reads for high-throughput authorization checks
/// - Atomic updates when policies change
/// - Resource version tracking to avoid unnecessary recompilation
#[derive(Debug)]
pub struct PolicyStore {
    /// Compiled policies keyed by (namespace, service)
    policies: DashMap<PolicyKey, PolicyEntry>,
    /// Policy compiler
    compiler: PolicyCompiler,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStore {
    /// Create a new empty policy store
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
            compiler: PolicyCompiler::new(),
        }
    }

    /// Create a policy store with a custom compiler
    pub fn with_compiler(compiler: PolicyCompiler) -> Self {
        Self {
            policies: DashMap::new(),
            compiler,
        }
    }

    /// Get a policy for a service
    ///
    /// Returns None if no policy is configured for the service.
    pub fn get(&self, namespace: &str, name: &str) -> Option<Arc<PolicySet>> {
        let key = PolicyKey::new(namespace, name);
        self.policies
            .get(&key)
            .map(|entry| entry.policy_set.clone())
    }

    /// Check if a policy exists for a service
    pub fn contains(&self, namespace: &str, name: &str) -> bool {
        let key = PolicyKey::new(namespace, name);
        self.policies.contains_key(&key)
    }

    /// Update or insert a policy for a service
    ///
    /// Compiles the policy text and stores it. Returns an error if compilation fails.
    /// Skips update if the resource version hasn't changed.
    pub fn upsert(
        &self,
        namespace: &str,
        name: &str,
        policy_text: &str,
        resource_version: &str,
    ) -> Result<()> {
        let key = PolicyKey::new(namespace, name);

        // Check if we already have this version
        if let Some(existing) = self.policies.get(&key) {
            if existing.resource_version == resource_version {
                debug!(
                    namespace = %namespace,
                    service = %name,
                    version = %resource_version,
                    "Policy unchanged, skipping compilation"
                );
                return Ok(());
            }
        }

        // Compile the policy
        let service_key = format!("{}/{}", namespace, name);
        let policy_set = self.compiler.compile(&service_key, policy_text)?;

        // Store the compiled policy
        let entry = PolicyEntry {
            policy_set: Arc::new(policy_set),
            source: policy_text.to_string(),
            resource_version: resource_version.to_string(),
        };

        self.policies.insert(key, entry);

        info!(
            namespace = %namespace,
            service = %name,
            version = %resource_version,
            "Policy updated"
        );

        Ok(())
    }

    /// Remove a policy for a service
    pub fn remove(&self, namespace: &str, name: &str) -> bool {
        let key = PolicyKey::new(namespace, name);
        let removed = self.policies.remove(&key).is_some();

        if removed {
            info!(
                namespace = %namespace,
                service = %name,
                "Policy removed"
            );
        }

        removed
    }

    /// Get the number of stored policies
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Clear all policies
    pub fn clear(&self) {
        self.policies.clear();
        info!("Policy store cleared");
    }

    /// Evaluate a request against a service's policy
    ///
    /// Returns Ok(true) if the request is allowed, Ok(false) if denied.
    /// Returns an error if the service has no policy configured.
    pub fn evaluate(
        &self,
        namespace: &str,
        name: &str,
        request: &cedar_policy::Request,
        entities: &cedar_policy::Entities,
    ) -> Result<cedar_policy::Response> {
        let policy_set = self
            .get(namespace, name)
            .ok_or_else(|| CedarError::service_not_found(namespace, name))?;

        let authorizer = cedar_policy::Authorizer::new();
        let response = authorizer.is_authorized(request, &policy_set, entities);

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_operations() {
        let store = PolicyStore::new();

        // Initially empty
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        // Add a policy
        let policy = r#"permit(principal, action, resource);"#;
        store.upsert("default", "api", policy, "v1").unwrap();

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.contains("default", "api"));
        assert!(!store.contains("default", "other"));

        // Get the policy
        let retrieved = store.get("default", "api");
        assert!(retrieved.is_some());

        // Remove the policy
        assert!(store.remove("default", "api"));
        assert!(!store.contains("default", "api"));
        assert!(store.is_empty());

        // Remove non-existent policy
        assert!(!store.remove("default", "api"));
    }

    #[test]
    fn test_resource_version_skips_recompilation() {
        let store = PolicyStore::new();

        let policy = r#"permit(principal, action, resource);"#;

        // First insert
        store.upsert("default", "api", policy, "v1").unwrap();

        // Same version - should skip
        store.upsert("default", "api", policy, "v1").unwrap();

        // Different version - should update
        let new_policy = r#"forbid(principal, action, resource);"#;
        store.upsert("default", "api", new_policy, "v2").unwrap();

        // Verify the policy was updated
        assert!(store.contains("default", "api"));
    }

    #[test]
    fn test_invalid_policy_returns_error() {
        let store = PolicyStore::new();

        let result = store.upsert("default", "api", "invalid cedar", "v1");
        assert!(result.is_err());

        // Store should not contain the failed policy
        assert!(!store.contains("default", "api"));
    }

    #[test]
    fn test_clear() {
        let store = PolicyStore::new();

        let policy = r#"permit(principal, action, resource);"#;
        store.upsert("ns1", "svc1", policy, "v1").unwrap();
        store.upsert("ns2", "svc2", policy, "v1").unwrap();

        assert_eq!(store.len(), 2);

        store.clear();

        assert!(store.is_empty());
    }

    #[test]
    fn test_policy_key_display() {
        let key = PolicyKey::new("default", "api-server");
        assert_eq!(key.to_string(), "default/api-server");
    }
}
