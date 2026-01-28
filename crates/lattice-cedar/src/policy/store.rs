//! Cedar policy store
//!
//! Concurrent policy storage using DashMap for fast, lock-free reads.
//!
//! ## Two-Tier Policy Model
//!
//! The store supports two types of policies:
//! 1. **Service policies** - embedded in LatticeService.authorization (inline, service-specific)
//! 2. **Inherited policies** - from LatticeServicePolicy via label selectors
//!
//! ## Evaluation Order
//!
//! 1. All matching inherited policy `forbid` rules -> if ANY matches, DENY
//! 2. Service-embedded policy -> if permit matches, ALLOW
//! 3. All matching inherited policy `permit` rules -> if ANY matches, ALLOW
//! 4. Default: DENY

use std::sync::Arc;

use cedar_policy::{Decision, PolicySet};
use dashmap::DashMap;
use tracing::{debug, info, trace};

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

/// Entry for an inherited (selector-based) policy
#[derive(Debug, Clone)]
pub struct InheritedPolicyEntry {
    /// Compiled policy set
    pub policy_set: Arc<PolicySet>,
    /// Original policy text
    #[allow(dead_code)]
    pub source: String,
    /// Resource version
    pub resource_version: String,
    /// Priority for evaluation ordering (higher = first)
    pub priority: i32,
}

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed
    Allow,
    /// Request is denied
    Deny,
    /// No policy matched (default deny applies)
    NoMatch,
}

/// Concurrent policy store backed by DashMap
///
/// Provides thread-safe access to compiled Cedar policies with:
/// - Lock-free reads for high-throughput authorization checks
/// - Atomic updates when policies change
/// - Resource version tracking to avoid unnecessary recompilation
/// - Two-tier policy model with inherited policies
#[derive(Debug)]
pub struct PolicyStore {
    /// Service-embedded policies keyed by (namespace, service)
    service_policies: DashMap<PolicyKey, PolicyEntry>,

    /// Inherited (selector-based) policies by name (namespace/name)
    inherited_policies: DashMap<String, InheritedPolicyEntry>,

    /// Mapping of (namespace, service) -> list of matching inherited policy names
    /// Sorted by priority (highest first), then alphabetically
    policy_matches: DashMap<PolicyKey, Vec<String>>,

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
            service_policies: DashMap::new(),
            inherited_policies: DashMap::new(),
            policy_matches: DashMap::new(),
            compiler: PolicyCompiler::new(),
        }
    }

    /// Create a policy store with a custom compiler
    pub fn with_compiler(compiler: PolicyCompiler) -> Self {
        Self {
            service_policies: DashMap::new(),
            inherited_policies: DashMap::new(),
            policy_matches: DashMap::new(),
            compiler,
        }
    }

    // =========================================================================
    // Service Policy Operations (original API)
    // =========================================================================

    /// Get a service-embedded policy
    ///
    /// Returns None if no policy is configured for the service.
    pub fn get(&self, namespace: &str, name: &str) -> Option<Arc<PolicySet>> {
        let key = PolicyKey::new(namespace, name);
        self.service_policies
            .get(&key)
            .map(|entry| entry.policy_set.clone())
    }

    /// Check if a service-embedded policy exists
    pub fn contains(&self, namespace: &str, name: &str) -> bool {
        let key = PolicyKey::new(namespace, name);
        self.service_policies.contains_key(&key)
    }

    /// Update or insert a service-embedded policy
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
        if let Some(existing) = self.service_policies.get(&key) {
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

        self.service_policies.insert(key, entry);

        info!(
            namespace = %namespace,
            service = %name,
            version = %resource_version,
            "Service policy updated"
        );

        Ok(())
    }

    /// Remove a service-embedded policy
    pub fn remove(&self, namespace: &str, name: &str) -> bool {
        let key = PolicyKey::new(namespace, name);
        let removed = self.service_policies.remove(&key).is_some();

        if removed {
            info!(
                namespace = %namespace,
                service = %name,
                "Service policy removed"
            );
        }

        removed
    }

    /// Get the number of service-embedded policies
    pub fn len(&self) -> usize {
        self.service_policies.len()
    }

    /// Check if the store has no service-embedded policies
    pub fn is_empty(&self) -> bool {
        self.service_policies.is_empty()
    }

    /// Clear all policies (service and inherited)
    pub fn clear(&self) {
        self.service_policies.clear();
        self.inherited_policies.clear();
        self.policy_matches.clear();
        info!("Policy store cleared");
    }

    // =========================================================================
    // Inherited Policy Operations
    // =========================================================================

    /// Update or insert an inherited (selector-based) policy
    ///
    /// The policy_name should be in format "namespace/name".
    pub fn upsert_inherited(
        &self,
        policy_name: &str,
        policy_text: &str,
        resource_version: &str,
        priority: i32,
    ) -> Result<()> {
        // Check if we already have this version
        if let Some(existing) = self.inherited_policies.get(policy_name) {
            if existing.resource_version == resource_version {
                debug!(
                    policy = %policy_name,
                    version = %resource_version,
                    "Inherited policy unchanged, skipping compilation"
                );
                return Ok(());
            }
        }

        // Compile the policy
        let policy_set = self.compiler.compile(policy_name, policy_text)?;

        // Store the compiled policy
        let entry = InheritedPolicyEntry {
            policy_set: Arc::new(policy_set),
            source: policy_text.to_string(),
            resource_version: resource_version.to_string(),
            priority,
        };

        self.inherited_policies
            .insert(policy_name.to_string(), entry);

        info!(
            policy = %policy_name,
            version = %resource_version,
            priority = priority,
            "Inherited policy updated"
        );

        Ok(())
    }

    /// Remove an inherited policy
    pub fn remove_inherited(&self, policy_name: &str) -> bool {
        let removed = self.inherited_policies.remove(policy_name).is_some();

        if removed {
            // Remove this policy from all service matches
            self.policy_matches.iter_mut().for_each(|mut entry| {
                entry.value_mut().retain(|p| p != policy_name);
            });

            info!(policy = %policy_name, "Inherited policy removed");
        }

        removed
    }

    /// Get an inherited policy
    pub fn get_inherited(&self, policy_name: &str) -> Option<Arc<PolicySet>> {
        self.inherited_policies
            .get(policy_name)
            .map(|e| e.policy_set.clone())
    }

    /// Check if an inherited policy exists
    pub fn contains_inherited(&self, policy_name: &str) -> bool {
        self.inherited_policies.contains_key(policy_name)
    }

    /// Get the number of inherited policies
    pub fn inherited_len(&self) -> usize {
        self.inherited_policies.len()
    }

    // =========================================================================
    // Policy Matching Operations
    // =========================================================================

    /// Set the list of matching inherited policies for a service
    ///
    /// The list is sorted by priority (highest first), then alphabetically.
    pub fn set_matches(&self, namespace: &str, service: &str, policy_names: Vec<String>) {
        let key = PolicyKey::new(namespace, service);

        // Sort by priority (descending), then alphabetically
        let mut sorted = policy_names;
        sorted.sort_by(|a, b| {
            let prio_a = self
                .inherited_policies
                .get(a)
                .map(|e| e.priority)
                .unwrap_or(0);
            let prio_b = self
                .inherited_policies
                .get(b)
                .map(|e| e.priority)
                .unwrap_or(0);
            prio_b.cmp(&prio_a).then_with(|| a.cmp(b))
        });

        if sorted.is_empty() {
            self.policy_matches.remove(&key);
        } else {
            debug!(
                namespace = %namespace,
                service = %service,
                policies = ?sorted,
                "Updated policy matches"
            );
            self.policy_matches.insert(key, sorted);
        }
    }

    /// Get the list of matching inherited policy names for a service
    pub fn get_matches(&self, namespace: &str, service: &str) -> Vec<String> {
        let key = PolicyKey::new(namespace, service);
        self.policy_matches
            .get(&key)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Clear all matches for a specific inherited policy
    ///
    /// Use this when a LatticeServicePolicy is deleted or updated.
    pub fn clear_matches_for_policy(&self, policy_name: &str) {
        self.policy_matches.iter_mut().for_each(|mut entry| {
            entry.value_mut().retain(|p| p != policy_name);
        });
    }

    /// Check if a service has any policy (embedded or inherited)
    pub fn has_any_policy(&self, namespace: &str, name: &str) -> bool {
        self.contains(namespace, name) || !self.get_matches(namespace, name).is_empty()
    }

    // =========================================================================
    // Evaluation
    // =========================================================================

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

    /// Evaluate a request with the two-tier policy model
    ///
    /// Evaluation order:
    /// 1. All matching inherited policy `forbid` rules -> if ANY forbid matches, DENY
    /// 2. Service-embedded policy -> if permit matches, ALLOW
    /// 3. All matching inherited policy `permit` rules -> if ANY matches, ALLOW
    /// 4. Default: DENY
    ///
    /// Note: Step 1 only triggers deny if there's an actual `forbid` rule that matched.
    /// A policy with only permit rules that don't match won't cause a deny in step 1.
    pub fn evaluate_with_inherited(
        &self,
        namespace: &str,
        service: &str,
        request: &cedar_policy::Request,
        entities: &cedar_policy::Entities,
    ) -> PolicyDecision {
        let authorizer = cedar_policy::Authorizer::new();
        let matching_policies = self.get_matches(namespace, service);

        trace!(
            namespace = %namespace,
            service = %service,
            inherited_count = matching_policies.len(),
            "Evaluating with two-tier model"
        );

        // Step 1: Check forbids from ALL matching inherited policies
        // Only deny if an actual forbid rule matched (not just "no permit matched")
        for policy_name in &matching_policies {
            if let Some(entry) = self.inherited_policies.get(policy_name) {
                let response = authorizer.is_authorized(request, &entry.policy_set, entities);

                // Check if this is a deny due to an explicit forbid rule
                // Cedar returns Deny if:
                // a) A forbid rule matches (what we want to catch here)
                // b) No permit rule matches (which is NOT a forbid match)
                //
                // We detect (a) by checking if there are any determining policies
                // that caused the deny. If the response is Deny and there are
                // determining policies, it means a forbid rule matched.
                if response.decision() == Decision::Deny {
                    // Check if any determining policy caused this deny
                    // (if forbid matched, there will be determining policies)
                    let has_determining_forbid = response.diagnostics().reason().next().is_some();

                    if has_determining_forbid {
                        debug!(
                            namespace = %namespace,
                            service = %service,
                            policy = %policy_name,
                            "Request denied by inherited policy forbid rule"
                        );
                        return PolicyDecision::Deny;
                    }
                    // If no determining policies, it's just "no permit matched"
                    // which is not a forbid - continue checking
                }
            }
        }

        // Step 2: Check service-level policy
        if let Some(svc_policy) = self.get(namespace, service) {
            let response = authorizer.is_authorized(request, &svc_policy, entities);
            if response.decision() == Decision::Allow {
                debug!(
                    namespace = %namespace,
                    service = %service,
                    "Request allowed by service-level policy"
                );
                return PolicyDecision::Allow;
            }
        }

        // Step 3: Check permits from inherited policies
        for policy_name in &matching_policies {
            if let Some(entry) = self.inherited_policies.get(policy_name) {
                let response = authorizer.is_authorized(request, &entry.policy_set, entities);
                if response.decision() == Decision::Allow {
                    debug!(
                        namespace = %namespace,
                        service = %service,
                        policy = %policy_name,
                        "Request allowed by inherited policy permit rule"
                    );
                    return PolicyDecision::Allow;
                }
            }
        }

        // Step 4: Check if we had any policies to evaluate
        let has_service_policy = self.contains(namespace, service);
        if !has_service_policy && matching_policies.is_empty() {
            trace!(
                namespace = %namespace,
                service = %service,
                "No policies configured"
            );
            return PolicyDecision::NoMatch;
        }

        // Default deny
        debug!(
            namespace = %namespace,
            service = %service,
            "Request denied by default (no permit matched)"
        );
        PolicyDecision::Deny
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

    #[test]
    fn test_inherited_policy_operations() {
        let store = PolicyStore::new();

        let policy = r#"permit(principal, action, resource);"#;

        // Add inherited policy
        store
            .upsert_inherited("default/require-auth", policy, "v1", 100)
            .unwrap();

        assert!(store.contains_inherited("default/require-auth"));
        assert_eq!(store.inherited_len(), 1);

        // Get inherited policy
        let retrieved = store.get_inherited("default/require-auth");
        assert!(retrieved.is_some());

        // Remove inherited policy
        assert!(store.remove_inherited("default/require-auth"));
        assert!(!store.contains_inherited("default/require-auth"));
    }

    #[test]
    fn test_policy_matches() {
        let store = PolicyStore::new();

        let policy = r#"permit(principal, action, resource);"#;

        // Add some inherited policies
        store
            .upsert_inherited("default/policy-a", policy, "v1", 50)
            .unwrap();
        store
            .upsert_inherited("default/policy-b", policy, "v1", 100)
            .unwrap();
        store
            .upsert_inherited("default/policy-c", policy, "v1", 50)
            .unwrap();

        // Set matches for a service
        store.set_matches(
            "default",
            "api",
            vec![
                "default/policy-a".into(),
                "default/policy-b".into(),
                "default/policy-c".into(),
            ],
        );

        // Should be sorted by priority (descending), then alphabetically
        let matches = store.get_matches("default", "api");
        assert_eq!(
            matches,
            vec!["default/policy-b", "default/policy-a", "default/policy-c"]
        );
    }

    #[test]
    fn test_has_any_policy() {
        let store = PolicyStore::new();

        // No policies yet
        assert!(!store.has_any_policy("default", "api"));

        // Add service policy
        let policy = r#"permit(principal, action, resource);"#;
        store.upsert("default", "api", policy, "v1").unwrap();
        assert!(store.has_any_policy("default", "api"));

        // Remove service policy, add inherited match
        store.remove("default", "api");
        store
            .upsert_inherited("default/baseline", policy, "v1", 0)
            .unwrap();
        store.set_matches("default", "api", vec!["default/baseline".into()]);
        assert!(store.has_any_policy("default", "api"));
    }

    #[test]
    fn test_evaluate_with_inherited_no_policies() {
        let store = PolicyStore::new();
        let entities = cedar_policy::Entities::empty();
        let request = build_test_request();

        let result = store.evaluate_with_inherited("default", "api", &request, &entities);
        assert_eq!(result, PolicyDecision::NoMatch);
    }

    #[test]
    fn test_evaluate_with_inherited_forbid_wins() {
        let store = PolicyStore::new();

        // Inherited policy with forbid
        let forbid_policy = r#"forbid(principal, action, resource);"#;
        store
            .upsert_inherited("default/deny-all", forbid_policy, "v1", 100)
            .unwrap();

        // Service policy with permit
        let permit_policy = r#"permit(principal, action, resource);"#;
        store.upsert("default", "api", permit_policy, "v1").unwrap();

        // Set up matches
        store.set_matches("default", "api", vec!["default/deny-all".into()]);

        let entities = cedar_policy::Entities::empty();
        let request = build_test_request();

        // Forbid should win even though service has permit
        let result = store.evaluate_with_inherited("default", "api", &request, &entities);
        assert_eq!(result, PolicyDecision::Deny);
    }

    #[test]
    fn test_evaluate_with_inherited_service_permit() {
        let store = PolicyStore::new();

        // Inherited policy with no rules that match (empty = no decision)
        let inherited = r#"permit(principal, action, resource) when { false };"#;
        store
            .upsert_inherited("default/never-match", inherited, "v1", 100)
            .unwrap();

        // Service policy with permit
        let permit_policy = r#"permit(principal, action, resource);"#;
        store.upsert("default", "api", permit_policy, "v1").unwrap();

        // Set up matches
        store.set_matches("default", "api", vec!["default/never-match".into()]);

        let entities = cedar_policy::Entities::empty();
        let request = build_test_request();

        // Service permit should allow
        let result = store.evaluate_with_inherited("default", "api", &request, &entities);
        assert_eq!(result, PolicyDecision::Allow);
    }

    #[test]
    fn test_evaluate_with_inherited_fallback_permit() {
        let store = PolicyStore::new();

        // Inherited policy with permit
        let permit_policy = r#"permit(principal, action, resource);"#;
        store
            .upsert_inherited("default/allow-all", permit_policy, "v1", 100)
            .unwrap();

        // No service policy

        // Set up matches
        store.set_matches("default", "api", vec!["default/allow-all".into()]);

        let entities = cedar_policy::Entities::empty();
        let request = build_test_request();

        // Inherited permit should allow
        let result = store.evaluate_with_inherited("default", "api", &request, &entities);
        assert_eq!(result, PolicyDecision::Allow);
    }

    #[test]
    fn test_evaluate_with_inherited_default_deny() {
        let store = PolicyStore::new();

        // Inherited policy that doesn't match
        let no_match = r#"permit(principal, action, resource) when { false };"#;
        store
            .upsert_inherited("default/never-match", no_match, "v1", 100)
            .unwrap();

        // Service policy that doesn't match
        store.upsert("default", "api", no_match, "v1").unwrap();

        // Set up matches
        store.set_matches("default", "api", vec!["default/never-match".into()]);

        let entities = cedar_policy::Entities::empty();
        let request = build_test_request();

        // Should default to deny
        let result = store.evaluate_with_inherited("default", "api", &request, &entities);
        assert_eq!(result, PolicyDecision::Deny);
    }

    // Helper to build a simple test request
    fn build_test_request() -> cedar_policy::Request {
        use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid};
        use std::str::FromStr;

        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("User").unwrap(),
            EntityId::new("testuser"),
        );
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::new("read"),
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::new("test-resource"),
        );
        let context = Context::empty();

        cedar_policy::Request::new(principal, action, resource, context, None).unwrap()
    }
}
