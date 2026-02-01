//! Cedar policy authorization
//!
//! Uses Cedar for fine-grained access control to clusters.
//!
//! # Policy Inheritance
//!
//! Policies are loaded in two phases:
//! 1. **Inherited policies** (labeled `lattice.dev/inherited: true`) - from parent clusters
//! 2. **Local policies** - defined directly on this cluster
//!
//! Within each phase, policies are sorted by priority (higher first). Inherited
//! policies are loaded first to ensure parent policies take precedence (parent's
//! word is law). Cedar's default-deny semantics mean any `forbid` policy will
//! override `permit` policies.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};
use kube::api::ListParams;
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::auth::UserIdentity;
use crate::error::{Error, Result};
use crate::is_local_resource;
use lattice_common::crd::CedarPolicy;
use lattice_common::INHERITED_LABEL;

/// Lattice Cedar schema namespace
const NAMESPACE: &str = "Lattice";

/// Cedar policy engine
///
/// Evaluates authorization requests using Cedar policies loaded from CRDs.
pub struct PolicyEngine {
    /// Cedar authorizer
    authorizer: Authorizer,
    /// Parsed policy set (updated when CRDs change)
    policy_set: Arc<RwLock<PolicySet>>,
    /// Known clusters for authorization checks
    known_clusters: Arc<RwLock<Vec<String>>>,
}

impl PolicyEngine {
    /// Create a new policy engine (placeholder)
    pub fn new() -> Self {
        Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(PolicySet::new())),
            known_clusters: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create policy engine from CedarPolicy CRDs
    ///
    /// Loads all enabled CedarPolicy resources from lattice-system namespace.
    /// Inherited policies (from parent clusters) are loaded first, then local policies.
    pub async fn from_crds(client: &Client) -> Result<Self> {
        let policy_set = Self::load_policies_from_crds(client).await?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            known_clusters: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Load policies from CRDs, respecting inheritance order
    ///
    /// Inherited policies are loaded first (parent's word is law), then local policies.
    /// Within each category, policies are sorted by priority (higher first).
    async fn load_policies_from_crds(client: &Client) -> Result<PolicySet> {
        let api: Api<CedarPolicy> = Api::namespaced(client.clone(), "lattice-system");

        // Fetch inherited policies (from parent clusters)
        let inherited_lp = ListParams::default().labels(&format!("{}=true", INHERITED_LABEL));
        let inherited_policies: Vec<CedarPolicy> = api
            .list(&inherited_lp)
            .await
            .map(|list| list.items)
            .unwrap_or_default();

        // Fetch local policies (not inherited)
        let all_policies = api.list(&Default::default()).await?;
        let local_policies: Vec<_> = all_policies
            .items
            .into_iter()
            .filter(|p| is_local_resource(&p.metadata))
            .collect();

        let mut policy_set = PolicySet::new();
        let mut inherited_count = 0;
        let mut local_count = 0;
        let mut error_count = 0;

        // Load inherited policies first (parent's word is law)
        let mut sorted_inherited = inherited_policies;
        sorted_inherited.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_inherited {
            let (loaded, errors) = Self::add_policy_to_set(&mut policy_set, &crd);
            inherited_count += loaded;
            error_count += errors;
        }

        // Load local policies second
        let mut sorted_local: Vec<_> = local_policies;
        sorted_local.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_local {
            let (loaded, errors) = Self::add_policy_to_set(&mut policy_set, &crd);
            local_count += loaded;
            error_count += errors;
        }

        info!(
            inherited = inherited_count,
            local = local_count,
            errors = error_count,
            "Loaded Cedar policies from CRDs"
        );

        Ok(policy_set)
    }

    /// Add policies from a CedarPolicy CRD to the policy set
    ///
    /// Returns (loaded_count, error_count)
    fn add_policy_to_set(policy_set: &mut PolicySet, crd: &CedarPolicy) -> (usize, usize) {
        if !crd.spec.enabled {
            debug!(
                name = ?crd.metadata.name,
                "Skipping disabled CedarPolicy"
            );
            return (0, 0);
        }

        let mut loaded = 0;
        let mut errors = 0;

        match crd.spec.policies.parse::<PolicySet>() {
            Ok(parsed) => {
                for policy in parsed.policies() {
                    if let Err(e) = policy_set.add(policy.clone()) {
                        warn!(
                            name = ?crd.metadata.name,
                            error = %e,
                            "Failed to add policy (duplicate ID?)"
                        );
                        errors += 1;
                    } else {
                        loaded += 1;
                    }
                }
            }
            Err(e) => {
                warn!(
                    name = ?crd.metadata.name,
                    error = %e,
                    "Failed to parse CedarPolicy"
                );
                errors += 1;
            }
        }

        (loaded, errors)
    }

    /// Create policy engine with explicit policies (for testing)
    pub fn with_policies(policy_text: &str) -> Result<Self> {
        let policy_set: PolicySet =
            policy_text
                .parse()
                .map_err(|e: cedar_policy::ParseErrors| {
                    Error::Config(format!("Invalid Cedar policy: {}", e))
                })?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            known_clusters: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Update the list of known clusters
    ///
    /// Called when the subtree registry changes.
    pub async fn set_known_clusters(&self, clusters: Vec<String>) {
        let mut known = self.known_clusters.write().await;
        *known = clusters;
    }

    /// Check if a user is authorized to access a cluster
    ///
    /// # Arguments
    /// * `identity` - The authenticated user
    /// * `cluster` - The target cluster name
    /// * `action` - The K8s verb (get, list, create, etc.)
    ///
    /// # Returns
    /// Ok(()) if authorized, Err(Forbidden) otherwise
    pub async fn authorize(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        action: &str,
    ) -> Result<()> {
        let policy_set = self.policy_set.read().await;
        self.authorize_with_policy_set(identity, cluster, action, &policy_set)
    }

    /// Check authorization with a specific policy set
    fn authorize_with_policy_set(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        action: &str,
        policy_set: &PolicySet,
    ) -> Result<()> {
        // Build principal - try as user first, if groups exist, also check group membership
        let principal = build_user_uid(&identity.username)?;

        // Build action
        let action_uid = build_action_uid(action)?;

        // Build resource
        let resource = build_cluster_uid(cluster)?;

        // Build entities - user and their group memberships
        let entities = build_entities(identity, cluster)?;

        // Build context (empty for now, could add request metadata)
        let context = Context::empty();

        // Create request
        let request = Request::new(
            principal.clone(),
            action_uid.clone(),
            resource.clone(),
            context,
            None, // No schema validation for now
        )
        .map_err(|e| Error::Internal(format!("Failed to build Cedar request: {}", e)))?;

        // Evaluate
        let response = self
            .authorizer
            .is_authorized(&request, policy_set, &entities);

        debug!(
            principal = %principal,
            action = %action_uid,
            resource = %resource,
            decision = ?response.decision(),
            "Cedar authorization result"
        );

        match response.decision() {
            Decision::Allow => Ok(()),
            Decision::Deny => Err(Error::Forbidden(format!(
                "Access denied: user '{}' cannot '{}' cluster '{}'",
                identity.username, action, cluster
            ))),
        }
    }

    /// Get list of clusters the user can access
    ///
    /// Used by kubeconfig generation to return all accessible clusters.
    ///
    /// # Arguments
    /// * `identity` - The authenticated user
    ///
    /// # Returns
    /// List of cluster names the user can access
    pub async fn accessible_clusters(&self, identity: &UserIdentity) -> Vec<String> {
        // Clone cluster names (cheap) to release lock, but hold policy_set lock during filter
        let known_clusters: Vec<String> = self.known_clusters.read().await.clone();
        let policy_set = self.policy_set.read().await;

        known_clusters
            .into_iter()
            .filter(|cluster| {
                self.authorize_with_policy_set(identity, cluster, "get", &policy_set)
                    .is_ok()
            })
            .collect()
    }

    /// Check if any policies are loaded
    pub async fn has_policies(&self) -> bool {
        let policy_set = self.policy_set.read().await;
        let has_any = policy_set.policies().next().is_some();
        has_any
    }

    /// Reload policies from CRDs
    ///
    /// Reloads all policies, respecting inheritance order (inherited first, then local).
    pub async fn reload(&self, client: &Client) -> Result<()> {
        let new_policy_set = Self::load_policies_from_crds(client).await?;

        let mut policy_set = self.policy_set.write().await;
        *policy_set = new_policy_set;

        info!("Reloaded Cedar policies");
        Ok(())
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an entity UID for a given type and ID
///
/// # Arguments
/// * `type_name` - The Cedar type name (e.g., "User", "Group", "Action", "Cluster")
/// * `id` - The entity identifier
///
/// # Returns
/// Result containing the EntityUid or an error if the type name is invalid
fn build_entity_uid(type_name: &str, id: &str) -> Result<EntityUid> {
    let full_type_name = format!("{}::{}", NAMESPACE, type_name);
    let entity_type: EntityTypeName =
        full_type_name
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| {
                Error::Internal(format!(
                    "Invalid Cedar entity type name '{}': {}",
                    full_type_name, e
                ))
            })?;
    let entity_id = EntityId::new(id);
    Ok(EntityUid::from_type_name_and_id(entity_type, entity_id))
}

/// Build a User entity UID
fn build_user_uid(username: &str) -> Result<EntityUid> {
    build_entity_uid("User", username)
}

/// Build a Group entity UID
fn build_group_uid(group: &str) -> Result<EntityUid> {
    build_entity_uid("Group", group)
}

/// Build an Action entity UID
fn build_action_uid(action: &str) -> Result<EntityUid> {
    build_entity_uid("Action", action)
}

/// Build a Cluster entity UID
fn build_cluster_uid(cluster: &str) -> Result<EntityUid> {
    build_entity_uid("Cluster", cluster)
}

/// Build the entities set for authorization
///
/// Creates entities for the user, their groups, and the cluster.
fn build_entities(identity: &UserIdentity, cluster: &str) -> Result<Entities> {
    let mut entities = Vec::new();

    // Create group entities
    let mut group_uids = Vec::new();
    for group in &identity.groups {
        group_uids.push(build_group_uid(group)?);
    }

    for group_uid in &group_uids {
        let group_entity = Entity::new(
            group_uid.clone(),
            HashMap::new(), // No attributes
            HashSet::new(), // Groups don't have parents in our model
        )
        .map_err(|e| Error::Internal(format!("Failed to create group entity: {}", e)))?;
        entities.push(group_entity);
    }

    // Create user entity with group membership
    let user_uid = build_user_uid(&identity.username)?;
    let user_entity = Entity::new(
        user_uid,
        HashMap::new(),                                 // No attributes
        group_uids.into_iter().collect::<HashSet<_>>(), // User is a member of groups
    )
    .map_err(|e| Error::Internal(format!("Failed to create user entity: {}", e)))?;
    entities.push(user_entity);

    // Create cluster entity
    let cluster_uid = build_cluster_uid(cluster)?;
    let cluster_entity = Entity::new(
        cluster_uid,
        HashMap::new(), // No attributes (could add labels here)
        HashSet::new(), // No parent clusters in this model
    )
    .map_err(|e| Error::Internal(format!("Failed to create cluster entity: {}", e)))?;
    entities.push(cluster_entity);

    Entities::from_entities(entities, None)
        .map_err(|e| Error::Internal(format!("Failed to create entities set: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_creation() {
        let _engine = PolicyEngine::new();
    }

    #[test]
    fn test_build_user_uid() {
        let uid = build_user_uid("alice@example.com").unwrap();
        assert!(uid.to_string().contains("User"));
        assert!(uid.to_string().contains("alice@example.com"));
    }

    #[test]
    fn test_build_group_uid() {
        let uid = build_group_uid("admins").unwrap();
        assert!(uid.to_string().contains("Group"));
        assert!(uid.to_string().contains("admins"));
    }

    #[test]
    fn test_build_action_uid() {
        let uid = build_action_uid("get").unwrap();
        assert!(uid.to_string().contains("Action"));
        assert!(uid.to_string().contains("get"));
    }

    #[test]
    fn test_build_cluster_uid() {
        let uid = build_cluster_uid("prod-frontend").unwrap();
        assert!(uid.to_string().contains("Cluster"));
        assert!(uid.to_string().contains("prod-frontend"));
    }

    #[test]
    fn test_build_entities() {
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec!["admins".to_string(), "developers".to_string()],
        };

        let entities = build_entities(&identity, "prod-cluster").unwrap();
        // Should have: 1 user + 2 groups + 1 cluster = 4 entities
        assert_eq!(entities.iter().count(), 4);
    }

    #[test]
    fn test_build_entity_uid_generic() {
        let uid = build_entity_uid("User", "test@example.com").unwrap();
        assert!(uid.to_string().contains("User"));
        assert!(uid.to_string().contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_permit_all_policy() {
        let policy = r#"
            permit(principal, action, resource);
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster", "get").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_deny_by_default() {
        // Empty policy set should deny by default
        let engine = PolicyEngine::new();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster", "get").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_user_specific_policy() {
        let policy = r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action,
                resource == Lattice::Cluster::"prod-frontend"
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        // Alice can access prod-frontend
        let alice = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };
        assert!(engine
            .authorize(&alice, "prod-frontend", "get")
            .await
            .is_ok());

        // Alice cannot access other clusters
        assert!(engine.authorize(&alice, "staging", "get").await.is_err());

        // Bob cannot access prod-frontend
        let bob = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec![],
        };
        assert!(engine
            .authorize(&bob, "prod-frontend", "get")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_group_policy() {
        let policy = r#"
            permit(
                principal in Lattice::Group::"admins",
                action,
                resource
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();

        // Admin can access any cluster
        let admin = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec!["admins".to_string()],
        };
        assert!(engine.authorize(&admin, "any-cluster", "get").await.is_ok());
        assert!(engine
            .authorize(&admin, "another-cluster", "delete")
            .await
            .is_ok());

        // Non-admin cannot access
        let user = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };
        assert!(engine.authorize(&user, "any-cluster", "get").await.is_err());
    }

    #[tokio::test]
    async fn test_action_specific_policy() {
        let policy = r#"
            permit(
                principal,
                action in [Lattice::Action::"get", Lattice::Action::"list"],
                resource
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        // Read actions allowed
        assert!(engine
            .authorize(&identity, "any-cluster", "get")
            .await
            .is_ok());
        assert!(engine
            .authorize(&identity, "any-cluster", "list")
            .await
            .is_ok());

        // Write actions denied
        assert!(engine
            .authorize(&identity, "any-cluster", "create")
            .await
            .is_err());
        assert!(engine
            .authorize(&identity, "any-cluster", "delete")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_accessible_clusters() {
        let policy = r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action,
                resource == Lattice::Cluster::"prod-frontend"
            );
            permit(
                principal == Lattice::User::"alice@example.com",
                action,
                resource == Lattice::Cluster::"staging-frontend"
            );
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();
        engine
            .set_known_clusters(vec![
                "prod-frontend".to_string(),
                "staging-frontend".to_string(),
                "prod-backend".to_string(),
            ])
            .await;

        let alice = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let accessible = engine.accessible_clusters(&alice).await;
        assert_eq!(accessible.len(), 2);
        assert!(accessible.contains(&"prod-frontend".to_string()));
        assert!(accessible.contains(&"staging-frontend".to_string()));
        assert!(!accessible.contains(&"prod-backend".to_string()));
    }

    #[tokio::test]
    async fn test_has_policies() {
        let empty_engine = PolicyEngine::new();
        assert!(!empty_engine.has_policies().await);

        let policy = "permit(principal, action, resource);";
        let engine = PolicyEngine::with_policies(policy).unwrap();
        assert!(engine.has_policies().await);
    }
}
