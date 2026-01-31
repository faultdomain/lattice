//! Cedar policy authorization
//!
//! Uses Cedar for fine-grained access control to clusters.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request,
};
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::auth::UserIdentity;
use crate::error::{Error, Result};
use lattice_common::crd::CedarPolicy;

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
    pub async fn from_crds(client: &Client) -> Result<Self> {
        let api: Api<CedarPolicy> = Api::namespaced(client.clone(), "lattice-system");
        let policies = api.list(&Default::default()).await?;

        let mut policy_set = PolicySet::new();
        let mut loaded_count = 0;
        let mut error_count = 0;

        // Sort policies by priority (higher first)
        let mut sorted_policies: Vec<_> = policies.items.into_iter().collect();
        sorted_policies.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_policies {
            if !crd.spec.enabled {
                debug!(
                    name = ?crd.metadata.name,
                    "Skipping disabled CedarPolicy"
                );
                continue;
            }

            match PolicySet::from_str(&crd.spec.policies) {
                Ok(parsed) => {
                    // Merge policies into the main set
                    for policy in parsed.policies() {
                        if let Err(e) = policy_set.add(policy.clone()) {
                            warn!(
                                name = ?crd.metadata.name,
                                error = %e,
                                "Failed to add policy (duplicate ID?)"
                            );
                            error_count += 1;
                        } else {
                            loaded_count += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        name = ?crd.metadata.name,
                        error = %e,
                        "Failed to parse CedarPolicy"
                    );
                    error_count += 1;
                }
            }
        }

        info!(
            loaded = loaded_count,
            errors = error_count,
            "Loaded Cedar policies from CRDs"
        );

        Ok(Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(policy_set)),
            known_clusters: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create policy engine with explicit policies (for testing)
    pub fn with_policies(policy_text: &str) -> Result<Self> {
        let policy_set = PolicySet::from_str(policy_text)
            .map_err(|e| Error::Config(format!("Invalid Cedar policy: {}", e)))?;

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
    pub fn authorize(&self, identity: &UserIdentity, cluster: &str, action: &str) -> Result<()> {
        // Build the authorization request synchronously
        // Use block_on for the async lock since this is called from sync context
        let policy_set = {
            // We need to handle this carefully - try_read to avoid blocking
            // In practice, the policy set is rarely updated
            futures::executor::block_on(self.policy_set.read()).clone()
        };

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
        let principal = build_user_uid(&identity.username);

        // Build action
        let action_uid = build_action_uid(action);

        // Build resource
        let resource = build_cluster_uid(cluster);

        // Build entities - user and their group memberships
        let entities = build_entities(identity, cluster);

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
        let response = self.authorizer.is_authorized(&request, policy_set, &entities);

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
    pub fn accessible_clusters(&self, identity: &UserIdentity) -> Vec<String> {
        let known_clusters = futures::executor::block_on(self.known_clusters.read()).clone();
        let policy_set = futures::executor::block_on(self.policy_set.read()).clone();

        known_clusters
            .into_iter()
            .filter(|cluster| {
                self.authorize_with_policy_set(identity, cluster, "get", &policy_set)
                    .is_ok()
            })
            .collect()
    }

    /// Async version of accessible_clusters
    pub async fn accessible_clusters_async(&self, identity: &UserIdentity) -> Vec<String> {
        let known_clusters = self.known_clusters.read().await.clone();
        let policy_set = self.policy_set.read().await.clone();

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
    pub async fn reload(&self, client: &Client) -> Result<()> {
        let api: Api<CedarPolicy> = Api::namespaced(client.clone(), "lattice-system");
        let policies = api.list(&Default::default()).await?;

        let mut new_policy_set = PolicySet::new();

        // Sort policies by priority (higher first)
        let mut sorted_policies: Vec<_> = policies.items.into_iter().collect();
        sorted_policies.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));

        for crd in sorted_policies {
            if !crd.spec.enabled {
                continue;
            }

            if let Ok(parsed) = PolicySet::from_str(&crd.spec.policies) {
                for policy in parsed.policies() {
                    let _ = new_policy_set.add(policy.clone());
                }
            }
        }

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

/// Build a User entity UID
fn build_user_uid(username: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(&format!("{}::User", NAMESPACE))
        .expect("User type name should be valid");
    let id = EntityId::from_str(username).expect("username should be valid entity ID");
    EntityUid::from_type_name_and_id(type_name, id)
}

/// Build a Group entity UID
fn build_group_uid(group: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(&format!("{}::Group", NAMESPACE))
        .expect("Group type name should be valid");
    let id = EntityId::from_str(group).expect("group should be valid entity ID");
    EntityUid::from_type_name_and_id(type_name, id)
}

/// Build an Action entity UID
fn build_action_uid(action: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(&format!("{}::Action", NAMESPACE))
        .expect("Action type name should be valid");
    let id = EntityId::from_str(action).expect("action should be valid entity ID");
    EntityUid::from_type_name_and_id(type_name, id)
}

/// Build a Cluster entity UID
fn build_cluster_uid(cluster: &str) -> EntityUid {
    let type_name = EntityTypeName::from_str(&format!("{}::Cluster", NAMESPACE))
        .expect("Cluster type name should be valid");
    let id = EntityId::from_str(cluster).expect("cluster should be valid entity ID");
    EntityUid::from_type_name_and_id(type_name, id)
}

/// Build the entities set for authorization
///
/// Creates entities for the user, their groups, and the cluster.
fn build_entities(identity: &UserIdentity, cluster: &str) -> Entities {
    let mut entities = Vec::new();

    // Create group entities
    let group_uids: Vec<EntityUid> = identity.groups.iter().map(|g| build_group_uid(g)).collect();

    for group_uid in &group_uids {
        let group_entity = Entity::new(
            group_uid.clone(),
            HashMap::new(),  // No attributes
            HashSet::new(),  // Groups don't have parents in our model
        )
        .expect("group entity should be valid");
        entities.push(group_entity);
    }

    // Create user entity with group membership
    let user_uid = build_user_uid(&identity.username);
    let user_entity = Entity::new(
        user_uid,
        HashMap::new(),                          // No attributes
        group_uids.into_iter().collect::<HashSet<_>>(), // User is a member of groups
    )
    .expect("user entity should be valid");
    entities.push(user_entity);

    // Create cluster entity
    let cluster_uid = build_cluster_uid(cluster);
    let cluster_entity = Entity::new(
        cluster_uid,
        HashMap::new(),  // No attributes (could add labels here)
        HashSet::new(),  // No parent clusters in this model
    )
    .expect("cluster entity should be valid");
    entities.push(cluster_entity);

    Entities::from_entities(entities, None)
        .expect("entities should be valid")
}

/// Helper trait for parsing entity UIDs
trait FromStrExt: Sized {
    fn from_str(s: &str) -> std::result::Result<Self, String>;
}

impl FromStrExt for EntityTypeName {
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        s.parse().map_err(|e: cedar_policy::ParseErrors| e.to_string())
    }
}

impl FromStrExt for EntityId {
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        Ok(Self::new(s))
    }
}

impl FromStrExt for PolicySet {
    fn from_str(s: &str) -> std::result::Result<Self, String> {
        s.parse().map_err(|e: cedar_policy::ParseErrors| e.to_string())
    }
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
        let uid = build_user_uid("alice@example.com");
        assert!(uid.to_string().contains("User"));
        assert!(uid.to_string().contains("alice@example.com"));
    }

    #[test]
    fn test_build_group_uid() {
        let uid = build_group_uid("admins");
        assert!(uid.to_string().contains("Group"));
        assert!(uid.to_string().contains("admins"));
    }

    #[test]
    fn test_build_action_uid() {
        let uid = build_action_uid("get");
        assert!(uid.to_string().contains("Action"));
        assert!(uid.to_string().contains("get"));
    }

    #[test]
    fn test_build_cluster_uid() {
        let uid = build_cluster_uid("prod-frontend");
        assert!(uid.to_string().contains("Cluster"));
        assert!(uid.to_string().contains("prod-frontend"));
    }

    #[test]
    fn test_build_entities() {
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec!["admins".to_string(), "developers".to_string()],
        };

        let entities = build_entities(&identity, "prod-cluster");
        // Should have: 1 user + 2 groups + 1 cluster = 4 entities
        assert_eq!(entities.iter().count(), 4);
    }

    #[test]
    fn test_permit_all_policy() {
        let policy = r#"
            permit(principal, action, resource);
        "#;

        let engine = PolicyEngine::with_policies(policy).unwrap();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster", "get");
        assert!(result.is_ok());
    }

    #[test]
    fn test_deny_by_default() {
        // Empty policy set should deny by default
        let engine = PolicyEngine::new();
        let identity = UserIdentity {
            username: "alice@example.com".to_string(),
            groups: vec![],
        };

        let result = engine.authorize(&identity, "any-cluster", "get");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_specific_policy() {
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
        assert!(engine.authorize(&alice, "prod-frontend", "get").is_ok());

        // Alice cannot access other clusters
        assert!(engine.authorize(&alice, "staging", "get").is_err());

        // Bob cannot access prod-frontend
        let bob = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec![],
        };
        assert!(engine.authorize(&bob, "prod-frontend", "get").is_err());
    }

    #[test]
    fn test_group_policy() {
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
        assert!(engine.authorize(&admin, "any-cluster", "get").is_ok());
        assert!(engine.authorize(&admin, "another-cluster", "delete").is_ok());

        // Non-admin cannot access
        let user = UserIdentity {
            username: "bob@example.com".to_string(),
            groups: vec!["developers".to_string()],
        };
        assert!(engine.authorize(&user, "any-cluster", "get").is_err());
    }

    #[test]
    fn test_action_specific_policy() {
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
        assert!(engine.authorize(&identity, "any-cluster", "get").is_ok());
        assert!(engine.authorize(&identity, "any-cluster", "list").is_ok());

        // Write actions denied
        assert!(engine.authorize(&identity, "any-cluster", "create").is_err());
        assert!(engine.authorize(&identity, "any-cluster", "delete").is_err());
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

        let accessible = engine.accessible_clusters_async(&alice).await;
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
