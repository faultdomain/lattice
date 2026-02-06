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
//!
//! # Cluster Attributes
//!
//! Clusters have attributes populated from labels:
//! - `environment` from `lattice.dev/environment` (required by policy, fail-closed)
//! - `region` from `lattice.dev/region` (default: "unknown")
//! - `tier` from `lattice.dev/tier` (default: "standard")

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};
use kube::api::ListParams;
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::auth::UserIdentity;
use crate::error::{Error, Result};
use crate::is_local_resource;
use lattice_common::crd::CedarPolicy;
use lattice_common::INHERITED_LABEL;

// ============================================================================
// Constants
// ============================================================================

/// Lattice Cedar schema namespace
const NAMESPACE: &str = "Lattice";

/// Label keys for cluster attributes
const ENVIRONMENT_LABEL: &str = "lattice.dev/environment";
const REGION_LABEL: &str = "lattice.dev/region";
const TIER_LABEL: &str = "lattice.dev/tier";

/// Default values for optional cluster attributes
const DEFAULT_REGION: &str = "unknown";
const DEFAULT_TIER: &str = "standard";

// ============================================================================
// ClusterAttributes
// ============================================================================

/// Cluster attributes for Cedar entity building
///
/// These are extracted from cluster labels and used to build Cedar entities
/// with attributes for policy evaluation.
#[derive(Debug, Clone, Default)]
pub struct ClusterAttributes {
    /// Environment (e.g., "prod", "staging", "dev")
    /// Only present if lattice.dev/environment label exists
    pub environment: Option<String>,
    /// Region (e.g., "us-west-2", "eu-central-1")
    /// Defaults to "unknown" if lattice.dev/region label is missing
    pub region: String,
    /// Tier (e.g., "standard", "premium", "critical")
    /// Defaults to "standard" if lattice.dev/tier label is missing
    pub tier: String,
}

impl ClusterAttributes {
    /// Create ClusterAttributes from a label map
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        Self {
            environment: labels.get(ENVIRONMENT_LABEL).cloned(),
            region: labels
                .get(REGION_LABEL)
                .cloned()
                .unwrap_or_else(|| DEFAULT_REGION.to_string()),
            tier: labels
                .get(TIER_LABEL)
                .cloned()
                .unwrap_or_else(|| DEFAULT_TIER.to_string()),
        }
    }
}

// ============================================================================
// PolicyEngine
// ============================================================================

/// Cedar policy engine
///
/// Evaluates authorization requests using Cedar policies loaded from CRDs.
/// Cluster attributes are passed at call time — the engine owns only policies.
pub struct PolicyEngine {
    /// Cedar authorizer
    authorizer: Authorizer,
    /// Parsed policy set (updated when CRDs change)
    policy_set: Arc<RwLock<PolicySet>>,
}

impl PolicyEngine {
    /// Create a new policy engine with no policies (default-deny)
    pub fn new() -> Self {
        Self {
            authorizer: Authorizer::new(),
            policy_set: Arc::new(RwLock::new(PolicySet::new())),
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
        })
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
        })
    }

    /// Check if a user is authorized to access a cluster
    #[instrument(
        skip(self, identity, attrs),
        fields(
            user = %identity.username,
            otel.kind = "internal"
        )
    )]
    pub async fn authorize(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        attrs: &ClusterAttributes,
    ) -> Result<()> {
        let policy_set = self.policy_set.read().await;
        self.evaluate(identity, cluster, attrs, Context::empty(), &policy_set)
    }

    /// Check if a user is authorized to access a cluster with Cedar context
    ///
    /// Context provides temporal/request metadata (e.g., hour, sourceIp, breakGlass).
    pub async fn authorize_with_context(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        attrs: &ClusterAttributes,
        context: Context,
    ) -> Result<()> {
        let policy_set = self.policy_set.read().await;
        self.evaluate(identity, cluster, attrs, context, &policy_set)
    }

    /// Get list of clusters the user can access
    pub async fn accessible_clusters(
        &self,
        identity: &UserIdentity,
        cluster_attrs: &HashMap<String, ClusterAttributes>,
    ) -> Vec<String> {
        let policy_set = self.policy_set.read().await;
        cluster_attrs
            .iter()
            .filter(|(cluster, attrs)| {
                self.evaluate(identity, cluster, attrs, Context::empty(), &policy_set)
                    .is_ok()
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Check if any policies are loaded
    pub async fn has_policies(&self) -> bool {
        self.policy_set.read().await.policies().next().is_some()
    }

    /// Reload policies from CRDs
    pub async fn reload(&self, client: &Client) -> Result<()> {
        let new_policy_set = Self::load_policies_from_crds(client).await?;
        let mut policy_set = self.policy_set.write().await;
        *policy_set = new_policy_set;
        info!("Reloaded Cedar policies");
        Ok(())
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Core authorization evaluation
    fn evaluate(
        &self,
        identity: &UserIdentity,
        cluster: &str,
        attrs: &ClusterAttributes,
        context: Context,
        policy_set: &PolicySet,
    ) -> Result<()> {
        let principal = build_entity_uid("User", &identity.username)?;
        let action_uid = build_entity_uid("Action", "AccessCluster")?;
        let resource = build_entity_uid("Cluster", cluster)?;
        let entities = build_entities(identity, cluster, attrs)?;

        let request = Request::new(
            principal.clone(),
            action_uid.clone(),
            resource.clone(),
            context,
            None,
        )
        .map_err(|e| Error::Internal(format!("Failed to build Cedar request: {}", e)))?;

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
            Decision::Allow => {
                lattice_common::metrics::record_cedar_decision(
                    lattice_common::metrics::AuthDecision::Allow,
                    "AccessCluster",
                );
                Ok(())
            }
            Decision::Deny => {
                lattice_common::metrics::record_cedar_decision(
                    lattice_common::metrics::AuthDecision::Deny,
                    "AccessCluster",
                );
                Err(Error::Forbidden(format!(
                    "Access denied: user '{}' cannot access cluster '{}'",
                    identity.username, cluster
                )))
            }
        }
    }

    /// Load policies from CRDs, respecting inheritance order
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
        let mut error_count = 0;

        // Load inherited policies first (parent's word is law), then local
        let inherited_count =
            Self::load_sorted_policies(&mut policy_set, inherited_policies, &mut error_count);
        let local_count =
            Self::load_sorted_policies(&mut policy_set, local_policies, &mut error_count);

        info!(
            inherited = inherited_count,
            local = local_count,
            errors = error_count,
            "Loaded Cedar policies from CRDs"
        );

        Ok(policy_set)
    }

    /// Sort policies by priority (descending) and add them to the policy set.
    /// Returns the number of successfully loaded policies.
    fn load_sorted_policies(
        policy_set: &mut PolicySet,
        mut policies: Vec<CedarPolicy>,
        error_count: &mut usize,
    ) -> usize {
        policies.sort_by(|a, b| b.spec.priority.cmp(&a.spec.priority));
        let mut loaded = 0;
        for crd in policies {
            let (l, e) = Self::add_policy_to_set(policy_set, &crd);
            loaded += l;
            *error_count += e;
        }
        loaded
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
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Entity Building
// ============================================================================

/// Build an entity UID for a given type and ID
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

/// Build the entities set for authorization
///
/// Creates entities for the user, their groups, and the cluster with attributes.
fn build_entities(
    identity: &UserIdentity,
    cluster: &str,
    attrs: &ClusterAttributes,
) -> Result<Entities> {
    let mut entities = Vec::new();

    // Create group entities and collect UIDs for user membership
    let mut group_uids = Vec::new();
    for group in &identity.groups {
        let uid = build_entity_uid("Group", group)?;
        let entity = Entity::new(uid.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| Error::Internal(format!("Failed to create group entity: {}", e)))?;
        entities.push(entity);
        group_uids.push(uid);
    }

    // Create user entity with group membership
    let user_uid = build_entity_uid("User", &identity.username)?;
    let user_entity = Entity::new(
        user_uid,
        HashMap::new(),
        group_uids.into_iter().collect::<HashSet<_>>(),
    )
    .map_err(|e| Error::Internal(format!("Failed to create user entity: {}", e)))?;
    entities.push(user_entity);

    // Create cluster entity with attributes
    let cluster_uid = build_entity_uid("Cluster", cluster)?;
    let mut attr_map = HashMap::new();

    // Environment is only added if present (fail-closed via policy pattern)
    if let Some(ref env) = attrs.environment {
        attr_map.insert(
            "environment".to_string(),
            RestrictedExpression::new_string(env.clone()),
        );
    }

    // Region and tier always have values (with defaults)
    attr_map.insert(
        "region".to_string(),
        RestrictedExpression::new_string(attrs.region.clone()),
    );
    attr_map.insert(
        "tier".to_string(),
        RestrictedExpression::new_string(attrs.tier.clone()),
    );

    let cluster_entity = Entity::new(cluster_uid, attr_map, HashSet::new())
        .map_err(|e| Error::Internal(format!("Failed to create cluster entity: {}", e)))?;
    entities.push(cluster_entity);

    Entities::from_entities(entities, None)
        .map_err(|e| Error::Internal(format!("Failed to create entities set: {}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(username: &str, groups: &[&str]) -> UserIdentity {
        UserIdentity {
            username: username.to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    // ========================================================================
    // Entity Building Tests
    // ========================================================================

    #[test]
    fn test_build_entity_uid() {
        for (type_name, id) in [
            ("User", "alice@example.com"),
            ("Group", "admins"),
            ("Action", "AccessCluster"),
            ("Cluster", "prod-frontend"),
        ] {
            let uid = build_entity_uid(type_name, id).unwrap();
            assert!(uid.to_string().contains(type_name));
            assert!(uid.to_string().contains(id));
        }
    }

    // ========================================================================
    // ClusterAttributes Tests
    // ========================================================================

    #[test]
    fn test_cluster_attributes_from_labels_all_present() {
        let mut labels = HashMap::new();
        labels.insert(ENVIRONMENT_LABEL.to_string(), "prod".to_string());
        labels.insert(REGION_LABEL.to_string(), "us-west-2".to_string());
        labels.insert(TIER_LABEL.to_string(), "premium".to_string());

        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, Some("prod".to_string()));
        assert_eq!(attrs.region, "us-west-2");
        assert_eq!(attrs.tier, "premium");
    }

    #[test]
    fn test_cluster_attributes_from_labels_defaults() {
        let labels = HashMap::new();
        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, None);
        assert_eq!(attrs.region, DEFAULT_REGION);
        assert_eq!(attrs.tier, DEFAULT_TIER);
    }

    #[test]
    fn test_cluster_attributes_from_labels_partial() {
        let mut labels = HashMap::new();
        labels.insert(ENVIRONMENT_LABEL.to_string(), "staging".to_string());

        let attrs = ClusterAttributes::from_labels(&labels);

        assert_eq!(attrs.environment, Some("staging".to_string()));
        assert_eq!(attrs.region, DEFAULT_REGION);
        assert_eq!(attrs.tier, DEFAULT_TIER);
    }

    // ========================================================================
    // Entities Building Tests
    // ========================================================================

    #[test]
    fn test_build_entities_with_groups() {
        let identity = test_identity("alice@example.com", &["admins", "developers"]);
        let attrs = ClusterAttributes {
            environment: Some("prod".to_string()),
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        let entities = build_entities(&identity, "prod-cluster", &attrs).unwrap();
        // 1 user + 2 groups + 1 cluster = 4
        assert_eq!(entities.iter().count(), 4);
    }

    #[test]
    fn test_build_entities_no_groups() {
        let identity = test_identity("alice@example.com", &[]);
        let entities =
            build_entities(&identity, "test-cluster", &ClusterAttributes::default()).unwrap();
        // 1 user + 0 groups + 1 cluster = 2
        assert_eq!(entities.iter().count(), 2);
    }

    // ========================================================================
    // Policy Engine Basic Tests
    // ========================================================================

    #[tokio::test]
    async fn test_permit_all_policy() {
        let engine = PolicyEngine::with_policies("permit(principal, action, resource);").unwrap();
        let identity = test_identity("alice@example.com", &[]);

        assert!(engine
            .authorize(&identity, "any-cluster", &ClusterAttributes::default())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_deny_by_default() {
        let engine = PolicyEngine::new();
        let identity = test_identity("alice@example.com", &[]);

        assert!(engine
            .authorize(&identity, "any-cluster", &ClusterAttributes::default())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_user_specific_policy() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod-frontend"
            );
            "#,
        )
        .unwrap();

        let alice = test_identity("alice@example.com", &[]);
        let bob = test_identity("bob@example.com", &[]);
        let attrs = ClusterAttributes::default();

        assert!(engine
            .authorize(&alice, "prod-frontend", &attrs)
            .await
            .is_ok());
        assert!(engine.authorize(&alice, "staging", &attrs).await.is_err());
        assert!(engine
            .authorize(&bob, "prod-frontend", &attrs)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_group_policy() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"admins",
                action == Lattice::Action::"AccessCluster",
                resource
            );
            "#,
        )
        .unwrap();

        let admin = test_identity("alice@example.com", &["admins"]);
        let user = test_identity("bob@example.com", &["developers"]);
        let attrs = ClusterAttributes::default();

        assert!(engine
            .authorize(&admin, "any-cluster", &attrs)
            .await
            .is_ok());
        assert!(engine
            .authorize(&admin, "another-cluster", &attrs)
            .await
            .is_ok());
        assert!(engine
            .authorize(&user, "any-cluster", &attrs)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_accessible_clusters() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod-frontend"
            );
            permit(
                principal == Lattice::User::"alice@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"staging-frontend"
            );
            "#,
        )
        .unwrap();

        let mut clusters = HashMap::new();
        clusters.insert("prod-frontend".to_string(), ClusterAttributes::default());
        clusters.insert("staging-frontend".to_string(), ClusterAttributes::default());
        clusters.insert("prod-backend".to_string(), ClusterAttributes::default());

        let alice = test_identity("alice@example.com", &[]);
        let accessible = engine.accessible_clusters(&alice, &clusters).await;

        assert_eq!(accessible.len(), 2);
        assert!(accessible.contains(&"prod-frontend".to_string()));
        assert!(accessible.contains(&"staging-frontend".to_string()));
        assert!(!accessible.contains(&"prod-backend".to_string()));
    }

    #[tokio::test]
    async fn test_has_policies() {
        assert!(!PolicyEngine::new().has_policies().await);

        let engine = PolicyEngine::with_policies("permit(principal, action, resource);").unwrap();
        assert!(engine.has_policies().await);
    }

    // ========================================================================
    // Environment-Based Policy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_environment_based_policy_allows_matching() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
            "#,
        )
        .unwrap();

        let developer = test_identity("dev@example.com", &["developers"]);
        let staging_attrs = ClusterAttributes {
            environment: Some("staging".to_string()),
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        assert!(engine
            .authorize(&developer, "staging", &staging_attrs)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_environment_based_policy_denies_prod() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
            "#,
        )
        .unwrap();

        let developer = test_identity("dev@example.com", &["developers"]);
        let prod_attrs = ClusterAttributes {
            environment: Some("prod".to_string()),
            region: "us-west-2".to_string(),
            tier: "premium".to_string(),
        };

        assert!(engine
            .authorize(&developer, "production", &prod_attrs)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_missing_environment_label_denied() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"developers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                resource has environment &&
                resource.environment != "prod"
            };
            "#,
        )
        .unwrap();

        let developer = test_identity("dev@example.com", &["developers"]);
        let no_env_attrs = ClusterAttributes {
            environment: None,
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        assert!(engine
            .authorize(&developer, "unlabeled", &no_env_attrs)
            .await
            .is_err());
    }

    // ========================================================================
    // Forbid Policy Tests (Deny Precedence)
    // ========================================================================

    #[tokio::test]
    async fn test_forbid_overrides_permit() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"admins",
                action == Lattice::Action::"AccessCluster",
                resource
            );
            forbid(
                principal == Lattice::User::"contractor@example.com",
                action == Lattice::Action::"AccessCluster",
                resource == Lattice::Cluster::"prod"
            );
            "#,
        )
        .unwrap();

        let attrs = ClusterAttributes::default();

        let admin = test_identity("admin@example.com", &["admins"]);
        assert!(engine.authorize(&admin, "prod", &attrs).await.is_ok());

        let contractor = test_identity("contractor@example.com", &["admins"]);
        assert!(engine.authorize(&contractor, "prod", &attrs).await.is_err());
    }

    // ========================================================================
    // Context-Based Policy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_time_based_policy_allows_within_hours() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"support",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.hour >= 9 && context.hour < 18
            };
            "#,
        )
        .unwrap();

        let user = test_identity("support@example.com", &["support"]);
        let attrs = ClusterAttributes::default();

        let business_hours = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(10),
        )])
        .unwrap();
        assert!(engine
            .authorize_with_context(&user, "prod", &attrs, business_hours)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_time_based_policy_denies_outside_hours() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"support",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.hour >= 9 && context.hour < 18
            };
            "#,
        )
        .unwrap();

        let user = test_identity("support@example.com", &["support"]);
        let attrs = ClusterAttributes::default();

        let after_hours = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(22),
        )])
        .unwrap();
        assert!(engine
            .authorize_with_context(&user, "prod", &attrs, after_hours)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_break_glass_policy() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"oncall",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.breakGlass == true &&
                context has incidentId
            };
            "#,
        )
        .unwrap();

        let oncall = test_identity("oncall@example.com", &["oncall"]);
        let attrs = ClusterAttributes::default();

        // With break-glass and incident ID - allowed
        let ctx_allowed = Context::from_pairs(vec![
            (
                "breakGlass".to_string(),
                RestrictedExpression::new_bool(true),
            ),
            (
                "incidentId".to_string(),
                RestrictedExpression::new_string("INC-12345".to_string()),
            ),
        ])
        .unwrap();
        assert!(engine
            .authorize_with_context(&oncall, "prod", &attrs, ctx_allowed)
            .await
            .is_ok());

        // Without incident ID - denied
        let ctx_no_incident = Context::from_pairs(vec![(
            "breakGlass".to_string(),
            RestrictedExpression::new_bool(true),
        )])
        .unwrap();
        assert!(engine
            .authorize_with_context(&oncall, "prod", &attrs, ctx_no_incident)
            .await
            .is_err());

        // breakGlass=false - denied
        let ctx_no_flag = Context::from_pairs(vec![
            (
                "breakGlass".to_string(),
                RestrictedExpression::new_bool(false),
            ),
            (
                "incidentId".to_string(),
                RestrictedExpression::new_string("INC-12345".to_string()),
            ),
        ])
        .unwrap();
        assert!(engine
            .authorize_with_context(&oncall, "prod", &attrs, ctx_no_flag)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_source_ip_policy() {
        let engine = PolicyEngine::with_policies(
            r#"
            permit(
                principal in Lattice::Group::"engineers",
                action == Lattice::Action::"AccessCluster",
                resource
            ) when {
                context.sourceIp like "10.0.*"
            };
            "#,
        )
        .unwrap();

        let engineer = test_identity("eng@example.com", &["engineers"]);
        let attrs = ClusterAttributes::default();

        // From VPN - allowed
        let ctx_vpn = Context::from_pairs(vec![(
            "sourceIp".to_string(),
            RestrictedExpression::new_string("10.0.1.100".to_string()),
        )])
        .unwrap();
        assert!(engine
            .authorize_with_context(&engineer, "prod", &attrs, ctx_vpn)
            .await
            .is_ok());

        // From outside - denied
        let ctx_outside = Context::from_pairs(vec![(
            "sourceIp".to_string(),
            RestrictedExpression::new_string("8.8.8.8".to_string()),
        )])
        .unwrap();
        assert!(engine
            .authorize_with_context(&engineer, "prod", &attrs, ctx_outside)
            .await
            .is_err());
    }
}
