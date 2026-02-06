//! Cedar policy engine
//!
//! Evaluates authorization requests using Cedar policies loaded from CRDs.
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

use std::collections::HashMap;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Response,
};
use kube::api::ListParams;
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::entities::{build_cluster_entity, build_entity_uid, build_user_entity};
use lattice_common::crd::CedarPolicy;
use lattice_common::INHERITED_LABEL;

// ============================================================================
// Error types
// ============================================================================

/// Error type for Cedar policy operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration error (invalid policy text, etc.)
    #[error("configuration error: {0}")]
    Config(String),
    /// Internal error (entity building, request construction)
    #[error("internal error: {0}")]
    Internal(String),
    /// Authorization denied
    #[error("authorization denied: {0}")]
    Forbidden(String),
    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
}

/// Result type for Cedar policy operations
pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Constants
// ============================================================================

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
    ///
    /// Accepts optional Cedar context for temporal/request metadata.
    #[instrument(
        skip(self, attrs, context),
        fields(otel.kind = "internal")
    )]
    pub async fn authorize_cluster(
        &self,
        username: &str,
        groups: &[String],
        cluster: &str,
        attrs: &ClusterAttributes,
        context: Option<Context>,
    ) -> Result<()> {
        let policy_set = self.policy_set.read().await;
        self.evaluate_cluster(
            username,
            groups,
            cluster,
            attrs,
            context.unwrap_or_else(Context::empty),
            &policy_set,
        )
    }

    /// Get list of clusters the user can access
    pub async fn accessible_clusters(
        &self,
        username: &str,
        groups: &[String],
        cluster_attrs: &HashMap<String, ClusterAttributes>,
    ) -> Vec<String> {
        let policy_set = self.policy_set.read().await;
        cluster_attrs
            .iter()
            .filter(|(cluster, attrs)| {
                self.evaluate_cluster(
                    username,
                    groups,
                    cluster,
                    attrs,
                    Context::empty(),
                    &policy_set,
                )
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

    /// Evaluate a Cedar authorization request with an arbitrary principal, action,
    /// resource, and entity set. Returns the raw Cedar response.
    ///
    /// Used internally by both cluster and secret authorization.
    pub(crate) fn evaluate_raw(
        &self,
        principal: &EntityUid,
        action: &EntityUid,
        resource: &EntityUid,
        context: Context,
        entities: &Entities,
        policy_set: &PolicySet,
    ) -> Result<Response> {
        let request = Request::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context,
            None,
        )
        .map_err(|e| Error::Internal(format!("Failed to build Cedar request: {}", e)))?;

        Ok(self
            .authorizer
            .is_authorized(&request, policy_set, entities))
    }

    /// Get a read lock on the policy set
    pub(crate) async fn read_policy_set(&self) -> tokio::sync::RwLockReadGuard<'_, PolicySet> {
        self.policy_set.read().await
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    /// Core cluster authorization evaluation
    fn evaluate_cluster(
        &self,
        username: &str,
        groups: &[String],
        cluster: &str,
        attrs: &ClusterAttributes,
        context: Context,
        policy_set: &PolicySet,
    ) -> Result<()> {
        let principal = build_entity_uid("User", username)?;
        let action_uid = build_entity_uid("Action", "AccessCluster")?;
        let resource = build_entity_uid("Cluster", cluster)?;

        // Build entities
        let mut entity_vec = build_user_entity(username, groups)?;
        entity_vec.push(build_cluster_entity(cluster, attrs)?);
        let entities = Entities::from_entities(entity_vec, None)
            .map_err(|e| Error::Internal(format!("Failed to create entities set: {}", e)))?;

        let response = self.evaluate_raw(
            &principal,
            &action_uid,
            &resource,
            context,
            &entities,
            policy_set,
        )?;

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
                    username, cluster
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

/// Check if a Kubernetes resource is a local resource (not inherited).
///
/// Resources without the `lattice.dev/inherited` label or with it set to a value
/// other than "true" are considered local.
fn is_local_resource(metadata: &kube::api::ObjectMeta) -> bool {
    !metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(INHERITED_LABEL))
        .map(|v| v == "true")
        .unwrap_or(false)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::RestrictedExpression;

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
    // Policy Engine Basic Tests
    // ========================================================================

    #[tokio::test]
    async fn test_permit_all_policy() {
        let engine = PolicyEngine::with_policies("permit(principal, action, resource);").unwrap();

        assert!(engine
            .authorize_cluster(
                "alice@example.com",
                &[],
                "any-cluster",
                &ClusterAttributes::default(),
                None,
            )
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_deny_by_default() {
        let engine = PolicyEngine::new();

        assert!(engine
            .authorize_cluster(
                "alice@example.com",
                &[],
                "any-cluster",
                &ClusterAttributes::default(),
                None,
            )
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

        let attrs = ClusterAttributes::default();

        assert!(engine
            .authorize_cluster("alice@example.com", &[], "prod-frontend", &attrs, None)
            .await
            .is_ok());
        assert!(engine
            .authorize_cluster("alice@example.com", &[], "staging", &attrs, None)
            .await
            .is_err());
        assert!(engine
            .authorize_cluster("bob@example.com", &[], "prod-frontend", &attrs, None)
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

        let admins = vec!["admins".to_string()];
        let devs = vec!["developers".to_string()];
        let attrs = ClusterAttributes::default();

        assert!(engine
            .authorize_cluster("alice@example.com", &admins, "any-cluster", &attrs, None)
            .await
            .is_ok());
        assert!(engine
            .authorize_cluster("bob@example.com", &devs, "any-cluster", &attrs, None)
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

        let accessible = engine
            .accessible_clusters("alice@example.com", &[], &clusters)
            .await;

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

        let groups = vec!["developers".to_string()];
        let staging_attrs = ClusterAttributes {
            environment: Some("staging".to_string()),
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        assert!(engine
            .authorize_cluster("dev@example.com", &groups, "staging", &staging_attrs, None)
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

        let groups = vec!["developers".to_string()];
        let prod_attrs = ClusterAttributes {
            environment: Some("prod".to_string()),
            region: "us-west-2".to_string(),
            tier: "premium".to_string(),
        };

        assert!(engine
            .authorize_cluster("dev@example.com", &groups, "production", &prod_attrs, None)
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

        let groups = vec!["developers".to_string()];
        let no_env_attrs = ClusterAttributes {
            environment: None,
            region: "us-west-2".to_string(),
            tier: "standard".to_string(),
        };

        assert!(engine
            .authorize_cluster("dev@example.com", &groups, "unlabeled", &no_env_attrs, None)
            .await
            .is_err());
    }

    // ========================================================================
    // Forbid Policy Tests
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

        let admins = vec!["admins".to_string()];
        let attrs = ClusterAttributes::default();

        assert!(engine
            .authorize_cluster("admin@example.com", &admins, "prod", &attrs, None)
            .await
            .is_ok());
        assert!(engine
            .authorize_cluster("contractor@example.com", &admins, "prod", &attrs, None)
            .await
            .is_err());
    }

    // ========================================================================
    // Context-Based Policy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_time_based_policy() {
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

        let groups = vec!["support".to_string()];
        let attrs = ClusterAttributes::default();

        let business_hours = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(10),
        )])
        .unwrap();
        assert!(engine
            .authorize_cluster(
                "support@example.com",
                &groups,
                "prod",
                &attrs,
                Some(business_hours)
            )
            .await
            .is_ok());

        let after_hours = Context::from_pairs(vec![(
            "hour".to_string(),
            RestrictedExpression::new_long(22),
        )])
        .unwrap();
        assert!(engine
            .authorize_cluster(
                "support@example.com",
                &groups,
                "prod",
                &attrs,
                Some(after_hours)
            )
            .await
            .is_err());
    }
}
