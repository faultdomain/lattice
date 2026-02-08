//! Cedar entity builders
//!
//! One function per semantic entity type. No call site ever constructs Cedar
//! entities inline — all policy meaning is centralized here.

use std::collections::{HashMap, HashSet};

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};

use crate::engine::{ClusterAttributes, Error, Result};

/// Lattice Cedar schema namespace
const NAMESPACE: &str = "Lattice";

// =============================================================================
// Low-Level Helpers
// =============================================================================

/// Build an entity UID for a given type and ID
pub fn build_entity_uid(type_name: &str, id: &str) -> Result<EntityUid> {
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

// =============================================================================
// User & Group Entities
// =============================================================================

/// Build a user entity with group membership
///
/// Creates:
/// - `Lattice::Group::<group>` entity for each group
/// - `Lattice::User::<username>` entity with group parents
///
/// Returns all entities (user + groups).
pub fn build_user_entity(username: &str, groups: &[String]) -> Result<Vec<Entity>> {
    let mut entities = Vec::new();

    // Create group entities and collect UIDs for user membership
    let mut group_uids = Vec::new();
    for group in groups {
        let uid = build_entity_uid("Group", group)?;
        let entity = Entity::new(uid.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| Error::Internal(format!("Failed to create group entity: {}", e)))?;
        entities.push(entity);
        group_uids.push(uid);
    }

    // Create user entity with group membership
    let user_uid = build_entity_uid("User", username)?;
    let user_entity = Entity::new(
        user_uid,
        HashMap::new(),
        group_uids.into_iter().collect::<HashSet<_>>(),
    )
    .map_err(|e| Error::Internal(format!("Failed to create user entity: {}", e)))?;
    entities.push(user_entity);

    Ok(entities)
}

// =============================================================================
// Cluster Entity
// =============================================================================

/// Build a cluster entity with attributes
///
/// Attributes:
/// - `environment`: only added if present (fail-closed via policy pattern)
/// - `region`: always present (defaults to "unknown")
/// - `tier`: always present (defaults to "standard")
pub fn build_cluster_entity(cluster_name: &str, attrs: &ClusterAttributes) -> Result<Entity> {
    let cluster_uid = build_entity_uid("Cluster", cluster_name)?;
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

    Entity::new(cluster_uid, attr_map, HashSet::new())
        .map_err(|e| Error::Internal(format!("Failed to create cluster entity: {}", e)))
}

// =============================================================================
// Service Entity (for secret access)
// =============================================================================

/// Build a service entity for secret access authorization
///
/// UID: `Lattice::Service::"namespace/name"`
///
/// Attributes:
/// - `namespace`: service namespace
/// - `name`: service name
pub fn build_service_entity(namespace: &str, name: &str) -> Result<Entity> {
    let uid_str = format!("{}/{}", namespace, name);
    let uid = build_entity_uid("Service", &uid_str)?;

    let mut attrs = HashMap::new();
    attrs.insert(
        "namespace".to_string(),
        RestrictedExpression::new_string(namespace.to_string()),
    );
    attrs.insert(
        "name".to_string(),
        RestrictedExpression::new_string(name.to_string()),
    );

    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| Error::Internal(format!("Failed to create service entity: {}", e)))
}

// =============================================================================
// SecretPath Entity (for secret access)
// =============================================================================

/// Build a secret path entity for secret access authorization
///
/// UID: `Lattice::SecretPath::"provider:remote_key"` — provider is part of identity
/// because two providers can legitimately share the same path string.
///
/// Attributes:
/// - `path`: full vault path
/// - `provider`: SecretProvider name
pub fn build_secret_path_entity(provider: &str, remote_key: &str) -> Result<Entity> {
    let uid_str = format!("{}:{}", provider, remote_key);
    let uid = build_entity_uid("SecretPath", &uid_str)?;

    let mut attrs = HashMap::new();
    attrs.insert(
        "path".to_string(),
        RestrictedExpression::new_string(remote_key.to_string()),
    );
    attrs.insert(
        "provider".to_string(),
        RestrictedExpression::new_string(provider.to_string()),
    );

    Entity::new(uid, attrs, HashSet::new())
        .map_err(|e| Error::Internal(format!("Failed to create secret path entity: {}", e)))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_entity_uid() {
        for (type_name, id) in [
            ("User", "alice@example.com"),
            ("Group", "admins"),
            ("Action", "AccessCluster"),
            ("Action", "AccessSecret"),
            ("Cluster", "prod-frontend"),
            ("Service", "payments/checkout"),
            ("SecretPath", "vault-prod:database/prod/creds"),
        ] {
            let uid = build_entity_uid(type_name, id).unwrap();
            assert!(uid.to_string().contains(type_name));
            assert!(uid.to_string().contains(id));
        }
    }

    #[test]
    fn test_build_user_entity_with_groups() {
        let groups = vec!["admins".to_string(), "developers".to_string()];
        let entities = build_user_entity("alice@example.com", &groups).unwrap();
        // 1 user + 2 groups = 3
        assert_eq!(entities.len(), 3);
    }

    #[test]
    fn test_build_user_entity_no_groups() {
        let entities = build_user_entity("alice@example.com", &[]).unwrap();
        // 1 user + 0 groups = 1
        assert_eq!(entities.len(), 1);
    }

    #[test]
    fn test_build_cluster_entity_with_environment() {
        let attrs = ClusterAttributes {
            environment: Some("prod".to_string()),
            region: "us-west-2".to_string(),
            tier: "premium".to_string(),
        };
        let entity = build_cluster_entity("prod-cluster", &attrs).unwrap();
        assert!(entity.uid().to_string().contains("prod-cluster"));
    }

    #[test]
    fn test_build_cluster_entity_without_environment() {
        let attrs = ClusterAttributes::default();
        let entity = build_cluster_entity("test", &attrs).unwrap();
        assert!(entity.uid().to_string().contains("test"));
    }

    #[test]
    fn test_build_service_entity() {
        let entity = build_service_entity("payments", "checkout").unwrap();
        assert!(entity.uid().to_string().contains("payments/checkout"));
    }

    #[test]
    fn test_build_secret_path_entity() {
        let entity = build_secret_path_entity("vault-prod", "database/prod/creds").unwrap();
        let uid_str = entity.uid().to_string();
        assert!(uid_str.contains("vault-prod:database/prod/creds"));
    }

    #[test]
    fn test_secret_path_entity_provider_uniqueness() {
        let entity_a = build_secret_path_entity("vault-a", "secret/foo").unwrap();
        let entity_b = build_secret_path_entity("vault-b", "secret/foo").unwrap();
        assert_ne!(entity_a.uid(), entity_b.uid());
    }
}
