//! Cedar entity builders
//!
//! Builds Cedar entities (Principal, Action, Resource) from HTTP request context.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use serde_json::Value;

use crate::error::{CedarError, Result};
use crate::jwt::ValidatedToken;

/// HTTP action mapped to Cedar action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// GET, HEAD, OPTIONS requests
    Read,
    /// POST, PUT, PATCH requests
    Write,
    /// DELETE requests
    Delete,
}

impl Action {
    /// Create action from HTTP method
    pub fn from_method(method: &str) -> Self {
        match method.to_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Action::Read,
            "POST" | "PUT" | "PATCH" => Action::Write,
            "DELETE" => Action::Delete,
            _ => Action::Read, // Default to read for unknown methods
        }
    }

    /// Get the Cedar action name
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Delete => "delete",
        }
    }

    /// Convert to Cedar EntityUid
    pub fn to_entity_uid(&self) -> EntityUid {
        let type_name = EntityTypeName::from_str("Action").expect("valid type name");
        let id = EntityId::from_str(self.as_str()).expect("valid entity id");
        EntityUid::from_type_name_and_id(type_name, id)
    }
}

/// Principal information from JWT
#[derive(Debug, Clone)]
pub struct Principal {
    /// Subject identifier
    pub sub: String,
    /// Roles
    pub roles: Vec<String>,
    /// Groups
    pub groups: Vec<String>,
    /// Additional claims
    pub claims: HashMap<String, Value>,
}

impl Principal {
    /// Create a principal from a validated JWT token
    pub fn from_token(token: &ValidatedToken, roles_claim: &str, groups_claim: &str) -> Self {
        Self {
            sub: token.subject().unwrap_or("anonymous").to_string(),
            roles: token.get_roles(roles_claim),
            groups: token.get_groups(groups_claim),
            claims: token.claims.extra.clone(),
        }
    }

    /// Create an anonymous principal (for unauthenticated requests)
    pub fn anonymous() -> Self {
        Self {
            sub: "anonymous".to_string(),
            roles: vec![],
            groups: vec![],
            claims: HashMap::new(),
        }
    }

    /// Convert to Cedar EntityUid
    pub fn to_entity_uid(&self) -> EntityUid {
        let type_name = EntityTypeName::from_str("User").expect("valid type name");
        let id = EntityId::from_str(&self.sub).expect("valid entity id");
        EntityUid::from_type_name_and_id(type_name, id)
    }

    /// Convert to Cedar Entity with attributes
    pub fn to_entity(&self) -> Result<Entity> {
        let uid = self.to_entity_uid();

        let mut attrs = HashMap::new();

        // Add sub
        attrs.insert(
            "sub".to_string(),
            RestrictedExpression::new_string(self.sub.clone()),
        );

        // Add roles as a set
        let roles_vec: Vec<_> = self
            .roles
            .iter()
            .map(|r| RestrictedExpression::new_string(r.clone()))
            .collect();
        attrs.insert(
            "roles".to_string(),
            RestrictedExpression::new_set(roles_vec),
        );

        // Add groups as a set
        let groups_vec: Vec<_> = self
            .groups
            .iter()
            .map(|g| RestrictedExpression::new_string(g.clone()))
            .collect();
        attrs.insert(
            "groups".to_string(),
            RestrictedExpression::new_set(groups_vec),
        );

        Entity::new(uid, attrs, HashSet::new()).map_err(|e| {
            CedarError::policy_evaluation(format!("failed to create principal entity: {}", e))
        })
    }
}

/// Resource information from HTTP request
#[derive(Debug, Clone)]
pub struct Resource {
    /// Request path
    pub path: String,
    /// Target service name
    pub service: String,
    /// Target namespace
    pub namespace: String,
    /// HTTP method
    pub method: String,
    /// Request headers
    pub headers: HashMap<String, String>,
}

impl Resource {
    /// Create a new resource
    pub fn new(
        path: impl Into<String>,
        service: impl Into<String>,
        namespace: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            service: service.into(),
            namespace: namespace.into(),
            method: method.into(),
            headers: HashMap::new(),
        }
    }

    /// Add headers to the resource
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Convert to Cedar EntityUid
    pub fn to_entity_uid(&self) -> EntityUid {
        let type_name = EntityTypeName::from_str("Resource").expect("valid type name");
        // Use a composite ID: namespace/service/path
        let id_str = format!("{}/{}{}", self.namespace, self.service, self.path);
        let id = EntityId::from_str(&id_str).expect("valid entity id");
        EntityUid::from_type_name_and_id(type_name, id)
    }

    /// Convert to Cedar Entity with attributes
    pub fn to_entity(&self) -> Result<Entity> {
        let uid = self.to_entity_uid();

        let mut attrs = HashMap::new();

        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(self.path.clone()),
        );
        attrs.insert(
            "service".to_string(),
            RestrictedExpression::new_string(self.service.clone()),
        );
        attrs.insert(
            "namespace".to_string(),
            RestrictedExpression::new_string(self.namespace.clone()),
        );
        attrs.insert(
            "method".to_string(),
            RestrictedExpression::new_string(self.method.clone()),
        );

        // Add headers as a record
        let header_pairs: Vec<(String, RestrictedExpression)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), RestrictedExpression::new_string(v.clone())))
            .collect();
        attrs.insert(
            "headers".to_string(),
            RestrictedExpression::new_record(header_pairs).map_err(|e| {
                CedarError::policy_evaluation(format!("failed to create headers record: {}", e))
            })?,
        );

        Entity::new(uid, attrs, HashSet::new()).map_err(|e| {
            CedarError::policy_evaluation(format!("failed to create resource entity: {}", e))
        })
    }
}

/// Builder for Cedar authorization requests
#[derive(Debug)]
pub struct EntityBuilder {
    /// Roles claim path in JWT
    roles_claim: String,
    /// Groups claim path in JWT
    groups_claim: String,
}

impl Default for EntityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityBuilder {
    /// Create a new entity builder with default claim paths
    pub fn new() -> Self {
        Self {
            roles_claim: "roles".to_string(),
            groups_claim: "groups".to_string(),
        }
    }

    /// Set the roles claim path
    pub fn with_roles_claim(mut self, path: impl Into<String>) -> Self {
        self.roles_claim = path.into();
        self
    }

    /// Set the groups claim path
    pub fn with_groups_claim(mut self, path: impl Into<String>) -> Self {
        self.groups_claim = path.into();
        self
    }

    /// Build a Cedar request from components
    pub fn build_request(
        &self,
        token: Option<&ValidatedToken>,
        action: Action,
        resource: &Resource,
    ) -> Result<(Request, Entities)> {
        // Build principal
        let principal = match token {
            Some(t) => Principal::from_token(t, &self.roles_claim, &self.groups_claim),
            None => Principal::anonymous(),
        };

        let principal_uid = principal.to_entity_uid();
        let action_uid = action.to_entity_uid();
        let resource_uid = resource.to_entity_uid();

        // Build entities
        let principal_entity = principal.to_entity()?;
        let resource_entity = resource.to_entity()?;

        let entities =
            Entities::from_entities([principal_entity, resource_entity], None).map_err(|e| {
                CedarError::policy_evaluation(format!("failed to create entities: {}", e))
            })?;

        // Build request
        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            Context::empty(),
            None, // No schema validation at request time
        )
        .map_err(|e| CedarError::policy_evaluation(format!("failed to create request: {}", e)))?;

        Ok((request, entities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_from_method() {
        assert_eq!(Action::from_method("GET"), Action::Read);
        assert_eq!(Action::from_method("get"), Action::Read);
        assert_eq!(Action::from_method("HEAD"), Action::Read);
        assert_eq!(Action::from_method("OPTIONS"), Action::Read);
        assert_eq!(Action::from_method("POST"), Action::Write);
        assert_eq!(Action::from_method("PUT"), Action::Write);
        assert_eq!(Action::from_method("PATCH"), Action::Write);
        assert_eq!(Action::from_method("DELETE"), Action::Delete);
        assert_eq!(Action::from_method("UNKNOWN"), Action::Read);
    }

    #[test]
    fn test_action_to_entity_uid() {
        let read = Action::Read.to_entity_uid();
        assert!(read.to_string().contains("read"));

        let write = Action::Write.to_entity_uid();
        assert!(write.to_string().contains("write"));

        let delete = Action::Delete.to_entity_uid();
        assert!(delete.to_string().contains("delete"));
    }

    #[test]
    fn test_principal_anonymous() {
        let anon = Principal::anonymous();
        assert_eq!(anon.sub, "anonymous");
        assert!(anon.roles.is_empty());
        assert!(anon.groups.is_empty());
    }

    #[test]
    fn test_principal_to_entity() {
        let principal = Principal {
            sub: "user123".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            groups: vec!["engineering".to_string()],
            claims: HashMap::new(),
        };

        let entity = principal.to_entity();
        assert!(entity.is_ok());
    }

    #[test]
    fn test_resource_new() {
        let resource = Resource::new("/api/users", "api-server", "default", "GET");

        assert_eq!(resource.path, "/api/users");
        assert_eq!(resource.service, "api-server");
        assert_eq!(resource.namespace, "default");
        assert_eq!(resource.method, "GET");
    }

    #[test]
    fn test_resource_to_entity() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let resource =
            Resource::new("/api/users", "api-server", "default", "GET").with_headers(headers);

        let entity = resource.to_entity();
        assert!(entity.is_ok());
    }

    #[test]
    fn test_entity_builder() {
        let builder = EntityBuilder::new()
            .with_roles_claim("custom.roles")
            .with_groups_claim("custom.groups");

        let resource = Resource::new("/test", "svc", "ns", "GET");
        let result = builder.build_request(None, Action::Read, &resource);

        assert!(result.is_ok());
    }
}
