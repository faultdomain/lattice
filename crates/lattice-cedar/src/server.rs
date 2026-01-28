//! Envoy ext_authz gRPC server
//!
//! Implements the Envoy external authorization service using Cedar policies.

use std::net::SocketAddr;
use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse,
};
use envoy_types::ext_authz::v3::CheckResponseExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use crate::controller::Context;
use crate::entity::{Action, EntityBuilder, Resource};
use crate::error::{CedarError, Result};
use crate::jwt::{ValidatedToken, ValidationConfig};
use crate::metrics::{CedarMetrics, Timer};
use crate::policy::PolicyDecision;

/// Cedar ExtAuth gRPC server
pub struct CedarAuthzServer {
    /// Shared context with policy store and JWT validator
    ctx: Arc<Context>,
    /// Metrics
    metrics: Arc<CedarMetrics>,
    /// Server address
    addr: SocketAddr,
}

impl CedarAuthzServer {
    /// Create a new Cedar authorization server
    pub fn new(ctx: Arc<Context>, addr: SocketAddr) -> Self {
        Self {
            ctx,
            metrics: Arc::new(CedarMetrics::new()),
            addr,
        }
    }

    /// Get metrics reference
    pub fn metrics(&self) -> Arc<CedarMetrics> {
        self.metrics.clone()
    }

    /// Run the gRPC server
    pub async fn run(self) -> Result<()> {
        let addr = self.addr;
        let service = CedarAuthzService {
            ctx: self.ctx.clone(),
            metrics: self.metrics.clone(),
            entity_builder: EntityBuilder::new(),
        };

        info!(?addr, "Starting Cedar ExtAuth gRPC server");

        tonic::transport::Server::builder()
            .add_service(AuthorizationServer::new(service))
            .serve(addr)
            .await
            .map_err(|e| CedarError::grpc(format!("server error: {}", e)))
    }
}

/// Internal gRPC service implementation
struct CedarAuthzService {
    ctx: Arc<Context>,
    metrics: Arc<CedarMetrics>,
    entity_builder: EntityBuilder,
}

impl CedarAuthzService {
    /// Extract the target service from request attributes
    fn extract_service_info(&self, request: &CheckRequest) -> Option<(String, String)> {
        let attrs = request.attributes.as_ref()?;
        let dest = attrs.destination.as_ref()?;

        // Try to get service name from destination
        // Format: service.namespace.svc.cluster.local or just service.namespace
        let address = dest.address.as_ref()?;

        // Extract from socket address
        if let Some(socket) = &address.address {
            if let envoy_types::pb::envoy::config::core::v3::address::Address::SocketAddress(sa) =
                socket
            {
                // The address might be in format: service.namespace.svc.cluster.local
                let parts: Vec<&str> = sa.address.split('.').collect();
                if parts.len() >= 2 {
                    return Some((parts[1].to_string(), parts[0].to_string()));
                }
            }
        }

        // Fallback: try to extract from headers
        if let Some(http) = attrs.request.as_ref().and_then(|r| r.http.as_ref()) {
            // Check for x-lattice-namespace and x-lattice-service headers
            if let (Some(ns), Some(svc)) = (
                http.headers.get("x-lattice-namespace"),
                http.headers.get("x-lattice-service"),
            ) {
                return Some((ns.clone(), svc.clone()));
            }

            // Try host header
            if let Some(host) = http
                .headers
                .get(":authority")
                .or_else(|| http.headers.get("host"))
            {
                let parts: Vec<&str> = host.split('.').collect();
                if parts.len() >= 2 {
                    return Some((parts[1].to_string(), parts[0].to_string()));
                }
            }
        }

        None
    }

    /// Extract HTTP method from request
    fn extract_method(&self, request: &CheckRequest) -> String {
        request
            .attributes
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .and_then(|r| r.http.as_ref())
            .map(|h| h.method.clone())
            .unwrap_or_else(|| "GET".to_string())
    }

    /// Extract request path from request
    fn extract_path(&self, request: &CheckRequest) -> String {
        request
            .attributes
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .and_then(|r| r.http.as_ref())
            .map(|h| h.path.clone())
            .unwrap_or_else(|| "/".to_string())
    }

    /// Extract headers from request
    fn extract_headers(&self, request: &CheckRequest) -> std::collections::HashMap<String, String> {
        request
            .attributes
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .and_then(|r| r.http.as_ref())
            .map(|h| h.headers.clone())
            .unwrap_or_default()
    }

    /// Extract JWT token from Authorization header
    fn extract_token(&self, request: &CheckRequest) -> Option<String> {
        let headers = self.extract_headers(request);

        // Check Authorization header
        if let Some(auth) = headers.get("authorization") {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }

        // Check custom header
        if let Some(token) = headers.get("x-lattice-token") {
            return Some(token.clone());
        }

        None
    }

    /// Build an allow response
    fn allow_response(&self) -> CheckResponse {
        CheckResponse::with_status(Status::ok("authorized"))
    }

    /// Build a deny response
    fn deny_response(&self, message: &str) -> CheckResponse {
        CheckResponse::with_status(Status::permission_denied(message))
    }

    /// Build an unauthorized response (401)
    fn unauthorized_response(&self, message: &str) -> CheckResponse {
        CheckResponse::with_status(Status::unauthenticated(message))
    }

    /// Perform authorization check using the two-tier policy model
    ///
    /// Evaluation order:
    /// 1. All matching LatticeServicePolicy `forbid` rules -> if ANY matches, DENY
    /// 2. LatticeService embedded Cedar policy -> if permit matches, ALLOW
    /// 3. All matching LatticeServicePolicy `permit` rules -> if ANY matches, ALLOW
    /// 4. Default: DENY (or ALLOW if no policies configured)
    async fn do_check(&self, request: CheckRequest) -> Result<CheckResponse> {
        let timer = Timer::start();

        // Extract service info
        let (namespace, service) = self
            .extract_service_info(&request)
            .ok_or_else(|| CedarError::header("could not determine target service"))?;

        debug!(
            namespace = %namespace,
            service = %service,
            "Processing authorization request"
        );

        let policies = self.ctx.policy_store();

        // Check if service has any policies (embedded or inherited)
        if !policies.has_any_policy(&namespace, &service) {
            // No policy configured - allow by default
            self.metrics.record_cache_miss();
            debug!(
                namespace = %namespace,
                service = %service,
                "No policy configured, allowing request"
            );
            return Ok(self.allow_response());
        }

        self.metrics.record_cache_hit();

        // Get OIDC config from service
        let oidc_config = self.ctx.get_oidc_config(&namespace, &service);

        // Validate JWT if OIDC is configured
        let validated_token: Option<ValidatedToken> = if let Some(oidc) = oidc_config {
            let jwt_timer = Timer::start();

            let token_str = self.extract_token(&request).ok_or_else(|| {
                self.metrics.record_jwt_failure();
                CedarError::header("missing authorization header")
            })?;

            let config = ValidationConfig {
                issuer: oidc.issuer,
                audience: oidc.audience,
                jwks_uri: oidc.jwks_uri,
                clock_skew: 60,
            };

            match self.ctx.jwt_validator().validate(&token_str, &config).await {
                Ok(token) => {
                    self.metrics.record_jwt_time(jwt_timer.elapsed());
                    Some(token)
                }
                Err(e) => {
                    self.metrics.record_jwt_failure();
                    warn!(error = %e, "JWT validation failed");
                    return Ok(self.unauthorized_response(&e.to_string()));
                }
            }
        } else {
            None
        };

        // Build Cedar request
        let method = self.extract_method(&request);
        let path = self.extract_path(&request);
        let headers = self.extract_headers(&request);

        let action = Action::from_method(&method);
        let resource = Resource::new(&path, &service, &namespace, &method).with_headers(headers);

        let (cedar_request, entities) =
            self.entity_builder
                .build_request(validated_token.as_ref(), action, &resource)?;

        // Evaluate using the two-tier policy model
        let decision =
            policies.evaluate_with_inherited(&namespace, &service, &cedar_request, &entities);

        let elapsed = timer.elapsed();

        match decision {
            PolicyDecision::Allow => {
                self.metrics.record_allowed(elapsed);
                debug!(
                    namespace = %namespace,
                    service = %service,
                    decision = "allow",
                    elapsed_us = elapsed.as_micros(),
                    "Authorization decision"
                );
                Ok(self.allow_response())
            }
            PolicyDecision::Deny => {
                self.metrics.record_denied(elapsed);
                debug!(
                    namespace = %namespace,
                    service = %service,
                    decision = "deny",
                    elapsed_us = elapsed.as_micros(),
                    "Authorization decision"
                );
                Ok(self.deny_response("access denied by policy"))
            }
            PolicyDecision::NoMatch => {
                // No policies matched - this shouldn't happen if has_any_policy returned true
                // But if it does, allow by default (same as no policy configured)
                self.metrics.record_allowed(elapsed);
                debug!(
                    namespace = %namespace,
                    service = %service,
                    decision = "allow (no match)",
                    elapsed_us = elapsed.as_micros(),
                    "Authorization decision"
                );
                Ok(self.allow_response())
            }
        }
    }
}

#[tonic::async_trait]
impl Authorization for CedarAuthzService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> std::result::Result<Response<CheckResponse>, Status> {
        let check_request = request.into_inner();

        match self.do_check(check_request).await {
            Ok(response) => Ok(Response::new(response)),
            Err(e) => {
                self.metrics.record_error();
                error!(error = %e, "Authorization check error");

                // Return a proper error response instead of Status error
                // This allows Envoy to handle it gracefully
                if e.is_auth_failure() {
                    Ok(Response::new(self.unauthorized_response(&e.to_string())))
                } else {
                    Ok(Response::new(self.deny_response("internal error")))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_from_method() {
        // These tests verify the action mapping
        assert_eq!(Action::from_method("GET"), Action::Read);
        assert_eq!(Action::from_method("POST"), Action::Write);
        assert_eq!(Action::from_method("DELETE"), Action::Delete);
    }
}
