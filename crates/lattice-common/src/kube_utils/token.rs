//! ServiceAccount token request utilities

use kube::api::Api;
use kube::Client;

/// Request a short-lived token for the `lattice-istiod-proxy` ServiceAccount.
///
/// This SA has read-only RBAC (get/list/watch on services, endpoints, pods,
/// endpointslices) — the minimum required for Istio multi-cluster service
/// discovery. Token expires after 1 hour.
pub async fn request_istiod_proxy_token(client: &Client) -> Result<String, kube::Error> {
    use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::PostParams;

    const SA_NAME: &str = "lattice-istiod-proxy";
    const SA_NAMESPACE: &str = "istio-system";
    const TOKEN_EXPIRATION_SECS: i64 = 3600;

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), SA_NAMESPACE);
    let token_request = TokenRequest {
        spec: TokenRequestSpec {
            audiences: vec![],
            expiration_seconds: Some(TOKEN_EXPIRATION_SECS),
            ..Default::default()
        },
        ..Default::default()
    };

    let response = sa_api
        .create_token_request(SA_NAME, &PostParams::default(), &token_request)
        .await?;

    let status = response.status.ok_or_else(|| {
        kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "TokenRequest response missing status".to_string(),
            reason: "MissingStatus".to_string(),
            code: 500,
        })
    })?;
    Ok(status.token)
}
