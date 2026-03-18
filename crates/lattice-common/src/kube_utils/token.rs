//! ServiceAccount token request utilities

use kube::api::Api;
use kube::Client;

/// Token lifetime in seconds (1 hour).
pub const PROXY_TOKEN_EXPIRATION_SECS: i64 = 3600;

/// Audience for proxy tokens. The auth proxy validates this audience
/// via TokenReview, preventing token reuse against the K8s API directly.
pub const PROXY_TOKEN_AUDIENCE: &str = "lattice-proxy";

/// Request a short-lived token for the istiod multi-cluster proxy.
///
/// Uses lattice-operator SA (cluster-admin) to give istiod full visibility
/// for cross-cluster service discovery via the auth proxy.
pub async fn request_istiod_proxy_token(client: &Client) -> Result<String, kube::Error> {
    use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::PostParams;

    const SA_NAME: &str = "lattice-operator";
    const SA_NAMESPACE: &str = "lattice-system";

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), SA_NAMESPACE);
    let token_request = TokenRequest {
        spec: TokenRequestSpec {
            audiences: vec![PROXY_TOKEN_AUDIENCE.to_string()],
            expiration_seconds: Some(PROXY_TOKEN_EXPIRATION_SECS),
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
