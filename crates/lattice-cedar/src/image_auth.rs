//! Image signature verification authorization
//!
//! Evaluates Cedar policies to determine if a service is allowed to skip
//! image signature verification. Default-deny: unsigned images are rejected
//! unless a Cedar policy permits `SkipImageVerification`.

use crate::engine::{DenialReason, PolicyEngine};
use crate::entities::{build_entity_uid, build_image_ref_entity, build_service_entity};

/// Request to check if a service can skip image verification for specific images.
pub struct ImageVerifyRequest {
    /// Service name.
    pub service_name: String,
    /// Service namespace.
    pub namespace: String,
    /// Workload kind ("service", "job", "model").
    pub kind: String,
    /// Image references that failed signature verification.
    pub unsigned_images: Vec<String>,
}

/// Result of image verification authorization.
pub struct ImageVerifyResult {
    /// Images that are denied (no Cedar policy permits skipping verification).
    pub denied: Vec<ImageDenial>,
}

impl ImageVerifyResult {
    /// Check if all unsigned images were allowed by Cedar policy.
    pub fn is_allowed(&self) -> bool {
        self.denied.is_empty()
    }
}

/// A denied unsigned image.
pub struct ImageDenial {
    /// The image reference that was denied.
    pub image: String,
    /// Why the image was denied.
    pub reason: DenialReason,
}

impl PolicyEngine {
    /// Check if a service is allowed to use unsigned images.
    ///
    /// Called after cosign verification fails for one or more images. If Cedar
    /// permits `SkipImageVerification` for the service + image, the image is
    /// allowed despite missing a valid signature.
    pub async fn authorize_unsigned_images(
        &self,
        request: &ImageVerifyRequest,
    ) -> ImageVerifyResult {
        let policy_set = self.read_policy_set();
        let action_uid = match build_entity_uid("Action", "SkipImageVerification") {
            Ok(uid) => uid,
            Err(e) => {
                return ImageVerifyResult {
                    denied: request
                        .unsigned_images
                        .iter()
                        .map(|image| ImageDenial {
                            image: image.clone(),
                            reason: DenialReason::InternalError(format!(
                                "failed to build Cedar action: {e}"
                            )),
                        })
                        .collect(),
                };
            }
        };

        let principal = match build_service_entity(
            &request.namespace,
            &request.service_name,
            &request.kind,
        ) {
            Ok(e) => e,
            Err(e) => {
                return ImageVerifyResult {
                    denied: request
                        .unsigned_images
                        .iter()
                        .map(|image| ImageDenial {
                            image: image.clone(),
                            reason: DenialReason::InternalError(format!(
                                "failed to build Cedar principal: {e}"
                            )),
                        })
                        .collect(),
                };
            }
        };

        let mut denied = Vec::new();

        for image in &request.unsigned_images {
            let resource = match build_image_ref_entity(image) {
                Ok(e) => e,
                Err(e) => {
                    denied.push(ImageDenial {
                        image: image.clone(),
                        reason: DenialReason::InternalError(format!(
                            "failed to build Cedar resource: {e}"
                        )),
                    });
                    continue;
                }
            };

            let resource_uid = resource.uid().clone();
            let entities =
                cedar_policy::Entities::from_entities([principal.clone(), resource], None)
                    .unwrap_or_default();

            let request = cedar_policy::Request::new(
                principal.uid().clone(),
                action_uid.clone(),
                resource_uid,
                cedar_policy::Context::empty(),
                None,
            );

            let response = match request {
                Ok(req) => {
                    let authorizer = cedar_policy::Authorizer::new();
                    authorizer.is_authorized(&req, &policy_set, &entities)
                }
                Err(e) => {
                    denied.push(ImageDenial {
                        image: image.clone(),
                        reason: DenialReason::InternalError(format!(
                            "failed to build Cedar request: {e}"
                        )),
                    });
                    continue;
                }
            };

            match response.decision() {
                cedar_policy::Decision::Deny => {
                    denied.push(ImageDenial {
                        image: image.clone(),
                        reason: DenialReason::NoPermitPolicy,
                    });
                }
                cedar_policy::Decision::Allow => {
                    // Cedar permits skipping verification for this image
                }
            }
        }

        ImageVerifyResult { denied }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_policies_denies_unsigned_images() {
        let engine = PolicyEngine::new();
        let result = engine
            .authorize_unsigned_images(&ImageVerifyRequest {
                service_name: "api".to_string(),
                namespace: "prod".to_string(),
                kind: "service".to_string(),
                unsigned_images: vec!["ghcr.io/acme/app:v1.0".to_string()],
            })
            .await;
        assert!(!result.is_allowed());
        assert_eq!(result.denied.len(), 1);
    }

    #[tokio::test]
    async fn permit_policy_allows_skip() {
        let engine = PolicyEngine::with_policies(
            r#"permit(
                principal,
                action == Lattice::Action::"SkipImageVerification",
                resource
            );"#,
        )
        .unwrap();

        let result = engine
            .authorize_unsigned_images(&ImageVerifyRequest {
                service_name: "api".to_string(),
                namespace: "prod".to_string(),
                kind: "service".to_string(),
                unsigned_images: vec!["ghcr.io/acme/app:v1.0".to_string()],
            })
            .await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn namespace_scoped_policy() {
        let engine = PolicyEngine::with_policies(
            r#"permit(
                principal,
                action == Lattice::Action::"SkipImageVerification",
                resource
            ) when {
                principal.namespace == "debug"
            };"#,
        )
        .unwrap();

        // debug namespace: allowed
        let result = engine
            .authorize_unsigned_images(&ImageVerifyRequest {
                service_name: "tool".to_string(),
                namespace: "debug".to_string(),
                kind: "service".to_string(),
                unsigned_images: vec!["alpine:latest".to_string()],
            })
            .await;
        assert!(result.is_allowed());

        // prod namespace: denied
        let result = engine
            .authorize_unsigned_images(&ImageVerifyRequest {
                service_name: "api".to_string(),
                namespace: "prod".to_string(),
                kind: "service".to_string(),
                unsigned_images: vec!["alpine:latest".to_string()],
            })
            .await;
        assert!(!result.is_allowed());
    }
}
