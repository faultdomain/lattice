//! ValidatingWebhookConfiguration management
//!
//! Builds and applies a single ValidatingWebhookConfiguration that covers
//! all validated Lattice CRDs, with the CA bundle injected for TLS trust.

use k8s_openapi::api::admissionregistration::v1::{
    RuleWithOperations, ServiceReference, ValidatingWebhook, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{ObjectMeta, Patch, PatchParams};
use kube::{Api, Client};

use crate::certs::{WEBHOOK_NAMESPACE, WEBHOOK_TLS_SECRET_NAME};
use crate::error::Error;

/// Name of the ValidatingWebhookConfiguration
const WEBHOOK_CONFIG_NAME: &str = "lattice-validating-webhook";

/// Service name for the webhook
const WEBHOOK_SERVICE_NAME: &str = lattice_common::OPERATOR_NAME;

/// Service namespace for the webhook
const WEBHOOK_SERVICE_NAMESPACE: &str = lattice_core::LATTICE_SYSTEM_NAMESPACE;

/// Port the webhook server listens on
const WEBHOOK_PORT: i32 = lattice_common::DEFAULT_WEBHOOK_PORT as i32;

/// Path for the validation endpoint
const WEBHOOK_PATH: &str = "/validate";

/// Apply the webhook Service and ValidatingWebhookConfiguration.
///
/// Called by the leader after CRDs are installed. First ensures a K8s
/// Service exists to route traffic to operator pods on the webhook port,
/// then reads the CA certificate from the webhook TLS Secret (created by
/// `start_webhook_server`) and applies the ValidatingWebhookConfiguration.
pub async fn ensure_webhook_configuration(client: &Client) -> Result<(), Error> {
    ensure_webhook_service(client).await?;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), WEBHOOK_NAMESPACE);
    let secret = secrets
        .get(WEBHOOK_TLS_SECRET_NAME)
        .await
        .map_err(|e| Error::Tls(format!("webhook TLS secret not found: {e}")))?;

    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| Error::Tls("webhook TLS secret has no data".to_string()))?;
    let ca_bytes = &data
        .get("ca.crt")
        .ok_or_else(|| Error::Tls("webhook TLS secret missing ca.crt".to_string()))?
        .0;

    let api: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());

    let config = build_webhook_configuration(ca_bytes);

    api.patch(
        WEBHOOK_CONFIG_NAME,
        &PatchParams::apply("lattice-webhook"),
        &Patch::Apply(&config),
    )
    .await?;

    tracing::info!(
        name = WEBHOOK_CONFIG_NAME,
        "Applied ValidatingWebhookConfiguration"
    );

    Ok(())
}

/// Ensure the K8s Service exists for the admission webhook.
///
/// The Service routes traffic from the API server to operator pods on the
/// webhook port. Uses server-side apply for idempotency.
async fn ensure_webhook_service(client: &Client) -> Result<(), Error> {
    let svc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": WEBHOOK_SERVICE_NAME,
            "namespace": WEBHOOK_SERVICE_NAMESPACE,
            "labels": {
                (lattice_common::LABEL_MANAGED_BY): lattice_common::LABEL_MANAGED_BY_LATTICE
            }
        },
        "spec": {
            "selector": {
                "app": lattice_common::OPERATOR_NAME
            },
            "ports": [{
                "name": "webhook",
                "port": WEBHOOK_PORT,
                "targetPort": WEBHOOK_PORT,
                "protocol": "TCP"
            }]
        }
    });

    let svc_api: Api<k8s_openapi::api::core::v1::Service> =
        Api::namespaced(client.clone(), WEBHOOK_SERVICE_NAMESPACE);
    svc_api
        .patch(
            WEBHOOK_SERVICE_NAME,
            &PatchParams::apply("lattice-webhook"),
            &Patch::Apply(&svc),
        )
        .await?;

    tracing::info!(
        service = WEBHOOK_SERVICE_NAME,
        namespace = WEBHOOK_SERVICE_NAMESPACE,
        port = WEBHOOK_PORT,
        "Ensured admission webhook service"
    );

    Ok(())
}

/// Build the ValidatingWebhookConfiguration manifest
fn build_webhook_configuration(ca_bundle: &[u8]) -> ValidatingWebhookConfiguration {
    let service_ref = ServiceReference {
        name: WEBHOOK_SERVICE_NAME.to_string(),
        namespace: WEBHOOK_SERVICE_NAMESPACE.to_string(),
        path: Some(WEBHOOK_PATH.to_string()),
        port: Some(WEBHOOK_PORT),
    };

    let rules = vec![
        // LatticeCluster (cluster-scoped)
        webhook_rule("latticeclusters", &["*"]),
        // LatticeJob (namespaced)
        webhook_rule("latticejobs", &["*"]),
        // LatticeService (namespaced)
        webhook_rule("latticeservices", &["*"]),
        // LatticeMeshMember (namespaced)
        webhook_rule("latticemeshmembers", &["*"]),
        // LatticeModel (namespaced)
        webhook_rule("latticemodels", &["*"]),
        // SecretProvider (namespaced)
        webhook_rule("secretproviders", &["*"]),
    ];

    let webhook = ValidatingWebhook {
        name: "validate.lattice.dev".to_string(),
        admission_review_versions: vec!["v1".to_string()],
        client_config: k8s_openapi::api::admissionregistration::v1::WebhookClientConfig {
            service: Some(service_ref),
            ca_bundle: Some(k8s_openapi::ByteString(ca_bundle.to_vec())),
            ..Default::default()
        },
        rules: Some(rules),
        failure_policy: Some("Fail".to_string()),
        side_effects: "None".to_string(),
        namespace_selector: Some(LabelSelector::default()),
        ..Default::default()
    };

    ValidatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some(WEBHOOK_CONFIG_NAME.to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![webhook]),
    }
}

/// Build a RuleWithOperations for a specific Lattice CRD resource
fn webhook_rule(resource: &str, api_versions: &[&str]) -> RuleWithOperations {
    RuleWithOperations {
        api_groups: Some(vec!["lattice.dev".to_string()]),
        api_versions: Some(api_versions.iter().map(|v| v.to_string()).collect()),
        operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
        resources: Some(vec![resource.to_string()]),
        scope: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_configuration_has_correct_structure() {
        let ca_bundle = b"test-ca-bundle";
        let config = build_webhook_configuration(ca_bundle);

        assert_eq!(config.metadata.name.as_deref(), Some(WEBHOOK_CONFIG_NAME));

        let webhooks = config.webhooks.expect("webhooks should be present");
        assert_eq!(webhooks.len(), 1);

        let webhook = &webhooks[0];
        assert_eq!(webhook.name, "validate.lattice.dev");
        assert_eq!(webhook.admission_review_versions, vec!["v1".to_string()]);
        assert_eq!(webhook.failure_policy.as_deref(), Some("Fail"));
        assert_eq!(webhook.side_effects, "None");

        // Check service reference
        let service = webhook
            .client_config
            .service
            .as_ref()
            .expect("service should be present");
        assert_eq!(service.name, WEBHOOK_SERVICE_NAME);
        assert_eq!(service.namespace, WEBHOOK_SERVICE_NAMESPACE);
        assert_eq!(service.port, Some(WEBHOOK_PORT));
        assert_eq!(service.path.as_deref(), Some(WEBHOOK_PATH));

        // Check CA bundle
        let bundle = webhook
            .client_config
            .ca_bundle
            .as_ref()
            .expect("ca_bundle should be present");
        assert_eq!(bundle.0, ca_bundle);
    }

    #[test]
    fn webhook_rules_cover_all_crds() {
        let config = build_webhook_configuration(b"ca");
        let webhooks = config.webhooks.expect("webhooks");
        let rules = webhooks[0].rules.as_ref().expect("rules should be present");

        let resources: Vec<&str> = rules
            .iter()
            .flat_map(|r| r.resources.as_ref().unwrap())
            .map(|s| s.as_str())
            .collect();

        assert!(resources.contains(&"latticeclusters"));
        assert!(resources.contains(&"latticejobs"));
        assert!(resources.contains(&"latticeservices"));
        assert!(resources.contains(&"latticemeshmembers"));
        assert!(resources.contains(&"latticemodels"));
        assert!(resources.contains(&"secretproviders"));
    }

    #[test]
    fn webhook_rules_have_create_and_update() {
        let config = build_webhook_configuration(b"ca");
        let webhooks = config.webhooks.expect("webhooks");
        let rules = webhooks[0].rules.as_ref().expect("rules");

        for rule in rules {
            let ops = rule.operations.as_ref().expect("operations");
            assert!(ops.contains(&"CREATE".to_string()));
            assert!(ops.contains(&"UPDATE".to_string()));
            assert!(!ops.contains(&"DELETE".to_string()));
        }
    }

    #[test]
    fn webhook_rules_use_lattice_group() {
        let config = build_webhook_configuration(b"ca");
        let webhooks = config.webhooks.expect("webhooks");
        let rules = webhooks[0].rules.as_ref().expect("rules");

        for rule in rules {
            let groups = rule.api_groups.as_ref().expect("api_groups");
            assert!(groups.contains(&"lattice.dev".to_string()));
        }
    }
}
