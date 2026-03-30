//! ClusterIssuer builder — converts CertIssuer specs into cert-manager ClusterIssuer JSON.
//!
//! Pure function: no I/O, no K8s client. Takes a CertIssuer spec and optional DNSProvider
//! spec with resolved credential secret name, and produces a `serde_json::Value` suitable
//! for server-side apply.

use serde_json::{json, Value};

use lattice_common::crd::{CertIssuerSpec, DNSProviderSpec, DNSProviderType, IssuerType};

use lattice_common::{LATTICE_MANAGED_BY_LABEL, LATTICE_MANAGED_BY_VALUE};

/// Resolved DNS provider info needed by the builder.
///
/// The caller fetches the `DNSProvider` CRD and resolves `k8s_secret_ref()`
/// to get the ESO-synced secret name. This struct bundles both so the
/// builder stays pure (no K8s client).
pub struct ResolvedDnsProvider<'a> {
    /// The DNSProvider spec (provider type, zone, provider-specific config).
    pub spec: &'a DNSProviderSpec,
    /// Name of the K8s Secret containing credentials (ESO-synced).
    /// `None` for providers that don't need credentials (e.g., Pihole).
    pub secret_name: Option<&'a str>,
}

/// Build a cert-manager ClusterIssuer JSON value from a CertIssuer spec.
///
/// `issuer_secret_name` is the ESO-synced secret name from `CertIssuer.k8s_secret_ref()`.
/// For ACME DNS-01 challenges, `dns_provider` must be provided when the
/// CertIssuer spec references a DNSProvider via `acme.dnsProviderRef`.
pub fn build_cluster_issuer(
    name: &str,
    spec: &CertIssuerSpec,
    issuer_secret_name: Option<&str>,
    dns_provider: Option<&ResolvedDnsProvider<'_>>,
) -> Result<Value, String> {
    let issuer_name = format!("lattice-{}", name);

    let cm_spec = match spec.type_ {
        IssuerType::SelfSigned => json!({ "selfSigned": {} }),
        IssuerType::Ca => {
            spec.ca
                .as_ref()
                .ok_or("ca config required when type is ca")?;
            let secret_name = issuer_secret_name
                .ok_or("CA issuer requires ESO credentials")?;
            json!({
                "ca": {
                    "secretName": secret_name
                }
            })
        }
        IssuerType::Acme => {
            let acme = spec
                .acme
                .as_ref()
                .ok_or("acme config required when type is acme")?;

            let private_key_secret = format!("lattice-{}-acme-key", name);

            let solver = match &acme.dns_provider_ref {
                None => {
                    json!({ "http01": { "ingress": { "class": "istio" } } })
                }
                Some(_dns_ref) => {
                    let dp = dns_provider
                        .ok_or("dns_provider must be provided when acme.dnsProviderRef is set")?;
                    build_dns01_solver(dp)?
                }
            };

            json!({
                "acme": {
                    "email": acme.email,
                    "server": acme.server,
                    "privateKeySecretRef": {
                        "name": private_key_secret
                    },
                    "solvers": [solver]
                }
            })
        }
        IssuerType::Vault => {
            let vault = spec
                .vault
                .as_ref()
                .ok_or("vault config required when type is vault")?;
            let secret_name = issuer_secret_name
                .ok_or("Vault issuer requires ESO credentials")?;
            json!({
                "vault": {
                    "server": vault.server,
                    "path": vault.path,
                    "auth": {
                        "kubernetes": {
                            "role": "cert-manager",
                            "secretRef": {
                                "name": secret_name,
                                "key": "token"
                            }
                        }
                    }
                }
            })
        }
        _ => return Err(format!("unsupported issuer type: {}", spec.type_)),
    };

    Ok(json!({
        "apiVersion": "cert-manager.io/v1",
        "kind": "ClusterIssuer",
        "metadata": {
            "name": issuer_name,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        },
        "spec": cm_spec
    }))
}

/// Build a DNS-01 solver from the resolved DNS provider.
fn build_dns01_solver(dp: &ResolvedDnsProvider<'_>) -> Result<Value, String> {
    match dp.spec.provider_type {
        DNSProviderType::Route53 => route53_dns01_solver(dp),
        DNSProviderType::Cloudflare => cloudflare_dns01_solver(dp),
        DNSProviderType::Google => google_dns01_solver(dp),
        DNSProviderType::Azure => azure_dns01_solver(dp),
        DNSProviderType::Pihole | DNSProviderType::Designate => Err(format!(
            "{} DNS-01 challenges require a cert-manager webhook solver — not yet supported",
            dp.spec.provider_type
        )),
        _ => Err(format!(
            "unsupported DNS provider type for ACME DNS-01: {}",
            dp.spec.provider_type
        )),
    }
}

fn require_secret_name<'a>(dp: &'a ResolvedDnsProvider<'_>, provider: &str) -> Result<&'a str, String> {
    dp.secret_name
        .ok_or_else(|| format!("{provider} DNS-01 requires ESO credentials on the DNSProvider"))
}

fn route53_dns01_solver(dp: &ResolvedDnsProvider<'_>) -> Result<Value, String> {
    let mut route53 = serde_json::Map::new();

    if let Some(ref r53) = dp.spec.route53 {
        if let Some(ref region) = r53.region {
            route53.insert("region".to_string(), json!(region));
        }
        if let Some(ref zone_id) = r53.hosted_zone_id {
            route53.insert("hostedZoneID".to_string(), json!(zone_id));
        }
    }

    if let Some(secret_name) = dp.secret_name {
        route53.insert(
            "accessKeyIDSecretRef".to_string(),
            json!({ "name": secret_name, "key": "access-key-id" }),
        );
        route53.insert(
            "secretAccessKeySecretRef".to_string(),
            json!({ "name": secret_name, "key": "secret-access-key" }),
        );
    }

    Ok(json!({ "dns01": { "route53": Value::Object(route53) } }))
}

fn cloudflare_dns01_solver(dp: &ResolvedDnsProvider<'_>) -> Result<Value, String> {
    let secret_name = require_secret_name(dp, "Cloudflare")?;

    Ok(json!({
        "dns01": {
            "cloudflare": {
                "apiTokenSecretRef": {
                    "name": secret_name,
                    "key": "api-token"
                }
            }
        }
    }))
}

fn google_dns01_solver(dp: &ResolvedDnsProvider<'_>) -> Result<Value, String> {
    let google = dp
        .spec
        .google
        .as_ref()
        .ok_or("google config required for Google DNS-01")?;
    let secret_name = require_secret_name(dp, "Google")?;

    Ok(json!({
        "dns01": {
            "cloudDNS": {
                "project": google.project,
                "serviceAccountSecretRef": {
                    "name": secret_name,
                    "key": "key.json"
                }
            }
        }
    }))
}

fn azure_dns01_solver(dp: &ResolvedDnsProvider<'_>) -> Result<Value, String> {
    let azure = dp
        .spec
        .azure
        .as_ref()
        .ok_or("azure config required for Azure DNS-01")?;

    Ok(json!({
        "dns01": {
            "azureDNS": {
                "subscriptionID": azure.subscription_id,
                "resourceGroupName": azure.resource_group,
                "hostedZoneName": dp.spec.zone,
                "environment": "AzurePublicCloud"
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        AcmeIssuerSpec, AzureDnsConfig, CaIssuerSpec, CloudflareConfig, GoogleDnsConfig,
        PiholeConfig, ResourceParams, ResourceType, Route53Config, SecretParams, VaultIssuerSpec,
    };
    use lattice_common::crd::workload::resources::ResourceSpec;

    fn assert_metadata(val: &Value, expected_name: &str) {
        assert_eq!(val["apiVersion"], "cert-manager.io/v1");
        assert_eq!(val["kind"], "ClusterIssuer");
        assert_eq!(val["metadata"]["name"], expected_name);
        assert_eq!(
            val["metadata"]["labels"][LATTICE_MANAGED_BY_LABEL],
            LATTICE_MANAGED_BY_VALUE
        );
    }

    #[test]
    fn self_signed_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::SelfSigned,
            acme: None,
            ca: None,
            vault: None,
        };
        let result = build_cluster_issuer("dev", &spec, None, None).unwrap();
        assert_metadata(&result, "lattice-dev");
        assert_eq!(result["spec"]["selfSigned"], json!({}));
    }

    #[test]
    fn ca_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: Some(CaIssuerSpec {
                credentials: ResourceSpec::test_secret("pki/internal-ca", "lattice-local"),
            }),
            vault: None,
        };
        let result = build_cluster_issuer("internal", &spec, Some("internal-credentials"), None).unwrap();
        assert_metadata(&result, "lattice-internal");
        assert_eq!(result["spec"]["ca"]["secretName"], "internal-credentials");
    }

    #[test]
    fn ca_missing_config_errors() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: None,
            vault: None,
        };
        let err = build_cluster_issuer("bad", &spec, None, None).unwrap_err();
        assert!(err.contains("ca config required"));
    }

    #[test]
    fn acme_http01_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: None,
            }),
            ca: None,
            vault: None,
        };
        let result = build_cluster_issuer("public", &spec, None, None).unwrap();
        assert_metadata(&result, "lattice-public");

        let acme = &result["spec"]["acme"];
        assert_eq!(acme["email"], "ops@example.com");
        assert_eq!(
            acme["server"],
            "https://acme-v2.api.letsencrypt.org/directory"
        );
        assert_eq!(
            acme["privateKeySecretRef"]["name"],
            "lattice-public-acme-key"
        );

        let solver = &acme["solvers"][0];
        assert_eq!(solver["http01"]["ingress"]["class"], "istio");
    }

    #[test]
    fn acme_missing_config_errors() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: None,
            ca: None,
            vault: None,
        };
        let err = build_cluster_issuer("bad", &spec, None, None).unwrap_err();
        assert!(err.contains("acme config required"));
    }

    #[test]
    fn acme_dns01_route53() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("route53-prod".to_string()),
            }),
            ca: None,
            vault: None,
        };
        let dp_spec = DNSProviderSpec {
            route53: Some(Route53Config {
                region: Some("us-east-1".to_string()),
                hosted_zone_id: Some("Z1234567890".to_string()),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Route53, "example.com")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("route53-prod-credentials"),
        };

        let result = build_cluster_issuer("public", &spec, None, Some(&dp)).unwrap();
        assert_metadata(&result, "lattice-public");

        let solver = &result["spec"]["acme"]["solvers"][0];
        let r53 = &solver["dns01"]["route53"];
        assert_eq!(r53["region"], "us-east-1");
        assert_eq!(r53["hostedZoneID"], "Z1234567890");
        assert_eq!(r53["accessKeyIDSecretRef"]["name"], "route53-prod-credentials");
        assert_eq!(r53["accessKeyIDSecretRef"]["key"], "access-key-id");
        assert_eq!(r53["secretAccessKeySecretRef"]["name"], "route53-prod-credentials");
        assert_eq!(r53["secretAccessKeySecretRef"]["key"], "secret-access-key");
    }

    #[test]
    fn acme_dns01_cloudflare() {
        let dp_spec = DNSProviderSpec {
            cloudflare: Some(CloudflareConfig { proxied: false }),
            ..DNSProviderSpec::new(DNSProviderType::Cloudflare, "example.com")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("cf-prod-credentials"),
        };
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("cf-prod".to_string()),
            }),
            ca: None,
            vault: None,
        };

        let result = build_cluster_issuer("cf", &spec, None, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let cf = &solver["dns01"]["cloudflare"];
        assert_eq!(cf["apiTokenSecretRef"]["name"], "cf-prod-credentials");
        assert_eq!(cf["apiTokenSecretRef"]["key"], "api-token");
    }

    #[test]
    fn cloudflare_missing_creds_errors() {
        let dp_spec = DNSProviderSpec::new(DNSProviderType::Cloudflare, "example.com");
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("requires ESO credentials"));
    }

    #[test]
    fn acme_dns01_google() {
        let dp_spec = DNSProviderSpec {
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Google, "example.com")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("gcp-dns-credentials"),
        };
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("gcp-dns".to_string()),
            }),
            ca: None,
            vault: None,
        };

        let result = build_cluster_issuer("gcp", &spec, None, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let gdns = &solver["dns01"]["cloudDNS"];
        assert_eq!(gdns["project"], "my-project");
        assert_eq!(gdns["serviceAccountSecretRef"]["name"], "gcp-dns-credentials");
        assert_eq!(gdns["serviceAccountSecretRef"]["key"], "key.json");
    }

    #[test]
    fn google_missing_config_errors() {
        let dp_spec = DNSProviderSpec::new(DNSProviderType::Google, "example.com");
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("gcp-creds"),
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("google config required"));
    }

    #[test]
    fn google_missing_creds_errors() {
        let dp_spec = DNSProviderSpec {
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Google, "example.com")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("requires ESO credentials"));
    }

    #[test]
    fn acme_dns01_azure() {
        let dp_spec = DNSProviderSpec {
            azure: Some(AzureDnsConfig {
                subscription_id: "sub-123".to_string(),
                resource_group: "rg-dns".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Azure, "example.com")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("azure-dns-credentials"),
        };
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("azure-dns".to_string()),
            }),
            ca: None,
            vault: None,
        };

        let result = build_cluster_issuer("az", &spec, None, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let az = &solver["dns01"]["azureDNS"];
        assert_eq!(az["subscriptionID"], "sub-123");
        assert_eq!(az["resourceGroupName"], "rg-dns");
        assert_eq!(az["hostedZoneName"], "example.com");
        assert_eq!(az["environment"], "AzurePublicCloud");
    }

    #[test]
    fn azure_missing_config_errors() {
        let dp_spec = DNSProviderSpec::new(DNSProviderType::Azure, "example.com");
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("azure config required"));
    }

    #[test]
    fn pihole_dns01_rejected() {
        let dp_spec = DNSProviderSpec {
            pihole: Some(PiholeConfig {
                url: "http://pihole.local".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Pihole, "home.local")
        };
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("webhook solver"));
    }

    #[test]
    fn acme_dns01_missing_provider_errors() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("missing".to_string()),
            }),
            ca: None,
            vault: None,
        };
        let err = build_cluster_issuer("bad", &spec, None, None).unwrap_err();
        assert!(err.contains("dns_provider must be provided"));
    }

    #[test]
    fn vault_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: Some(VaultIssuerSpec {
                server: "https://vault.example.com".to_string(),
                path: "pki/issue/my-role".to_string(),
                auth_credentials: ResourceSpec::test_secret("vault/auth", "lattice-local"),
            }),
        };
        let result = build_cluster_issuer("vault-pki", &spec, Some("vault-pki-credentials"), None).unwrap();
        assert_metadata(&result, "lattice-vault-pki");

        let vault = &result["spec"]["vault"];
        assert_eq!(vault["server"], "https://vault.example.com");
        assert_eq!(vault["path"], "pki/issue/my-role");
        assert_eq!(vault["auth"]["kubernetes"]["role"], "cert-manager");
        assert_eq!(
            vault["auth"]["kubernetes"]["secretRef"]["name"],
            "vault-pki-credentials"
        );
        assert_eq!(vault["auth"]["kubernetes"]["secretRef"]["key"], "token");
    }

    #[test]
    fn vault_missing_config_errors() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: None,
        };
        let err = build_cluster_issuer("bad", &spec, None, None).unwrap_err();
        assert!(err.contains("vault config required"));
    }

    #[test]
    fn route53_minimal_no_region_no_zone() {
        let dp_spec = DNSProviderSpec::new(DNSProviderType::Route53, "example.com");
        let dp = ResolvedDnsProvider {
            spec: &dp_spec,
            secret_name: Some("aws-creds"),
        };
        let solver = build_dns01_solver(&dp).unwrap();
        let r53 = &solver["dns01"]["route53"];
        assert!(r53.get("region").is_none());
        assert!(r53.get("hostedZoneID").is_none());
        assert_eq!(r53["accessKeyIDSecretRef"]["name"], "aws-creds");
    }
}
