//! ClusterIssuer builder — converts CertIssuer specs into cert-manager ClusterIssuer JSON.
//!
//! Pure function: no I/O, no K8s client. Takes a CertIssuer spec and optional DNSProvider
//! spec and produces a `serde_json::Value` suitable for server-side apply.

use serde_json::{json, Value};

use lattice_common::crd::{
    CertIssuerSpec, DNSProviderSpec, DNSProviderType, IssuerType,
};

/// Label applied to all managed ClusterIssuers for garbage collection.
pub const MANAGED_BY_LABEL: &str = "lattice.dev/managed-by";

/// Value of the managed-by label.
pub const MANAGED_BY_VALUE: &str = "lattice-operator";

/// Build a cert-manager ClusterIssuer JSON value from a CertIssuer spec.
///
/// The `name` parameter is the logical issuer name (e.g., "public") which becomes
/// the ClusterIssuer metadata name (e.g., "lattice-public").
///
/// For ACME DNS-01 challenges, `dns_provider` must be provided when the CertIssuer
/// spec references a DNSProvider via `acme.dnsProviderRef`.
pub fn build_cluster_issuer(
    name: &str,
    spec: &CertIssuerSpec,
    dns_provider: Option<&DNSProviderSpec>,
) -> Result<Value, String> {
    let issuer_name = format!("lattice-{}", name);

    let cm_spec = match spec.type_ {
        IssuerType::SelfSigned => json!({ "selfSigned": {} }),
        IssuerType::Ca => {
            let ca = spec
                .ca
                .as_ref()
                .ok_or("ca config required when type is ca")?;
            json!({
                "ca": {
                    "secretName": ca.secret_ref.name
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
                    // HTTP-01 solver
                    json!({ "http01": { "ingress": { "class": "istio" } } })
                }
                Some(_dns_ref) => {
                    let dp = dns_provider.ok_or(
                        "dns_provider must be provided when acme.dnsProviderRef is set",
                    )?;
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
            json!({
                "vault": {
                    "server": vault.server,
                    "path": vault.path,
                    "auth": {
                        "kubernetes": {
                            "role": "cert-manager",
                            "secretRef": {
                                "name": vault.auth_secret_ref.name,
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
                MANAGED_BY_LABEL: MANAGED_BY_VALUE
            }
        },
        "spec": cm_spec
    }))
}

/// Build a DNS-01 solver object from a DNSProvider spec.
fn build_dns01_solver(dp: &DNSProviderSpec) -> Result<Value, String> {
    let creds_secret = dp
        .credentials_secret_ref
        .as_ref()
        .map(|s| s.name.as_str());

    match dp.provider_type {
        DNSProviderType::Route53 => {
            let mut route53 = serde_json::Map::new();

            if let Some(ref r53) = dp.route53 {
                if let Some(ref region) = r53.region {
                    route53.insert("region".to_string(), json!(region));
                }
                if let Some(ref zone_id) = r53.hosted_zone_id {
                    route53.insert("hostedZoneID".to_string(), json!(zone_id));
                }
            }

            if let Some(secret_name) = creds_secret {
                route53.insert(
                    "accessKeyIDSecretRef".to_string(),
                    json!({
                        "name": secret_name,
                        "key": "access-key-id"
                    }),
                );
                route53.insert(
                    "secretAccessKeySecretRef".to_string(),
                    json!({
                        "name": secret_name,
                        "key": "secret-access-key"
                    }),
                );
            }

            Ok(json!({ "dns01": { "route53": Value::Object(route53) } }))
        }
        DNSProviderType::Cloudflare => {
            let secret_name = creds_secret
                .ok_or("credentials_secret_ref required for Cloudflare DNS-01")?;
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
        DNSProviderType::Google => {
            let google = dp
                .google
                .as_ref()
                .ok_or("google config required for Google DNS-01")?;
            let secret_name = creds_secret
                .ok_or("credentials_secret_ref required for Google DNS-01")?;
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
        DNSProviderType::Azure => {
            let azure = dp
                .azure
                .as_ref()
                .ok_or("azure config required for Azure DNS-01")?;
            Ok(json!({
                "dns01": {
                    "azureDNS": {
                        "subscriptionID": azure.subscription_id,
                        "resourceGroupName": azure.resource_group,
                        "hostedZoneName": dp.zone,
                        "environment": "AzurePublicCloud"
                    }
                }
            }))
        }
        DNSProviderType::Pihole => {
            Err("Pi-hole cannot be used for ACME DNS-01 challenges".to_string())
        }
        DNSProviderType::Designate => {
            Err("Designate DNS-01 challenges require a cert-manager webhook solver — not yet supported".to_string())
        }
        _ => Err(format!(
            "unsupported DNS provider type for ACME DNS-01: {}",
            dp.provider_type
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        AcmeIssuerSpec, AzureDnsConfig, CaIssuerSpec, CloudflareConfig, GoogleDnsConfig,
        Route53Config, SecretRef, VaultIssuerSpec,
    };

    // =========================================================================
    // Helpers
    // =========================================================================

    fn assert_metadata(val: &Value, expected_name: &str) {
        assert_eq!(val["apiVersion"], "cert-manager.io/v1");
        assert_eq!(val["kind"], "ClusterIssuer");
        assert_eq!(val["metadata"]["name"], expected_name);
        assert_eq!(
            val["metadata"]["labels"][MANAGED_BY_LABEL],
            MANAGED_BY_VALUE
        );
    }

    // =========================================================================
    // SelfSigned
    // =========================================================================

    #[test]
    fn self_signed_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::SelfSigned,
            acme: None,
            ca: None,
            vault: None,
        };
        let result = build_cluster_issuer("dev", &spec, None).unwrap();
        assert_metadata(&result, "lattice-dev");
        assert_eq!(result["spec"]["selfSigned"], json!({}));
    }

    // =========================================================================
    // CA
    // =========================================================================

    #[test]
    fn ca_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: Some(CaIssuerSpec {
                secret_ref: SecretRef {
                    name: "my-ca-secret".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
            vault: None,
        };
        let result = build_cluster_issuer("internal", &spec, None).unwrap();
        assert_metadata(&result, "lattice-internal");
        assert_eq!(result["spec"]["ca"]["secretName"], "my-ca-secret");
    }

    #[test]
    fn ca_missing_config_errors() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: None,
            vault: None,
        };
        let err = build_cluster_issuer("bad", &spec, None).unwrap_err();
        assert!(err.contains("ca config required"));
    }

    // =========================================================================
    // ACME HTTP-01
    // =========================================================================

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
        let result = build_cluster_issuer("public", &spec, None).unwrap();
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
        let err = build_cluster_issuer("bad", &spec, None).unwrap_err();
        assert!(err.contains("acme config required"));
    }

    // =========================================================================
    // ACME DNS-01 — Route53
    // =========================================================================

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
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Route53,
            zone: "example.com".to_string(),
            credentials_secret_ref: Some(SecretRef {
                name: "aws-dns-creds".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: Some(Route53Config {
                region: Some("us-east-1".to_string()),
                hosted_zone_id: Some("Z1234567890".to_string()),
            }),
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };

        let result = build_cluster_issuer("public", &spec, Some(&dp)).unwrap();
        assert_metadata(&result, "lattice-public");

        let solver = &result["spec"]["acme"]["solvers"][0];
        let r53 = &solver["dns01"]["route53"];
        assert_eq!(r53["region"], "us-east-1");
        assert_eq!(r53["hostedZoneID"], "Z1234567890");
        assert_eq!(r53["accessKeyIDSecretRef"]["name"], "aws-dns-creds");
        assert_eq!(r53["accessKeyIDSecretRef"]["key"], "access-key-id");
        assert_eq!(r53["secretAccessKeySecretRef"]["name"], "aws-dns-creds");
        assert_eq!(r53["secretAccessKeySecretRef"]["key"], "secret-access-key");
    }

    // =========================================================================
    // ACME DNS-01 — Cloudflare
    // =========================================================================

    #[test]
    fn acme_dns01_cloudflare() {
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
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Cloudflare,
            zone: "example.com".to_string(),
            credentials_secret_ref: Some(SecretRef {
                name: "cf-api-token".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: None,
            cloudflare: Some(CloudflareConfig { proxied: false }),
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };

        let result = build_cluster_issuer("cf", &spec, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let cf = &solver["dns01"]["cloudflare"];
        assert_eq!(cf["apiTokenSecretRef"]["name"], "cf-api-token");
        assert_eq!(cf["apiTokenSecretRef"]["key"], "api-token");
    }

    #[test]
    fn cloudflare_missing_creds_errors() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Cloudflare,
            zone: "example.com".to_string(),
            credentials_secret_ref: None,
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("credentials_secret_ref required"));
    }

    // =========================================================================
    // ACME DNS-01 — Google
    // =========================================================================

    #[test]
    fn acme_dns01_google() {
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
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Google,
            zone: "example.com".to_string(),
            credentials_secret_ref: Some(SecretRef {
                name: "gcp-sa-key".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: None,
            cloudflare: None,
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            azure: None,
            designate: None,
            resolver: None,
        };

        let result = build_cluster_issuer("gcp", &spec, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let gdns = &solver["dns01"]["cloudDNS"];
        assert_eq!(gdns["project"], "my-project");
        assert_eq!(gdns["serviceAccountSecretRef"]["name"], "gcp-sa-key");
        assert_eq!(gdns["serviceAccountSecretRef"]["key"], "key.json");
    }

    #[test]
    fn google_missing_config_errors() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Google,
            zone: "example.com".to_string(),
            credentials_secret_ref: Some(SecretRef {
                name: "gcp-sa-key".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("google config required"));
    }

    #[test]
    fn google_missing_creds_errors() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Google,
            zone: "example.com".to_string(),
            credentials_secret_ref: None,
            pihole: None,
            route53: None,
            cloudflare: None,
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            azure: None,
            designate: None,
            resolver: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("credentials_secret_ref required"));
    }

    // =========================================================================
    // ACME DNS-01 — Azure
    // =========================================================================

    #[test]
    fn acme_dns01_azure() {
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
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Azure,
            zone: "example.com".to_string(),
            credentials_secret_ref: None,
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: Some(AzureDnsConfig {
                subscription_id: "sub-123".to_string(),
                resource_group: "rg-dns".to_string(),
            }),
            designate: None,
            resolver: None,
        };

        let result = build_cluster_issuer("az", &spec, Some(&dp)).unwrap();
        let solver = &result["spec"]["acme"]["solvers"][0];
        let az = &solver["dns01"]["azureDNS"];
        assert_eq!(az["subscriptionID"], "sub-123");
        assert_eq!(az["resourceGroupName"], "rg-dns");
        assert_eq!(az["hostedZoneName"], "example.com");
        assert_eq!(az["environment"], "AzurePublicCloud");
    }

    #[test]
    fn azure_missing_config_errors() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Azure,
            zone: "example.com".to_string(),
            credentials_secret_ref: None,
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("azure config required"));
    }

    // =========================================================================
    // ACME DNS-01 — PiHole (rejected)
    // =========================================================================

    #[test]
    fn pihole_dns01_rejected() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Pihole,
            zone: "home.local".to_string(),
            credentials_secret_ref: None,
            pihole: Some(lattice_common::crd::PiholeConfig {
                url: "http://pihole.local".to_string(),
            }),
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };
        let err = build_dns01_solver(&dp).unwrap_err();
        assert!(err.contains("Pi-hole cannot be used"));
    }

    // =========================================================================
    // ACME DNS-01 — missing dns_provider
    // =========================================================================

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
        let err = build_cluster_issuer("bad", &spec, None).unwrap_err();
        assert!(err.contains("dns_provider must be provided"));
    }

    // =========================================================================
    // Vault
    // =========================================================================

    #[test]
    fn vault_issuer() {
        let spec = CertIssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: Some(VaultIssuerSpec {
                server: "https://vault.example.com".to_string(),
                path: "pki/issue/my-role".to_string(),
                auth_secret_ref: SecretRef {
                    name: "vault-token".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
        };
        let result = build_cluster_issuer("vault-pki", &spec, None).unwrap();
        assert_metadata(&result, "lattice-vault-pki");

        let vault = &result["spec"]["vault"];
        assert_eq!(vault["server"], "https://vault.example.com");
        assert_eq!(vault["path"], "pki/issue/my-role");
        assert_eq!(vault["auth"]["kubernetes"]["role"], "cert-manager");
        assert_eq!(
            vault["auth"]["kubernetes"]["secretRef"]["name"],
            "vault-token"
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
        let err = build_cluster_issuer("bad", &spec, None).unwrap_err();
        assert!(err.contains("vault config required"));
    }

    // =========================================================================
    // Route53 minimal (no region/zone ID)
    // =========================================================================

    #[test]
    fn route53_minimal_no_region_no_zone() {
        let dp = DNSProviderSpec {
            provider_type: DNSProviderType::Route53,
            zone: "example.com".to_string(),
            credentials_secret_ref: Some(SecretRef {
                name: "aws-creds".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
            resolver: None,
        };
        let solver = build_dns01_solver(&dp).unwrap();
        let r53 = &solver["dns01"]["route53"];
        // No region or hostedZoneID keys
        assert!(r53.get("region").is_none());
        assert!(r53.get("hostedZoneID").is_none());
        // Creds still present
        assert_eq!(r53["accessKeyIDSecretRef"]["name"], "aws-creds");
    }
}
