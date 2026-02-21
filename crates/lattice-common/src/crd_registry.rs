//! Centralized CRD discovery registry
//!
//! Single registry shared across all controllers for third-party CRD API
//! version resolution. Replaces per-controller discovery structs with a
//! unified `DashMap`-based cache that supports lazy resolution.

use dashmap::DashMap;
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{info, warn};

use crate::kube_utils::{build_api_resource, find_discovered_resource};

/// Known third-party CRD types managed by Lattice controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrdKind {
    /// ExternalSecret (external-secrets.io)
    ExternalSecret,
    /// ScaledObject (keda.sh)
    ScaledObject,
    /// VMServiceScrape (operator.victoriametrics.com)
    VMServiceScrape,
    /// CiliumNetworkPolicy (cilium.io)
    CiliumNetworkPolicy,
    /// AuthorizationPolicy (security.istio.io)
    AuthorizationPolicy,
    /// ServiceEntry (networking.istio.io)
    ServiceEntry,
    /// PeerAuthentication (security.istio.io)
    PeerAuthentication,
    /// Gateway (gateway.networking.k8s.io)
    Gateway,
    /// HTTPRoute (gateway.networking.k8s.io)
    HttpRoute,
    /// GRPCRoute (gateway.networking.k8s.io)
    GrpcRoute,
    /// TCPRoute (gateway.networking.k8s.io)
    TcpRoute,
    /// Certificate (cert-manager.io)
    Certificate,
    /// LatticeMeshMember (lattice.dev)
    MeshMember,
    /// TracingPolicyNamespaced (cilium.io)
    TracingPolicyNamespaced,
    /// Volcano Job (batch.volcano.sh)
    VolcanoJob,
}

/// All CrdKind variants for iteration.
const ALL_CRD_KINDS: &[CrdKind] = &[
    CrdKind::ExternalSecret,
    CrdKind::ScaledObject,
    CrdKind::VMServiceScrape,
    CrdKind::CiliumNetworkPolicy,
    CrdKind::AuthorizationPolicy,
    CrdKind::ServiceEntry,
    CrdKind::PeerAuthentication,
    CrdKind::Gateway,
    CrdKind::HttpRoute,
    CrdKind::GrpcRoute,
    CrdKind::TcpRoute,
    CrdKind::Certificate,
    CrdKind::MeshMember,
    CrdKind::TracingPolicyNamespaced,
    CrdKind::VolcanoJob,
];

impl CrdKind {
    /// API group for discovery lookup.
    pub fn group(&self) -> &'static str {
        match self {
            Self::ExternalSecret => "external-secrets.io",
            Self::ScaledObject => "keda.sh",
            Self::VMServiceScrape => "operator.victoriametrics.com",
            Self::CiliumNetworkPolicy | Self::TracingPolicyNamespaced => "cilium.io",
            Self::AuthorizationPolicy | Self::PeerAuthentication => "security.istio.io",
            Self::ServiceEntry => "networking.istio.io",
            Self::Gateway | Self::HttpRoute | Self::GrpcRoute | Self::TcpRoute => {
                "gateway.networking.k8s.io"
            }
            Self::Certificate => "cert-manager.io",
            Self::MeshMember => "lattice.dev",
            Self::VolcanoJob => "batch.volcano.sh",
        }
    }

    /// Kubernetes Kind string for discovery lookup.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::ExternalSecret => "ExternalSecret",
            Self::ScaledObject => "ScaledObject",
            Self::VMServiceScrape => "VMServiceScrape",
            Self::CiliumNetworkPolicy => "CiliumNetworkPolicy",
            Self::AuthorizationPolicy => "AuthorizationPolicy",
            Self::ServiceEntry => "ServiceEntry",
            Self::PeerAuthentication => "PeerAuthentication",
            Self::Gateway => "Gateway",
            Self::HttpRoute => "HTTPRoute",
            Self::GrpcRoute => "GRPCRoute",
            Self::TcpRoute => "TCPRoute",
            Self::Certificate => "Certificate",
            Self::MeshMember => "LatticeMeshMember",
            Self::TracingPolicyNamespaced => "TracingPolicyNamespaced",
            Self::VolcanoJob => "Job",
        }
    }

    /// Hardcoded API version used when discovery fails entirely.
    fn hardcoded_api_version(&self) -> &'static str {
        match self {
            Self::ExternalSecret => "external-secrets.io/v1",
            Self::ScaledObject => "keda.sh/v1alpha1",
            Self::VMServiceScrape => "operator.victoriametrics.com/v1beta1",
            Self::CiliumNetworkPolicy => "cilium.io/v2",
            Self::AuthorizationPolicy | Self::PeerAuthentication => "security.istio.io/v1",
            Self::ServiceEntry => "networking.istio.io/v1",
            Self::Gateway | Self::HttpRoute | Self::GrpcRoute => "gateway.networking.k8s.io/v1",
            Self::TcpRoute => "gateway.networking.k8s.io/v1alpha2",
            Self::Certificate => "cert-manager.io/v1",
            Self::MeshMember => "lattice.dev/v1alpha1",
            Self::TracingPolicyNamespaced => "cilium.io/v1alpha1",
            Self::VolcanoJob => "batch.volcano.sh/v1alpha1",
        }
    }
}

/// Centralized cache of discovered CRD API versions.
///
/// Created once at startup and shared across all controllers via `Arc<CrdRegistry>`.
/// Uses `DashMap` for per-key granularity: resolving one missing CRD doesn't
/// block reads for others.
pub struct CrdRegistry {
    client: Client,
    entries: DashMap<CrdKind, ApiResource>,
}

impl CrdRegistry {
    /// Run API discovery once and populate all known CRDs.
    ///
    /// Replaces the 3 separate `Discovery::new().run()` calls that previously
    /// happened at startup (one each for Service, MeshMember, and Job controllers).
    pub async fn discover(client: Client) -> Self {
        use kube::discovery::Discovery;

        let entries = DashMap::new();

        match Discovery::new(client.clone()).run().await {
            Ok(discovery) => {
                for kind in ALL_CRD_KINDS {
                    if let Some(ar) =
                        find_discovered_resource(&discovery, kind.group(), kind.kind_str())
                    {
                        entries.insert(*kind, ar);
                    }
                }
                info!(
                    discovered = entries.len(),
                    total = ALL_CRD_KINDS.len(),
                    "CRD registry populated via API discovery"
                );
            }
            Err(e) => {
                warn!(error = %e, "API discovery failed, falling back to hardcoded CRD versions");
                for kind in ALL_CRD_KINDS {
                    entries.insert(
                        *kind,
                        build_api_resource(kind.hardcoded_api_version(), kind.kind_str()),
                    );
                }
            }
        }

        Self { client, entries }
    }

    /// Get a CRD, running lazy re-discovery if it was missing at startup.
    ///
    /// Returns immediately from cache when the CRD was found during initial
    /// discovery. On first miss, runs full API discovery and caches all
    /// newly-found CRDs. Returns `None` only if the CRD is genuinely not
    /// installed after re-discovery.
    pub async fn resolve(&self, kind: CrdKind) -> Option<ApiResource> {
        if let Some(ar) = self.entries.get(&kind) {
            return Some(ar.clone());
        }

        info!(
            kind = kind.kind_str(),
            group = kind.group(),
            "CRD missing at startup, attempting lazy discovery"
        );

        self.rediscover().await;
        self.entries.get(&kind).map(|r| r.clone())
    }

    /// Re-run API discovery and populate any newly-installed CRDs.
    ///
    /// Only inserts entries that are currently missing — existing entries
    /// are not overwritten (the initially-discovered version is stable).
    async fn rediscover(&self) {
        use kube::discovery::Discovery;

        let discovery = match Discovery::new(self.client.clone()).run().await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "CRD re-discovery failed");
                return;
            }
        };

        let mut newly_found = 0u32;
        for kind in ALL_CRD_KINDS {
            if self.entries.contains_key(kind) {
                continue;
            }
            if let Some(ar) = find_discovered_resource(&discovery, kind.group(), kind.kind_str()) {
                self.entries.insert(*kind, ar);
                newly_found += 1;
            }
        }

        if newly_found > 0 {
            info!(newly_found, "CRD re-discovery found new CRDs");
        }
    }

    /// Populate the registry with hardcoded API versions for all CRDs.
    ///
    /// Used as a fallback when API discovery fails entirely, and in tests.
    pub fn hardcoded_defaults(client: Client) -> Self {
        let entries = DashMap::new();
        for kind in ALL_CRD_KINDS {
            entries.insert(
                *kind,
                build_api_resource(kind.hardcoded_api_version(), kind.kind_str()),
            );
        }
        Self { client, entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crd_kind_group_and_kind_are_consistent() {
        for kind in ALL_CRD_KINDS {
            assert!(!kind.group().is_empty(), "{:?} has empty group", kind);
            assert!(!kind.kind_str().is_empty(), "{:?} has empty kind", kind);
            assert!(
                !kind.hardcoded_api_version().is_empty(),
                "{:?} has empty api version",
                kind
            );
            // api_version should contain the group (except for core types)
            assert!(
                kind.hardcoded_api_version().contains(kind.group()),
                "{:?}: api_version '{}' doesn't contain group '{}'",
                kind,
                kind.hardcoded_api_version(),
                kind.group()
            );
        }
    }

    #[test]
    fn all_crd_kinds_is_exhaustive() {
        // Ensure ALL_CRD_KINDS contains every variant
        assert_eq!(ALL_CRD_KINDS.len(), 15);
    }
}
