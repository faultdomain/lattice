//! Centralized CRD discovery registry
//!
//! Single registry shared across all controllers for third-party CRD API
//! version resolution. Replaces per-controller discovery structs with a
//! unified `DashMap`-based cache that supports lazy resolution.

use dashmap::DashMap;
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{info, warn};

use crate::kube_utils::build_api_resource;

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
    /// Volcano CronJob (batch.volcano.sh)
    VolcanoCronJob,
    /// Kthena ModelServing (workload.serving.volcano.sh)
    ModelServing,
    /// Kthena ModelServer (networking.serving.volcano.sh)
    KthenaModelServer,
    /// Kthena ModelRoute (networking.serving.volcano.sh)
    KthenaModelRoute,
    /// Kthena AutoscalingPolicy (workload.serving.volcano.sh)
    AutoscalingPolicy,
    /// Kthena AutoscalingPolicyBinding (workload.serving.volcano.sh)
    AutoscalingPolicyBinding,
    /// Volcano PodGroup (scheduling.volcano.sh)
    PodGroup,
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
    CrdKind::VolcanoCronJob,
    CrdKind::ModelServing,
    CrdKind::KthenaModelServer,
    CrdKind::KthenaModelRoute,
    CrdKind::AutoscalingPolicy,
    CrdKind::AutoscalingPolicyBinding,
    CrdKind::PodGroup,
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
            Self::VolcanoJob | Self::VolcanoCronJob => "batch.volcano.sh",
            Self::PodGroup => "scheduling.volcano.sh",
            Self::ModelServing | Self::AutoscalingPolicy | Self::AutoscalingPolicyBinding => {
                "workload.serving.volcano.sh"
            }
            Self::KthenaModelServer | Self::KthenaModelRoute => "networking.serving.volcano.sh",
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
            Self::VolcanoCronJob => "CronJob",
            Self::ModelServing => "ModelServing",
            Self::KthenaModelServer => "ModelServer",
            Self::KthenaModelRoute => "ModelRoute",
            Self::AutoscalingPolicy => "AutoscalingPolicy",
            Self::AutoscalingPolicyBinding => "AutoscalingPolicyBinding",
            Self::PodGroup => "PodGroup",
        }
    }

    /// Reverse of `kind_str()` — parse a Kubernetes Kind string into a `CrdKind`.
    ///
    /// Returns `None` for unrecognized kind strings.
    pub fn from_kind_str(s: &str) -> Option<Self> {
        match s {
            "ExternalSecret" => Some(Self::ExternalSecret),
            "ScaledObject" => Some(Self::ScaledObject),
            "VMServiceScrape" => Some(Self::VMServiceScrape),
            "CiliumNetworkPolicy" => Some(Self::CiliumNetworkPolicy),
            "AuthorizationPolicy" => Some(Self::AuthorizationPolicy),
            "ServiceEntry" => Some(Self::ServiceEntry),
            "PeerAuthentication" => Some(Self::PeerAuthentication),
            "Gateway" => Some(Self::Gateway),
            "HTTPRoute" => Some(Self::HttpRoute),
            "GRPCRoute" => Some(Self::GrpcRoute),
            "TCPRoute" => Some(Self::TcpRoute),
            "Certificate" => Some(Self::Certificate),
            "LatticeMeshMember" => Some(Self::MeshMember),
            "TracingPolicyNamespaced" => Some(Self::TracingPolicyNamespaced),
            "Job" => Some(Self::VolcanoJob),
            "CronJob" => Some(Self::VolcanoCronJob),
            "ModelServing" => Some(Self::ModelServing),
            "ModelServer" => Some(Self::KthenaModelServer),
            "ModelRoute" => Some(Self::KthenaModelRoute),
            "AutoscalingPolicy" => Some(Self::AutoscalingPolicy),
            "AutoscalingPolicyBinding" => Some(Self::AutoscalingPolicyBinding),
            "PodGroup" => Some(Self::PodGroup),
            _ => None,
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
            Self::VolcanoJob | Self::VolcanoCronJob => "batch.volcano.sh/v1alpha1",
            Self::PodGroup => "scheduling.volcano.sh/v1beta1",
            Self::ModelServing | Self::AutoscalingPolicy | Self::AutoscalingPolicyBinding => {
                "workload.serving.volcano.sh/v1alpha1"
            }
            Self::KthenaModelServer | Self::KthenaModelRoute => {
                "networking.serving.volcano.sh/v1alpha1"
            }
        }
    }
}

/// Centralized cache of discovered CRD API versions.
///
/// Created once at startup and shared across all controllers via `Arc<CrdRegistry>`.
/// Uses `DashMap` for per-key granularity: resolving one missing CRD doesn't
/// block reads for others.
pub struct CrdRegistry {
    /// Client for API discovery. None in tests (discovery becomes a no-op).
    client: Option<Client>,
    entries: DashMap<CrdKind, ApiResource>,
}

impl CrdRegistry {
    /// Create a new registry and run initial API discovery.
    ///
    /// Discovery is best-effort at startup — if it fails, the cache starts
    /// empty and `resolve()` will retry lazily on first access.
    pub async fn new(client: Client) -> Self {
        let registry = Self {
            client: Some(client),
            entries: DashMap::new(),
        };

        if let Err(e) = registry.run_discovery().await {
            warn!(error = %e, "Initial CRD discovery failed, will retry lazily on first resolve");
        }

        registry
    }

    /// Return the cached ApiResource for a CRD without triggering discovery.
    ///
    /// Returns `Some(ar)` if the CRD was found during startup or a previous
    /// `resolve()` call, `None` otherwise. Use this in synchronous contexts
    /// where lazy discovery is not needed (e.g., cache lookups).
    pub fn resolve_cached(&self, kind: CrdKind) -> Option<ApiResource> {
        self.entries.get(&kind).map(|r| r.clone())
    }

    /// Resolve a CRD's ApiResource, running lazy discovery on cache miss.
    ///
    /// Returns `Ok(Some(ar))` when the CRD is found, `Ok(None)` when discovery
    /// succeeds but the CRD is not installed, and `Err` when discovery itself
    /// fails (e.g. a broken APIService poisoning the discovery API).
    pub async fn resolve(&self, kind: CrdKind) -> Result<Option<ApiResource>, kube::Error> {
        if let Some(ar) = self.entries.get(&kind) {
            return Ok(Some(ar.clone()));
        }

        if self.client.is_none() {
            return Ok(None);
        }

        info!(
            kind = kind.kind_str(),
            group = kind.group(),
            "CRD not cached, running discovery"
        );

        self.run_discovery().await?;
        Ok(self.entries.get(&kind).map(|r| r.clone()))
    }

    /// Run per-group API discovery and cache any newly-found CRDs.
    ///
    /// Discovers each API group independently via `oneshot::group()` so that
    /// a broken APIService (e.g. KEDA returning 503) only skips that group
    /// instead of poisoning the entire discovery pass.
    ///
    /// Only inserts entries that are currently missing — existing entries
    /// are not overwritten (the initially-discovered version is stable).
    async fn run_discovery(&self) -> Result<(), kube::Error> {
        use std::collections::BTreeSet;

        let client = match &self.client {
            Some(c) => c.clone(),
            None => return Ok(()),
        };

        // Collect the unique groups we need to discover (only for missing entries)
        let groups_needed: BTreeSet<&str> = ALL_CRD_KINDS
            .iter()
            .filter(|k| !self.entries.contains_key(k))
            .map(|k| k.group())
            .collect();

        if groups_needed.is_empty() {
            return Ok(());
        }

        let mut newly_found = 0u32;
        let mut failed_groups = Vec::new();

        for group in &groups_needed {
            match kube::discovery::oneshot::group(&client, group).await {
                Ok(api_group) => {
                    for (ar, _caps) in api_group.resources_by_stability() {
                        if let Some(kind) = CrdKind::from_kind_str(&ar.kind) {
                            if !self.entries.contains_key(&kind) {
                                self.entries.insert(kind, ar);
                                newly_found += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(group = %group, error = %e, "API group discovery failed, skipping");
                    failed_groups.push(*group);
                }
            }
        }

        info!(
            newly_found,
            total = self.entries.len(),
            failed_groups = ?failed_groups,
            "CRD discovery completed"
        );

        Ok(())
    }

    /// Create a registry pre-populated with hardcoded API versions and no client.
    ///
    /// Discovery is a no-op since there's no client. Used in unit tests that
    /// need CRD resolution without a real API server.
    pub fn for_testing() -> Self {
        let entries = DashMap::new();
        for kind in ALL_CRD_KINDS {
            entries.insert(
                *kind,
                build_api_resource(kind.hardcoded_api_version(), kind.kind_str()),
            );
        }
        Self {
            client: None,
            entries,
        }
    }

    /// Create an empty registry with no entries and no client.
    ///
    /// Used to test behavior when CRDs are not installed.
    pub fn empty_for_testing() -> Self {
        Self {
            client: None,
            entries: DashMap::new(),
        }
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
        assert_eq!(ALL_CRD_KINDS.len(), 22);
    }

    #[test]
    fn from_kind_str_is_inverse_of_kind_str() {
        for kind in ALL_CRD_KINDS {
            let s = kind.kind_str();
            let roundtripped = CrdKind::from_kind_str(s);
            assert_eq!(
                roundtripped,
                Some(*kind),
                "from_kind_str({:?}) should return {:?}",
                s,
                kind
            );
        }
    }
}
