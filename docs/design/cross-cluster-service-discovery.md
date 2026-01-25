# Cross-Cluster Service Discovery Design

## Executive Summary

This document describes the design for cross-cluster service dependencies in Lattice. When a `LatticeService` in Cluster A depends on a `LatticeService` in Cluster B, the system must:

1. Detect that the dependency is not local (Unknown node in ServiceGraph)
2. Propagate service metadata up the cluster hierarchy to enable discovery
3. Query parent clusters to resolve cross-cluster dependencies
4. Generate Gateway API + External DNS configuration for cross-cluster routing
5. Maintain bilateral agreement enforcement across cluster boundaries

The design leverages the existing outbound-only gRPC stream between agents and parent cells, adding new message types for service announcements and queries.

---

## Architecture Overview

```
                    ┌──────────────────────────────────────────────┐
                    │            Root Parent Cluster               │
                    │  ┌────────────────────────────────────────┐  │
                    │  │           ServiceCatalog               │  │
                    │  │  ┌──────────────────────────────────┐  │  │
                    │  │  │ (env, name) -> CatalogEntry      │  │  │
                    │  │  │  - source_cluster                │  │  │
                    │  │  │  - qualified_dns_name            │  │  │
                    │  │  │  - gateway_endpoint              │  │  │
                    │  │  │  - allowed_callers (bilateral)   │  │  │
                    │  │  │  - ports                         │  │  │
                    │  │  └──────────────────────────────────┘  │  │
                    │  └────────────────────────────────────────┘  │
                    └──────────────────────────────────────────────┘
                              ▲                           ▲
         ServiceAnnouncement  │                           │  ServiceQuery
         (services pushed up) │                           │  (resolve unknown deps)
                              │                           │
         ┌────────────────────┴────┐          ┌──────────┴─────────────────┐
         │      Cluster A          │          │        Cluster B           │
         │  ┌───────────────────┐  │          │  ┌───────────────────────┐ │
         │  │ LatticeService:   │  │          │  │ LatticeService:       │ │
         │  │   name: api       │  │◄─────────│  │   name: frontend      │ │
         │  │   allowed: [*]    │  │ Gateway  │  │   depends: [api]      │ │
         │  │   ports: [8080]   │  │  Route   │  │                       │ │
         │  └───────────────────┘  │          │  └───────────────────────┘ │
         │  ┌───────────────────┐  │          │  ┌───────────────────────┐ │
         │  │ ServiceGraph      │  │          │  │ ServiceGraph          │ │
         │  │   api: Local      │  │          │  │   frontend: Local     │ │
         │  │                   │  │          │  │   api: Remote (cached)│ │
         │  └───────────────────┘  │          │  └───────────────────────┘ │
         │  ┌───────────────────┐  │          │  ┌───────────────────────┐ │
         │  │ RemoteServiceCache│  │          │  │ RemoteServiceCache    │ │
         │  │   (empty)         │  │          │  │   api -> CatalogEntry │ │
         │  └───────────────────┘  │          │  └───────────────────────┘ │
         │  ┌───────────────────┐  │          │  ┌───────────────────────┐ │
         │  │ Gateway           │  │          │  │ Generated Resources:  │ │
         │  │   api.prod.a.lat..│  │          │  │  - ServiceEntry (api) │ │
         │  │   -> internal svc │  │          │  │  - HTTPRoute          │ │
         │  └───────────────────┘  │          │  │  - AuthorizationPolicy│ │
         └─────────────────────────┘          │  │  - CiliumNetworkPolicy│ │
                                              │  └───────────────────────┘ │
                                              └────────────────────────────┘
```

---

## Component Design

### 1. Protocol Extensions

**File: `crates/lattice-proto/proto/agent.proto`**

Add new message types to the existing agent-cell protocol:

```protobuf
// =============================================================================
// Cross-Cluster Service Discovery Messages
// =============================================================================

// Metadata about a service's exposed port
message ServicePort {
  // Port name (e.g., "http", "grpc")
  string name = 1;
  // Port number
  uint32 port = 2;
  // Protocol (HTTP, HTTPS, TCP, GRPC)
  string protocol = 3;
}

// Agent -> Cell: Announce a local service to parent for cross-cluster discovery
//
// Sent when:
//   - A LatticeService is created or updated
//   - Agent reconnects to cell (full catalog sync)
//   - A LatticeService is deleted (deleted=true)
message ServiceAnnouncement {
  // Environment this service belongs to (e.g., "prod", "staging")
  string environment = 1;

  // Service name (matches LatticeService.metadata.name)
  string service_name = 2;

  // Exposed ports with protocol information
  repeated ServicePort ports = 3;

  // Services allowed to call this service (from LatticeServiceSpec.resources with direction=inbound)
  // Used by parent to validate bilateral agreements for cross-cluster dependencies
  // Special value "*" means allow all callers
  repeated string allowed_callers = 4;

  // Cluster that owns this service (filled by agent from its cluster identity)
  string source_cluster = 5;

  // Fully qualified DNS name for cross-cluster routing
  // Format: "{service}.{env}.{cluster}.{base_domain}"
  // Example: "api.prod.cluster-a.lattice.example.com"
  string qualified_dns_name = 6;

  // Gateway endpoint for routing cross-cluster traffic
  // Format: "{gateway-host}:{port}"
  // Example: "gateway.cluster-a.lattice.example.com:443"
  // Traffic to qualified_dns_name routes through this gateway
  string gateway_endpoint = 7;

  // True if this announcement is for a deleted service
  bool deleted = 8;

  // Monotonically increasing version for conflict resolution
  // Typically the LatticeService's metadata.resourceVersion
  int64 version = 9;
}

// Agent -> Cell: Batch sync of all services in this cluster
//
// Sent when:
//   - Agent first connects to cell
//   - Agent reconnects after disconnect
//   - Periodic full reconciliation (every 5 minutes)
message ServiceCatalogSync {
  // All services currently in this cluster
  repeated ServiceAnnouncement services = 1;

  // If true, parent should delete services not in this list (full sync)
  // If false, only add/update services in this list (incremental)
  bool full_sync = 2;

  // Cluster name for identification
  string cluster_name = 3;
}

// Agent -> Cell: Query parent for a service not found locally
//
// Sent when:
//   - Service controller encounters Unknown node in ServiceGraph
//   - Controller needs to resolve cross-cluster dependency
message ServiceQuery {
  // Unique ID for correlating response
  string query_id = 1;

  // Environment to search in
  string environment = 2;

  // Service name being queried
  string service_name = 3;

  // Service making the request (for bilateral agreement validation)
  // Parent will check if target service allows this caller
  string requesting_service = 4;
}

// Cell -> Agent: Response to a ServiceQuery
message ServiceQueryResponse {
  // Correlates to ServiceQuery.query_id
  string query_id = 1;

  // Whether the service was found in the catalog
  bool found = 2;

  // Service details (present if found=true)
  ServiceAnnouncement service = 3;

  // Whether bilateral agreement exists between requesting_service and target
  // True if target's allowed_callers contains requesting_service or "*"
  bool bilateral_agreement = 4;

  // Error message if query failed (not found, permission denied, etc.)
  string error_message = 5;
}

// Cell -> Agent: Push discovered remote services to child
//
// Sent when:
//   - A service in the catalog is updated that this cluster depends on
//   - Periodic refresh of cached remote services
//   - After answering a ServiceQuery (proactive push)
message RemoteServiceUpdate {
  // Services relevant to this cluster (dependencies it has queried)
  repeated ServiceAnnouncement services = 1;

  // If true, this is a complete list; delete cached services not included
  // If false, incremental update
  bool full_sync = 2;
}

// Extend AgentMessage with new payload types
message AgentMessage {
  string cluster_name = 1;

  oneof payload {
    AgentReady ready = 2;
    BootstrapComplete bootstrap_complete = 3;
    PivotComplete pivot_complete = 4;
    Heartbeat heartbeat = 5;
    ClusterHealth cluster_health = 6;
    StatusResponse status_response = 7;
    ClusterDeleting cluster_deleting = 8;

    // New: Cross-cluster service discovery
    ServiceAnnouncement service_announcement = 9;
    ServiceCatalogSync catalog_sync = 10;
    ServiceQuery service_query = 11;
  }
}

// Extend CellCommand with new command types
message CellCommand {
  string command_id = 1;

  oneof command {
    ApplyManifestsCommand apply_manifests = 2;
    StatusRequest status_request = 3;
    PivotManifestsCommand pivot_manifests = 4;
    SyncDistributedResourcesCommand sync_resources = 5;

    // New: Cross-cluster service discovery
    ServiceQueryResponse service_query_response = 6;
    RemoteServiceUpdate remote_service_update = 7;
  }
}
```

---

### 2. Service Catalog (Parent Clusters)

**New file: `crates/lattice-cluster/src/catalog/mod.rs`**

The ServiceCatalog aggregates service announcements from all child clusters. It runs on parent clusters (those with `parent_config` set in LatticeClusterSpec).

```rust
//! Cross-cluster service catalog for parent clusters
//!
//! Aggregates service announcements from all child clusters and provides
//! query resolution for cross-cluster dependencies.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tracing::{debug, info, warn};

/// Composite key for catalog entries: (environment, service_name)
type CatalogKey = (String, String);

/// A service registered in the cross-cluster catalog
#[derive(Clone, Debug)]
pub struct CatalogEntry {
    /// Service name
    pub name: String,

    /// Environment (e.g., "prod", "staging")
    pub environment: String,

    /// Cluster that owns this service
    pub source_cluster: String,

    /// Exposed ports
    pub ports: BTreeMap<String, ServicePort>,

    /// Services allowed to call this service (for bilateral agreement checks)
    /// Contains service names or "*" for allow-all
    pub allowed_callers: HashSet<String>,

    /// Fully qualified DNS name for routing
    /// Format: "{service}.{env}.{cluster}.{base_domain}"
    pub qualified_dns_name: String,

    /// Gateway endpoint for cross-cluster traffic
    pub gateway_endpoint: String,

    /// Version for conflict resolution (higher wins)
    pub version: i64,

    /// Last update timestamp
    pub last_updated: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ServicePort {
    pub name: String,
    pub port: u16,
    pub protocol: String,
}

/// Query result with bilateral agreement check
#[derive(Clone, Debug)]
pub struct QueryResult {
    /// The service entry
    pub entry: CatalogEntry,

    /// Whether bilateral agreement exists with the requesting service
    pub bilateral_agreement: bool,
}

/// Cross-cluster service catalog
///
/// Thread-safe catalog using DashMap for concurrent access:
/// - O(1) lookups by (environment, service_name)
/// - O(1) cleanup by source_cluster on agent disconnect
/// - O(n) listing by environment where n = services in that environment
pub struct ServiceCatalog {
    /// Primary index: (env, name) -> CatalogEntry
    entries: DashMap<CatalogKey, CatalogEntry>,

    /// Cluster index: cluster_name -> Set of (env, name) keys
    /// Used for efficient cleanup when a cluster disconnects
    by_cluster: DashMap<String, HashSet<CatalogKey>>,

    /// Environment index: env -> Set of service names
    /// Used for listing services in an environment
    by_environment: DashMap<String, HashSet<String>>,

    /// This cluster's name (for identifying local vs remote services)
    local_cluster: String,
}

impl ServiceCatalog {
    /// Create a new service catalog
    ///
    /// # Arguments
    /// * `local_cluster` - Name of this cluster (services from this cluster are local)
    pub fn new(local_cluster: impl Into<String>) -> Self {
        Self {
            entries: DashMap::new(),
            by_cluster: DashMap::new(),
            by_environment: DashMap::new(),
            local_cluster: local_cluster.into(),
        }
    }

    /// Register or update a service from a child cluster
    ///
    /// Only updates if the new version is higher than existing version.
    /// This prevents out-of-order updates from overwriting newer data.
    pub fn register(&self, entry: CatalogEntry) {
        let key = (entry.environment.clone(), entry.name.clone());

        // Check if we should update (version comparison)
        let should_update = self.entries
            .get(&key)
            .map(|existing| existing.version < entry.version)
            .unwrap_or(true);

        if !should_update {
            debug!(
                service = %entry.name,
                env = %entry.environment,
                "Skipping registration: existing version is newer"
            );
            return;
        }

        // Update cluster index
        self.by_cluster
            .entry(entry.source_cluster.clone())
            .or_default()
            .insert(key.clone());

        // Update environment index
        self.by_environment
            .entry(entry.environment.clone())
            .or_default()
            .insert(entry.name.clone());

        // Store entry
        info!(
            service = %entry.name,
            env = %entry.environment,
            cluster = %entry.source_cluster,
            version = entry.version,
            "Registered service in catalog"
        );
        self.entries.insert(key, entry);
    }

    /// Remove a service from the catalog
    ///
    /// Only removes if the service is from the specified source cluster.
    /// This prevents one cluster from deleting another cluster's services.
    pub fn unregister(&self, env: &str, name: &str, source_cluster: &str) {
        let key = (env.to_string(), name.to_string());

        // Only remove if from the correct source cluster
        if let Some((_, entry)) = self.entries.remove(&key) {
            if entry.source_cluster == source_cluster {
                // Clean up indices
                if let Some(mut cluster_set) = self.by_cluster.get_mut(source_cluster) {
                    cluster_set.remove(&key);
                }
                if let Some(mut env_set) = self.by_environment.get_mut(env) {
                    env_set.remove(name);
                }
                info!(
                    service = %name,
                    env = %env,
                    cluster = %source_cluster,
                    "Unregistered service from catalog"
                );
            } else {
                // Wrong source cluster tried to delete - re-insert
                warn!(
                    service = %name,
                    env = %env,
                    attempted_by = %source_cluster,
                    owned_by = %entry.source_cluster,
                    "Rejected unregister: service owned by different cluster"
                );
                self.entries.insert(key, entry);
            }
        }
    }

    /// Query for a service with bilateral agreement check
    ///
    /// # Arguments
    /// * `env` - Environment to search in
    /// * `service_name` - Service name to find
    /// * `requesting_service` - Service making the request (for bilateral check)
    ///
    /// # Returns
    /// * `Some(QueryResult)` - Service found with bilateral agreement status
    /// * `None` - Service not found
    pub fn query(
        &self,
        env: &str,
        service_name: &str,
        requesting_service: &str,
    ) -> Option<QueryResult> {
        let key = (env.to_string(), service_name.to_string());

        self.entries.get(&key).map(|entry| {
            // Check bilateral agreement: does target allow this caller?
            let bilateral = entry.allowed_callers.contains("*")
                || entry.allowed_callers.contains(requesting_service);

            QueryResult {
                entry: entry.clone(),
                bilateral_agreement: bilateral,
            }
        })
    }

    /// Remove all services from a cluster
    ///
    /// Called when an agent disconnects to clean up stale entries.
    /// This is important for preventing stale routing after cluster deletion.
    pub fn remove_cluster(&self, cluster_name: &str) {
        if let Some((_, keys)) = self.by_cluster.remove(cluster_name) {
            let count = keys.len();
            for key in keys {
                self.entries.remove(&key);
                if let Some(mut env_set) = self.by_environment.get_mut(&key.0) {
                    env_set.remove(&key.1);
                }
            }
            info!(
                cluster = %cluster_name,
                services_removed = count,
                "Removed all services for disconnected cluster"
            );
        }
    }

    /// List all services in an environment
    pub fn list_services(&self, env: &str) -> Vec<CatalogEntry> {
        self.by_environment
            .get(env)
            .map(|names| {
                names.iter()
                    .filter_map(|name| {
                        let key = (env.to_string(), name.clone());
                        self.entries.get(&key).map(|e| e.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get count of services in the catalog
    pub fn service_count(&self) -> usize {
        self.entries.len()
    }

    /// Get count of clusters contributing to the catalog
    pub fn cluster_count(&self) -> usize {
        self.by_cluster.len()
    }
}

/// Thread-safe shared reference
pub type SharedServiceCatalog = Arc<ServiceCatalog>;
```

---

### 3. Remote Service Cache (All Clusters)

**New file: `crates/lattice-cluster/src/catalog/cache.rs`**

The RemoteServiceCache provides resilience against parent disconnection. Clusters can continue operating with cached remote service information even if the parent becomes unavailable.

```rust
//! Remote service cache for cross-cluster dependencies
//!
//! Caches remote services discovered via parent queries.
//!
//! **Design Principle: Cache entries NEVER expire or become unusable.**
//!
//! The cache tracks staleness for observability/alerting but always returns
//! cached data if available. A cluster should never fail because cached
//! data is "too old" - stale data is better than no data.
//!
//! Staleness tracking enables:
//! - Metrics/alerts when data is getting old
//! - Prioritizing background refresh for stale entries
//! - Logging warnings when using very stale data

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use super::{CatalogEntry, ServicePort};

/// Staleness level for observability
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Staleness {
    /// Data refreshed recently (within refresh interval)
    Fresh,
    /// Data is getting old (1-5x refresh interval)
    Stale,
    /// Data is very old (5-10x refresh interval)
    VeryStale,
    /// Data is extremely old (>10x refresh interval)
    Ancient,
}

impl Staleness {
    /// Calculate staleness from age and refresh interval
    pub fn from_age(age: Duration, refresh_interval: Duration) -> Self {
        let ratio = age.as_secs_f64() / refresh_interval.as_secs_f64();
        if ratio < 1.0 {
            Staleness::Fresh
        } else if ratio < 5.0 {
            Staleness::Stale
        } else if ratio < 10.0 {
            Staleness::VeryStale
        } else {
            Staleness::Ancient
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Staleness::Fresh => "fresh",
            Staleness::Stale => "stale",
            Staleness::VeryStale => "very stale",
            Staleness::Ancient => "ancient",
        }
    }
}

/// Cached remote service entry
#[derive(Clone, Debug)]
pub struct CachedRemoteService {
    /// Service metadata from parent catalog
    pub entry: CatalogEntry,

    /// When this entry was last refreshed from parent
    pub cached_at: Instant,

    /// Whether bilateral agreement was confirmed
    pub bilateral_agreement: bool,

    /// Refresh interval for staleness calculation
    refresh_interval: Duration,
}

impl CachedRemoteService {
    /// How long since this entry was refreshed
    pub fn age(&self) -> Duration {
        self.cached_at.elapsed()
    }

    /// Calculate staleness level for observability
    pub fn staleness(&self) -> Staleness {
        Staleness::from_age(self.age(), self.refresh_interval)
    }

    /// Whether this entry should be refreshed (staleness > Fresh)
    ///
    /// Note: This does NOT mean the entry is unusable - just that
    /// we should try to refresh it if possible.
    pub fn needs_refresh(&self) -> bool {
        self.staleness() != Staleness::Fresh
    }
}

/// Remote service cache
///
/// **Key Invariant: Cached entries are ALWAYS usable.**
///
/// The cache tracks staleness for metrics and prioritizing refreshes,
/// but never rejects queries due to staleness. A stale answer is
/// always better than no answer for cross-cluster dependencies.
pub struct RemoteServiceCache {
    /// Cached services: (env, name) -> CachedRemoteService
    cache: DashMap<(String, String), CachedRemoteService>,

    /// Target refresh interval (used for staleness calculation)
    /// This is how often we WANT to refresh, not an expiration time
    refresh_interval: Duration,
}

impl RemoteServiceCache {
    /// Target refresh interval: 5 minutes
    ///
    /// This is how often we aim to refresh data from parent.
    /// Data older than this is considered "stale" for metrics purposes
    /// but is still always usable.
    pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

    /// Create a new remote service cache
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            refresh_interval: Self::DEFAULT_REFRESH_INTERVAL,
        }
    }

    /// Get a cached service
    ///
    /// **Always returns the cached entry if it exists, regardless of age.**
    /// Use `entry.staleness()` for observability if needed.
    pub fn get(&self, env: &str, name: &str) -> Option<CachedRemoteService> {
        let key = (env.to_string(), name.to_string());
        self.cache.get(&key).map(|e| {
            let entry = e.clone();
            // Log if using very stale data
            if entry.staleness() >= Staleness::VeryStale {
                warn!(
                    service = %name,
                    env = %env,
                    age_secs = entry.age().as_secs(),
                    staleness = entry.staleness().description(),
                    "Using {} cached data for remote service",
                    entry.staleness().description()
                );
            }
            entry
        })
    }

    /// Get all entries that need refresh (staleness > Fresh)
    ///
    /// Useful for background refresh tasks to prioritize which
    /// entries to query parent for.
    pub fn entries_needing_refresh(&self) -> Vec<(String, String)> {
        self.cache
            .iter()
            .filter(|e| e.value().needs_refresh())
            .map(|e| e.key().clone())
            .collect()
    }

    /// Get all entries with staleness at or above a threshold
    ///
    /// Useful for alerting on very stale data.
    pub fn entries_at_staleness(&self, min_staleness: Staleness) -> Vec<(String, String, Duration)> {
        self.cache
            .iter()
            .filter(|e| e.value().staleness() >= min_staleness)
            .map(|e| {
                let (env, name) = e.key().clone();
                let age = e.value().age();
                (env, name, age)
            })
            .collect()
    }

    /// Insert or update a cached service
    ///
    /// # Arguments
    /// * `entry` - Service metadata from parent
    /// * `bilateral` - Whether bilateral agreement was confirmed
    pub fn insert(&self, entry: CatalogEntry, bilateral: bool) {
        let key = (entry.environment.clone(), entry.name.clone());

        debug!(
            service = %entry.name,
            env = %entry.environment,
            source_cluster = %entry.source_cluster,
            bilateral = bilateral,
            "Cached remote service"
        );

        self.cache.insert(key, CachedRemoteService {
            entry,
            cached_at: Instant::now(),
            bilateral_agreement: bilateral,
            refresh_interval: self.refresh_interval,
        });
    }

    /// Mark an entry as refreshed (reset cached_at to now)
    ///
    /// Call this when you've confirmed the cached data is still valid
    /// without needing to replace the entry.
    pub fn mark_refreshed(&self, env: &str, name: &str) {
        let key = (env.to_string(), name.to_string());
        if let Some(mut entry) = self.cache.get_mut(&key) {
            entry.cached_at = Instant::now();
        }
    }

    /// Remove a specific service from cache
    ///
    /// Only call this when you know the service no longer exists,
    /// not just because data is old.
    pub fn remove(&self, env: &str, name: &str) {
        let key = (env.to_string(), name.to_string());
        self.cache.remove(&key);
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get count of cached entries
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get staleness statistics for metrics
    pub fn staleness_stats(&self) -> StalenessStats {
        let mut stats = StalenessStats::default();
        for entry in self.cache.iter() {
            match entry.value().staleness() {
                Staleness::Fresh => stats.fresh += 1,
                Staleness::Stale => stats.stale += 1,
                Staleness::VeryStale => stats.very_stale += 1,
                Staleness::Ancient => stats.ancient += 1,
            }
        }
        stats
    }
}

/// Statistics about cache staleness for metrics/observability
#[derive(Clone, Debug, Default)]
pub struct StalenessStats {
    pub fresh: usize,
    pub stale: usize,
    pub very_stale: usize,
    pub ancient: usize,
}

impl StalenessStats {
    pub fn total(&self) -> usize {
        self.fresh + self.stale + self.very_stale + self.ancient
    }
}

impl Default for RemoteServiceCache {
    fn default() -> Self {
        Self::new()
    }
}
```

---

### 4. Discovery Coordinator

**New file: `crates/lattice-cluster/src/discovery/mod.rs`**

The DiscoveryCoordinator orchestrates service announcements and queries. It bridges the service controller with the agent gRPC stream.

```rust
//! Cross-cluster service discovery coordinator
//!
//! Manages:
//! - Service announcements to parent (on create/update/delete)
//! - Queries to parent for Unknown dependencies
//! - Caching of remote service metadata
//! - Bilateral agreement validation

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

use super::catalog::{CatalogEntry, RemoteServiceCache, ServiceCatalog, ServicePort, Staleness};
use crate::proto::{
    ServiceAnnouncement, ServiceCatalogSync, ServiceQuery, ServiceQueryResponse,
};

/// Configuration for the discovery coordinator
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Timeout for parent queries
    pub query_timeout: Duration,

    /// Base domain for DNS names (e.g., "lattice.example.com")
    pub base_domain: String,

    /// This cluster's name
    pub cluster_name: String,

    /// Gateway endpoint for this cluster
    pub gateway_endpoint: String,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(5),
            base_domain: "lattice.local".to_string(),
            cluster_name: "unknown".to_string(),
            gateway_endpoint: "localhost:443".to_string(),
        }
    }
}

/// Discovery coordinator for cross-cluster service resolution
pub struct DiscoveryCoordinator {
    /// Configuration
    config: DiscoveryConfig,

    /// Local service catalog (for parent clusters)
    catalog: Option<Arc<ServiceCatalog>>,

    /// Remote service cache (for all clusters)
    remote_cache: Arc<RemoteServiceCache>,

    /// Channel to send messages to parent via agent stream
    parent_tx: Option<mpsc::Sender<AgentMessage>>,

    /// Pending query responses: query_id -> response sender
    pending_queries: DashMap<String, oneshot::Sender<ServiceQueryResponse>>,

    /// Whether parent connection is active
    parent_connected: std::sync::atomic::AtomicBool,
}

/// Message types sent to parent (wraps proto messages)
pub enum AgentMessage {
    Announcement(ServiceAnnouncement),
    CatalogSync(ServiceCatalogSync),
    Query(ServiceQuery),
}

impl DiscoveryCoordinator {
    /// Create a new discovery coordinator
    ///
    /// # Arguments
    /// * `config` - Coordinator configuration
    /// * `is_parent` - Whether this cluster is a parent (has catalog)
    /// * `parent_tx` - Channel to send messages to parent (None for root)
    pub fn new(
        config: DiscoveryConfig,
        is_parent: bool,
        parent_tx: Option<mpsc::Sender<AgentMessage>>,
    ) -> Self {
        let catalog = if is_parent {
            Some(Arc::new(ServiceCatalog::new(&config.cluster_name)))
        } else {
            None
        };

        Self {
            config,
            catalog,
            remote_cache: Arc::new(RemoteServiceCache::new()),
            parent_tx,
            pending_queries: DashMap::new(),
            parent_connected: std::sync::atomic::AtomicBool::new(parent_tx.is_some()),
        }
    }

    /// Generate qualified DNS name for a service
    ///
    /// Format: "{service}.{env}.{cluster}.{base_domain}"
    pub fn qualified_dns_name(&self, env: &str, service_name: &str) -> String {
        format!(
            "{}.{}.{}.{}",
            service_name,
            env,
            self.config.cluster_name,
            self.config.base_domain
        )
    }

    /// Announce a local service to parent
    ///
    /// Call this when a LatticeService is created or updated.
    pub async fn announce_service(
        &self,
        name: &str,
        env: &str,
        ports: &[(String, u16, String)], // (name, port, protocol)
        allowed_callers: &[String],
        version: i64,
    ) -> Result<(), DiscoveryError> {
        let Some(tx) = &self.parent_tx else {
            // Root cluster - no parent to announce to
            return Ok(());
        };

        let announcement = ServiceAnnouncement {
            environment: env.to_string(),
            service_name: name.to_string(),
            ports: ports
                .iter()
                .map(|(n, p, proto)| crate::proto::ServicePort {
                    name: n.clone(),
                    port: *p as u32,
                    protocol: proto.clone(),
                })
                .collect(),
            allowed_callers: allowed_callers.to_vec(),
            source_cluster: self.config.cluster_name.clone(),
            qualified_dns_name: self.qualified_dns_name(env, name),
            gateway_endpoint: self.config.gateway_endpoint.clone(),
            deleted: false,
            version,
        };

        tx.send(AgentMessage::Announcement(announcement))
            .await
            .map_err(|_| DiscoveryError::ParentDisconnected)?;

        debug!(service = %name, env = %env, "Announced service to parent");
        Ok(())
    }

    /// Announce service deletion to parent
    pub async fn announce_deletion(
        &self,
        name: &str,
        env: &str,
    ) -> Result<(), DiscoveryError> {
        let Some(tx) = &self.parent_tx else {
            return Ok(());
        };

        let announcement = ServiceAnnouncement {
            environment: env.to_string(),
            service_name: name.to_string(),
            ports: vec![],
            allowed_callers: vec![],
            source_cluster: self.config.cluster_name.clone(),
            qualified_dns_name: String::new(),
            gateway_endpoint: String::new(),
            deleted: true,
            version: 0, // Deletion always wins
        };

        tx.send(AgentMessage::Announcement(announcement))
            .await
            .map_err(|_| DiscoveryError::ParentDisconnected)?;

        debug!(service = %name, env = %env, "Announced service deletion to parent");
        Ok(())
    }

    /// Resolve an Unknown service dependency
    ///
    /// Resolution strategy:
    /// 1. Always check cache first - if we have data, use it
    /// 2. If cache entry needs refresh AND parent available, query parent
    /// 3. Return cached data (fresh or stale - staleness is tracked but doesn't block)
    /// 4. Only return NotFound if we've never seen this service
    ///
    /// **Key Principle: Stale data is ALWAYS better than no data.**
    /// The cache never "expires" in a way that blocks queries.
    ///
    /// # Arguments
    /// * `env` - Environment to search in
    /// * `service_name` - Service to resolve
    /// * `requesting_service` - Service making the request (for bilateral check)
    ///
    /// # Returns
    /// * `Ok(Some(entry))` - Service found with bilateral agreement
    /// * `Ok(None)` - Service found but no bilateral agreement
    /// * `Err(NotFound)` - Service never seen (not in cache, not found by parent)
    pub async fn resolve_unknown(
        &self,
        env: &str,
        service_name: &str,
        requesting_service: &str,
    ) -> Result<Option<CatalogEntry>, DiscoveryError> {
        let parent_connected = self.parent_connected.load(std::sync::atomic::Ordering::Relaxed);

        // 1. Check cache - this ALWAYS returns data if we've ever seen this service
        let cached = self.remote_cache.get(env, service_name);

        // 2. Decide if we should query parent for a refresh
        let should_query = match &cached {
            Some(c) => c.needs_refresh() && parent_connected,
            None => true, // Never seen this service, must query
        };

        // 3. Query parent if needed
        if should_query {
            if let Some(tx) = &self.parent_tx {
                if parent_connected {
                    match self.query_parent(tx, env, service_name, requesting_service).await {
                        Ok(Some((entry, bilateral))) => {
                            // Got fresh data from parent
                            self.remote_cache.insert(entry.clone(), bilateral);
                            if bilateral {
                                return Ok(Some(entry));
                            } else {
                                return Ok(None);
                            }
                        }
                        Ok(None) => {
                            // Parent says service doesn't exist
                            // If we had cached data, keep using it (service might have been
                            // temporarily removed). If no cached data, return NotFound.
                            if cached.is_none() {
                                return Err(DiscoveryError::NotFound {
                                    env: env.to_string(),
                                    service: service_name.to_string(),
                                });
                            }
                            // Fall through to use cached data
                        }
                        Err(e) => {
                            // Query failed - log and fall through to cached data
                            debug!(
                                service = %service_name,
                                env = %env,
                                error = %e,
                                "Parent query failed, using cached data"
                            );
                        }
                    }
                }
            }
        }

        // 4. Return cached data (regardless of staleness)
        if let Some(cached) = cached {
            // Log staleness for observability
            let staleness = cached.staleness();
            if staleness >= Staleness::VeryStale {
                warn!(
                    service = %service_name,
                    env = %env,
                    staleness = staleness.description(),
                    age_secs = cached.age().as_secs(),
                    "Using {} cached data for cross-cluster dependency",
                    staleness.description()
                );
            }

            if cached.bilateral_agreement {
                return Ok(Some(cached.entry));
            } else {
                return Ok(None);
            }
        }

        // 5. Never seen this service and couldn't query parent
        Err(DiscoveryError::NotFound {
            env: env.to_string(),
            service: service_name.to_string(),
        })
    }

    /// Query parent for service information
    async fn query_parent(
        &self,
        tx: &mpsc::Sender<AgentMessage>,
        env: &str,
        service_name: &str,
        requesting_service: &str,
    ) -> Result<Option<(CatalogEntry, bool)>, DiscoveryError> {
        let query_id = Uuid::new_v4().to_string();
        let (response_tx, response_rx) = oneshot::channel();

        self.pending_queries.insert(query_id.clone(), response_tx);

        let query = ServiceQuery {
            query_id: query_id.clone(),
            environment: env.to_string(),
            service_name: service_name.to_string(),
            requesting_service: requesting_service.to_string(),
        };

        // Send query
        if let Err(_) = tx.send(AgentMessage::Query(query)).await {
            self.pending_queries.remove(&query_id);
            return Err(DiscoveryError::ParentDisconnected);
        }

        // Wait for response with timeout
        match tokio::time::timeout(self.config.query_timeout, response_rx).await {
            Ok(Ok(response)) => {
                if response.found {
                    let entry = catalog_entry_from_proto(response.service.unwrap());
                    Ok(Some((entry, response.bilateral_agreement)))
                } else {
                    Ok(None) // Service not found
                }
            }
            Ok(Err(_)) => Err(DiscoveryError::ParentDisconnected),
            Err(_) => Err(DiscoveryError::QueryTimeout),
        }
    }

    /// Handle a query response from parent
    ///
    /// Called by the agent gRPC handler when a ServiceQueryResponse is received.
    pub fn handle_query_response(&self, response: ServiceQueryResponse) {
        if let Some((_, tx)) = self.pending_queries.remove(&response.query_id) {
            let _ = tx.send(response);
        }
    }

    /// Handle parent connection state change
    pub fn on_parent_connected(&self) {
        self.parent_connected.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("Parent connected");
    }

    /// Handle parent disconnection
    ///
    /// Note: Cache entries remain usable - staleness is tracked for
    /// observability but doesn't prevent queries from returning data.
    pub fn on_parent_disconnected(&self) {
        self.parent_connected.store(false, std::sync::atomic::Ordering::Relaxed);
        info!("Parent disconnected - cached data remains available");
    }

    /// Get the local service catalog (for parent clusters)
    pub fn catalog(&self) -> Option<&Arc<ServiceCatalog>> {
        self.catalog.as_ref()
    }

    /// Get the remote service cache
    pub fn cache(&self) -> &Arc<RemoteServiceCache> {
        &self.remote_cache
    }
}

/// Convert proto ServiceAnnouncement to CatalogEntry
fn catalog_entry_from_proto(proto: ServiceAnnouncement) -> CatalogEntry {
    CatalogEntry {
        name: proto.service_name,
        environment: proto.environment,
        source_cluster: proto.source_cluster,
        ports: proto
            .ports
            .into_iter()
            .map(|p| {
                (
                    p.name.clone(),
                    ServicePort {
                        name: p.name,
                        port: p.port as u16,
                        protocol: p.protocol,
                    },
                )
            })
            .collect(),
        allowed_callers: proto.allowed_callers.into_iter().collect(),
        qualified_dns_name: proto.qualified_dns_name,
        gateway_endpoint: proto.gateway_endpoint,
        version: proto.version,
        last_updated: chrono::Utc::now(),
    }
}

/// Discovery errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("service not found: {service} in {env}")]
    NotFound { env: String, service: String },

    #[error("parent cluster disconnected")]
    ParentDisconnected,

    #[error("query timeout")]
    QueryTimeout,

    #[error("bilateral agreement not satisfied")]
    NoBilateralAgreement,
}
```

---

### 5. Service Controller Integration

**Modify: `crates/lattice-service/src/controller.rs`**

Integrate the DiscoveryCoordinator into the service reconciliation loop.

```rust
// In the service controller reconcile function:

async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let name = service.metadata.name.as_deref().unwrap_or("unknown");
    let env = &service.spec.environment;
    let namespace = service.metadata.namespace.as_deref().unwrap_or("default");

    // 1. Add service to local graph
    ctx.graph.put_service(env, name, &service.spec);

    // 2. Announce to parent (for cross-cluster discovery)
    if let Some(discovery) = &ctx.discovery {
        let ports: Vec<_> = service.spec.ports()
            .into_iter()
            .map(|(n, p)| (n.to_string(), p, "TCP".to_string()))
            .collect();
        let allowed_callers: Vec<_> = service.spec.allowed_callers()
            .into_iter()
            .map(String::from)
            .collect();
        let version = service.metadata.resource_version
            .as_deref()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        discovery.announce_service(name, env, &ports, &allowed_callers, version)
            .await
            .ok(); // Log error but don't fail reconciliation
    }

    // 3. Check for missing dependencies
    let (local_missing, remote_resolved) = check_dependencies(&service.spec, &ctx, env).await;

    if !local_missing.is_empty() {
        // Some dependencies not found locally or remotely
        // Requeue to wait for them
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // 4. Compile and apply resources (including remote ServiceEntries)
    let compiled = compile_service(&service.spec, &ctx, namespace, env, &remote_resolved)?;
    ctx.client.apply_compiled_service(name, namespace, &compiled).await?;

    // 5. Update status
    update_status(&service, &ctx, ServicePhase::Ready).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Check for missing dependencies, resolving cross-cluster where possible
async fn check_dependencies(
    spec: &LatticeServiceSpec,
    ctx: &Context,
    env: &str,
) -> (Vec<String>, Vec<(String, CatalogEntry)>) {
    let service_name = spec.name(); // Need to get this from somewhere
    let mut local_missing = Vec::new();
    let mut remote_resolved = Vec::new();

    for dep in spec.internal_dependencies() {
        // Check local graph first
        if let Some(node) = ctx.graph.get_service(env, dep) {
            if node.type_ != ServiceType::Unknown {
                continue; // Found locally
            }
        }

        // Try to resolve via discovery coordinator
        if let Some(discovery) = &ctx.discovery {
            match discovery.resolve_unknown(env, dep, service_name).await {
                Ok(Some(entry)) => {
                    remote_resolved.push((dep.to_string(), entry));
                    continue;
                }
                Ok(None) => {
                    // Found but no bilateral agreement - treat as missing
                    warn!(
                        service = %service_name,
                        dependency = %dep,
                        "Cross-cluster dependency found but no bilateral agreement"
                    );
                }
                Err(e) => {
                    debug!(
                        service = %service_name,
                        dependency = %dep,
                        error = %e,
                        "Failed to resolve cross-cluster dependency"
                    );
                }
            }
        }

        // Not found anywhere
        local_missing.push(dep.to_string());
    }

    (local_missing, remote_resolved)
}
```

---

### 6. Remote Service Policy Generation

**Modify: `crates/lattice-service/src/policy/mod.rs`**

Add methods to generate policies for remote (cross-cluster) services.

```rust
impl<'a> PolicyCompiler<'a> {
    /// Compile ServiceEntry for a remote service (from another cluster)
    ///
    /// Uses the gateway endpoint from the source cluster to route traffic
    /// through the cross-cluster gateway. The service is treated as
    /// MESH_INTERNAL so it participates in the service mesh.
    pub fn compile_remote_service_entry(
        &self,
        remote: &CatalogEntry,
        namespace: &str,
    ) -> ServiceEntry {
        let ports: Vec<ServiceEntryPort> = remote.ports.values()
            .map(|p| ServiceEntryPort {
                number: p.port,
                name: p.name.clone(),
                protocol: p.protocol.to_uppercase(),
            })
            .collect();

        let mut metadata = PolicyMetadata::new(
            format!("remote-{}-{}", remote.source_cluster, remote.name),
            namespace,
        );
        metadata.labels.insert(
            "lattice.dev/source-cluster".to_string(),
            remote.source_cluster.clone(),
        );
        metadata.labels.insert(
            "lattice.dev/remote-service".to_string(),
            "true".to_string(),
        );
        // Route through waypoint for L7 policy enforcement
        metadata.labels.insert(
            "istio.io/use-waypoint".to_string(),
            format!("{}-waypoint", namespace),
        );

        ServiceEntry {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "ServiceEntry".to_string(),
            metadata,
            spec: ServiceEntrySpec {
                // The qualified DNS name is what services use to call this
                hosts: vec![remote.qualified_dns_name.clone()],
                ports,
                // MESH_INTERNAL: participates in mesh mTLS
                location: "MESH_INTERNAL".to_string(),
                // DNS resolution to the gateway endpoint
                resolution: "DNS".to_string(),
            },
        }
    }

    /// Compile AuthorizationPolicy for a remote service caller
    ///
    /// This allows a local service to call a remote service through
    /// the cross-cluster gateway.
    pub fn compile_remote_access_policy(
        &self,
        caller: &str,
        remote: &CatalogEntry,
        namespace: &str,
    ) -> AuthorizationPolicy {
        let ports: Vec<String> = remote.ports.values()
            .map(|p| p.port.to_string())
            .collect();

        AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(
                format!("allow-{}-to-remote-{}", caller, remote.name),
                namespace,
            ),
            spec: AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: format!("remote-{}-{}", remote.source_cluster, remote.name),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.spiffe_principal(namespace, caller)],
                        },
                    }],
                    to: if ports.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        }
    }

    /// Compile CiliumNetworkPolicy egress rule for remote service
    pub fn compile_remote_egress_rule(
        &self,
        remote: &CatalogEntry,
    ) -> CiliumEgressRule {
        // Route through the gateway endpoint
        // Gateway typically uses domain name, so use FQDN rule
        let gateway_host = remote.gateway_endpoint
            .split(':')
            .next()
            .unwrap_or(&remote.gateway_endpoint);

        let gateway_port = remote.gateway_endpoint
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(443u16);

        CiliumEgressRule {
            to_endpoints: vec![],
            to_fqdns: vec![FqdnSelector {
                match_name: Some(gateway_host.to_string()),
                match_pattern: None,
            }],
            to_cidr: vec![],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: gateway_port.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        }
    }
}
```

---

### 7. External DNS Integration

**New file: `crates/lattice-service/src/dns/mod.rs`**

Generate DNSEndpoint CRDs for external-dns to create DNS records.

```rust
//! DNS endpoint generation for cross-cluster service discovery
//!
//! Generates DNSEndpoint CRDs that external-dns reconciles to actual DNS records.
//! This is provider-agnostic and works with any DNS provider supported by external-dns.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// external-dns DNSEndpoint CRD
///
/// Reference: https://github.com/kubernetes-sigs/external-dns/blob/master/docs/contributing/crd-source.md
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsEndpoint {
    pub api_version: String,
    pub kind: String,
    pub metadata: DnsEndpointMetadata,
    pub spec: DnsEndpointSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsEndpointMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsEndpointSpec {
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    /// DNS name (e.g., "api.prod.cluster-a.lattice.example.com")
    pub dns_name: String,

    /// Record type (A, CNAME, SRV)
    pub record_type: String,

    /// Target addresses or hostnames
    pub targets: Vec<String>,

    /// TTL in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_ttl: Option<i64>,

    /// Provider-specific configuration
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_specific: BTreeMap<String, String>,
}

/// DNS endpoint generator for cross-cluster service discovery
pub struct DnsEndpointGenerator {
    /// Base domain for the cluster (e.g., "lattice.example.com")
    base_domain: String,

    /// Cluster name
    cluster_name: String,

    /// Default TTL for DNS records
    default_ttl: i64,
}

impl DnsEndpointGenerator {
    /// Default DNS TTL: 5 minutes (300 seconds)
    pub const DEFAULT_TTL: i64 = 300;

    pub fn new(
        base_domain: impl Into<String>,
        cluster_name: impl Into<String>,
    ) -> Self {
        Self {
            base_domain: base_domain.into(),
            cluster_name: cluster_name.into(),
            default_ttl: Self::DEFAULT_TTL,
        }
    }

    /// Generate qualified DNS name for a service
    ///
    /// Format: "{service}.{env}.{cluster}.{base_domain}"
    pub fn qualified_name(&self, env: &str, service_name: &str) -> String {
        format!(
            "{}.{}.{}.{}",
            service_name, env, self.cluster_name, self.base_domain
        )
    }

    /// Generate DNSEndpoint for a local service
    ///
    /// Creates an A record pointing to the gateway IP.
    /// Cross-cluster traffic routes: caller -> DNS -> gateway -> target service
    pub fn generate_a_record(
        &self,
        service_name: &str,
        env: &str,
        namespace: &str,
        gateway_ip: &str,
    ) -> DnsEndpoint {
        let dns_name = self.qualified_name(env, service_name);

        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/managed-by".to_string(), "lattice".to_string());
        labels.insert("lattice.dev/service".to_string(), service_name.to_string());
        labels.insert("lattice.dev/environment".to_string(), env.to_string());
        labels.insert("lattice.dev/cluster".to_string(), self.cluster_name.clone());

        DnsEndpoint {
            api_version: "externaldns.k8s.io/v1alpha1".to_string(),
            kind: "DNSEndpoint".to_string(),
            metadata: DnsEndpointMetadata {
                name: format!("{}-{}-dns", service_name, env),
                namespace: namespace.to_string(),
                labels,
                annotations: BTreeMap::new(),
            },
            spec: DnsEndpointSpec {
                endpoints: vec![Endpoint {
                    dns_name,
                    record_type: "A".to_string(),
                    targets: vec![gateway_ip.to_string()],
                    record_ttl: Some(self.default_ttl),
                    provider_specific: BTreeMap::new(),
                }],
            },
        }
    }

    /// Generate DNSEndpoint for a service with CNAME to gateway
    ///
    /// Useful when gateway has a hostname instead of IP.
    pub fn generate_cname_record(
        &self,
        service_name: &str,
        env: &str,
        namespace: &str,
        gateway_hostname: &str,
    ) -> DnsEndpoint {
        let dns_name = self.qualified_name(env, service_name);

        let mut labels = BTreeMap::new();
        labels.insert("app.kubernetes.io/managed-by".to_string(), "lattice".to_string());
        labels.insert("lattice.dev/service".to_string(), service_name.to_string());
        labels.insert("lattice.dev/environment".to_string(), env.to_string());
        labels.insert("lattice.dev/cluster".to_string(), self.cluster_name.clone());

        DnsEndpoint {
            api_version: "externaldns.k8s.io/v1alpha1".to_string(),
            kind: "DNSEndpoint".to_string(),
            metadata: DnsEndpointMetadata {
                name: format!("{}-{}-dns", service_name, env),
                namespace: namespace.to_string(),
                labels,
                annotations: BTreeMap::new(),
            },
            spec: DnsEndpointSpec {
                endpoints: vec![Endpoint {
                    dns_name,
                    record_type: "CNAME".to_string(),
                    targets: vec![gateway_hostname.to_string()],
                    record_ttl: Some(self.default_ttl),
                    provider_specific: BTreeMap::new(),
                }],
            },
        }
    }
}
```

---

### 8. Gateway API Configuration

**Modify: `crates/lattice-service/src/ingress/mod.rs`**

Add cross-cluster Gateway and HTTPRoute generation.

```rust
/// Compile cross-cluster Gateway for receiving traffic from other clusters
///
/// This gateway accepts mTLS traffic from sibling clusters and routes
/// to local services based on hostname.
pub fn compile_cross_cluster_gateway(
    namespace: &str,
    cluster_name: &str,
    gateway_port: u16,
) -> Gateway {
    Gateway {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        metadata: GatewayMetadata::new(
            format!("{}-cross-cluster-gateway", namespace),
            namespace,
        ),
        spec: GatewaySpec {
            gateway_class_name: "istio".to_string(), // Use Istio for mTLS
            listeners: vec![GatewayListener {
                name: "cross-cluster".to_string(),
                hostname: Some(format!("*.{}.*.lattice.local", cluster_name)), // Wildcard for all services
                port: gateway_port,
                protocol: "HTTPS".to_string(),
                tls: Some(GatewayTlsConfig {
                    mode: "MUTUAL".to_string(), // Require client cert
                    certificate_refs: vec![CertificateRef {
                        kind: "Secret".to_string(),
                        name: format!("{}-cross-cluster-tls", namespace),
                        namespace: Some(namespace.to_string()),
                    }],
                }),
            }],
        },
    }
}

/// Compile HTTPRoute for a local service to receive cross-cluster traffic
///
/// Routes traffic from the cross-cluster gateway to the local K8s Service.
pub fn compile_cross_cluster_route(
    service_name: &str,
    namespace: &str,
    qualified_dns_name: &str,
    service_port: u16,
) -> HttpRoute {
    HttpRoute {
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "HTTPRoute".to_string(),
        metadata: GatewayMetadata::new(
            format!("{}-cross-cluster-route", service_name),
            namespace,
        ),
        spec: HttpRouteSpec {
            parent_refs: vec![ParentRef {
                group: Some("gateway.networking.k8s.io".to_string()),
                kind: Some("Gateway".to_string()),
                name: format!("{}-cross-cluster-gateway", namespace),
                namespace: Some(namespace.to_string()),
                section_name: None,
                port: None,
            }],
            hostnames: vec![qualified_dns_name.to_string()],
            rules: vec![HttpRouteRule {
                matches: vec![HttpRouteMatch {
                    path: Some(HttpPathMatch {
                        type_: "PathPrefix".to_string(),
                        value: "/".to_string(),
                    }),
                    headers: None,
                    method: None,
                }],
                filters: vec![],
                backend_refs: vec![BackendRef {
                    kind: Some("Service".to_string()),
                    name: service_name.to_string(),
                    namespace: None, // Same namespace
                    port: Some(service_port),
                    weight: None,
                }],
            }],
        },
    }
}
```

---

## Data Flow Diagrams

### Service Announcement Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Service Announcement Flow                            │
└─────────────────────────────────────────────────────────────────────────────┘

1. LatticeService created/updated in Cluster A

   ┌──────────────────┐
   │ LatticeService   │
   │   name: api      │
   │   env: prod      │
   │   allowed: [*]   │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Service          │
   │ Controller       │
   │ reconcile()      │
   └────────┬─────────┘
            │
            ├───────────────────────────────────────┐
            │                                       │
            ▼                                       ▼
   ┌──────────────────┐                    ┌──────────────────┐
   │ graph.put_       │                    │ discovery.       │
   │   service()      │                    │   announce_      │
   │                  │                    │   service()      │
   └──────────────────┘                    └────────┬─────────┘
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │ Agent gRPC       │
                                           │ Stream           │
                                           │ (outbound)       │
                                           └────────┬─────────┘
                                                    │
                                                    │ ServiceAnnouncement
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │ Parent Cell      │
                                           │ gRPC Server      │
                                           └────────┬─────────┘
                                                    │
                                                    ▼
                                           ┌──────────────────┐
                                           │ catalog.         │
                                           │   register()     │
                                           │                  │
                                           │ (env,name) ->    │
                                           │   CatalogEntry   │
                                           └──────────────────┘
```

### Cross-Cluster Dependency Resolution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               Cross-Cluster Dependency Resolution Flow                      │
└─────────────────────────────────────────────────────────────────────────────┘

1. LatticeService in Cluster B depends on "api" service

   ┌──────────────────┐
   │ LatticeService   │
   │   name: frontend │
   │   depends: [api] │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Service          │
   │ Controller       │
   │ reconcile()      │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐      ┌──────────────────┐
   │ graph.get_       │─────►│ ServiceNode      │
   │   service()      │      │   type: Unknown  │ ◄─── Not found locally
   └────────┬─────────┘      └──────────────────┘
            │
            ▼
   ┌──────────────────┐
   │ discovery.       │
   │   resolve_       │
   │   unknown()      │
   └────────┬─────────┘
            │
            ├──────────────────────────────────────────────────────────┐
            │                                                          │
            ▼                                                          │
   ┌──────────────────┐                                               │
   │ 1. Check fresh   │                                               │
   │    cache         │──── miss ─────────────────────┐               │
   └──────────────────┘                               │               │
                                                      │               │
                                                      ▼               │
                                             ┌──────────────────┐     │
                                             │ 2. Query parent  │     │
                                             │    via gRPC      │     │
                                             └────────┬─────────┘     │
                                                      │               │
                                                      │ ServiceQuery  │
                                                      │               │
                                                      ▼               │
                                             ┌──────────────────┐     │
                                             │ Parent Cell      │     │
                                             │ catalog.query()  │     │
                                             └────────┬─────────┘     │
                                                      │               │
                                                      │ QueryResponse │
                                                      │ (found +      │
                                                      │  bilateral)   │
                                                      ▼               │
                                             ┌──────────────────┐     │
                                             │ 3. Cache result  │     │
                                             │    locally       │     │
                                             └────────┬─────────┘     │
                                                      │               │
            ┌─────────────────────────────────────────┘               │
            │                                                          │
            ▼                                                          │
   ┌──────────────────┐                                               │
   │ Return           │                                               │
   │ CatalogEntry     │◄──────────────────────────────────────────────┘
   │ (remote api)     │         (fallback: use stale cache)
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │ Generate:        │
   │  - ServiceEntry  │
   │  - HTTPRoute     │
   │  - AuthzPolicy   │
   │  - CiliumPolicy  │
   │  - DNSEndpoint   │
   └──────────────────┘
```

---

## Failure Handling Matrix

**Key Principle: The cache NEVER causes query failures.** Cached data is always usable regardless of age. Staleness is tracked for observability/alerting but does not block queries.

| Scenario | Detection | Behavior | Recovery |
|----------|-----------|----------|----------|
| Parent unreachable | gRPC stream error | Continue using cached data (staleness tracked) | Auto-reconnect with backoff |
| Query timeout (5s) | Timeout error | Return cached data, log warning | Retry on next reconcile |
| Service not found | Never seen + 404 from parent | Return NotFound error | Will retry on next reconcile |
| Service removed | Parent says not found, but we have cache | **Keep using cached data** (might be temporary) | Background task can clean up eventually |
| Bilateral agreement fails | Response indicates no agreement | Return None (deny access) | User must add bilateral agreement |
| Agent disconnect | Stream closed | Parent removes cluster from catalog | Agent reconnects, full sync |
| Cache "stale" | Age > refresh interval | Data still usable, prioritize for refresh | Background refresh task |
| Cache "ancient" | Age > 10x refresh interval | Data still usable, emit warning metrics | Alert on ancient entries |
| Parent restart | New connection | Full catalog sync from all children | Children detect and resync |

### Staleness Levels (for observability, NOT for rejection)

| Level | Age | Behavior |
|-------|-----|----------|
| Fresh | < 5 min | Normal operation |
| Stale | 5-25 min | Log debug, prioritize for refresh |
| VeryStale | 10-30 min | Log warning, emit metric |
| Ancient | > 50 min | Log error, emit alert metric |

All levels return cached data successfully. Staleness only affects logging and metrics.

---

## Security Considerations

### Bilateral Agreement Enforcement

Cross-cluster bilateral agreements work the same as local:

1. **Caller declares dependency**: `resources: { api: { type: service, direction: outbound } }`
2. **Callee allows caller**: `resources: { frontend: { type: service, direction: inbound } }`

The parent catalog stores `allowed_callers` and validates bilateral agreement before returning query results. If the agreement is not satisfied, `bilateral_agreement: false` is returned and no ServiceEntry is generated.

### mTLS Between Clusters

All cross-cluster traffic uses mTLS via the Istio service mesh:

1. **ServiceEntry**: `location: MESH_INTERNAL` ensures traffic participates in mesh
2. **Gateway**: `tls.mode: MUTUAL` requires client certificates
3. **AuthorizationPolicy**: SPIFFE principals enforce identity-based access

### Network Policy

Cilium policies restrict egress to only the gateway endpoint for remote services:

```yaml
egress:
  - toFQDNs:
      - matchName: gateway.cluster-a.lattice.example.com
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
```

---

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `crates/lattice-proto/proto/agent.proto` | Modify | Add ServiceAnnouncement, ServiceQuery, etc. |
| `crates/lattice-cluster/src/catalog/mod.rs` | **New** | ServiceCatalog for parent clusters |
| `crates/lattice-cluster/src/catalog/cache.rs` | **New** | RemoteServiceCache for all clusters |
| `crates/lattice-cluster/src/discovery/mod.rs` | **New** | DiscoveryCoordinator |
| `crates/lattice-cluster/src/agent/server.rs` | Modify | Handle new AgentMessage types |
| `crates/lattice-cluster/src/agent/client.rs` | Modify | Send announcements and queries |
| `crates/lattice-service/src/controller.rs` | Modify | Integrate discovery coordinator |
| `crates/lattice-service/src/policy/mod.rs` | Modify | Add remote service policy generation |
| `crates/lattice-service/src/dns/mod.rs` | **New** | DNSEndpoint generation |
| `crates/lattice-service/src/ingress/mod.rs` | Modify | Cross-cluster Gateway/HTTPRoute |
| `crates/lattice-service/src/compiler/mod.rs` | Modify | Include remote resources in CompiledService |

---

## Testing Strategy

### Unit Tests

- `ServiceCatalog`: register, unregister, query, version conflicts, cluster cleanup
- `RemoteServiceCache`: TTL expiration, stale fallback, TTL extension
- `DiscoveryCoordinator`: announce, query, timeout handling, cache integration
- `PolicyCompiler`: remote ServiceEntry, remote AuthorizationPolicy, remote Cilium egress
- `DnsEndpointGenerator`: A records, CNAME records, qualified names

### Integration Tests

- Service announcement propagates to parent catalog
- Service query resolves across cluster boundary
- Bilateral agreement enforcement for cross-cluster deps
- Cache fallback when parent unavailable

### E2E Tests

1. **Basic Cross-Cluster Dependency**
   - Create `api` service in Cluster A (allows `frontend`)
   - Create `frontend` service in Cluster B (depends on `api`)
   - Verify ServiceEntry created in Cluster B
   - Verify HTTPRoute routes through gateway
   - Verify DNS record created

2. **Parent Disconnect Resilience**
   - Establish cross-cluster dependency
   - Kill parent cluster
   - Verify Cluster B continues operating with cached data
   - Verify extended TTL (1 hour)

3. **Bilateral Agreement Denial**
   - Create `api` service in Cluster A (allows `authorized` only)
   - Create `unauthorized` service in Cluster B (depends on `api`)
   - Verify no ServiceEntry created (bilateral agreement fails)

4. **Service Update Propagation**
   - Create service with allowed_callers: [*]
   - Update to allowed_callers: [specific]
   - Verify catalog updated
   - Verify dependent services recompiled

---

## Configuration

### Cluster Configuration

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: cluster-a
spec:
  provider:
    type: aws
  # Enable cross-cluster discovery
  discovery:
    enabled: true
    baseDomain: lattice.example.com
    gatewayPort: 443
  # Parent configuration (enables this cluster to be a parent)
  parentConfig:
    host: cell.cluster-a.example.com
    grpcPort: 50051
```

### External DNS Configuration

Requires external-dns deployment with CRD source enabled:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  template:
    spec:
      containers:
        - name: external-dns
          args:
            - --source=crd
            - --crd-source-apiversion=externaldns.k8s.io/v1alpha1
            - --crd-source-kind=DNSEndpoint
            - --provider=aws  # or other provider
            - --domain-filter=lattice.example.com
```

---

## Future Considerations

1. **Multi-Level Hierarchy**: Current design supports one level (parent-child). Could extend to grandparent queries.

2. **Service Mesh Federation**: Could integrate with Istio multi-cluster federation for direct pod-to-pod mTLS.

3. **Query Caching at Parent**: Parent could cache query results to reduce load on children.

4. **Push-Based Updates**: Parent could proactively push service updates to children that have queried them.

5. **Topology-Aware Routing**: Route to closest cluster when service exists in multiple clusters.
