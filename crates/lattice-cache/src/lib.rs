//! Per-controller resource cache backed by kube-rs reflector watches.
//!
//! Each controller builds its own `ResourceCache` with exactly the resource
//! types it needs. All reads are memory hits — controllers never call the
//! K8s API at point of use.
//!
//! Duplicate watches across controllers are cheap: each is a single
//! persistent HTTP connection to the API server's watch cache.
//!
//! ```rust,ignore
//! let cache = ResourceCache::builder()
//!     .watch(Api::<LatticeQuota>::namespaced(client.clone(), "lattice-system"))
//!     .watch(Api::<Namespace>::all(client.clone()))
//!     .build();
//!
//! // In reconcile — zero API calls:
//! let quotas: Vec<Arc<LatticeQuota>> = cache.list::<LatticeQuota>();
//! let ns: Option<Arc<Namespace>> = cache.get::<Namespace>("my-namespace");
//! ```

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::watcher::{self, Config as WatcherConfig};
use kube::runtime::WatchStreamExt;
use kube::Resource;

/// Watcher timeout — must be less than the kube client read_timeout (30s).
const WATCH_TIMEOUT_SECS: u32 = 25;

// ---------------------------------------------------------------------------
// Type-erased store
// ---------------------------------------------------------------------------

trait AnyStore: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &'static str;
}

struct TypedStore<K>
where
    K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
{
    store: Store<K>,
}

impl<K> AnyStore for TypedStore<K>
where
    K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn type_name(&self) -> &'static str {
        std::any::type_name::<K>()
    }
}

// ---------------------------------------------------------------------------
// ResourceCache
// ---------------------------------------------------------------------------

/// In-memory cache of Kubernetes resources backed by reflector watches.
///
/// Built per-controller with exactly the types that controller needs.
/// All reads are local — no API calls at point of use.
#[derive(Clone)]
pub struct ResourceCache {
    stores: Arc<HashMap<TypeId, Arc<dyn AnyStore>>>,
}

impl ResourceCache {
    /// Create a builder.
    pub fn builder() -> ResourceCacheBuilder {
        ResourceCacheBuilder {
            stores: HashMap::new(),
        }
    }

    /// Create an empty cache (no watches). Used in tests.
    pub fn empty() -> Self {
        Self {
            stores: Arc::new(HashMap::new()),
        }
    }

    /// List all cached objects of type `K`.
    ///
    /// Returns an empty vec if the type was not registered.
    pub fn list<K>(&self) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        match self.store_for::<K>() {
            Some(store) => store.state(),
            None => vec![],
        }
    }

    /// Get a single cached object by name (cluster-scoped resources).
    pub fn get<K>(&self, name: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.store_for::<K>()?.get(&ObjectRef::new(name))
    }

    /// Get a single cached object by name and namespace.
    pub fn get_namespaced<K>(&self, name: &str, namespace: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.store_for::<K>()?
            .get(&ObjectRef::new(name).within(namespace))
    }

    fn store_for<K>(&self) -> Option<&Store<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.stores
            .get(&TypeId::of::<K>())
            .and_then(|s| s.as_any().downcast_ref::<TypedStore<K>>())
            .map(|ts| &ts.store)
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `ResourceCache`.
pub struct ResourceCacheBuilder {
    stores: HashMap<TypeId, Arc<dyn AnyStore>>,
}

impl ResourceCacheBuilder {
    /// Register a resource type to watch. Spawns a background watcher.
    pub fn watch<K>(mut self, api: Api<K>) -> Self
    where
        K: Resource<DynamicType = ()>
            + Clone
            + fmt::Debug
            + Send
            + Sync
            + serde::de::DeserializeOwned
            + 'static,
    {
        let (reader, writer) = reflector::store();
        let stream = watcher::watcher(api, WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS));

        let type_name = std::any::type_name::<K>();
        tokio::spawn(async move {
            let mut stream = std::pin::pin!(reflector::reflector(writer, stream)
                .default_backoff()
                .applied_objects());
            while let Some(result) = stream.next().await {
                if let Err(e) = result {
                    tracing::debug!(
                        resource = type_name,
                        error = %e,
                        "Cache watcher error (will reconnect)"
                    );
                }
            }
            tracing::warn!(resource = type_name, "Cache watcher stream ended");
        });

        self.stores
            .insert(TypeId::of::<K>(), Arc::new(TypedStore { store: reader }));
        self
    }

    /// Build the cache. All watchers are already running.
    pub fn build(self) -> ResourceCache {
        let type_names: Vec<&str> = self.stores.values().map(|s| s.type_name()).collect();
        tracing::info!(types = ?type_names, "Resource cache ready");
        ResourceCache {
            stores: Arc::new(self.stores),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_returns_empty() {
        let cache = ResourceCache::empty();
        let result = cache.list::<k8s_openapi::api::core::v1::Namespace>();
        assert!(result.is_empty());
        assert!(cache.get::<k8s_openapi::api::core::v1::Namespace>("test").is_none());
        assert!(
            cache
                .get_namespaced::<k8s_openapi::api::core::v1::ConfigMap>("cm", "ns")
                .is_none()
        );
    }
}
