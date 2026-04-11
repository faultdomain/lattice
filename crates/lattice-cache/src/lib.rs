//! Per-controller resource cache backed by kube-rs reflector watches.
//!
//! Each controller builds its own `ResourceCache` with exactly the resource
//! types it needs. All reads are memory hits — controllers never call the
//! K8s API at point of use.
//!
//! Supports both typed resources (compile-time safe) and dynamic resources
//! (runtime GVK). Internally keyed by `group/version/kind` string.
//!
//! ```rust,ignore
//! // Typed (compile-time safe):
//! let cache = ResourceCache::builder()
//!     .watch(Api::<LatticeQuota>::namespaced(client.clone(), "lattice-system"))
//!     .watch(Api::<Namespace>::all(client.clone()))
//!     .build();
//! let quotas: Vec<Arc<LatticeQuota>> = cache.list::<LatticeQuota>();
//!
//! // Dynamic (any GVK):
//! let cache = ResourceCache::builder()
//!     .watch_dynamic(api, ar.clone())
//!     .build();
//! let gateways: Vec<Arc<DynamicObject>> = cache.list_dynamic(&ar);
//! ```

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use dashmap::DashMap;
use futures::StreamExt;
use kube::api::{Api, ApiResource, DynamicObject};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::watcher::{self, Config as WatcherConfig};
use kube::runtime::WatchStreamExt;
use kube::Resource;

/// Watcher timeout — must be less than the kube client read_timeout (30s).
const WATCH_TIMEOUT_SECS: u32 = 25;

/// Spawn a reflector watcher for a dynamic resource and return the store reader.
///
/// Shared by both `ResourceCacheBuilder::watch_dynamic_with` (startup) and
/// `ResourceCache::ensure_dynamic` (lazy registration).
fn spawn_dynamic_watcher(
    api: Api<DynamicObject>,
    ar: &ApiResource,
    config: WatcherConfig,
) -> Store<DynamicObject> {
    let writer = reflector::store::Writer::<DynamicObject>::new(ar.clone());
    let reader = writer.as_reader();
    let label = format!("DynamicObject({})", ar.kind);
    let stream = watcher::watcher(api, config);
    tokio::spawn(async move {
        let mut stream = std::pin::pin!(reflector::reflector(writer, stream)
            .default_backoff()
            .applied_objects());
        while let Some(result) = stream.next().await {
            if let Err(e) = result {
                tracing::debug!(
                    resource = %label,
                    error = %e,
                    "Cache watcher error (will reconnect)"
                );
            }
        }
        tracing::warn!(resource = %label, "Cache watcher stream ended");
    });
    reader
}

// ---------------------------------------------------------------------------
// GVK key
// ---------------------------------------------------------------------------

/// Derive a stable string key from group/version/kind.
fn gvk_key(group: &str, version: &str, kind: &str) -> String {
    format!("{group}/{version}/{kind}")
}

/// Derive a GVK key from a typed resource.
fn gvk_key_for<K: Resource<DynamicType = ()>>() -> String {
    gvk_key(&K::group(&()), &K::version(&()), &K::kind(&()))
}

/// Derive a GVK key from an ApiResource (for dynamic objects).
fn gvk_key_for_ar(ar: &ApiResource) -> String {
    gvk_key(&ar.group, &ar.version, &ar.kind)
}

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

/// Store wrapper for DynamicObject (keyed by ApiResource).
struct DynamicStore {
    store: Store<DynamicObject>,
}

impl AnyStore for DynamicStore {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn type_name(&self) -> &'static str {
        "DynamicObject"
    }
}

// ---------------------------------------------------------------------------
// ResourceCache
// ---------------------------------------------------------------------------

/// In-memory cache of Kubernetes resources backed by reflector watches.
///
/// Built per-controller with exactly the types that controller needs.
/// All reads are local — no API calls at point of use.
///
/// Supports lazy registration of dynamic watches via `ensure_dynamic`
/// for CRDs that may not be installed at startup.
#[derive(Clone)]
pub struct ResourceCache {
    stores: Arc<DashMap<String, Arc<dyn AnyStore>>>,
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
            stores: Arc::new(DashMap::new()),
        }
    }

    /// Ensure a dynamic watch exists for the given ApiResource.
    ///
    /// If the cache already has a store for this GVK, this is a no-op and
    /// returns `true`. Otherwise it spawns a new reflector watcher and
    /// returns `false` — the caller should requeue to let the reflector
    /// populate before reading.
    pub fn ensure_dynamic(&self, api: Api<DynamicObject>, ar: ApiResource) -> bool {
        let key = gvk_key_for_ar(&ar);
        if self.stores.contains_key(&key) {
            return true;
        }

        let reader = spawn_dynamic_watcher(
            api,
            &ar,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        );
        self.stores
            .insert(key, Arc::new(DynamicStore { store: reader }));
        tracing::info!(kind = %ar.kind, "Lazily registered dynamic cache watch");
        false
    }

    // -- Typed reads --

    /// List all cached objects of type `K`.
    pub fn list<K>(&self) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        match self.typed_store::<K>() {
            Some(store) => store.state(),
            None => vec![],
        }
    }

    /// List cached objects of type `K` matching the predicate.
    pub fn list_filtered<K>(&self, predicate: impl Fn(&K) -> bool) -> Vec<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        match self.typed_store::<K>() {
            Some(store) => store
                .state()
                .into_iter()
                .filter(|obj| predicate(obj))
                .collect(),
            None => vec![],
        }
    }

    /// Get a single cached object by name (cluster-scoped).
    pub fn get<K>(&self, name: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.typed_store::<K>()?.get(&ObjectRef::new(name))
    }

    /// Get a single cached object by name and namespace.
    pub fn get_namespaced<K>(&self, name: &str, namespace: &str) -> Option<Arc<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.typed_store::<K>()?
            .get(&ObjectRef::new(name).within(namespace))
    }

    // -- Dynamic reads --

    /// List all cached dynamic objects for the given ApiResource.
    pub fn list_dynamic(&self, ar: &ApiResource) -> Vec<Arc<DynamicObject>> {
        match self.dynamic_store(ar) {
            Some(store) => store.state(),
            None => vec![],
        }
    }

    /// List cached dynamic objects matching the predicate.
    pub fn list_dynamic_filtered(
        &self,
        ar: &ApiResource,
        predicate: impl Fn(&DynamicObject) -> bool,
    ) -> Vec<Arc<DynamicObject>> {
        match self.dynamic_store(ar) {
            Some(store) => store
                .state()
                .into_iter()
                .filter(|obj| predicate(obj))
                .collect(),
            None => vec![],
        }
    }

    /// Get a single cached dynamic object by name (cluster-scoped).
    pub fn get_dynamic(&self, ar: &ApiResource, name: &str) -> Option<Arc<DynamicObject>> {
        self.dynamic_store(ar)?
            .get(&ObjectRef::new_with(name, ar.clone()))
    }

    /// Get a single cached dynamic object by name and namespace.
    pub fn get_dynamic_namespaced(
        &self,
        ar: &ApiResource,
        name: &str,
        namespace: &str,
    ) -> Option<Arc<DynamicObject>> {
        self.dynamic_store(ar)?
            .get(&ObjectRef::new_with(name, ar.clone()).within(namespace))
    }

    // -- Domain helpers --

    /// Resolve ImageProvider credentials from the cache by name.
    ///
    /// For each provider name, looks up the ImageProvider CRD in `lattice-system`
    /// and extracts its credentials. Missing or credential-less providers are
    /// skipped — the workload compiler produces the authoritative error when a
    /// referenced provider is absent from the resolved map.
    pub fn resolve_image_providers(
        &self,
        provider_names: &[String],
    ) -> std::collections::BTreeMap<String, lattice_common::crd::CredentialSpec> {
        use lattice_common::crd::ImageProvider;

        let mut result = std::collections::BTreeMap::new();
        for name in provider_names {
            if let Some(provider) =
                self.get_namespaced::<ImageProvider>(name, lattice_core::LATTICE_SYSTEM_NAMESPACE)
            {
                if let Some(ref credentials) = provider.spec.credentials {
                    result.insert(name.clone(), credentials.clone());
                }
            }
        }
        result
    }

    // -- Internal --

    fn typed_store<K>(&self) -> Option<Store<K>>
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        self.stores.get(&gvk_key_for::<K>()).and_then(|entry| {
            entry
                .value()
                .as_any()
                .downcast_ref::<TypedStore<K>>()
                .map(|ts| ts.store.clone())
        })
    }

    fn dynamic_store(&self, ar: &ApiResource) -> Option<Store<DynamicObject>> {
        self.stores.get(&gvk_key_for_ar(ar)).and_then(|entry| {
            entry
                .value()
                .as_any()
                .downcast_ref::<DynamicStore>()
                .map(|ds| ds.store.clone())
        })
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for constructing a `ResourceCache`.
pub struct ResourceCacheBuilder {
    stores: HashMap<String, Arc<dyn AnyStore>>,
}

impl ResourceCacheBuilder {
    /// Watch a typed resource with the default config.
    pub fn watch<K>(self, api: Api<K>) -> Self
    where
        K: Resource<DynamicType = ()>
            + Clone
            + fmt::Debug
            + Send
            + Sync
            + serde::de::DeserializeOwned
            + 'static,
    {
        self.watch_with(api, WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS))
    }

    /// Watch a typed resource with a custom config (e.g., label selector).
    pub fn watch_with<K>(mut self, api: Api<K>, config: WatcherConfig) -> Self
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
        Self::spawn_typed_watcher(api, writer, config);
        self.stores
            .insert(gvk_key_for::<K>(), Arc::new(TypedStore { store: reader }));
        self
    }

    /// Watch a dynamic resource (any GVK).
    pub fn watch_dynamic(self, api: Api<DynamicObject>, ar: ApiResource) -> Self {
        self.watch_dynamic_with(
            api,
            ar,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
    }

    /// Watch a dynamic resource with a custom config.
    pub fn watch_dynamic_with(
        mut self,
        api: Api<DynamicObject>,
        ar: ApiResource,
        config: WatcherConfig,
    ) -> Self {
        let reader = spawn_dynamic_watcher(api, &ar, config);
        self.stores.insert(
            gvk_key_for_ar(&ar),
            Arc::new(DynamicStore { store: reader }),
        );
        self
    }

    /// Seed typed objects without spawning a watcher.
    pub fn seed<K>(mut self, objects: Vec<K>) -> Self
    where
        K: Resource<DynamicType = ()> + Clone + fmt::Debug + Send + Sync + 'static,
    {
        let (reader, mut writer) = reflector::store();
        for obj in objects {
            writer.apply_watcher_event(&watcher::Event::Apply(obj));
        }
        self.stores
            .insert(gvk_key_for::<K>(), Arc::new(TypedStore { store: reader }));
        self
    }

    /// Build the cache. All watchers are already running.
    pub fn build(self) -> ResourceCache {
        let type_names: Vec<&str> = self.stores.values().map(|s| s.type_name()).collect();
        tracing::info!(types = ?type_names, "Resource cache ready");
        let map = DashMap::with_capacity(self.stores.len());
        for (k, v) in self.stores {
            map.insert(k, v);
        }
        ResourceCache {
            stores: Arc::new(map),
        }
    }

    fn spawn_typed_watcher<K>(
        api: Api<K>,
        writer: reflector::store::Writer<K>,
        config: WatcherConfig,
    ) where
        K: Resource<DynamicType = ()>
            + Clone
            + fmt::Debug
            + Send
            + Sync
            + serde::de::DeserializeOwned
            + 'static,
    {
        let label = std::any::type_name::<K>();
        tokio::spawn(async move {
            let mut stream =
                std::pin::pin!(reflector::reflector(writer, watcher::watcher(api, config))
                    .default_backoff()
                    .applied_objects());
            while let Some(result) = stream.next().await {
                if let Err(e) = result {
                    tracing::debug!(
                        resource = label,
                        error = %e,
                        "Cache watcher error (will reconnect)"
                    );
                }
            }
            tracing::warn!(resource = label, "Cache watcher stream ended");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
    use kube::api::ObjectMeta;

    fn make_namespace(name: &str) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_configmap(name: &str, namespace: &str) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn empty_cache_returns_empty() {
        let cache = ResourceCache::empty();
        assert!(cache.list::<Namespace>().is_empty());
        assert!(cache.get::<Namespace>("test").is_none());
        assert!(cache.get_namespaced::<ConfigMap>("cm", "ns").is_none());
    }

    #[test]
    fn seed_and_list() {
        let cache = ResourceCache::builder()
            .seed(vec![make_namespace("alpha"), make_namespace("beta")])
            .build();
        assert_eq!(cache.list::<Namespace>().len(), 2);
    }

    #[test]
    fn seed_and_get() {
        let cache = ResourceCache::builder()
            .seed(vec![make_namespace("alpha")])
            .build();
        assert!(cache.get::<Namespace>("alpha").is_some());
        assert!(cache.get::<Namespace>("missing").is_none());
    }

    #[test]
    fn seed_namespaced_and_get() {
        let cache = ResourceCache::builder()
            .seed(vec![
                make_configmap("cm1", "ns-a"),
                make_configmap("cm2", "ns-b"),
            ])
            .build();
        assert!(cache.get_namespaced::<ConfigMap>("cm1", "ns-a").is_some());
        assert!(cache.get_namespaced::<ConfigMap>("cm1", "ns-b").is_none());
    }

    #[test]
    fn list_filtered_returns_matching() {
        let cache = ResourceCache::builder()
            .seed(vec![
                make_configmap("app-config", "prod"),
                make_configmap("db-config", "prod"),
                make_configmap("app-config", "staging"),
            ])
            .build();

        let prod_only =
            cache.list_filtered::<ConfigMap>(|cm| cm.metadata.namespace.as_deref() == Some("prod"));
        assert_eq!(prod_only.len(), 2);
    }

    #[test]
    fn gvk_key_is_stable() {
        assert_eq!(gvk_key_for::<Namespace>(), "/v1/Namespace");
        assert_eq!(gvk_key_for::<ConfigMap>(), "/v1/ConfigMap");
    }
}
