//! Shared quota store — watch channel for quota distribution.
//!
//! The quota controller sends updates via a `watch::Sender`. Workload
//! controllers hold `watch::Receiver`s and read the latest snapshot.
//! Same pattern as tokio's broadcast but optimized for "latest value" semantics.

use std::collections::BTreeMap;

use lattice_common::crd::LatticeQuota;
use tokio::sync::watch;

/// Snapshot of quota state, sent through the watch channel.
#[derive(Clone, Debug, Default)]
pub struct QuotaSnapshot {
    /// All enabled quotas with their statuses
    pub quotas: Vec<LatticeQuota>,
    /// Cached namespace labels (namespace -> labels)
    pub namespace_labels: BTreeMap<String, BTreeMap<String, String>>,
}

/// Sender side — owned by the quota controller.
pub type QuotaSender = watch::Sender<QuotaSnapshot>;

/// Receiver side — cloned into each workload controller context.
#[derive(Clone)]
pub struct QuotaStore {
    rx: watch::Receiver<QuotaSnapshot>,
}

impl QuotaStore {
    /// Resolve a `QuotaBudget` for a specific workload from the latest snapshot.
    pub fn resolve_budget(
        &self,
        namespace: &str,
        name: &str,
        workload_annotations: &BTreeMap<String, String>,
    ) -> crate::QuotaBudget {
        let snapshot = self.rx.borrow();
        let ns_labels = snapshot
            .namespace_labels
            .get(namespace)
            .cloned()
            .unwrap_or_default();
        crate::QuotaBudget::from_matching_quotas(
            &snapshot.quotas,
            namespace,
            name,
            &ns_labels,
            workload_annotations,
        )
    }
}

/// Create a paired sender/receiver for the quota watch channel.
pub fn channel() -> (QuotaSender, QuotaStore) {
    let (tx, rx) = watch::channel(QuotaSnapshot::default());
    (tx, QuotaStore { rx })
}

impl QuotaStore {
    /// Create an empty store for testing (no sender, always empty).
    pub fn empty() -> Self {
        let (_tx, rx) = watch::channel(QuotaSnapshot::default());
        Self { rx }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::LatticeQuotaSpec;

    #[test]
    fn empty_store_returns_empty_budget() {
        let (_tx, store) = channel();
        let budget = store.resolve_budget("ns", "svc", &BTreeMap::new());
        assert!(budget.remaining.is_empty());
    }

    #[test]
    fn send_and_resolve() {
        let (tx, store) = channel();

        let mut quota = LatticeQuota::new(
            "test",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), "10".to_string())]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );
        quota.metadata.namespace = Some("lattice-system".to_string());

        let mut ns_labels = BTreeMap::new();
        ns_labels.insert(
            "ns".to_string(),
            BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]),
        );

        tx.send(QuotaSnapshot {
            quotas: vec![quota],
            namespace_labels: ns_labels,
        })
        .unwrap();

        let budget = store.resolve_budget("ns", "svc", &BTreeMap::new());
        assert_eq!(budget.remaining.get("cpu"), Some(&10000));
    }

    #[test]
    fn cloned_receivers_see_updates() {
        let (tx, store1) = channel();
        let store2 = store1.clone();

        let quota = LatticeQuota::new(
            "test",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), "20".to_string())]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );

        tx.send(QuotaSnapshot {
            quotas: vec![quota],
            namespace_labels: BTreeMap::from([(
                "ns".to_string(),
                BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())]),
            )]),
        })
        .unwrap();

        let b1 = store1.resolve_budget("ns", "svc", &BTreeMap::new());
        let b2 = store2.resolve_budget("ns", "svc", &BTreeMap::new());
        assert_eq!(b1.remaining.get("cpu"), b2.remaining.get("cpu"));
    }
}
