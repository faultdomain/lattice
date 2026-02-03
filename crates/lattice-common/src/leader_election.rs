//! Leader election using Kubernetes Leases
//!
//! Provides leader election for HA deployments using the Kubernetes
//! coordination.k8s.io/v1 Lease API. Only the leader runs controllers
//! and accepts traffic.
//!
//! # Atomicity
//!
//! Uses resourceVersion for compare-and-swap semantics. If the lease changes
//! between read and write, the update fails with 409 Conflict and we retry.
//! This prevents race conditions where two pods both think they acquired leadership.
//!
//! # Traffic Routing
//!
//! The leader adds a `lattice.dev/leader=true` label to its pod. The Service
//! selector includes this label, so only the leader receives traffic. Kubernetes
//! readiness probes ensure the old leader is removed from Endpoints before the
//! lease expires (30s lease > 15s readiness removal time).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use serde_json::json;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::LATTICE_SYSTEM_NAMESPACE;

/// Lease name for the Lattice operator leader election
pub const LEADER_LEASE_NAME: &str = "lattice-operator-leader";

/// Label key added to leader pod for Service selector
pub const LEADER_LABEL_KEY: &str = "lattice.dev/leader";

/// Label value for leader pod
pub const LEADER_LABEL_VALUE: &str = "true";

// Timing constants
const LEASE_DURATION: Duration = Duration::from_secs(30);
const RENEW_INTERVAL: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const FIELD_MANAGER: &str = "lattice-operator";

/// Leader election errors
#[derive(Debug, Error)]
pub enum LeaderElectionError {
    /// Kubernetes API error
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

/// Leader elector using Kubernetes Leases
///
/// Manages leader election for HA deployments. Only one pod holds the
/// lease at a time. The leader adds a label to route traffic to itself.
pub struct LeaderElector {
    client: Client,
    lease_name: String,
    namespace: String,
    identity: String,
    lease_duration: Duration,
    renew_interval: Duration,
    retry_interval: Duration,
    is_leader: Arc<AtomicBool>,
}

impl LeaderElector {
    /// Create a new leader elector with default timing (30s lease, 10s renew, 5s retry)
    pub fn new(client: Client, lease_name: &str, namespace: &str, identity: &str) -> Self {
        Self {
            client,
            lease_name: lease_name.to_string(),
            namespace: namespace.to_string(),
            identity: identity.to_string(),
            lease_duration: LEASE_DURATION,
            renew_interval: RENEW_INTERVAL,
            retry_interval: RETRY_INTERVAL,
            is_leader: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Block until leadership is acquired, then return a guard
    ///
    /// The guard maintains leadership through periodic renewal.
    /// When the guard is dropped or leadership is lost, the lost channel signals.
    pub async fn acquire(self: Arc<Self>) -> Result<LeaderGuard, LeaderElectionError> {
        info!(
            identity = %self.identity,
            lease = %self.lease_name,
            "Waiting for leadership..."
        );

        loop {
            match self.try_acquire_or_renew().await {
                Ok(true) => {
                    info!(identity = %self.identity, "Leadership acquired");
                    self.is_leader.store(true, Ordering::SeqCst);
                    return Ok(self.create_guard());
                }
                Ok(false) => {
                    debug!(
                        identity = %self.identity,
                        retry_secs = self.retry_interval.as_secs(),
                        "Lease held by another, waiting..."
                    );
                }
                Err(e) => {
                    // Log but continue - transient errors shouldn't stop us
                    warn!(
                        identity = %self.identity,
                        error = %e,
                        retry_secs = self.retry_interval.as_secs(),
                        "Failed to acquire lease, retrying..."
                    );
                }
            }
            tokio::time::sleep(self.retry_interval).await;
        }
    }

    /// Create a LeaderGuard with renewal task
    fn create_guard(self: &Arc<Self>) -> LeaderGuard {
        let (lost_tx, lost_rx) = oneshot::channel();
        let elector = Arc::clone(self);
        let renewal_task = tokio::spawn(async move {
            elector.renewal_loop(lost_tx).await;
        });

        LeaderGuard {
            elector: Arc::clone(self),
            renewal_task,
            lost_rx: Some(lost_rx),
        }
    }

    /// Try to acquire or renew the lease atomically
    ///
    /// Uses resourceVersion for compare-and-swap semantics:
    /// - Read lease and its resourceVersion
    /// - Decide if we can acquire/renew
    /// - Update with resourceVersion - fails if lease changed since read
    async fn try_acquire_or_renew(&self) -> Result<bool, LeaderElectionError> {
        let api: Api<Lease> = Api::namespaced(self.client.clone(), &self.namespace);
        let now = Utc::now();

        // Try to get existing lease
        let existing = match api.get(&self.lease_name).await {
            Ok(lease) => Some(lease),
            Err(kube::Error::Api(e)) if e.code == 404 => None,
            Err(e) => return Err(e.into()),
        };

        match existing {
            None => {
                // No lease exists - create it (first leader)
                self.create_lease(&api, now).await
            }
            Some(lease) => {
                let spec = lease.spec.as_ref();
                let holder = spec.and_then(|s| s.holder_identity.as_ref());
                let resource_version = lease.metadata.resource_version.clone();

                // Do we already hold it?
                if holder == Some(&self.identity) {
                    return self.renew_lease(&api, &lease, now).await;
                }

                // Check if expired
                let renew_time = spec.and_then(|s| s.renew_time.as_ref());
                let duration_secs = spec.and_then(|s| s.lease_duration_seconds);
                let is_expired = match (renew_time, duration_secs) {
                    (Some(rt), Some(duration)) => {
                        now > rt.0 + chrono::Duration::seconds(duration as i64)
                    }
                    _ => true,
                };

                if is_expired {
                    let transitions = spec.and_then(|s| s.lease_transitions).unwrap_or(0);
                    self.take_over_lease(&api, resource_version, now, transitions).await
                } else {
                    // Lease held by someone else and not expired
                    Ok(false)
                }
            }
        }
    }

    /// Create a new lease (first leader)
    async fn create_lease(
        &self,
        api: &Api<Lease>,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, LeaderElectionError> {
        let lease = Lease {
            metadata: ObjectMeta {
                name: Some(self.lease_name.clone()),
                namespace: Some(self.namespace.clone()),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some(self.identity.clone()),
                lease_duration_seconds: Some(self.lease_duration.as_secs() as i32),
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                lease_transitions: Some(0),
                ..Default::default()
            }),
        };

        match api.create(&PostParams::default(), &lease).await {
            Ok(_) => {
                info!(identity = %self.identity, "Created new lease");
                Ok(true)
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                // Someone else created it first - not an error, just retry
                debug!(identity = %self.identity, "Lease creation conflict, will retry");
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Renew an existing lease that we hold (atomic with resourceVersion)
    async fn renew_lease(
        &self,
        api: &Api<Lease>,
        existing: &Lease,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, LeaderElectionError> {
        let resource_version = existing
            .metadata
            .resource_version
            .as_ref()
            .ok_or_else(|| LeaderElectionError::Kube(kube::Error::Api(
                kube::error::ErrorResponse {
                    status: "Failed".to_string(),
                    message: "Lease missing resourceVersion".to_string(),
                    reason: "Invalid".to_string(),
                    code: 500,
                },
            )))?;

        // Build updated lease with same resourceVersion for atomic update
        let mut updated = existing.clone();
        if let Some(ref mut spec) = updated.spec {
            spec.renew_time = Some(MicroTime(now));
        }
        updated.metadata.resource_version = Some(resource_version.clone());

        match api
            .replace(&self.lease_name, &PostParams::default(), &updated)
            .await
        {
            Ok(_) => {
                debug!(identity = %self.identity, "Lease renewed");
                Ok(true)
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                // Conflict - lease was modified, we lost leadership
                warn!(identity = %self.identity, "Lease renewal conflict - lost leadership");
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Take over an expired lease (atomic with resourceVersion)
    async fn take_over_lease(
        &self,
        api: &Api<Lease>,
        resource_version: Option<String>,
        now: chrono::DateTime<Utc>,
        transitions: i32,
    ) -> Result<bool, LeaderElectionError> {
        let rv = resource_version.ok_or_else(|| {
            LeaderElectionError::Kube(kube::Error::Api(kube::error::ErrorResponse {
                status: "Failed".to_string(),
                message: "Lease missing resourceVersion".to_string(),
                reason: "Invalid".to_string(),
                code: 500,
            }))
        })?;

        let lease = Lease {
            metadata: ObjectMeta {
                name: Some(self.lease_name.clone()),
                namespace: Some(self.namespace.clone()),
                resource_version: Some(rv),
                ..Default::default()
            },
            spec: Some(LeaseSpec {
                holder_identity: Some(self.identity.clone()),
                lease_duration_seconds: Some(self.lease_duration.as_secs() as i32),
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                lease_transitions: Some(transitions + 1),
                ..Default::default()
            }),
        };

        match api
            .replace(&self.lease_name, &PostParams::default(), &lease)
            .await
        {
            Ok(_) => {
                info!(
                    identity = %self.identity,
                    transitions = transitions + 1,
                    "Took over expired lease"
                );
                Ok(true)
            }
            Err(kube::Error::Api(e)) if e.code == 409 => {
                // Conflict - someone else got it first
                debug!(identity = %self.identity, "Lease takeover conflict, will retry");
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Renewal loop that runs while we hold leadership
    async fn renewal_loop(&self, lost_tx: oneshot::Sender<()>) {
        loop {
            tokio::time::sleep(self.renew_interval).await;

            match self.try_acquire_or_renew().await {
                Ok(true) => {} // Still leader
                Ok(false) | Err(_) => {
                    warn!(identity = %self.identity, "Leadership lost");
                    self.is_leader.store(false, Ordering::SeqCst);
                    let _ = lost_tx.send(());
                    return;
                }
            }
        }
    }
}

/// Guard that maintains leadership
///
/// While this guard exists, the elector holds leadership and periodically
/// renews the lease. Use `lost()` to wait for leadership loss.
/// The renewal task is aborted when the guard is dropped.
pub struct LeaderGuard {
    elector: Arc<LeaderElector>,
    renewal_task: JoinHandle<()>,
    lost_rx: Option<oneshot::Receiver<()>>,
}

impl LeaderGuard {
    /// Wait until leadership is lost
    pub async fn lost(&mut self) {
        if let Some(rx) = self.lost_rx.take() {
            let _ = rx.await;
        }
    }

    /// Add leader label to this pod so Service routes traffic to it
    ///
    /// The Service selector includes `lattice.dev/leader=true`, so only the
    /// leader pod receives traffic. Kubernetes readiness probes handle removal
    /// of unresponsive pods from Endpoints.
    pub async fn claim_traffic(&self, pod_name: &str) -> Result<(), LeaderElectionError> {
        let api: Api<Pod> =
            Api::namespaced(self.elector.client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let patch = json!({
            "metadata": {
                "labels": {
                    LEADER_LABEL_KEY: LEADER_LABEL_VALUE
                }
            }
        });

        api.patch(
            pod_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await?;

        info!(pod = pod_name, "Leader label added, traffic claimed");
        Ok(())
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        self.elector.is_leader.store(false, Ordering::SeqCst);
        self.renewal_task.abort();
        info!(identity = %self.elector.identity, "Leadership released");
    }
}
