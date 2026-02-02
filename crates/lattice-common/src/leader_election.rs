//! Leader election using Kubernetes Leases
//!
//! Provides leader election for HA deployments using the Kubernetes
//! coordination.k8s.io/v1 Lease API. Only the leader runs controllers
//! and accepts traffic.
//!
//! # Split-Brain Prevention
//!
//! Split-brain is prevented by timing: `lease_duration` (30s) > `renew_interval` (10s)
//! means the old leader detects loss and stops at least 20s before the new leader
//! can acquire the expired lease.
//!
//! # Traffic Routing
//!
//! The leader writes Endpoints directly (Service has no selector). This ensures
//! clean handoff: new leader overwrites Endpoints with its own IP, no stale state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{EndpointAddress, EndpointPort, EndpointSubset, Endpoints};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, ObjectMeta};
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use thiserror::Error;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::LATTICE_SYSTEM_NAMESPACE;

/// Lease name for the Lattice operator leader election
pub const LEADER_LEASE_NAME: &str = "lattice-operator-leader";

// Timing constants (not public - use new() defaults)
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
/// lease at a time. The leader writes Endpoints to route all traffic to itself.
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
            match self.try_acquire_lease().await {
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

    /// Try to acquire or renew the lease
    async fn try_acquire_lease(&self) -> Result<bool, LeaderElectionError> {
        let api: Api<Lease> = Api::namespaced(self.client.clone(), &self.namespace);
        let now = Utc::now();

        match api.get(&self.lease_name).await {
            Ok(lease) => {
                let spec = lease.spec.as_ref();
                let holder = spec.and_then(|s| s.holder_identity.as_ref());

                // Already hold it? Renew.
                if holder == Some(&self.identity) {
                    return self.renew_lease(&api, now).await;
                }

                // Check expiry
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
                    self.take_over_lease(&api, now, transitions).await
                } else {
                    Ok(false)
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => self.create_lease(&api, now).await,
            Err(e) => Err(e.into()),
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
            spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
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
            Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Renew an existing lease that we hold
    async fn renew_lease(
        &self,
        api: &Api<Lease>,
        now: chrono::DateTime<Utc>,
    ) -> Result<bool, LeaderElectionError> {
        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": self.lease_name,
                "namespace": self.namespace,
            },
            "spec": {
                "renewTime": MicroTime(now),
            }
        });

        api.patch(
            &self.lease_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(&patch),
        )
        .await?;

        debug!(identity = %self.identity, "Lease renewed");
        Ok(true)
    }

    /// Take over an expired lease
    async fn take_over_lease(
        &self,
        api: &Api<Lease>,
        now: chrono::DateTime<Utc>,
        transitions: i32,
    ) -> Result<bool, LeaderElectionError> {
        let patch = serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": self.lease_name,
                "namespace": self.namespace,
            },
            "spec": {
                "holderIdentity": self.identity,
                "acquireTime": MicroTime(now),
                "renewTime": MicroTime(now),
                "leaseDurationSeconds": self.lease_duration.as_secs() as i32,
                "leaseTransitions": transitions + 1,
            }
        });

        match api
            .patch(
                &self.lease_name,
                &PatchParams::apply(FIELD_MANAGER),
                &Patch::Apply(&patch),
            )
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
            Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Renewal loop that runs while we hold leadership
    async fn renewal_loop(&self, lost_tx: oneshot::Sender<()>) {
        loop {
            tokio::time::sleep(self.renew_interval).await;

            match self.try_acquire_lease().await {
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

    /// Update Endpoints to route all Service traffic to this pod
    ///
    /// The Endpoints object is overwritten completely via SSA, ensuring
    /// clean handoff even if the previous leader crashed.
    pub async fn claim_traffic(
        &self,
        service_name: &str,
        pod_ip: &str,
        ports: &[(String, i32)],
    ) -> Result<(), LeaderElectionError> {
        let api: Api<Endpoints> =
            Api::namespaced(self.elector.client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let endpoints = Endpoints {
            metadata: ObjectMeta {
                name: Some(service_name.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            subsets: Some(vec![EndpointSubset {
                addresses: Some(vec![EndpointAddress {
                    ip: pod_ip.to_string(),
                    ..Default::default()
                }]),
                ports: Some(
                    ports
                        .iter()
                        .map(|(name, port)| EndpointPort {
                            name: Some(name.clone()),
                            port: *port,
                            protocol: Some("TCP".to_string()),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }]),
        };

        api.patch(
            service_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(&endpoints),
        )
        .await?;

        info!(service = service_name, pod_ip = pod_ip, "Traffic claimed");
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
