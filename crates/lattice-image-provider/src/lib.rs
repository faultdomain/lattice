//! ImageProvider controller for Lattice
//!
//! Watches ImageProvider CRDs and creates ESO ExternalSecrets that sync
//! registry credentials into `kubernetes.io/dockerconfigjson` Secrets.
//! These Secrets are referenced as `imagePullSecrets` by operator
//! deployments and workload pods.

mod controller;

pub use controller::reconcile;
