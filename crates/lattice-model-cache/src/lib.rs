//! ModelCache controller for Lattice
//!
//! Watches ModelArtifact CRDs and manages the download lifecycle:
//! - Creates pre-fetch Jobs to populate model cache PVCs
//! - Tracks download progress via ModelArtifact status
//! - Removes scheduling gates when models are ready
//!
//! Model discovery is driven by a secondary watch on LatticeService CRDs.
//! When a service declares a `type: model` resource, the controller ensures
//! a corresponding ModelArtifact CRD exists and reconciles it.

#![deny(missing_docs)]

mod controller;
mod gate;
mod job;

pub use controller::{discover_models, error_policy, reconcile, ModelCacheContext};
