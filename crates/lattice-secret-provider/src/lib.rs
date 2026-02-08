//! SecretProvider controller for Lattice
//!
//! This controller watches SecretProvider CRDs and ensures the corresponding
//! ESO ClusterSecretStore exists. It continuously reconciles to handle cases
//! where ESO is installed after the SecretProvider is created.

#![deny(missing_docs)]

mod controller;
mod eso;
mod webhook;

pub use controller::{ensure_local_webhook_infrastructure, reconcile};
pub use eso::{
    apply_external_secret, build_external_secret, build_templated_external_secret, ExternalSecret,
    ExternalSecretData, ExternalSecretSpec, ExternalSecretTarget, ExternalSecretTemplate,
    RemoteRef, SecretStoreRef,
};
pub use webhook::start_webhook_server;
