//! SecretsProvider controller for Lattice
//!
//! This controller watches SecretsProvider CRDs and ensures the corresponding
//! ESO ClusterSecretStore exists. It continuously reconciles to handle cases
//! where ESO is installed after the SecretsProvider is created.

#![deny(missing_docs)]

mod controller;
mod eso;
mod webhook;

pub use controller::reconcile;
pub use eso::{
    ClusterSecretStore, ExternalSecret, ExternalSecretData, ExternalSecretDataFrom,
    ExternalSecretExtract, ExternalSecretMetadata, ExternalSecretSpec, ExternalSecretTarget,
    ExternalSecretTemplate, RemoteRef, SecretStoreRef, WebhookProvider, WebhookResult,
};
pub use webhook::start_webhook_server;
