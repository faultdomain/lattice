//! Per-integration E2E test: Vault secrets integration (Vault KV v2 ESO backend)
//!
//! Sets up mgmt + workload, runs Vault secrets tests, then tears down.
//! Skips internally if Vault is not available.
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_vault_secrets_e2e -- --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use super::context::run_per_integration_e2e;
use super::integration;

#[tokio::test]
async fn test_vault_secrets_e2e() {
    run_per_integration_e2e(
        "Vault Secrets",
        Duration::from_secs(2400),
        |ctx| async move {
            integration::vault_secrets::run_vault_secrets_tests(ctx.require_workload()?).await
        },
    )
    .await;
}
