//! Media server integration tests - run against existing cluster
//!
//! Tests LatticeService with a media server stack (jellyfin, nzbget, sonarr, plex).
//! Verifies volume sharing, pod co-location, volume authorization (unauthorized
//! access denied), gateway routes, and bilateral agreements.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_media_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

/// Standalone test - run media server tests on existing cluster
#[tokio::test]
#[ignore]
async fn test_media_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    super::super::media_server_e2e::run_media_server_test(&resolved.kubeconfig)
        .await
        .unwrap();
}
