//! FIPS 140-3 compliance constants and initialization.
//!
//! All Lattice builds enforce FIPS mode via aws-lc-rs. This module provides
//! the shared constants and initialization function used across all binaries.

/// FIPS-approved TLS 1.2 cipher suites for Kubernetes API servers.
///
/// These cipher suites are supported by both aws-lc-rs (Rust) and Go's FIPS module.
/// TLS 1.3 suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384) are always
/// enabled by Go's crypto/tls and don't need to be listed here.
///
/// Used for kubeadm and RKE2 API server configurations and kind cluster configs.
pub const FIPS_TLS_CIPHER_SUITES: &str = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

/// Minimum TLS version for Kubernetes API servers (FIPS requires TLS 1.2+).
pub const FIPS_TLS_MIN_VERSION: &str = "VersionTLS12";

/// Install the FIPS-validated crypto provider for rustls and verify FIPS mode.
///
/// This must be called before creating any TLS connections (including kube clients).
/// Safe to call multiple times — subsequent calls are no-ops.
///
/// Panics if FIPS mode cannot be activated (aws-lc-rs not compiled with fips feature).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(e) = aws_lc_rs::try_fips_mode() {
        panic!(
            "CRITICAL: FIPS mode failed to activate: {e}. \
             Ensure aws-lc-rs is compiled with the fips feature."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_mode_activates() {
        install_crypto_provider();
        // If we get here, FIPS mode is active
    }

    #[test]
    fn cipher_suites_are_fips_approved() {
        // All listed suites must use AES-GCM (FIPS-approved AEAD)
        for suite in FIPS_TLS_CIPHER_SUITES.split(',') {
            assert!(
                suite.contains("AES") && suite.contains("GCM"),
                "Non-FIPS cipher suite found: {suite}"
            );
        }
    }
}
