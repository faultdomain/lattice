//! FIPS 140-3 compliance constants and initialization.
//!
//! All production Lattice builds enforce FIPS mode via aws-lc-rs. The `fips`
//! feature (enabled by default on binary crates) activates the FIPS-validated
//! cryptographic module. When disabled, a non-FIPS aws-lc-rs backend is used
//! and loud warnings are emitted — this is only acceptable for local
//! development on platforms where FIPS dynamic libraries are unsupported
//! (e.g. macOS).

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

/// Install the crypto provider for rustls and verify FIPS mode if enabled.
///
/// This must be called before creating any TLS connections (including kube clients).
/// Safe to call multiple times — subsequent calls are no-ops.
///
/// # FIPS mode (feature = "fips")
///
/// Activates and verifies FIPS 140-3 mode. Panics if FIPS cannot be activated.
/// This is the default for all production/container builds.
///
/// # Non-FIPS mode (feature = "fips" disabled)
///
/// Uses the standard aws-lc-rs provider without FIPS validation. Emits prominent
/// warnings on every call. **NOT suitable for regulated or production environments.**
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[cfg(feature = "fips")]
    if let Err(e) = aws_lc_rs::try_fips_mode() {
        eprintln!(
            "CRITICAL: FIPS mode failed to activate: {e}. \
             Ensure aws-lc-rs is compiled with the fips feature."
        );
        std::process::abort();
    }

    #[cfg(not(feature = "fips"))]
    {
        eprintln!();
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!("!!  WARNING: FIPS MODE IS DISABLED                         !!");
        eprintln!("!!                                                         !!");
        eprintln!("!!  This build uses non-FIPS cryptography and is NOT       !!");
        eprintln!("!!  suitable for regulated or production environments.     !!");
        eprintln!("!!  All production builds MUST enable the `fips` feature.  !!");
        eprintln!("!!                                                         !!");
        eprintln!("!!  To enable: cargo build --features fips                 !!");
        eprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        eprintln!();
    }
}

/// Returns true if this build has FIPS support compiled in.
pub fn is_fips_build() -> bool {
    cfg!(feature = "fips")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "fips")]
    #[test]
    fn fips_mode_activates() {
        install_crypto_provider();
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn non_fips_mode_installs_provider() {
        install_crypto_provider();
        assert!(!is_fips_build());
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
