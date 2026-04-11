//! PiHole dev service helpers for e2e tests.
//!
//! PiHole runs in docker-compose and is accessible from the host and K8s nodes.
//! Configure via `LATTICE_PIHOLE_URL` and `LATTICE_PIHOLE_RESOLVER` env vars.

use super::dev_service_url;

/// PiHole web admin password (plaintext, from docker-compose WEBPASSWORD).
/// Used by the DNSProvider credential secret so external-dns can authenticate.
pub const PIHOLE_PASSWORD: &str = "lattice";

/// PiHole API auth token — double-SHA256 of the WEBPASSWORD.
/// PiHole v5 hashes the plaintext password on startup and stores the hash
/// as WEBPASSWORD in setupVars.conf. The API requires this hash, not the
/// plaintext. This is the SHA-256(SHA-256("lattice")).
pub const PIHOLE_API_TOKEN: &str =
    "69ae05654e2beb7a6d3cb269e4c338902bb7c3da13ec7a03a36903e4394cb07c";

/// PiHole URL (web admin + API).
pub fn pihole_url() -> String {
    dev_service_url("LATTICE_PIHOLE_URL")
}

/// PiHole DNS resolver address (IP:port) for CoreDNS forwarding.
pub fn pihole_resolver() -> String {
    dev_service_url("LATTICE_PIHOLE_RESOLVER")
}
