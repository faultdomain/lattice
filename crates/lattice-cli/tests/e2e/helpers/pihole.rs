//! PiHole dev service helpers for e2e tests.
//!
//! PiHole runs in docker-compose and is accessible from the host and K8s nodes.
//! Configure via `LATTICE_PIHOLE_URL` and `LATTICE_PIHOLE_RESOLVER` env vars.

use super::dev_service_url;

/// PiHole web admin password (plaintext, from docker-compose WEBPASSWORD).
/// Used by the DNSProvider credential secret so external-dns can authenticate.
pub const PIHOLE_PASSWORD: &str = "lattice";


/// PiHole URL (web admin + API).
pub fn pihole_url() -> String {
    dev_service_url("LATTICE_PIHOLE_URL")
}

/// PiHole DNS resolver address (IP:port) for CoreDNS forwarding.
pub fn pihole_resolver() -> String {
    dev_service_url("LATTICE_PIHOLE_RESOLVER")
}
