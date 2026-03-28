//! PiHole dev service helpers for e2e tests.
//!
//! PiHole runs in docker-compose and is accessible from the host and K8s nodes.
//! Configure via `LATTICE_PIHOLE_URL` env var or use the default.

use super::{dev_service_reachable, dev_service_url};

/// PiHole web admin password (from docker-compose WEBPASSWORD).
pub const PIHOLE_PASSWORD: &str = "lattice";

/// PiHole URL (web admin + API).
pub fn pihole_url() -> String {
    dev_service_url("LATTICE_PIHOLE_URL", "http://127.0.0.1:8053")
}

/// PiHole DNS resolver address (IP:port) for CoreDNS forwarding.
pub fn pihole_resolver() -> String {
    dev_service_url("LATTICE_PIHOLE_RESOLVER", "127.0.0.1:5353")
}

/// Check if PiHole is reachable from the test runner.
pub fn pihole_available() -> bool {
    dev_service_reachable(&format!("{}/admin/", pihole_url()))
}
