//! Startup utilities for the Lattice operator
//!
//! This module contains all startup and initialization logic extracted from main.rs.

mod ca_rotation;
mod cell;
mod crds;
mod infrastructure;
mod polling;
mod recovery;

pub use ca_rotation::start_ca_rotation;
pub use cell::{discover_cell_host, ensure_cell_service_exists, get_cell_server_sans};
pub use crds::{ensure_cluster_crds, ensure_service_crds};
pub use infrastructure::{ensure_capi_infrastructure, spawn_general_infrastructure};
pub use polling::{
    wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT, LOAD_BALANCER_POLL_INTERVAL,
};
pub use recovery::{re_register_existing_clusters, wait_for_api_ready_for};
