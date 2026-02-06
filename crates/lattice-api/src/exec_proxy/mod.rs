//! WebSocket proxy for exec/attach
//!
//! Handles WebSocket upgrade for kubectl exec/attach requests
//! and bridges them to the gRPC tunnel or local K8s API.
//!
//! Portforward is handled separately by the `portforward` module using
//! transparent HTTP upgrade proxying.

mod handlers;
mod websocket;

pub use handlers::{handle_exec_websocket, has_websocket_upgrade_headers};
