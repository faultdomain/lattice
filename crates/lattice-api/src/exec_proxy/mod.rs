//! WebSocket proxy for exec/attach
//!
//! Handles WebSocket upgrade for kubectl exec/attach requests
//! and bridges them to the gRPC tunnel or local K8s API.
//!
//! Portforward is handled separately by the `portforward` module using
//! transparent HTTP upgrade proxying.

pub mod handlers;
mod io;
mod local_io;
mod remote_io;
mod websocket;
