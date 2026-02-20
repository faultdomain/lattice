//! Exec I/O abstraction
//!
//! Defines a trait that abstracts over local (kube-rs) and remote (gRPC tunnel)
//! exec backends, allowing a single WebSocket bridge function to handle both.

use async_trait::async_trait;
use tokio::sync::mpsc;

/// Output from an exec session (stdout, stderr, or status)
pub struct ExecOutput {
    /// K8s channel ID (1=stdout, 2=stderr, 3=error/status)
    pub stream_id: u8,
    /// Data payload
    pub data: Vec<u8>,
    /// Whether this is the final message (session complete)
    pub is_terminal: bool,
}

/// Abstraction over exec I/O backends (local kube-rs vs remote tunnel)
///
/// Implementations handle the specifics of sending input and receiving output,
/// while the WebSocket bridge function (`run_exec_bridge`) handles the common
/// WebSocket ↔ ExecIo message loop.
#[async_trait]
pub trait ExecIo: Send {
    /// Send stdin data to the process
    async fn send_stdin(&mut self, data: Vec<u8>) -> Result<(), String>;

    /// Send terminal resize event
    async fn send_resize(&mut self, width: u16, height: u16);

    /// Get the output receiver for stdout/stderr/status messages
    fn output_rx(&mut self) -> &mut mpsc::Receiver<ExecOutput>;

    /// Get the request ID for this session (used for log correlation)
    fn request_id(&self) -> &str;

    /// Finalize the session after the main loop exits.
    ///
    /// Returns an optional final message to send (e.g., exit status on channel 3).
    /// For local sessions, this collects the exit status from kube-rs.
    /// For remote sessions, the exit status arrives through the output channel,
    /// so this returns None.
    async fn finalize(self: Box<Self>) -> Option<ExecOutput>;
}
