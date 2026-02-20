//! Remote exec I/O using the gRPC tunnel backend
//!
//! Wraps an ExecSessionHandle and ExecData receiver to implement ExecIo,
//! adapting the tunnel protocol to the common exec bridge interface.

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::backend::ExecSessionHandle;
use lattice_proto::{stream_id, ExecData};

use super::io::{ExecIo, ExecOutput};

/// Remote exec I/O backed by gRPC tunnel to agent
pub struct RemoteExecIo {
    exec_session: Box<dyn ExecSessionHandle>,
    output_rx: mpsc::Receiver<ExecOutput>,
    request_id: String,
}

impl RemoteExecIo {
    /// Create a new RemoteExecIo from an exec session handle and data receiver
    ///
    /// Spawns an adapter task that converts ExecData to ExecOutput.
    pub fn new(
        exec_session: Box<dyn ExecSessionHandle>,
        data_rx: mpsc::Receiver<ExecData>,
    ) -> Self {
        let request_id = exec_session.request_id().to_string();

        let (output_tx, output_rx) = mpsc::channel::<ExecOutput>(64);

        let adapter_request_id = request_id.clone();
        tokio::spawn(async move {
            let mut data_rx = data_rx;
            while let Some(data) = data_rx.recv().await {
                let is_terminal = data.stream_id == stream_id::ERROR && data.stream_end;
                let output = ExecOutput {
                    stream_id: data.stream_id as u8,
                    data: data.data,
                    is_terminal,
                };
                if output_tx.send(output).await.is_err() {
                    break;
                }
            }
            debug!(request_id = %adapter_request_id, "Remote exec adapter output channel closed");
        });

        Self {
            exec_session,
            output_rx,
            request_id,
        }
    }
}

#[async_trait]
impl ExecIo for RemoteExecIo {
    async fn send_stdin(&mut self, data: Vec<u8>) -> Result<(), String> {
        self.exec_session.send_stdin(data).await.map_err(|e| {
            warn!(request_id = %self.request_id, error = %e, "Failed to send stdin");
            e.to_string()
        })
    }

    async fn send_resize(&mut self, width: u16, height: u16) {
        if let Err(e) = self
            .exec_session
            .send_resize(width as u32, height as u32)
            .await
        {
            warn!(request_id = %self.request_id, error = %e, "Failed to send resize");
        }
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }

    fn output_rx(&mut self) -> &mut mpsc::Receiver<ExecOutput> {
        &mut self.output_rx
    }

    async fn finalize(self: Box<Self>) -> Option<ExecOutput> {
        // Remote exit status arrives through the output channel (is_terminal=true),
        // so no additional finalization needed.
        None
    }
}
