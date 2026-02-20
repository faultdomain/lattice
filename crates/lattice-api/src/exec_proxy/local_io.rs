//! Local exec I/O using kube-rs AttachedProcess
//!
//! Wraps the kube-rs `AttachedProcess` type to implement `ExecIo`,
//! spawning reader tasks for stdout/stderr and collecting exit status.

use async_trait::async_trait;
use futures::SinkExt;
use kube::api::TerminalSize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use super::io::{ExecIo, ExecOutput};
use super::websocket::channel;

/// Build a K8s success Status JSON for exec sessions that exit cleanly.
fn k8s_success_status() -> serde_json::Value {
    serde_json::json!({
        "status": "Success",
        "metadata": {}
    })
}

/// Local exec I/O backed by kube-rs AttachedProcess
pub struct LocalExecIo {
    request_id: String,
    stdin_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
    terminal_size_tx: Option<futures::channel::mpsc::Sender<TerminalSize>>,
    output_rx: mpsc::Receiver<ExecOutput>,
    reader_handles: Vec<tokio::task::JoinHandle<()>>,
    attached: kube::api::AttachedProcess,
}

impl LocalExecIo {
    /// Create a new LocalExecIo from a kube-rs AttachedProcess
    ///
    /// Spawns background tasks to read stdout/stderr into the output channel.
    pub fn new(mut attached: kube::api::AttachedProcess, request_id: String) -> Self {
        let (output_tx, output_rx) = mpsc::channel::<ExecOutput>(64);
        let mut handles = vec![];

        if let Some(stdout) = attached.stdout() {
            let tx = output_tx.clone();
            let rid = request_id.clone();
            handles.push(tokio::spawn(async move {
                forward_reader_to_channel(stdout, tx, channel::STDOUT, &rid).await;
            }));
        }

        if let Some(stderr) = attached.stderr() {
            let tx = output_tx.clone();
            let rid = request_id.clone();
            handles.push(tokio::spawn(async move {
                forward_reader_to_channel(stderr, tx, channel::STDERR, &rid).await;
            }));
        }

        // Drop our copy so the channel closes when reader tasks complete
        drop(output_tx);

        let stdin_writer = attached
            .stdin()
            .map(|w| Box::new(w) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>);
        let terminal_size_tx = attached.terminal_size();

        Self {
            request_id,
            stdin_writer,
            terminal_size_tx,
            output_rx,
            reader_handles: handles,
            attached,
        }
    }
}

#[async_trait]
impl ExecIo for LocalExecIo {
    async fn send_stdin(&mut self, data: Vec<u8>) -> Result<(), String> {
        if let Some(ref mut writer) = self.stdin_writer {
            writer.write_all(&data).await.map_err(|e| e.to_string())?;
            let _ = writer.flush().await;
            Ok(())
        } else {
            Err("stdin not available".to_string())
        }
    }

    async fn send_resize(&mut self, width: u16, height: u16) {
        if let Some(ref mut tx) = self.terminal_size_tx {
            let _ = SinkExt::send(tx, TerminalSize { width, height }).await;
        }
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }

    fn output_rx(&mut self) -> &mut mpsc::Receiver<ExecOutput> {
        &mut self.output_rx
    }

    async fn finalize(mut self: Box<Self>) -> Option<ExecOutput> {
        // Reader tasks are already done — the bridge loop only breaks when
        // output_rx returns None, which means all senders (reader tasks) dropped.
        // Just drop the handles; no need to re-await them.
        drop(self.reader_handles);

        // Drop stdin/resize so kube-rs can close the WebSocket connection.
        drop(self.stdin_writer.take());
        drop(self.terminal_size_tx.take());

        // Collect exit status from kube-rs
        let status_json = match self.attached.take_status() {
            Some(status_future) => match status_future.await {
                Some(status) => serde_json::to_vec(&status).unwrap_or_default(),
                None => serde_json::to_vec(&k8s_success_status()).unwrap_or_default(),
            },
            None => serde_json::to_vec(&k8s_success_status()).unwrap_or_default(),
        };

        Some(ExecOutput {
            stream_id: channel::ERROR,
            data: status_json,
            is_terminal: true,
        })
    }
}

/// Forward an async reader to the output channel
async fn forward_reader_to_channel<R: AsyncRead + Unpin>(
    mut reader: R,
    tx: mpsc::Sender<ExecOutput>,
    stream_id: u8,
    request_id: &str,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let output = ExecOutput {
                    stream_id,
                    data: buf[..n].to_vec(),
                    is_terminal: false,
                };
                if tx.send(output).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(request_id = %request_id, error = %e, stream_id, "Reader error");
                break;
            }
        }
    }
}
