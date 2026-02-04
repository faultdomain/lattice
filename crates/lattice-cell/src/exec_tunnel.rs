//! Exec/attach/portforward tunneling through gRPC
//!
//! Handles bidirectional streaming for kubectl exec, attach, and portforward
//! commands through the gRPC tunnel to agents.

use tokio::sync::mpsc;
use tracing::{debug, error};
use uuid::Uuid;

use lattice_proto::{cell_command, CellCommand, ExecData, ExecRequest, ExecResize};

use crate::connection::SharedAgentRegistry;

/// Channel buffer size for exec data
pub const EXEC_CHANNEL_SIZE: usize = 64;

/// Parameters for starting an exec session
pub struct ExecRequestParams {
    /// API path (e.g., /api/v1/namespaces/default/pods/nginx/exec)
    pub path: String,
    /// Query string (command=sh&stdin=true&stdout=true&tty=true)
    pub query: String,
    /// Target cluster - the final destination cluster
    pub target_cluster: String,
    /// Source user identity (preserved through routing chain for Cedar)
    pub source_user: String,
    /// Source user groups (preserved through routing chain for Cedar)
    pub source_groups: Vec<String>,
}

/// An active exec session handle
///
/// Provides methods to send stdin and resize events to the agent.
/// Drop this handle to cancel the exec session.
pub struct ExecSession {
    /// Unique request ID for this session
    pub request_id: String,
    /// Sender for commands to the agent
    command_tx: mpsc::Sender<CellCommand>,
    /// Registry reference for cleanup
    registry: SharedAgentRegistry,
}

impl ExecSession {
    /// Send stdin data to the remote process
    pub async fn send_stdin(&self, data: Vec<u8>) -> Result<(), ExecTunnelError> {
        let command = CellCommand {
            command_id: Uuid::new_v4().to_string(),
            command: Some(cell_command::Command::ExecStdin(ExecData {
                request_id: self.request_id.clone(),
                stream_id: 0, // STDIN
                data,
                stream_end: false,
            })),
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|e| ExecTunnelError::SendFailed(e.to_string()))
    }

    /// Send terminal resize event
    pub async fn send_resize(&self, width: u32, height: u32) -> Result<(), ExecTunnelError> {
        let command = CellCommand {
            command_id: Uuid::new_v4().to_string(),
            command: Some(cell_command::Command::ExecResize(ExecResize {
                request_id: self.request_id.clone(),
                width,
                height,
            })),
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|e| ExecTunnelError::SendFailed(e.to_string()))
    }

    /// Close stdin (signal EOF to remote process)
    pub async fn close_stdin(&self) -> Result<(), ExecTunnelError> {
        let command = CellCommand {
            command_id: Uuid::new_v4().to_string(),
            command: Some(cell_command::Command::ExecStdin(ExecData {
                request_id: self.request_id.clone(),
                stream_id: 0, // STDIN
                data: vec![],
                stream_end: true,
            })),
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|e| ExecTunnelError::SendFailed(e.to_string()))
    }
}

impl Drop for ExecSession {
    fn drop(&mut self) {
        // Clean up pending exec data registration
        self.registry.take_pending_exec_data(&self.request_id);
        debug!(request_id = %self.request_id, "Exec session dropped");
    }
}

/// Start an exec session through the gRPC tunnel
///
/// Returns a tuple of:
/// - ExecSession handle for sending stdin/resize
/// - Receiver for stdout/stderr data from the agent
pub async fn start_exec_session(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: ExecRequestParams,
) -> Result<(ExecSession, mpsc::Receiver<ExecData>), ExecTunnelError> {
    let request_id = Uuid::new_v4().to_string();

    // Create channel for receiving exec data from agent
    let (data_tx, data_rx) = mpsc::channel::<ExecData>(EXEC_CHANNEL_SIZE);

    // Register pending exec data handler
    registry.register_pending_exec_data(&request_id, data_tx);

    // Build and send ExecRequest
    let exec_request = ExecRequest {
        request_id: request_id.clone(),
        path: params.path,
        query: params.query,
        target_cluster: params.target_cluster,
        source_user: params.source_user,
        source_groups: params.source_groups,
    };

    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(cell_command::Command::ExecRequest(exec_request)),
    };

    if let Err(e) = command_tx.send(command).await {
        registry.take_pending_exec_data(&request_id);
        error!(
            cluster = %cluster_name,
            request_id = %request_id,
            error = %e,
            "Failed to send exec request to agent"
        );
        return Err(ExecTunnelError::SendFailed(e.to_string()));
    }

    debug!(
        cluster = %cluster_name,
        request_id = %request_id,
        "Started exec session"
    );

    let session = ExecSession {
        request_id,
        command_tx,
        registry: registry.clone(),
    };

    Ok((session, data_rx))
}

// Re-export stream_id from lattice_proto for external use
pub use lattice_proto::stream_id;

/// Errors that can occur during exec tunneling
#[derive(Debug, thiserror::Error)]
pub enum ExecTunnelError {
    /// Failed to send request to agent
    #[error("failed to send request: {0}")]
    SendFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentRegistry;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_start_exec_session() {
        let registry = Arc::new(AgentRegistry::new());
        let (command_tx, mut command_rx) = mpsc::channel::<CellCommand>(16);

        let params = ExecRequestParams {
            path: "/api/v1/namespaces/default/pods/nginx/exec".to_string(),
            query: "command=sh&stdin=true&stdout=true&tty=true".to_string(),
            target_cluster: "child-cluster".to_string(),
            source_user: "admin".to_string(),
            source_groups: vec!["system:masters".to_string()],
        };

        let result = start_exec_session(&registry, "child-cluster", command_tx, params).await;
        assert!(result.is_ok());

        let (session, _data_rx) = result.unwrap();
        assert!(!session.request_id.is_empty());

        // Verify command was sent
        let cmd = command_rx.recv().await.expect("should receive command");
        assert!(matches!(
            cmd.command,
            Some(cell_command::Command::ExecRequest(_))
        ));

        // Verify pending exec data is registered
        assert!(registry.has_pending_exec_data(&session.request_id));

        // Drop session should clean up
        drop(session);
    }

    #[tokio::test]
    async fn test_exec_session_send_stdin() {
        let registry = Arc::new(AgentRegistry::new());
        let (command_tx, mut command_rx) = mpsc::channel::<CellCommand>(16);

        let params = ExecRequestParams {
            path: "/api/v1/namespaces/default/pods/nginx/exec".to_string(),
            query: "command=sh&stdin=true&stdout=true".to_string(),
            target_cluster: "test".to_string(),
            source_user: "user".to_string(),
            source_groups: vec![],
        };

        let (session, _data_rx) =
            start_exec_session(&registry, "test", command_tx, params)
                .await
                .unwrap();

        // Drain the initial ExecRequest
        let _ = command_rx.recv().await;

        // Send stdin
        session.send_stdin(b"ls -la\n".to_vec()).await.unwrap();

        let cmd = command_rx.recv().await.expect("should receive stdin");
        match cmd.command {
            Some(cell_command::Command::ExecStdin(data)) => {
                assert_eq!(data.request_id, session.request_id);
                assert_eq!(data.stream_id, stream_id::STDIN);
                assert_eq!(data.data, b"ls -la\n");
                assert!(!data.stream_end);
            }
            _ => panic!("expected ExecStdin"),
        }
    }

    #[tokio::test]
    async fn test_exec_session_send_resize() {
        let registry = Arc::new(AgentRegistry::new());
        let (command_tx, mut command_rx) = mpsc::channel::<CellCommand>(16);

        let params = ExecRequestParams {
            path: "/api/v1/namespaces/default/pods/nginx/exec".to_string(),
            query: "command=sh&tty=true".to_string(),
            target_cluster: "test".to_string(),
            source_user: "user".to_string(),
            source_groups: vec![],
        };

        let (session, _data_rx) =
            start_exec_session(&registry, "test", command_tx, params)
                .await
                .unwrap();

        // Drain the initial ExecRequest
        let _ = command_rx.recv().await;

        // Send resize
        session.send_resize(120, 40).await.unwrap();

        let cmd = command_rx.recv().await.expect("should receive resize");
        match cmd.command {
            Some(cell_command::Command::ExecResize(resize)) => {
                assert_eq!(resize.request_id, session.request_id);
                assert_eq!(resize.width, 120);
                assert_eq!(resize.height, 40);
            }
            _ => panic!("expected ExecResize"),
        }
    }

    #[tokio::test]
    async fn test_exec_session_close_stdin() {
        let registry = Arc::new(AgentRegistry::new());
        let (command_tx, mut command_rx) = mpsc::channel::<CellCommand>(16);

        let params = ExecRequestParams {
            path: "/api/v1/namespaces/default/pods/nginx/exec".to_string(),
            query: "command=cat".to_string(),
            target_cluster: "test".to_string(),
            source_user: "user".to_string(),
            source_groups: vec![],
        };

        let (session, _data_rx) =
            start_exec_session(&registry, "test", command_tx, params)
                .await
                .unwrap();

        // Drain the initial ExecRequest
        let _ = command_rx.recv().await;

        // Close stdin (EOF)
        session.close_stdin().await.unwrap();

        let cmd = command_rx.recv().await.expect("should receive close");
        match cmd.command {
            Some(cell_command::Command::ExecStdin(data)) => {
                assert_eq!(data.request_id, session.request_id);
                assert!(data.data.is_empty());
                assert!(data.stream_end);
            }
            _ => panic!("expected ExecStdin with stream_end"),
        }
    }
}
