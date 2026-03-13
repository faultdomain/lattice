//! Status request command handler.

use lattice_proto::{agent_message::Payload, AgentMessage, StatusResponse};
use tracing::{debug, error};

use super::CommandContext;

/// Handle a status request from the cell.
pub async fn handle(command_id: &str, ctx: &CommandContext) {
    debug!("Received status request");

    let current_state = *ctx.agent_state.read().await;
    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let command_id = command_id.to_string();

    tokio::spawn(async move {
        let msg = AgentMessage {
            cluster_name,
            payload: Some(Payload::StatusResponse(StatusResponse {
                request_id: command_id,
                state: current_state.into(),
                health: None,
                capi_status: None,
            })),
        };

        if let Err(e) = message_tx.send(msg).await {
            error!(error = %e, "Failed to send status response");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_proto::AgentState;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    #[tokio::test]
    async fn test_handle_status_request() {
        let (tx, mut rx) = mpsc::channel(1);
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));

        let ctx = CommandContext {
            cluster_name: "test-cluster".to_string(),
            message_tx: tx,
            agent_state,
            watch_registry: Arc::new(crate::watch::WatchRegistry::new()),
            exec_registry: Arc::new(crate::exec::ExecRegistry::new()),
            forwarder: None,
            exec_forwarder: None,
            forwarded_exec_sessions: Arc::new(
                moka::future::Cache::builder()
                    .time_to_live(std::time::Duration::from_secs(1800))
                    .build(),
            ),
            kube_provider: Arc::new(crate::kube_client::InClusterClientProvider),
        };

        handle("req-123", &ctx).await;

        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.cluster_name, "test-cluster");

        if let Some(Payload::StatusResponse(resp)) = msg.payload {
            assert_eq!(resp.request_id, "req-123");
            assert_eq!(resp.state, AgentState::Ready as i32);
        } else {
            panic!("Expected StatusResponse payload");
        }
    }
}
