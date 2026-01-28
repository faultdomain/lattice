//! Cedar authorization server startup

use std::sync::Arc;

use kube::Client;

/// Start the Cedar ExtAuth gRPC server
pub fn start_cedar_server(client: Client, port: u16) {
    tokio::spawn(async move {
        tracing::info!(port, "Starting Cedar ExtAuth gRPC server");
        let addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", port).parse().expect("valid address");
        let ctx = Arc::new(lattice_cedar::Context::new(client.clone()));

        tokio::select! {
            result = lattice_cedar::controller::run_controller(ctx.clone()) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Cedar policy controller error");
                }
            }
            result = async {
                let server = lattice_cedar::CedarAuthzServer::new(ctx, addr);
                server.run().await
            } => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Cedar ExtAuth server error");
                }
            }
        }
    });
}
