//! HAProxy route adapter for LatticeClusterRoutes
//!
//! Watches LatticeClusterRoutes CRDs, renders haproxy.cfg, and sends
//! SIGUSR2 to the HAProxy master process for zero-downtime reload.
//!
//! This is a standalone sidecar — not part of Lattice core. Anyone can
//! write an adapter for their preferred data plane (nginx, envoy, etc.)
//! by watching the same CRD.

use std::fmt::Write;
use std::path::PathBuf;

use futures::TryStreamExt;
use kube::api::{Api, DynamicObject};
use kube::discovery::ApiResource;
use kube::runtime::watcher::{self, Event};
use kube::Client;
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterRoutesSpec {
    #[serde(default)]
    routes: Vec<ClusterRoute>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterRoute {
    service_name: String,
    service_namespace: String,
    hostname: String,
    port: u16,
    #[serde(default)]
    service_ports: std::collections::BTreeMap<String, u16>,
}

impl ClusterRoute {
    /// Namespace-qualified backend name for HAProxy config.
    fn backend_name(&self) -> String {
        format!("{}-{}", self.service_namespace, self.service_name)
    }

    /// Sanitized ACL name (alphanumeric + underscores only).
    fn acl_name(&self) -> String {
        self.backend_name()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    /// The actual service port to connect to (first service_port, or gateway port).
    fn service_port(&self) -> u16 {
        self.service_ports
            .values()
            .next()
            .copied()
            .unwrap_or(self.port)
    }
}

fn render_haproxy_config(routes: &[ClusterRoute]) -> String {
    let mut cfg = String::with_capacity(4096);

    // Global + defaults
    cfg.push_str(
        r#"global
    log stdout format raw local0
    master-worker

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-keep-alive 5s
    retries 3
    retry-on 502 conn-failure empty-response response-timeout
    option http-server-close
    http-reuse never

frontend stats
    bind *:8405
    http-request return status 200 content-type text/plain string "ok" if { path /healthz }
    stats enable
    stats uri /stats

"#,
    );

    if routes.is_empty() {
        cfg.push_str(
            r#"frontend http_in
    bind *:8080
    default_backend empty

backend empty
    http-request return status 503 content-type text/plain string "no backends configured"
"#,
        );
        return cfg;
    }

    // Frontend: ACLs + routing
    cfg.push_str("frontend http_in\n    bind *:8080\n");

    for route in routes {
        let _ = writeln!(
            cfg,
            "    acl host_{} hdr(host) -i {}",
            route.acl_name(),
            route.hostname
        );
    }
    cfg.push('\n');

    for route in routes {
        let _ = writeln!(
            cfg,
            "    use_backend {} if host_{}",
            route.backend_name(),
            route.acl_name()
        );
    }
    cfg.push_str("    default_backend fallback\n\n");

    // Backends — connect to the local service stub (ClusterIP) and let
    // ztunnel handle cross-cluster HBONE tunneling transparently.
    for route in routes {
        let svc_host = format!(
            "{}.{}.svc.cluster.local",
            route.service_name, route.service_namespace
        );
        let svc_port = route.service_port();
        let _ = writeln!(
            cfg,
            "backend {}\n    server gw {}:{}\n",
            route.backend_name(),
            svc_host,
            svc_port
        );
    }

    cfg.push_str(
        r#"backend fallback
    http-request return status 404 content-type text/plain string "unknown host"
"#,
    );

    cfg
}

fn find_pid(process_name: &str) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_str().unwrap_or("");
        if pid_str.is_empty() || !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline")) {
            if cmdline
                .split('\0')
                .next()
                .map_or(false, |a| a.contains(process_name))
            {
                return pid_str.parse().ok();
            }
        }
    }
    None
}

fn reload_haproxy(process_name: &str) {
    match find_pid(process_name) {
        Some(pid) => {
            let result = unsafe { libc::kill(pid, libc::SIGUSR2) };
            if result == 0 {
                info!(pid, "sent SIGUSR2 to haproxy");
            } else {
                let err = std::io::Error::last_os_error();
                error!(pid, %err, "failed to send SIGUSR2");
            }
        }
        None => warn!("haproxy process not found, skipping reload"),
    }
}

/// Collect all routes from all LatticeClusterRoutes CRDs.
async fn list_all_routes(client: &Client, ar: &ApiResource) -> Vec<ClusterRoute> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
    let list = match api.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            error!(%e, "failed to list LatticeClusterRoutes");
            return Vec::new();
        }
    };

    let mut routes = Vec::new();
    for item in &list.items {
        if let Some(spec) = item.data.get("spec") {
            if let Ok(parsed) = serde_json::from_value::<ClusterRoutesSpec>(spec.clone()) {
                routes.extend(parsed.routes);
            }
        }
    }
    routes
}

/// Run the watch loop. Returns when the stream ends or errors.
async fn run_watcher(
    client: &Client,
    ar: &ApiResource,
    config_path: &PathBuf,
    process_name: &str,
) {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
    let mut stream = std::pin::pin!(watcher::watcher(api, watcher::Config::default()));
    let mut last_config = String::new();

    loop {
        match stream.try_next().await {
            Ok(Some(event)) => {
                if !matches!(event, Event::Apply(_) | Event::Delete(_) | Event::InitDone) {
                    continue;
                }

                let all_routes = list_all_routes(client, ar).await;
                let config = render_haproxy_config(&all_routes);

                if config == last_config {
                    continue;
                }

                match std::fs::write(config_path, &config) {
                    Ok(()) => {
                        info!(routes = all_routes.len(), "wrote haproxy.cfg");
                        reload_haproxy(process_name);
                        last_config = config;
                    }
                    Err(e) => error!(%e, "failed to write haproxy.cfg"),
                }
            }
            Ok(None) => {
                warn!("watcher stream ended");
                break;
            }
            Err(e) => {
                error!(%e, "watcher error");
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let config_path = PathBuf::from(
        std::env::var("CONFIG_PATH").unwrap_or_else(|_| "/config/haproxy.cfg".to_string()),
    );
    let process_name =
        std::env::var("HAPROXY_PROCESS_NAME").unwrap_or_else(|_| "haproxy".to_string());

    info!(?config_path, %process_name, "route adapter starting");

    // Write initial empty config so HAProxy can start
    std::fs::write(&config_path, render_haproxy_config(&[]))?;

    let client = Client::try_default().await?;
    let ar = ApiResource {
        group: "lattice.dev".into(),
        version: "v1alpha1".into(),
        api_version: "lattice.dev/v1alpha1".into(),
        kind: "LatticeClusterRoutes".into(),
        plural: "latticeclusterroutes".into(),
    };

    // Reconnect on watcher errors — the K8s API closes watches periodically
    loop {
        run_watcher(&client, &ar, &config_path, &process_name).await;
        info!("reconnecting watcher in 5s...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
