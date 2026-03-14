//! HAProxy route adapter for LatticeClusterRoutes
//!
//! Watches LatticeClusterRoutes CRDs, renders haproxy.cfg, and sends
//! SIGUSR2 to the HAProxy master process for zero-downtime reload.
//!
//! This is a standalone sidecar — not part of Lattice core. Anyone can
//! write an adapter for their preferred data plane (nginx, envoy, etc.)
//! by watching the same CRD.

use std::path::PathBuf;

use futures::{StreamExt, TryStreamExt};
use kube::api::{Api, DynamicObject, GroupVersionKind};
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
    hostname: String,
    address: String,
    port: u16,
}

fn render_haproxy_config(routes: &[ClusterRoute]) -> String {
    let mut cfg = String::from(
        "global\n\
         \x20   log stdout format raw local0\n\
         \x20   master-worker\n\
         \n\
         defaults\n\
         \x20   log     global\n\
         \x20   mode    http\n\
         \x20   option  httplog\n\
         \x20   option  dontlognull\n\
         \x20   option  forwardfor\n\
         \x20   timeout connect 5s\n\
         \x20   timeout client  30s\n\
         \x20   timeout server  30s\n\
         \x20   retries 3\n\
         \n\
         frontend stats\n\
         \x20   bind *:8405\n\
         \x20   http-request return status 200 content-type text/plain string \"ok\" if { path /healthz }\n\
         \x20   stats enable\n\
         \x20   stats uri /stats\n\
         \n",
    );

    if routes.is_empty() {
        cfg.push_str(
            "frontend http_in\n\
             \x20   bind *:80\n\
             \x20   default_backend empty\n\
             \n\
             backend empty\n\
             \x20   http-request return status 503 content-type text/plain string \"no backends configured\"\n",
        );
        return cfg;
    }

    cfg.push_str("frontend http_in\n    bind *:80\n");

    for route in routes {
        let acl = route.service_name.replace(['-', '.'], "_");
        cfg.push_str(&format!(
            "    acl host_{acl} hdr(host) -i {}\n",
            route.hostname
        ));
    }
    cfg.push('\n');

    for route in routes {
        let acl = route.service_name.replace(['-', '.'], "_");
        cfg.push_str(&format!(
            "    use_backend {} if host_{acl}\n",
            route.service_name
        ));
    }
    cfg.push_str("    default_backend fallback\n\n");

    for route in routes {
        cfg.push_str(&format!(
            "backend {}\n    server gw {}:{}\n\n",
            route.service_name, route.address, route.port
        ));
    }

    cfg.push_str(
        "backend fallback\n\
         \x20   http-request return status 404 content-type text/plain string \"unknown host\"\n",
    );

    cfg
}

fn find_pid(process_name: &str) -> Option<i32> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_str().unwrap_or("");
        if pid_str.is_empty() || !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline")) {
            if cmdline.split('\0').next().map_or(false, |a| a.contains(process_name)) {
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

    let gvk = GroupVersionKind::gvk("lattice.dev", "v1alpha1", "LatticeClusterRoutes");
    let ar = ApiResource::from_gvk(&gvk);
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let mut last_config = String::new();

    loop {
        match stream.try_next().await {
            Ok(Some(event)) => {
                let should_rebuild = matches!(
                    event,
                    Event::Apply(_) | Event::Delete(_) | Event::InitDone
                );

                if let Event::Apply(ref obj) | Event::InitApply(ref obj) = event {
                    // Collect routes from all CRDs by re-listing
                    let _ = obj; // trigger rebuild on next flag check
                }

                if !should_rebuild {
                    continue;
                }

                // Re-list all route tables to get full picture
                let gvk = GroupVersionKind::gvk("lattice.dev", "v1alpha1", "LatticeClusterRoutes");
                let ar = ApiResource::from_gvk(&gvk);
                let list_api: Api<DynamicObject> =
                    Api::all_with(Client::try_default().await.unwrap(), &ar);

                let mut all_routes = Vec::new();
                if let Ok(list) = list_api.list(&Default::default()).await {
                    for item in &list.items {
                        if let Some(spec) = item.data.get("spec") {
                            if let Ok(parsed) =
                                serde_json::from_value::<ClusterRoutesSpec>(spec.clone())
                            {
                                all_routes.extend(parsed.routes);
                            }
                        }
                    }
                }

                let config = render_haproxy_config(&all_routes);

                if config == last_config {
                    continue;
                }

                match std::fs::write(&config_path, &config) {
                    Ok(()) => {
                        info!(routes = all_routes.len(), "wrote haproxy.cfg");
                        reload_haproxy(&process_name);
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
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}
