//! Shared port-forward module for accessing the Lattice auth proxy.
//!
//! Provides a resilient `kubectl port-forward` wrapper that automatically
//! restarts when the underlying process dies, detects stale connections via
//! active health checking, and uses OS-assigned ports to avoid conflicts.
//!
//! Also provides proxy kubeconfig detection: when a kubeconfig has server URLs
//! like `https://127.0.0.1:PORT/clusters/NAME` and the port is dead, we
//! automatically restart a port-forward and rewrite the URLs.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kube::config::Kubeconfig;
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// Default service name for the Lattice cell (hosts the auth proxy).
const PROXY_SERVICE_NAME: &str = "lattice-cell";

/// Default namespace for Lattice system resources.
const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// How often the watchdog checks the port-forward process.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often the watchdog performs active health checks even when the process is alive.
/// Catches stale tunnels where kubectl is alive but the pod was restarted.
const ACTIVE_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time to wait for kubectl to emit its "Forwarding from" line.
const PORT_PARSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for initial port-forward startup (spawn + health).
const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum number of health probes during cold startup.
const STARTUP_MAX_PROBES: u32 = 15;

/// Maximum time to wait for a warm restart (watchdog-initiated).
/// Shorter than cold startup because the service is already running.
const WARM_RESTART_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of health probes during warm restart.
const WARM_RESTART_MAX_PROBES: u32 = 10;

/// How long to wait per health check probe during startup.
const STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait per health check probe during watchdog.
const WATCHDOG_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// A resilient port-forward that automatically restarts when it dies.
///
/// Key design decisions:
///
/// - **OS-assigned ports**: The initial spawn uses port 0 (`:remote` syntax) so the
///   OS picks a free port. No zombie cleanup, no hash collisions, no `lsof`.
///   The watchdog re-uses the same port on restart (it's free because kubectl just died).
///
/// - **Active health checking**: Even when kubectl is alive, the watchdog periodically
///   hits `/healthz` to catch stale tunnels (e.g. the target pod was restarted).
///   Requires 2 consecutive failures before restarting to tolerate brief blips.
///
/// - **Exponential backoff on restart**: Avoids hammering kubectl when the cluster
///   is temporarily unreachable (1s → 2s → 4s → ... → 30s cap).
///
/// - **Restart counter**: Exposes how many times the port-forward has been restarted.
pub struct PortForward {
    port: u16,
    /// The localhost URL for this port-forward (e.g. `https://127.0.0.1:54321`).
    pub url: String,
    stop_flag: Arc<AtomicBool>,
    restart_count: Arc<AtomicU64>,
    /// Set `false` by watchdog before restart, `true` after successful restart.
    healthy: Arc<AtomicBool>,
    /// Wakes callers blocked in `wait_for_ready()` when the port-forward becomes healthy.
    ready_notify: Arc<tokio::sync::Notify>,
    watchdog_handle: Option<std::thread::JoinHandle<()>>,
}

impl PortForward {
    /// Start a resilient port-forward to the auth proxy.
    ///
    /// The OS picks a free local port. The watchdog thread monitors the process
    /// and restarts it (on the same port) if it dies or becomes unhealthy.
    pub async fn start(kubeconfig: &str, remote_port: u16) -> Result<Self> {
        // Use LATTICE_PROXY_PORT if set, so callers can reuse old kubeconfigs
        // that have a hardcoded port baked in. Otherwise let the OS pick.
        let fixed_port = std::env::var("LATTICE_PROXY_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok());
        let (port, initial_child) = start_port_forward(
            kubeconfig,
            fixed_port,
            remote_port,
            STARTUP_TIMEOUT,
            STARTUP_MAX_PROBES,
        )
        .await?;
        let url = format!("https://127.0.0.1:{}", port);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let restart_count = Arc::new(AtomicU64::new(0));
        let healthy = Arc::new(AtomicBool::new(true));
        let ready_notify = Arc::new(tokio::sync::Notify::new());
        let stop_clone = stop_flag.clone();
        let restart_clone = restart_count.clone();
        let healthy_clone = healthy.clone();
        let notify_clone = ready_notify.clone();
        let kc = kubeconfig.to_string();
        let url_clone = url.clone();

        // Capture the tokio handle so the watchdog thread can call async functions.
        let handle = tokio::runtime::Handle::current();

        let watchdog_handle = std::thread::spawn(move || {
            let cfg = WatchdogConfig {
                kubeconfig: kc,
                local_port: port,
                remote_port,
                url: url_clone,
                stop_flag: stop_clone,
                restart_count: restart_clone,
                healthy: healthy_clone,
                ready_notify: notify_clone,
                handle,
            };
            watchdog_loop(initial_child, &cfg);
        });

        info!("[PortForward] Started with watchdog on port {}", port);

        Ok(Self {
            port,
            url,
            stop_flag,
            restart_count,
            healthy,
            ready_notify,
            watchdog_handle: Some(watchdog_handle),
        })
    }

    /// Get the local port being used.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if the port-forward is currently healthy (makes a network call).
    pub async fn is_healthy(&self) -> bool {
        check_health(&self.url, WATCHDOG_PROBE_TIMEOUT).await
    }

    /// Check if the watchdog considers the port-forward healthy.
    ///
    /// This is a cheap atomic read with no network call. Returns `false` while
    /// the watchdog is restarting the underlying kubectl process.
    pub fn is_known_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// How many times the watchdog has restarted the port-forward.
    pub fn restart_count(&self) -> u64 {
        self.restart_count.load(Ordering::Relaxed)
    }

    /// Wait until the port-forward is healthy or timeout expires.
    ///
    /// If the watchdog has marked the port-forward healthy, returns immediately.
    /// Otherwise waits on a notification from the watchdog (no polling).
    pub async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        if self.healthy.load(Ordering::Acquire) {
            return Ok(());
        }

        info!(
            "[PortForward] Port {} unhealthy, waiting for watchdog restart...",
            self.port
        );

        match tokio::time::timeout(timeout, self.ready_notify.notified()).await {
            Ok(()) => {
                info!("[PortForward] Port {} healthy again", self.port);
                Ok(())
            }
            Err(_) => Err(Error::command_failed(format!(
                "port-forward on port {} not healthy after {:?}",
                self.port, timeout
            ))),
        }
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        info!("[PortForward] Stopping watchdog on port {}", self.port);
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.watchdog_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Check if a proxy URL is healthy by hitting its `/healthz` endpoint.
pub async fn check_health(url: &str, timeout: Duration) -> bool {
    let health_url = format!("{}/healthz", url);

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&health_url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Spawn `kubectl port-forward` and return the child process.
///
/// If `local_port` is `None`, uses `:remote` syntax so the OS picks a free port.
/// If `Some(port)`, binds to that specific port (used by the watchdog on restart).
fn spawn_kubectl(kubeconfig: &str, local_port: Option<u16>, remote_port: u16) -> Result<Child> {
    let port_arg = match local_port {
        Some(p) => format!("{}:{}", p, remote_port),
        None => format!(":{}", remote_port),
    };

    Command::new("kubectl")
        .args([
            "--kubeconfig",
            kubeconfig,
            "port-forward",
            &format!("svc/{}", PROXY_SERVICE_NAME),
            &port_arg,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::command_failed(format!("failed to spawn port-forward: {}", e)))
}

/// Parse the local port from kubectl's stdout.
///
/// kubectl outputs: `Forwarding from 127.0.0.1:XXXXX -> YYYYY`
/// We read lines on a background thread with a timeout to avoid blocking forever.
fn parse_forwarded_port(child: &mut Child) -> Result<u16> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::command_failed("kubectl stdout not captured"))?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut sent = false;
        for line in reader.lines().map_while(std::result::Result::ok) {
            if !sent && line.contains("Forwarding from") {
                let _ = tx.send(line);
                sent = true;
            }
        }
        // Keep reading (draining) stdout until kubectl exits. Returning early
        // would drop the pipe and SIGPIPE kubectl when it writes its second
        // "Forwarding from [::1]:..." line.
    });

    let line = rx.recv_timeout(PORT_PARSE_TIMEOUT).map_err(|_| {
        Error::command_failed("timeout waiting for kubectl to report forwarded port")
    })?;

    // Parse "Forwarding from 127.0.0.1:54321 -> 8082" or "[::1]:54321"
    let port_str = line
        .split("Forwarding from ")
        .nth(1)
        .and_then(|rest| {
            // Handle both "127.0.0.1:PORT" and "[::1]:PORT"
            rest.rsplit_once(':')
                .map(|(_, port_and_rest)| port_and_rest)
        })
        .and_then(|s| s.split_whitespace().next())
        .ok_or_else(|| {
            Error::command_failed(format!(
                "failed to parse port from kubectl output: {}",
                line
            ))
        })?;

    port_str
        .parse::<u16>()
        .map_err(|e| Error::command_failed(format!("invalid port '{}': {}", port_str, e)))
}

/// Spawn a port-forward, parse the assigned port, and wait for it to become healthy.
///
/// Returns `(local_port, child)` on success.
///
/// `timeout` and `max_probes` are parameterised so that cold starts (90s, 15 probes)
/// and warm restarts (30s, 10 probes) can use different budgets.
async fn start_port_forward(
    kubeconfig: &str,
    local_port: Option<u16>,
    remote_port: u16,
    timeout: Duration,
    max_probes: u32,
) -> Result<(u16, Child)> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;

    while Instant::now() < deadline {
        attempt += 1;

        let mut child = match spawn_kubectl(kubeconfig, local_port, remote_port) {
            Ok(c) => c,
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
                warn!(
                    "[PortForward] Failed to spawn kubectl (attempt {}): {}",
                    attempt, e
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        // Parse the actual port from kubectl stdout
        let port = match parse_forwarded_port(&mut child) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "[PortForward] Failed to parse port (attempt {}): {}",
                    attempt, e
                );
                let _ = child.kill();
                let _ = child.wait();
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let url = format!("https://127.0.0.1:{}", port);

        // Wait for the health check to pass
        for probe in 0..max_probes {
            if let Ok(Some(status)) = child.try_wait() {
                debug!(
                    "[PortForward] kubectl exited with {} on attempt {} probe {}",
                    status, attempt, probe
                );
                break;
            }

            if check_health(&url, STARTUP_PROBE_TIMEOUT).await {
                info!(
                    "[PortForward] Ready at {} (attempt {}, probe {})",
                    url, attempt, probe
                );
                return Ok((port, child));
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let _ = child.kill();
        let _ = child.wait();

        if attempt.is_multiple_of(10) {
            info!(
                "[PortForward] Not ready after {} attempts, {:.0}s remaining",
                attempt,
                (deadline - Instant::now()).as_secs_f64()
            );
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(Error::command_failed(format!(
        "port-forward failed to become ready after {:?}",
        timeout
    )))
}

/// Config for the watchdog thread.
struct WatchdogConfig {
    kubeconfig: String,
    local_port: u16,
    remote_port: u16,
    url: String,
    stop_flag: Arc<AtomicBool>,
    restart_count: Arc<AtomicU64>,
    healthy: Arc<AtomicBool>,
    ready_notify: Arc<tokio::sync::Notify>,
    handle: tokio::runtime::Handle,
}

/// Background watchdog that monitors and restarts the port-forward.
///
/// Two detection mechanisms:
/// 1. **Process exit**: `try_wait()` catches kubectl crashes immediately.
/// 2. **Active health check**: Periodic `/healthz` probe catches stale tunnels
///    where kubectl is alive but the connection is broken.
///
/// On restart, re-uses the same local port (it's free because kubectl just died).
///
/// The `handle` is used to call async functions (`check_health`, `start_port_forward`)
/// from this std::thread via `block_on`.
fn watchdog_loop(mut child: Child, cfg: &WatchdogConfig) {
    let mut last_health_check = Instant::now();
    let mut consecutive_health_failures = 0u32;

    loop {
        if cfg.stop_flag.load(Ordering::Relaxed) {
            info!("[PortForward] Watchdog stopping, killing port-forward");
            let _ = child.kill();
            let _ = child.wait();
            return;
        }

        let mut needs_restart = false;
        let mut reason = String::new();

        // Detection 1: Process death
        match child.try_wait() {
            Ok(Some(status)) => {
                needs_restart = true;
                reason = format!("process exited (status: {})", status);
            }
            Ok(None) => {
                // Process alive - periodic active health check
                if last_health_check.elapsed() >= ACTIVE_HEALTH_CHECK_INTERVAL {
                    last_health_check = Instant::now();
                    if !cfg
                        .handle
                        .block_on(check_health(&cfg.url, WATCHDOG_PROBE_TIMEOUT))
                    {
                        consecutive_health_failures += 1;
                        warn!(
                            "[PortForward] Health check failed ({} consecutive)",
                            consecutive_health_failures
                        );
                        // 2 consecutive failures before restarting to tolerate brief blips
                        if consecutive_health_failures >= 2 {
                            needs_restart = true;
                            reason = format!(
                                "health check failed {} times consecutively",
                                consecutive_health_failures
                            );
                        }
                    } else {
                        consecutive_health_failures = 0;
                    }
                }
            }
            Err(e) => {
                warn!("[PortForward] Error checking process status: {}", e);
            }
        }

        if needs_restart {
            info!(
                "[PortForward] Restarting on port {} (reason: {})",
                cfg.local_port, reason
            );

            // Mark unhealthy so callers know not to use the port
            cfg.healthy.store(false, Ordering::Release);
            info!("[PortForward] Marked unhealthy on port {}", cfg.local_port);

            let _ = child.kill();
            let _ = child.wait();

            // Exponential backoff: 1s → 2s → 4s → ... → 30s cap
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(30);
            let mut restart_attempts = 0u32;

            loop {
                if cfg.stop_flag.load(Ordering::Relaxed) {
                    return;
                }

                restart_attempts += 1;
                // Re-use the same local port (free because kubectl just died)
                // Use warm restart budget (shorter timeout, fewer probes)
                match cfg.handle.block_on(start_port_forward(
                    &cfg.kubeconfig,
                    Some(cfg.local_port),
                    cfg.remote_port,
                    WARM_RESTART_TIMEOUT,
                    WARM_RESTART_MAX_PROBES,
                )) {
                    Ok((_, new_child)) => {
                        child = new_child;
                        let count = cfg.restart_count.fetch_add(1, Ordering::Relaxed) + 1;
                        consecutive_health_failures = 0;
                        last_health_check = Instant::now();

                        // Mark healthy and wake any callers waiting in wait_for_ready()
                        cfg.healthy.store(true, Ordering::Release);
                        cfg.ready_notify.notify_waiters();
                        info!(
                            "[PortForward] Restarted and healthy at {} (total restarts: {})",
                            cfg.url, count
                        );
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "[PortForward] Restart attempt {} failed: {} (backoff: {:?})",
                            restart_attempts, e, backoff
                        );
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }
        }

        std::thread::sleep(WATCHDOG_POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// Proxy kubeconfig helpers
// ---------------------------------------------------------------------------

/// Detect a proxy kubeconfig and start a port-forward if the proxy is unreachable.
///
/// A proxy kubeconfig has server URLs like `https://127.0.0.1:PORT/clusters/NAME`.
/// When the port is dead (e.g. the generating process exited), we extract the
/// management kubeconfig path from the exec credential args, start a new
/// port-forward, and rewrite the server URLs in place.
pub(crate) async fn ensure_proxy_reachable(kubeconfig: &mut Kubeconfig) -> Option<PortForward> {
    let proxy_base = find_proxy_base_url(kubeconfig)?;

    if check_health(&proxy_base, Duration::from_secs(2)).await {
        debug!(
            "Proxy at {} is reachable, no port-forward needed",
            proxy_base
        );
        return None;
    }

    info!(
        "Proxy at {} is unreachable, attempting auto port-forward",
        proxy_base
    );

    let mgmt_kubeconfig = extract_mgmt_kubeconfig(kubeconfig)?;

    let pf =
        match PortForward::start(&mgmt_kubeconfig, lattice_common::DEFAULT_AUTH_PROXY_PORT).await {
            Ok(pf) => pf,
            Err(e) => {
                warn!("Failed to auto-start port-forward: {}", e);
                return None;
            }
        };

    let new_base = &pf.url;
    rewrite_proxy_urls(kubeconfig, &proxy_base, new_base);
    info!("Rewrote proxy URLs from {} to {}", proxy_base, new_base);

    Some(pf)
}

/// Find the common proxy base URL (e.g. `https://127.0.0.1:49284`) from a kubeconfig.
///
/// Returns `Some(base_url)` if any cluster server URL matches the proxy pattern
/// (localhost with `/clusters/` path). Returns `None` for normal kubeconfigs.
fn find_proxy_base_url(kubeconfig: &Kubeconfig) -> Option<String> {
    for named_cluster in &kubeconfig.clusters {
        if let Some(ref cluster) = named_cluster.cluster {
            if let Some(ref server) = cluster.server {
                if let Some(path_start) = server.find("/clusters/") {
                    let base = &server[..path_start];
                    if base.contains("127.0.0.1")
                        || base.contains("localhost")
                        || base.contains("[::1]")
                    {
                        return Some(base.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract the management kubeconfig path from exec credential args.
///
/// The proxy kubeconfig uses `lattice token --kubeconfig=<path>` as the exec
/// credential plugin. We parse the `--kubeconfig=` arg to find the management
/// cluster's kubeconfig.
fn extract_mgmt_kubeconfig(kubeconfig: &Kubeconfig) -> Option<String> {
    for auth in &kubeconfig.auth_infos {
        if let Some(ref info) = auth.auth_info {
            if let Some(ref exec) = info.exec {
                if let Some(ref args) = exec.args {
                    for arg in args {
                        if let Some(path) = arg.strip_prefix("--kubeconfig=") {
                            return Some(path.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Rewrite proxy server URLs from the old base to the new base.
///
/// E.g. `https://127.0.0.1:49284/clusters/foo` -> `https://127.0.0.1:55555/clusters/foo`
fn rewrite_proxy_urls(kubeconfig: &mut Kubeconfig, old_base: &str, new_base: &str) {
    for named_cluster in &mut kubeconfig.clusters {
        if let Some(ref mut cluster) = named_cluster.cluster {
            if let Some(ref mut server) = cluster.server {
                if server.starts_with(old_base) {
                    let path = &server[old_base.len()..];
                    *server = format!("{}{}", new_base, path);
                }
            }
        }
    }
}
