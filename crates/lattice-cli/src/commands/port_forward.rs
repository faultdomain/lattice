//! Shared port-forward module for accessing the Lattice auth proxy.
//!
//! Provides a resilient `kubectl port-forward` wrapper that automatically
//! restarts when the underlying process dies, detects stale connections via
//! active health checking, and uses OS-assigned ports to avoid conflicts.
//!
//! Used by both the CLI (`lattice kubeconfig`) and E2E tests.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    watchdog_handle: Option<std::thread::JoinHandle<()>>,
}

impl PortForward {
    /// Start a resilient port-forward to the auth proxy.
    ///
    /// The OS picks a free local port. The watchdog thread monitors the process
    /// and restarts it (on the same port) if it dies or becomes unhealthy.
    pub fn start(kubeconfig: &str, remote_port: u16) -> Result<Self> {
        // Initial spawn: let the OS pick a free port
        let (port, initial_child) = start_port_forward(kubeconfig, None, remote_port)?;
        let url = format!("https://127.0.0.1:{}", port);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let restart_count = Arc::new(AtomicU64::new(0));
        let stop_clone = stop_flag.clone();
        let restart_clone = restart_count.clone();
        let kc = kubeconfig.to_string();
        let url_clone = url.clone();

        let watchdog_handle = std::thread::spawn(move || {
            watchdog_loop(
                initial_child,
                &kc,
                port,
                remote_port,
                &url_clone,
                &stop_clone,
                &restart_clone,
            );
        });

        info!("[PortForward] Started with watchdog on port {}", port);

        Ok(Self {
            port,
            url,
            stop_flag,
            restart_count,
            watchdog_handle: Some(watchdog_handle),
        })
    }

    /// Get the local port being used.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if the port-forward is currently healthy.
    pub fn is_healthy(&self) -> bool {
        check_health(&self.url, WATCHDOG_PROBE_TIMEOUT)
    }

    /// How many times the watchdog has restarted the port-forward.
    pub fn restart_count(&self) -> u64 {
        self.restart_count.load(Ordering::Relaxed)
    }

    /// Block until the port-forward is healthy or timeout expires.
    ///
    /// The watchdog handles the actual restart; this just waits for it to finish.
    pub fn wait_until_healthy(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.is_healthy() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(Error::command_failed(format!(
            "port-forward on port {} not healthy after {:?}",
            self.port, timeout
        )))
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
pub fn check_health(url: &str, timeout: Duration) -> bool {
    let health_url = format!("{}/healthz", url);

    let client = match reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&health_url).send() {
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
        for line in reader.lines().map_while(std::result::Result::ok) {
            if line.contains("Forwarding from") {
                let _ = tx.send(line);
                return;
            }
        }
        // Pipe closed without finding the line
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
fn start_port_forward(
    kubeconfig: &str,
    local_port: Option<u16>,
    remote_port: u16,
) -> Result<(u16, Child)> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
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
                std::thread::sleep(Duration::from_secs(1));
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
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };

        let url = format!("https://127.0.0.1:{}", port);

        // Wait for the health check to pass
        for probe in 0..15 {
            if let Ok(Some(status)) = child.try_wait() {
                debug!(
                    "[PortForward] kubectl exited with {} on attempt {} probe {}",
                    status, attempt, probe
                );
                break;
            }

            if check_health(&url, STARTUP_PROBE_TIMEOUT) {
                info!(
                    "[PortForward] Ready at {} (attempt {}, probe {})",
                    url, attempt, probe
                );
                return Ok((port, child));
            }

            std::thread::sleep(Duration::from_millis(500));
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

        std::thread::sleep(Duration::from_millis(500));
    }

    Err(Error::command_failed(format!(
        "port-forward failed to become ready after {:?}",
        STARTUP_TIMEOUT
    )))
}

/// Background watchdog that monitors and restarts the port-forward.
///
/// Two detection mechanisms:
/// 1. **Process exit**: `try_wait()` catches kubectl crashes immediately.
/// 2. **Active health check**: Periodic `/healthz` probe catches stale tunnels
///    where kubectl is alive but the connection is broken.
///
/// On restart, re-uses the same local port (it's free because kubectl just died).
fn watchdog_loop(
    mut child: Child,
    kubeconfig: &str,
    local_port: u16,
    remote_port: u16,
    url: &str,
    stop_flag: &AtomicBool,
    restart_count: &AtomicU64,
) {
    let mut last_health_check = Instant::now();
    let mut consecutive_health_failures = 0u32;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
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
                    if !check_health(url, WATCHDOG_PROBE_TIMEOUT) {
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
                local_port, reason
            );

            let _ = child.kill();
            let _ = child.wait();

            // Exponential backoff: 1s → 2s → 4s → ... → 30s cap
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(30);
            let mut restart_attempts = 0u32;

            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }

                restart_attempts += 1;
                // Re-use the same local port (free because kubectl just died)
                match start_port_forward(kubeconfig, Some(local_port), remote_port) {
                    Ok((_, new_child)) => {
                        child = new_child;
                        let count = restart_count.fetch_add(1, Ordering::Relaxed) + 1;
                        consecutive_health_failures = 0;
                        last_health_check = Instant::now();
                        info!(
                            "[PortForward] Restarted at {} (total restarts: {})",
                            url, count
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
