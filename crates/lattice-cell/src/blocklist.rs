//! Certificate blocklist for immediate revocation of compromised agent certificates.
//!
//! Stores SHA-256 fingerprints of blocked certificates and checks them during
//! mTLS authentication. Persisted to a ConfigMap for crash recovery.

use std::sync::Arc;

use dashmap::DashMap;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tracing::{info, warn};

use lattice_core::LATTICE_SYSTEM_NAMESPACE;

/// ConfigMap name for persisting blocked certificate fingerprints
const BLOCKLIST_CONFIGMAP: &str = "lattice-cert-blocklist";
/// Key within the ConfigMap data
const BLOCKLIST_DATA_KEY: &str = "fingerprints";
/// Field manager for server-side apply
const FIELD_MANAGER: &str = "lattice-cert-blocklist";

/// Thread-safe certificate blocklist using SHA-256 fingerprints.
///
/// Each entry stores the certificate's expiry timestamp (Unix seconds).
/// Entries are automatically pruned after the certificate has expired,
/// since expired certs are already rejected by the validity check.
///
/// Checked during mTLS authentication to reject compromised certificates
/// without waiting for them to expire.
#[derive(Clone)]
pub struct CertificateBlocklist {
    /// Maps fingerprint → certificate expiry (Unix timestamp, seconds)
    entries: Arc<DashMap<String, i64>>,
}

impl CertificateBlocklist {
    /// Create an empty blocklist.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
        }
    }

    /// Check if a certificate fingerprint is blocked.
    pub fn is_blocked(&self, fingerprint: &str) -> bool {
        self.entries.contains_key(fingerprint)
    }

    /// Add a certificate fingerprint with its expiry timestamp.
    pub fn add(&self, fingerprint: String, expires_at: i64) {
        info!(fingerprint = %fingerprint, expires_at, "Blocking certificate");
        self.entries.insert(fingerprint, expires_at);
    }

    /// Remove a certificate fingerprint from the blocklist.
    pub fn remove(&self, fingerprint: &str) -> bool {
        self.entries.remove(fingerprint).is_some()
    }

    /// Number of blocked certificates.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries whose certificates have expired.
    /// Returns the number of entries pruned.
    pub fn prune_expired(&self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let before = self.entries.len();
        self.entries.retain(|_, expires_at| *expires_at > now);
        let pruned = before - self.entries.len();
        if pruned > 0 {
            info!(
                pruned,
                remaining = self.entries.len(),
                "Pruned expired blocklist entries"
            );
        }
        pruned
    }

    /// Compute the SHA-256 fingerprint of a DER-encoded certificate.
    ///
    /// Uses FIPS-validated `aws_lc_rs::digest::SHA256`.
    pub fn fingerprint(cert_der: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, cert_der);
        digest
            .as_ref()
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Load blocklist from a ConfigMap in lattice-system namespace.
    ///
    /// Fail-closed: if the ConfigMap does not exist, this returns an error
    /// rather than an empty blocklist. Starting without the blocklist would
    /// silently re-admit any previously revoked agent certificates. The
    /// ConfigMap must be created (even if empty) during cluster bootstrap.
    pub async fn load_from_configmap(client: &Client) -> Result<Self, kube::Error> {
        let cm = configmap_api(client).get(BLOCKLIST_CONFIGMAP).await?;
        let blocklist = Self::new();
        let added = blocklist.ingest_configmap_data(&cm);
        info!(count = added, "Loaded certificate blocklist from ConfigMap");
        Ok(blocklist)
    }

    /// Persist the current blocklist to a ConfigMap.
    ///
    /// Each line is stored as `fingerprint:expiry_timestamp`.
    pub async fn persist_to_configmap(&self, client: &Client) -> Result<(), kube::Error> {
        let fingerprints: Vec<String> = self
            .entries
            .iter()
            .map(|entry| format!("{}:{}", entry.key(), entry.value()))
            .collect();

        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": BLOCKLIST_CONFIGMAP,
                "namespace": LATTICE_SYSTEM_NAMESPACE,
            },
            "data": {
                BLOCKLIST_DATA_KEY: fingerprints.join("\n"),
            }
        });

        let params = PatchParams::apply(FIELD_MANAGER).force();
        configmap_api(client)
            .patch(BLOCKLIST_CONFIGMAP, &params, &Patch::Apply(&cm))
            .await?;

        info!(
            count = fingerprints.len(),
            "Persisted certificate blocklist to ConfigMap"
        );
        Ok(())
    }

    /// Sync from a ConfigMap, adding any new entries not already present.
    pub async fn sync_from_configmap(&self, client: &Client) -> Result<(), kube::Error> {
        match configmap_api(client).get(BLOCKLIST_CONFIGMAP).await {
            Ok(cm) => {
                let added = self.ingest_configmap_data(&cm);
                if added > 0 {
                    info!(
                        added,
                        total = self.len(),
                        "Synced new entries from blocklist ConfigMap"
                    );
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                warn!("Blocklist ConfigMap not found during sync — may have been deleted");
            }
            Err(e) => {
                warn!(error = %e, "Failed to sync blocklist from ConfigMap");
            }
        }
        Ok(())
    }

    /// Parse fingerprints from a ConfigMap and insert them. Returns count of newly added entries.
    ///
    /// Supports both legacy format (fingerprint only) and new format (fingerprint:expiry).
    /// Legacy entries get `i64::MAX` expiry so they're never auto-pruned.
    fn ingest_configmap_data(&self, cm: &k8s_openapi::api::core::v1::ConfigMap) -> usize {
        let raw = cm
            .data
            .as_ref()
            .and_then(|d| d.get(BLOCKLIST_DATA_KEY))
            .map(|s| s.as_str())
            .unwrap_or("");

        let mut added = 0usize;
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (fp, expiry) = if let Some((f, e)) = line.rsplit_once(':') {
                (f, e.parse::<i64>().unwrap_or(i64::MAX))
            } else {
                (line, i64::MAX)
            };
            if !self.entries.contains_key(fp) {
                self.entries.insert(fp.to_string(), expiry);
                added += 1;
            }
        }
        added
    }
}

/// Namespaced ConfigMap API for the blocklist.
fn configmap_api(client: &Client) -> Api<k8s_openapi::api::core::v1::ConfigMap> {
    Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE)
}

impl Default for CertificateBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAR_FUTURE: i64 = 4_000_000_000; // ~2096

    #[test]
    fn empty_blocklist_blocks_nothing() {
        let blocklist = CertificateBlocklist::new();
        assert!(!blocklist.is_blocked("abc123"));
        assert!(blocklist.is_empty());
        assert_eq!(blocklist.len(), 0);
    }

    #[test]
    fn add_and_check_fingerprint() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("deadbeef".to_string(), FAR_FUTURE);

        assert!(blocklist.is_blocked("deadbeef"));
        assert!(!blocklist.is_blocked("other"));
        assert_eq!(blocklist.len(), 1);
    }

    #[test]
    fn remove_fingerprint() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("deadbeef".to_string(), FAR_FUTURE);
        assert!(blocklist.is_blocked("deadbeef"));

        assert!(blocklist.remove("deadbeef"));
        assert!(!blocklist.is_blocked("deadbeef"));
        assert!(blocklist.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let blocklist = CertificateBlocklist::new();
        assert!(!blocklist.remove("nonexistent"));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let data = b"test certificate data";
        let fp1 = CertificateBlocklist::fingerprint(data);
        let fp2 = CertificateBlocklist::fingerprint(data);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn fingerprint_differs_for_different_certs() {
        let fp1 = CertificateBlocklist::fingerprint(b"cert one");
        let fp2 = CertificateBlocklist::fingerprint(b"cert two");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn clone_shares_state() {
        let blocklist = CertificateBlocklist::new();
        let clone = blocklist.clone();

        blocklist.add("shared".to_string(), FAR_FUTURE);
        assert!(clone.is_blocked("shared"));
    }

    #[test]
    fn duplicate_add_is_idempotent() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("dup".to_string(), FAR_FUTURE);
        blocklist.add("dup".to_string(), FAR_FUTURE);
        assert_eq!(blocklist.len(), 1);
    }

    #[test]
    fn prune_expired_removes_old_entries() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("expired".to_string(), 0); // epoch = already expired
        blocklist.add("valid".to_string(), FAR_FUTURE);
        assert_eq!(blocklist.len(), 2);

        let pruned = blocklist.prune_expired();
        assert_eq!(pruned, 1);
        assert!(!blocklist.is_blocked("expired"));
        assert!(blocklist.is_blocked("valid"));
        assert_eq!(blocklist.len(), 1);
    }

    #[test]
    fn prune_expired_no_op_when_all_valid() {
        let blocklist = CertificateBlocklist::new();
        blocklist.add("a".to_string(), FAR_FUTURE);
        blocklist.add("b".to_string(), FAR_FUTURE);

        let pruned = blocklist.prune_expired();
        assert_eq!(pruned, 0);
        assert_eq!(blocklist.len(), 2);
    }
}
