//! Repository operations
//!
//! Reads and writes the lattice-clusters repository structure.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// A cluster definition from the repository
#[derive(Debug, Clone)]
pub struct ClusterInfo {
    /// Cluster name
    pub name: String,
    /// Parent cluster name (None for root)
    pub parent: Option<String>,
    /// Path to the cluster.yaml file
    pub path: PathBuf,
    /// Whether this is a cell (can provision children)
    pub is_cell: bool,
    /// Provider type (aws, openstack, docker, proxmox)
    pub provider: Option<String>,
    /// Kubernetes version
    pub k8s_version: Option<String>,
    /// Number of control plane nodes
    pub control_plane_nodes: Option<i32>,
    /// Number of worker nodes
    pub worker_nodes: Option<i32>,
}

/// A service registration from the repository
#[derive(Debug, Clone)]
pub struct RegistrationInfo {
    /// Registration name
    pub name: String,
    /// Git URL
    pub git_url: String,
    /// Path in the git repo
    pub git_path: String,
    /// Branch or tag
    pub git_ref: String,
    /// Path to the registration file
    pub path: PathBuf,
}

/// A service placement from the repository
#[derive(Debug, Clone)]
pub struct PlacementInfo {
    /// Placement name
    pub name: String,
    /// Service reference (registration name)
    pub service_ref: String,
    /// Cluster this placement is for
    pub cluster: String,
    /// Replicas override
    pub replicas: Option<i32>,
    /// Path to the placement file
    pub path: PathBuf,
}

/// Repository structure reader
pub struct LatticeRepo {
    /// Root path of the repository
    root: PathBuf,
}

impl LatticeRepo {
    /// Open a lattice repository
    pub fn open(path: &Path) -> Result<Self> {
        // Check if this looks like a lattice repo
        let cluster_yaml = path.join("cluster.yaml");
        if !cluster_yaml.exists() {
            return Err(Error::NotLatticeRepo {
                path: path.to_path_buf(),
            });
        }

        Ok(Self {
            root: path.to_path_buf(),
        })
    }

    /// Get the root path
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// List all clusters in the repository
    pub fn list_clusters(&self) -> Result<Vec<ClusterInfo>> {
        let mut clusters = Vec::new();

        // Read root cluster
        if let Ok(cluster) = self.read_cluster_at(&self.root.join("cluster.yaml"), None) {
            clusters.push(cluster);
        }

        // Recursively find clusters in children/ folders
        self.find_clusters_recursive(&self.root, &mut clusters)?;

        Ok(clusters)
    }

    /// Find clusters recursively
    fn find_clusters_recursive(&self, dir: &Path, clusters: &mut Vec<ClusterInfo>) -> Result<()> {
        let children_dir = dir.join("children");
        if !children_dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(&children_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let cluster_yaml = path.join("cluster.yaml");
                if cluster_yaml.exists() {
                    // Determine parent from directory structure
                    let parent = self.parent_name_from_path(&path);

                    if let Ok(cluster) = self.read_cluster_at(&cluster_yaml, parent) {
                        clusters.push(cluster);
                    }

                    // Recurse into this cluster's children
                    self.find_clusters_recursive(&path, clusters)?;
                }
            }
        }

        Ok(())
    }

    /// Determine parent name from path
    fn parent_name_from_path(&self, cluster_dir: &Path) -> Option<String> {
        // Go up two levels (past children/) and read that cluster's name
        let parent_dir = cluster_dir.parent()?.parent()?;
        let parent_cluster_yaml = parent_dir.join("cluster.yaml");

        if parent_cluster_yaml.exists() {
            if let Ok(content) = std::fs::read_to_string(&parent_cluster_yaml) {
                if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                    return value
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string());
                }
            }
        }

        None
    }

    /// Read a cluster definition from a file
    fn read_cluster_at(&self, path: &Path, parent: Option<String>) -> Result<ClusterInfo> {
        let content = std::fs::read_to_string(path)?;
        let value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let name = value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::validation("cluster missing metadata.name"))?
            .to_string();

        let spec = value.get("spec");

        let is_cell = spec
            .and_then(|s| s.get("cell"))
            .and_then(|c| c.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        let provider = spec
            .and_then(|s| s.get("provider"))
            .and_then(|p| p.get("config"))
            .and_then(|c| {
                if c.get("aws").is_some() {
                    Some("aws")
                } else if c.get("openstack").is_some() {
                    Some("openstack")
                } else if c.get("docker").is_some() {
                    Some("docker")
                } else if c.get("proxmox").is_some() {
                    Some("proxmox")
                } else {
                    None
                }
            })
            .map(|s| s.to_string());

        let k8s_version = spec
            .and_then(|s| s.get("provider"))
            .and_then(|p| p.get("kubernetes"))
            .and_then(|k| k.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let control_plane_nodes = spec
            .and_then(|s| s.get("nodes"))
            .and_then(|n| n.get("controlPlane"))
            .and_then(|c| c.as_i64())
            .map(|n| n as i32);

        let worker_nodes = spec
            .and_then(|s| s.get("nodes"))
            .and_then(|n| n.get("workers"))
            .and_then(|w| w.as_i64())
            .map(|n| n as i32);

        Ok(ClusterInfo {
            name,
            parent,
            path: path.to_path_buf(),
            is_cell,
            provider,
            k8s_version,
            control_plane_nodes,
            worker_nodes,
        })
    }

    /// Get cluster by name
    pub fn get_cluster(&self, name: &str) -> Result<ClusterInfo> {
        let clusters = self.list_clusters()?;
        clusters
            .into_iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::ClusterNotFound {
                name: name.to_string(),
            })
    }

    /// Build cluster hierarchy tree
    pub fn build_tree(&self) -> Result<HashMap<String, Vec<String>>> {
        let clusters = self.list_clusters()?;
        let mut tree: HashMap<String, Vec<String>> = HashMap::new();

        for cluster in clusters {
            let parent_key = cluster.parent.clone().unwrap_or_default();
            tree.entry(parent_key).or_default().push(cluster.name);
        }

        Ok(tree)
    }

    /// List all registrations
    pub fn list_registrations(&self) -> Result<Vec<RegistrationInfo>> {
        let mut registrations = Vec::new();

        // Find all registrations/ folders
        self.find_registrations_recursive(&self.root, &mut registrations)?;

        Ok(registrations)
    }

    /// Find registrations recursively
    fn find_registrations_recursive(
        &self,
        dir: &Path,
        registrations: &mut Vec<RegistrationInfo>,
    ) -> Result<()> {
        let reg_dir = dir.join("registrations");
        if reg_dir.exists() {
            for entry in std::fs::read_dir(&reg_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path
                    .extension()
                    .map(|e| e == "yaml" || e == "yml")
                    .unwrap_or(false)
                {
                    if let Ok(reg) = self.read_registration_at(&path) {
                        registrations.push(reg);
                    }
                }
            }
        }

        // Recurse into children
        let children_dir = dir.join("children");
        if children_dir.exists() {
            for entry in std::fs::read_dir(&children_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    self.find_registrations_recursive(&entry.path(), registrations)?;
                }
            }
        }

        Ok(())
    }

    /// Read a registration file
    fn read_registration_at(&self, path: &Path) -> Result<RegistrationInfo> {
        let content = std::fs::read_to_string(path)?;
        let value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let name = value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::validation("registration missing metadata.name"))?
            .to_string();

        let source = value
            .get("spec")
            .and_then(|s| s.get("source"))
            .and_then(|s| s.get("git"));

        let git_url = source
            .and_then(|g| g.get("url"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();

        let git_path = source
            .and_then(|g| g.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or(".")
            .to_string();

        let git_ref = source
            .and_then(|g| g.get("branch").or_else(|| g.get("tag")))
            .and_then(|r| r.as_str())
            .unwrap_or("main")
            .to_string();

        Ok(RegistrationInfo {
            name,
            git_url,
            git_path,
            git_ref,
            path: path.to_path_buf(),
        })
    }

    /// List placements for a specific cluster
    pub fn list_placements(&self, cluster_name: &str) -> Result<Vec<PlacementInfo>> {
        let cluster = self.get_cluster(cluster_name)?;
        let placements_dir = cluster.path.parent().unwrap().join("placements");

        if !placements_dir.exists() {
            return Ok(Vec::new());
        }

        let mut placements = Vec::new();

        for entry in std::fs::read_dir(&placements_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path
                .extension()
                .map(|e| e == "yaml" || e == "yml")
                .unwrap_or(false)
                && path
                    .file_name()
                    .map(|f| f != "kustomization.yaml")
                    .unwrap_or(true)
            {
                if let Ok(placement) = self.read_placement_at(&path, cluster_name) {
                    placements.push(placement);
                }
            }
        }

        Ok(placements)
    }

    /// Read a placement file
    fn read_placement_at(&self, path: &Path, cluster: &str) -> Result<PlacementInfo> {
        let content = std::fs::read_to_string(path)?;
        let value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let name = value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| Error::validation("placement missing metadata.name"))?
            .to_string();

        let service_ref = value
            .get("spec")
            .and_then(|s| s.get("serviceRef"))
            .and_then(|r| r.as_str())
            .ok_or_else(|| Error::validation("placement missing spec.serviceRef"))?
            .to_string();

        let replicas = value
            .get("spec")
            .and_then(|s| s.get("overrides"))
            .and_then(|o| o.get("replicas"))
            .and_then(|r| r.as_i64())
            .map(|n| n as i32);

        Ok(PlacementInfo {
            name,
            service_ref,
            cluster: cluster.to_string(),
            replicas,
            path: path.to_path_buf(),
        })
    }
}
