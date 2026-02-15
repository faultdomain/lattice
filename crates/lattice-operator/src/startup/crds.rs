//! CRD installation utilities
//!
//! Provides functions for installing Lattice CRDs on startup using server-side apply.
//! CRDs are organized into per-mode sets so each ControllerMode only installs
//! the CRDs it needs.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, CustomResourceExt};

use lattice_common::crd::{
    CedarPolicy, CloudProvider, LatticeBackupPolicy, LatticeCluster, LatticeExternalService,
    LatticeMeshMember, LatticeRestore, LatticeService, LatticeServicePolicy, OIDCProvider,
    SecretProvider,
};

/// CRD definition with name and resource
struct CrdDef {
    name: &'static str,
    crd: CustomResourceDefinition,
}

/// CRDs needed by Cluster mode:
/// LatticeCluster, CloudProvider, SecretProvider, CedarPolicy, OIDCProvider
fn cluster_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "latticeclusters.lattice.dev",
            crd: LatticeCluster::crd(),
        },
        CrdDef {
            name: "cloudproviders.lattice.dev",
            crd: CloudProvider::crd(),
        },
        CrdDef {
            name: "secretproviders.lattice.dev",
            crd: SecretProvider::crd(),
        },
        CrdDef {
            name: "cedarpolicies.lattice.dev",
            crd: CedarPolicy::crd(),
        },
        CrdDef {
            name: "oidcproviders.lattice.dev",
            crd: OIDCProvider::crd(),
        },
    ]
}

/// CRDs needed by Service mode:
/// LatticeService, LatticeExternalService, LatticeServicePolicy,
/// LatticeBackupPolicy, LatticeRestore, CedarPolicy
fn service_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "latticeservices.lattice.dev",
            crd: LatticeService::crd(),
        },
        CrdDef {
            name: "latticeexternalservices.lattice.dev",
            crd: LatticeExternalService::crd(),
        },
        CrdDef {
            name: "latticeservicepolicies.lattice.dev",
            crd: LatticeServicePolicy::crd(),
        },
        CrdDef {
            name: "latticebackuppolicies.lattice.dev",
            crd: LatticeBackupPolicy::crd(),
        },
        CrdDef {
            name: "latticerestores.lattice.dev",
            crd: LatticeRestore::crd(),
        },
        CrdDef {
            name: "cedarpolicies.lattice.dev",
            crd: CedarPolicy::crd(),
        },
        CrdDef {
            name: "latticemeshmembers.lattice.dev",
            crd: LatticeMeshMember::crd(),
        },
    ]
}

/// Install a set of CRDs using server-side apply
async fn install_crds(client: &Client, crds_to_install: Vec<CrdDef>) -> anyhow::Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-controller").force();

    for def in crds_to_install {
        tracing::info!("Installing {} CRD...", def.name);
        crds.patch(def.name, &params, &Patch::Apply(&def.crd))
            .await
            .map_err(|e| anyhow::anyhow!("failed to install {} CRD: {}", def.name, e))?;
    }

    Ok(())
}

/// Ensure CRDs needed by Cluster mode are installed
pub async fn ensure_cluster_crds(client: &Client) -> anyhow::Result<()> {
    tracing::info!("Installing Cluster mode CRDs...");
    install_crds(client, cluster_crds()).await?;
    tracing::info!("Cluster mode CRDs installed/updated");
    Ok(())
}

/// Ensure CRDs needed by Service mode are installed
pub async fn ensure_service_crds(client: &Client) -> anyhow::Result<()> {
    tracing::info!("Installing Service mode CRDs...");
    install_crds(client, service_crds()).await?;
    tracing::info!("Service mode CRDs installed/updated");
    Ok(())
}
