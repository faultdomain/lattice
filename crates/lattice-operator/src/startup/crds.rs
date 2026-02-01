//! CRD installation utilities
//!
//! Provides functions for installing Lattice CRDs on startup using server-side apply.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, Patch, PatchParams};
use kube::{Client, CustomResourceExt};

use crate::crd::{
    CedarPolicy, CloudProvider, LatticeCluster, LatticeExternalService, LatticeService,
    OIDCProvider, SecretsProvider,
};

/// CRD definition with name and resource
struct CrdDef {
    name: &'static str,
    crd: CustomResourceDefinition,
}

/// Get all Lattice CRD definitions
fn all_crds() -> Vec<CrdDef> {
    vec![
        CrdDef {
            name: "latticeclusters.lattice.dev",
            crd: LatticeCluster::crd(),
        },
        CrdDef {
            name: "latticeservices.lattice.dev",
            crd: LatticeService::crd(),
        },
        CrdDef {
            name: "latticeexternalservices.lattice.dev",
            crd: LatticeExternalService::crd(),
        },
        CrdDef {
            name: "cloudproviders.lattice.dev",
            crd: CloudProvider::crd(),
        },
        CrdDef {
            name: "secretsproviders.lattice.dev",
            crd: SecretsProvider::crd(),
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

/// Ensure all Lattice CRDs are installed
///
/// The operator installs its own CRDs on startup using server-side apply.
/// This ensures the CRD versions always match the operator version.
pub async fn ensure_crds_installed(client: &Client) -> anyhow::Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-controller").force();

    for def in all_crds() {
        tracing::info!("Installing {} CRD...", def.name);
        crds.patch(def.name, &params, &Patch::Apply(&def.crd))
            .await
            .map_err(|e| anyhow::anyhow!("failed to install {} CRD: {}", def.name, e))?;
    }

    tracing::info!("All Lattice CRDs installed/updated");
    Ok(())
}
