//! Distributed clusterctl move implementation for CAPI pivot over gRPC
//!
//! This crate implements the clusterctl move algorithm in Rust, replacing direct
//! target k8s API calls with gRPC message passing. This enables pivot operations
//! where the cell (parent cluster) doesn't have direct k8s API access to the
//! agent (child cluster).
//!
//! ## Architecture
//!
//! ```text
//! Cell (Parent)                          Agent (Child)
//! ─────────────────                      ──────────────────
//! 1. Discover CAPI CRDs
//! 2. List objects, build ownership graph
//! 3. Compute move sequence (topo sort)
//! 4. Pause Clusters/ClusterClasses
//! 5. For each batch (in order):
//!    ├─ Extract objects
//!    ├─ Strip transient fields
//!    ├─ Send MoveObjectBatch ─────────────►  6. For each object:
//!    │                                           ├─ Ensure namespace
//!    │                                           ├─ Rebuild ownerRefs (new UIDs)
//!    │                                           ├─ Create object
//!    │                                           └─ Capture new UID
//!    ◄───────────────── MoveObjectAck ──────  7. Return UID mappings
//! 8. After all batches:
//!    ├─ Send MoveComplete ────────────────►  9. Unpause Clusters/ClusterClasses
//!    ◄─────────────── MoveCompleteAck ────  10. Confirm unpause
//! 11. Delete source objects (reverse order)
//!     ├─ Add delete-for-move annotation
//!     ├─ Remove finalizers
//!     └─ Delete
//! ```
//!
//! ## Key Differences from clusterctl move --to-directory
//!
//! The `--to-directory` and `--from-directory` flags have **backup semantics**:
//! - Source cluster is unpaused after export
//! - Source resources are NOT deleted
//! - Requires manual cleanup
//!
//! This implementation provides the exact semantics of `--to-kubeconfig`:
//! - Source cluster stays paused until deletion
//! - Source resources ARE deleted after successful import
//! - Target cluster is unpaused after all objects created
//! - Full object graph with topological ordering and UID remapping

mod agent;
mod cell;
mod error;
mod graph;
mod sequence;
mod utils;

pub use agent::{
    AgentMover, MoveObjectError, MoveObjectInput, SourceOwnerRefInput, SOURCE_UID_ANNOTATION,
};
pub use cell::{
    // Standalone functions (used by both pivot and unpivot)
    prepare_move_objects,
    // Data types
    BatchAck,
    CellMover,
    CellMoverConfig,
    CompleteAck,
    MoveBatch,
    MoveCommandSender,
    MoveCompleteInput,
    MoveObjectOutput,
    MoveResult,
    SourceOwnerRefOutput,
};
pub use error::MoveError;
pub use graph::{GraphNode, ObjectGraph, ObjectIdentity};
pub use sequence::MoveSequence;

/// Annotation added before deletion (matches clusterctl behavior)
pub const DELETE_FOR_MOVE_ANNOTATION: &str = "clusterctl.cluster.x-k8s.io/delete-for-move";

/// Label indicating a CRD should be included in move operations
/// CAPI uses the label key with empty value: `clusterctl.cluster.x-k8s.io: ""`
pub const MOVE_LABEL: &str = "clusterctl.cluster.x-k8s.io";

/// Label indicating a CRD's hierarchy should be included in move operations
pub const MOVE_HIERARCHY_LABEL: &str = "clusterctl.cluster.x-k8s.io/move-hierarchy";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(
            DELETE_FOR_MOVE_ANNOTATION,
            "clusterctl.cluster.x-k8s.io/delete-for-move"
        );
        assert_eq!(MOVE_LABEL, "clusterctl.cluster.x-k8s.io");
        assert_eq!(
            MOVE_HIERARCHY_LABEL,
            "clusterctl.cluster.x-k8s.io/move-hierarchy"
        );
    }
}
