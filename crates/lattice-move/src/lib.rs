//! Distributed CAPI resource move for pivot operations
//!
//! Moves CAPI resources between clusters using ownership-aware topological
//! ordering and UID remapping. Supports both gRPC (for pivot over outbound
//! stream) and local mode (for CLI install/uninstall with both kubeconfigs).
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
//! ## Modes
//!
//! - **gRPC mode**: Cell sends batches over outbound gRPC stream to agent.
//!   Used during pivot when the parent can't access the child's K8s API directly.
//! - **Local mode** (`local_move()`): Both kubeconfigs accessible locally.
//!   Uses `LocalMoveSender` wrapping `AgentMover` directly. Used by CLI
//!   install/uninstall commands.

mod agent;
mod cell;
mod error;
mod graph;
pub mod local;
mod sequence;
mod utils;

pub use agent::{AgentMover, MoveObjectError, SOURCE_UID_ANNOTATION};
pub use cell::{
    // Standalone functions (used by both pivot and unpivot)
    pause_cluster, prepare_move_objects, unpause_cluster,
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
pub use local::local_move;
pub use sequence::MoveSequence;

/// Label indicating a CRD should be included in move operations.
/// All upstream CAPI provider CRDs carry `cluster.x-k8s.io/provider: <name>`.
pub const MOVE_LABEL: &str = "cluster.x-k8s.io/provider";
