//! Backup and restore controllers for Lattice
//!
//! This crate provides controllers that manage Velero resources for backup/restore:
//!
//! - **backup_policy_controller**: Reconciles LatticeBackupPolicy CRDs into Velero
//!   Schedule and BackupStorageLocation resources
//! - **restore_controller**: Reconciles LatticeRestore CRDs into Velero Restore
//!   resources, with optional LatticeAware two-phase ordering
//! - **velero**: Typed structs for Velero resources (Schedule, BSL, Restore)

pub mod backup_policy_controller;
pub mod restore_controller;
pub mod velero;

pub use backup_policy_controller::reconcile as backup_policy_reconcile;
pub use restore_controller::reconcile as restore_reconcile;
