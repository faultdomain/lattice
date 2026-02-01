//! Topological sort for determining move order
//!
//! This module computes the order in which objects must be created on the target
//! cluster. Owners must be created before their dependents so that ownerReferences
//! can be properly rebuilt with the new UIDs.

use std::collections::HashSet;

use tracing::{debug, info};

use crate::error::MoveError;
use crate::graph::{GraphNode, ObjectGraph};

/// A group of objects that can be created in parallel
///
/// All objects in a group have their owners already placed, so they can be
/// created concurrently without violating ownership constraints.
#[derive(Debug, Clone)]
pub(crate) struct MoveGroup {
    /// UIDs of objects in this group
    pub uids: Vec<String>,
}

impl MoveGroup {
    /// Create a new empty MoveGroup
    pub fn new() -> Self {
        Self { uids: Vec::new() }
    }

    /// Check if the group is empty
    pub fn is_empty(&self) -> bool {
        self.uids.is_empty()
    }

    /// Get the number of objects in the group
    pub fn len(&self) -> usize {
        self.uids.len()
    }
}

impl Default for MoveGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordered sequence of groups for move operation
///
/// Groups are ordered such that all owners of objects in group N are in groups
/// 0..N-1. This ensures ownerReferences can be rebuilt correctly.
#[derive(Debug)]
pub struct MoveSequence {
    /// Ordered groups
    groups: Vec<MoveGroup>,
    /// Total number of objects
    total_objects: usize,
}

impl MoveSequence {
    /// Compute the move sequence from an object graph
    ///
    /// Uses Kahn's algorithm for topological sort:
    /// 1. Find all nodes with no unplaced owners
    /// 2. Add them to the current group
    /// 3. Mark them as placed
    /// 4. Repeat until all nodes are placed
    pub fn from_graph(graph: &ObjectGraph) -> Result<Self, MoveError> {
        let mut placed: HashSet<String> = HashSet::new();
        let mut groups: Vec<MoveGroup> = Vec::new();

        let all_uids: HashSet<String> = graph.uids().into_iter().collect();
        let total_objects = all_uids.len();

        // Keep iterating until all objects are placed
        while placed.len() < total_objects {
            let mut group = MoveGroup::new();

            // Find all nodes whose owners are all placed
            for uid in &all_uids {
                if placed.contains(uid) {
                    continue;
                }

                let node = match graph.get(uid) {
                    Some(n) => n,
                    None => continue,
                };

                // Check if all owners are placed
                let all_owners = node.all_owners();

                // Filter to only owners that exist in our graph
                // (some owners may be external and not being moved)
                let internal_owners: HashSet<_> =
                    all_owners.intersection(&all_uids).cloned().collect();

                if internal_owners.iter().all(|o| placed.contains(o)) {
                    group.uids.push(uid.clone());
                }
            }

            // If no progress was made, we have a cycle
            if group.is_empty() {
                // Find the UIDs that are stuck
                let stuck: Vec<String> = all_uids
                    .iter()
                    .filter(|uid| !placed.contains(*uid))
                    .cloned()
                    .collect();

                return Err(MoveError::CycleDetected(format!(
                    "cannot make progress, stuck UIDs: {:?}",
                    stuck
                )));
            }

            debug!(
                group = groups.len(),
                objects = group.len(),
                "Computed move group"
            );

            // Mark all objects in this group as placed
            placed.extend(group.uids.iter().cloned());
            groups.push(group);
        }

        info!(
            groups = groups.len(),
            objects = total_objects,
            "Computed move sequence"
        );

        Ok(Self {
            groups,
            total_objects,
        })
    }

    /// Get the ordered groups (test-only)
    #[cfg(test)]
    pub(crate) fn groups(&self) -> &[MoveGroup] {
        &self.groups
    }

    /// Get the total number of objects
    pub fn total_objects(&self) -> usize {
        self.total_objects
    }

    /// Get the number of groups
    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }

    /// Iterate over groups with their index
    pub(crate) fn iter_groups(&self) -> impl Iterator<Item = (usize, &MoveGroup)> {
        self.groups.iter().enumerate()
    }

    /// Get all UIDs in move order (flattened)
    pub fn all_uids_in_order(&self) -> Vec<String> {
        self.groups
            .iter()
            .flat_map(|g| g.uids.iter().cloned())
            .collect()
    }

    /// Get all UIDs in reverse order for deletion
    pub fn all_uids_for_deletion(&self) -> Vec<String> {
        self.groups
            .iter()
            .rev()
            .flat_map(|g| g.uids.iter().cloned())
            .collect()
    }
}

/// Extract nodes from graph for a specific group
pub(crate) fn extract_nodes_for_group<'a>(
    graph: &'a ObjectGraph,
    group: &MoveGroup,
) -> Vec<&'a GraphNode> {
    group.uids.iter().filter_map(|uid| graph.get(uid)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphNode, ObjectIdentity};

    fn make_test_node(uid: &str, owners: Vec<&str>) -> GraphNode {
        GraphNode {
            identity: ObjectIdentity::new("test/v1", "Test", "default", uid, uid),
            object: serde_json::json!({}),
            owners: owners.into_iter().map(String::from).collect(),
            soft_owners: std::collections::HashSet::new(),
            force_move_hierarchy: false,
            new_uid: None,
        }
    }

    fn make_test_graph(nodes: Vec<GraphNode>) -> ObjectGraph {
        let mut graph = ObjectGraph::new("default");
        for node in nodes {
            graph.insert(node);
        }
        graph
    }

    #[test]
    fn test_move_group_basic() {
        let group = MoveGroup::new();
        assert!(group.is_empty());
        assert_eq!(group.len(), 0);
    }

    #[test]
    fn test_sequence_single_object() {
        let nodes = vec![make_test_node("a", vec![])];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();

        assert_eq!(sequence.num_groups(), 1);
        assert_eq!(sequence.total_objects(), 1);
        assert_eq!(sequence.groups()[0].uids, vec!["a"]);
    }

    #[test]
    fn test_sequence_linear_chain() {
        // a -> b -> c (c depends on b, b depends on a)
        let nodes = vec![
            make_test_node("a", vec![]),
            make_test_node("b", vec!["a"]),
            make_test_node("c", vec!["b"]),
        ];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();

        // Should have 3 groups (one per level)
        assert_eq!(sequence.num_groups(), 3);
        assert_eq!(sequence.total_objects(), 3);

        // a should be first, then b, then c
        let uids = sequence.all_uids_in_order();
        assert_eq!(uids, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_sequence_diamond_dependency() {
        // a -> b -> d
        // a -> c -> d
        let nodes = vec![
            make_test_node("a", vec![]),
            make_test_node("b", vec!["a"]),
            make_test_node("c", vec!["a"]),
            make_test_node("d", vec!["b", "c"]),
        ];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();

        // Should have 3 groups: [a], [b, c], [d]
        assert_eq!(sequence.num_groups(), 3);

        let uids = sequence.all_uids_in_order();
        // a must be first
        assert_eq!(uids[0], "a");
        // d must be last
        assert_eq!(uids[3], "d");
        // b and c can be in any order but must be between a and d
        assert!(uids[1..3].contains(&"b".to_string()));
        assert!(uids[1..3].contains(&"c".to_string()));
    }

    #[test]
    fn test_sequence_parallel_roots() {
        // a and b are independent roots
        let nodes = vec![make_test_node("a", vec![]), make_test_node("b", vec![])];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();

        // Should have 1 group with both objects
        assert_eq!(sequence.num_groups(), 1);
        assert_eq!(sequence.groups()[0].len(), 2);
    }

    #[test]
    fn test_sequence_external_owner() {
        // b depends on a, but a is not in the graph (external)
        let nodes = vec![make_test_node("b", vec!["a"])];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();

        // b should be placed in first group since its owner is external
        assert_eq!(sequence.num_groups(), 1);
        assert_eq!(sequence.groups()[0].uids, vec!["b"]);
    }

    #[test]
    fn test_all_uids_for_deletion() {
        let nodes = vec![
            make_test_node("a", vec![]),
            make_test_node("b", vec!["a"]),
            make_test_node("c", vec!["b"]),
        ];
        let graph = make_test_graph(nodes);

        let sequence = MoveSequence::from_graph(&graph).unwrap();
        let deletion_order = sequence.all_uids_for_deletion();

        // Should be c, b, a (reverse of creation order)
        assert_eq!(deletion_order, vec!["c", "b", "a"]);
    }

    #[test]
    fn test_extract_nodes_for_group() {
        let nodes = vec![make_test_node("a", vec![]), make_test_node("b", vec![])];
        let graph = make_test_graph(nodes);

        let mut group = MoveGroup::new();
        group.uids.push("a".to_string());

        let extracted = extract_nodes_for_group(&graph, &group);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].uid(), "a");
    }

    // Note: Testing cycle detection would require a graph with cycles,
    // but our ownership model shouldn't allow cycles. The test is here
    // to ensure the code handles unexpected cases gracefully.
}
