//! Role hierarchy types and tree structures for optional hierarchy access.
//!
//! This module provides types for representing role hierarchies in structured
//! formats, enabling use cases like API responses, admin interfaces, JWT claims,
//! and database integration while maintaining backward compatibility.
use crate::role::Role;
#[cfg(feature = "persistence")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a complete role hierarchy tree structure.
///
/// This type provides a structured view of role relationships that can be
/// used for visualization, API responses, or external system integration.
///
/// # Example
/// ```no_run
/// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
/// # use role_system::hierarchy::RoleHierarchyTree;
/// # tokio_test::block_on(async {
/// let storage = MemoryStorage::new();
/// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
/// let role_system = AsyncRoleSystem::new(role_sys);
///
/// // Get hierarchy tree from role system
/// let tree = role_system.get_hierarchy_tree(None).await?;
/// println!("Total roles: {}, Max depth: {}", tree.total_roles, tree.max_depth);
/// # Ok::<(), role_system::Error>(())
/// # });
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct RoleHierarchyTree {
    /// Root node of the hierarchy tree
    pub root: RoleNode,
    /// Total number of roles in the tree
    pub total_roles: usize,
    /// Maximum depth of the hierarchy
    pub max_depth: usize,
    /// Metadata about the tree structure
    pub metadata: HierarchyMetadata,
}

/// Represents a single node in the role hierarchy tree.
///
/// Each node contains a role and its direct children, along with
/// structural information like depth in the hierarchy.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct RoleNode {
    /// The role at this node
    pub role: Role,
    /// Direct child roles
    pub children: Vec<RoleNode>,
    /// Depth in the hierarchy (root = 0)
    pub depth: usize,
    /// Number of descendants (including indirect children)
    pub descendant_count: usize,
}

/// Metadata about a role hierarchy structure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct HierarchyMetadata {
    /// When the hierarchy was generated
    #[cfg(feature = "persistence")]
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Version of the hierarchy schema
    pub schema_version: String,
    /// Total permission count across all roles
    pub total_permissions: usize,
    /// Performance metrics for generation
    pub generation_time_ms: u64,
}

/// Represents a relationship between two roles in the hierarchy.
///
/// This type captures both direct parent-child relationships and
/// inherited relationships through the hierarchy chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct RoleRelationship {
    /// ID of the child role
    pub child_role_id: String,
    /// ID of the parent role
    pub parent_role_id: String,
    /// Type of relationship (direct or inherited)
    pub relationship_type: RelationshipType,
    /// When this relationship was created (if tracked)
    #[cfg(feature = "persistence")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Additional metadata about the relationship
    pub metadata: HashMap<String, String>,
}

/// Type of relationship between roles in the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub enum RelationshipType {
    /// Direct parent-child relationship
    Direct,
    /// Inherited relationship through hierarchy chain
    Inherited,
}

/// Configuration for hierarchy access and traversal.
///
/// This configuration controls whether hierarchy information can be
/// accessed and how traversal operations behave.
#[derive(Debug, Clone)]
pub struct HierarchyConfig {
    /// Enable hierarchy access methods (default: false for backward compatibility)
    pub enable_hierarchy_access: bool,
    /// Maximum hierarchy depth to prevent infinite recursion
    pub max_hierarchy_depth: usize,
    /// Cache hierarchy calculations for performance
    pub cache_hierarchy: bool,
    /// Maximum number of roles to traverse in a single operation
    pub max_traversal_size: usize,
    /// Include permission counts in hierarchy metadata
    pub include_permission_counts: bool,
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        Self {
            enable_hierarchy_access: false, // Maintain current behavior by default
            max_hierarchy_depth: 10,
            cache_hierarchy: true,
            max_traversal_size: 1000,
            include_permission_counts: true,
        }
    }
}

/// Builder for creating hierarchy configurations.
///
/// # Example
/// ```rust
/// use role_system::hierarchy::HierarchyConfigBuilder;
///
/// let config = HierarchyConfigBuilder::new()
///     .enable_hierarchy_access(true)
///     .max_depth(15)
///     .enable_caching(true)
///     .build();
/// ```
pub struct HierarchyConfigBuilder {
    config: HierarchyConfig,
}

impl HierarchyConfigBuilder {
    /// Create a new hierarchy configuration builder.
    pub fn new() -> Self {
        Self {
            config: HierarchyConfig::default(),
        }
    }

    /// Enable or disable hierarchy access methods.
    pub fn enable_hierarchy_access(mut self, enable: bool) -> Self {
        self.config.enable_hierarchy_access = enable;
        self
    }

    /// Set the maximum hierarchy depth.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.config.max_hierarchy_depth = depth;
        self
    }

    /// Enable or disable hierarchy caching.
    pub fn enable_caching(mut self, enable: bool) -> Self {
        self.config.cache_hierarchy = enable;
        self
    }

    /// Set the maximum traversal size.
    pub fn max_traversal_size(mut self, size: usize) -> Self {
        self.config.max_traversal_size = size;
        self
    }

    /// Include permission counts in metadata.
    pub fn include_permission_counts(mut self, include: bool) -> Self {
        self.config.include_permission_counts = include;
        self
    }

    /// Build the hierarchy configuration.
    pub fn build(self) -> HierarchyConfig {
        self.config
    }
}

impl Default for HierarchyConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleHierarchyTree {
    /// Create a new empty hierarchy tree.
    pub fn new(root: RoleNode) -> Self {
        let total_roles = root.descendant_count + 1;
        let max_depth = Self::calculate_max_depth(&root);

        Self {
            root,
            total_roles,
            max_depth,
            metadata: HierarchyMetadata {
                #[cfg(feature = "persistence")]
                generated_at: chrono::Utc::now(),
                schema_version: "1.1.0".to_string(),
                total_permissions: 0, // Will be calculated later
                generation_time_ms: 0,
            },
        }
    }

    /// Calculate the maximum depth of the hierarchy tree.
    fn calculate_max_depth(node: &RoleNode) -> usize {
        if node.children.is_empty() {
            node.depth
        } else {
            node.children
                .iter()
                .map(Self::calculate_max_depth)
                .max()
                .unwrap_or(node.depth)
        }
    }

    /// Get all roles in the tree as a flattened list.
    pub fn flatten(&self) -> Vec<&Role> {
        let mut roles = Vec::new();
        Self::flatten_node(&self.root, &mut roles);
        roles
    }

    /// Recursively flatten a node and its children.
    fn flatten_node<'a>(node: &'a RoleNode, roles: &mut Vec<&'a Role>) {
        roles.push(&node.role);
        for child in &node.children {
            Self::flatten_node(child, roles);
        }
    }

    /// Find a node by role ID.
    pub fn find_node(&self, role_id: &str) -> Option<&RoleNode> {
        Self::find_node_recursive(&self.root, role_id)
    }

    /// Recursively search for a node by role ID.
    fn find_node_recursive<'a>(node: &'a RoleNode, role_id: &str) -> Option<&'a RoleNode> {
        if node.role.id() == role_id {
            return Some(node);
        }

        for child in &node.children {
            if let Some(found) = Self::find_node_recursive(child, role_id) {
                return Some(found);
            }
        }

        None
    }
}

impl RoleNode {
    /// Create a new role node.
    pub fn new(role: Role, depth: usize) -> Self {
        Self {
            role,
            children: Vec::new(),
            depth,
            descendant_count: 0,
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: RoleNode) {
        self.descendant_count += child.descendant_count + 1;
        self.children.push(child);
    }

    /// Get all descendant role IDs.
    pub fn get_descendant_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for child in &self.children {
            ids.push(child.role.id().to_string());
            ids.extend(child.get_descendant_ids());
        }
        ids
    }

    /// Check if this node is a leaf (has no children).
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Check if this node is the root (depth 0).
    pub fn is_root(&self) -> bool {
        self.depth == 0
    }
}

impl RoleRelationship {
    /// Create a new role relationship.
    pub fn new(
        child_role_id: String,
        parent_role_id: String,
        relationship_type: RelationshipType,
    ) -> Self {
        Self {
            child_role_id,
            parent_role_id,
            relationship_type,
            #[cfg(feature = "persistence")]
            created_at: Some(chrono::Utc::now()),
            metadata: HashMap::new(),
        }
    }

    /// Create a direct relationship.
    pub fn direct(child_role_id: String, parent_role_id: String) -> Self {
        Self::new(child_role_id, parent_role_id, RelationshipType::Direct)
    }

    /// Create an inherited relationship.
    pub fn inherited(child_role_id: String, parent_role_id: String) -> Self {
        Self::new(child_role_id, parent_role_id, RelationshipType::Inherited)
    }

    /// Add metadata to the relationship.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Check if this is a direct relationship.
    pub fn is_direct(&self) -> bool {
        self.relationship_type == RelationshipType::Direct
    }

    /// Check if this is an inherited relationship.
    pub fn is_inherited(&self) -> bool {
        self.relationship_type == RelationshipType::Inherited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::Role;

    #[test]
    fn test_hierarchy_config_builder() {
        let config = HierarchyConfigBuilder::new()
            .enable_hierarchy_access(true)
            .max_depth(15)
            .enable_caching(false)
            .max_traversal_size(500)
            .build();

        assert!(config.enable_hierarchy_access);
        assert_eq!(config.max_hierarchy_depth, 15);
        assert!(!config.cache_hierarchy);
        assert_eq!(config.max_traversal_size, 500);
    }

    #[test]
    fn test_role_node_creation() {
        let role = Role::new("test_role");
        let node = RoleNode::new(role, 2);

        assert_eq!(node.depth, 2);
        assert_eq!(node.descendant_count, 0);
        assert!(node.is_leaf());
        assert!(!node.is_root());
    }

    #[test]
    fn test_role_relationship_creation() {
        let rel = RoleRelationship::direct("child".to_string(), "parent".to_string());

        assert_eq!(rel.child_role_id, "child");
        assert_eq!(rel.parent_role_id, "parent");
        assert!(rel.is_direct());
        assert!(!rel.is_inherited());
    }

    #[test]
    fn test_hierarchy_tree_creation() {
        let role = Role::new("root");
        let root_node = RoleNode::new(role, 0);
        let tree = RoleHierarchyTree::new(root_node);

        assert_eq!(tree.total_roles, 1);
        assert_eq!(tree.max_depth, 0);
        assert_eq!(tree.metadata.schema_version, "1.1.0");
    }
}
