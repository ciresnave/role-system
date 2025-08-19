//! Role definitions and management.

use crate::{
    error::{Error, Result},
    permission::{Permission, PermissionSet},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// A role hierarchy system for managing role inheritance.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct RoleHierarchy {
    /// Map of child role ID to parent role ID
    parent_map: HashMap<String, String>,
    /// Map of parent role ID to set of child role IDs
    children_map: HashMap<String, Vec<String>>,
    /// All roles in the hierarchy
    roles: HashMap<String, Role>,
}

impl RoleHierarchy {
    /// Create a new empty role hierarchy.
    pub fn new() -> Self {
        Self {
            parent_map: HashMap::new(),
            children_map: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// Add a role to the hierarchy.
    pub fn add_role(&mut self, role: Role) -> Result<()> {
        let role_id = role.id().to_string();
        self.roles.insert(role_id, role);
        Ok(())
    }

    /// Set a parent-child relationship between roles.
    pub fn set_parent(&mut self, child_id: &str, parent_id: &str) -> Result<()> {
        // Verify both roles exist
        if !self.roles.contains_key(child_id) {
            return Err(Error::RoleNotFound(child_id.to_string()));
        }
        if !self.roles.contains_key(parent_id) {
            return Err(Error::RoleNotFound(parent_id.to_string()));
        }

        // Check for circular dependencies
        if self.would_create_cycle(child_id, parent_id) {
            return Err(Error::CircularDependency(format!(
                "{} -> {}",
                child_id, parent_id
            )));
        }

        // Remove any existing parent relationship for this child
        if let Some(old_parent) = self.parent_map.remove(child_id)
            && let Some(siblings) = self.children_map.get_mut(&old_parent)
        {
            siblings.retain(|id| id != child_id);
        }

        // Set the new parent relationship
        self.parent_map
            .insert(child_id.to_string(), parent_id.to_string());
        self.children_map
            .entry(parent_id.to_string())
            .or_default()
            .push(child_id.to_string());

        Ok(())
    }

    /// Get the parent role of a given role.
    pub fn get_parent(&self, role_id: &str) -> Option<&Role> {
        self.parent_map
            .get(role_id)
            .and_then(|parent_id| self.roles.get(parent_id))
    }

    /// Get all child roles of a given role.
    pub fn get_children(&self, role_id: &str) -> Vec<&Role> {
        self.children_map
            .get(role_id)
            .map(|child_ids| {
                child_ids
                    .iter()
                    .filter_map(|id| self.roles.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all ancestor roles (parents, grandparents, etc.) of a given role.
    pub fn get_ancestors(&self, role_id: &str) -> Vec<&Role> {
        let mut ancestors = Vec::new();
        let mut current = role_id;

        while let Some(parent_id) = self.parent_map.get(current) {
            if let Some(parent_role) = self.roles.get(parent_id) {
                ancestors.push(parent_role);
                current = parent_id;
            } else {
                break;
            }
        }

        ancestors
    }

    /// Get all permissions for a role, including inherited permissions.
    pub fn get_effective_permissions(&self, role_id: &str) -> Result<PermissionSet> {
        let role = self
            .roles
            .get(role_id)
            .ok_or_else(|| Error::RoleNotFound(role_id.to_string()))?;

        let mut permissions = role.permissions().clone();

        // Add inherited permissions from ancestors
        for ancestor in self.get_ancestors(role_id) {
            for permission in ancestor.permissions().permissions() {
                permissions.add(permission.clone());
            }
        }

        Ok(permissions)
    }

    /// Check if a role has a specific permission, including inherited permissions.
    pub fn has_permission(
        &self,
        role_id: &str,
        action: &str,
        resource: &str,
        context: &HashMap<String, String>,
    ) -> Result<bool> {
        let effective_permissions = self.get_effective_permissions(role_id)?;
        Ok(effective_permissions.grants(action, resource, context))
    }

    /// Get a role by ID.
    pub fn get_role(&self, role_id: &str) -> Option<&Role> {
        self.roles.get(role_id)
    }

    /// Get all roles in the hierarchy.
    pub fn get_all_roles(&self) -> Vec<&Role> {
        self.roles.values().collect()
    }

    /// Remove a role from the hierarchy.
    pub fn remove_role(&mut self, role_id: &str) -> Result<()> {
        // Remove the role itself
        if self.roles.remove(role_id).is_none() {
            return Err(Error::RoleNotFound(role_id.to_string()));
        }

        // Remove from parent mapping
        if let Some(parent_id) = self.parent_map.remove(role_id)
            && let Some(siblings) = self.children_map.get_mut(&parent_id)
        {
            siblings.retain(|id| id != role_id);
        }

        // Remove from children mapping and reparent children
        if let Some(child_ids) = self.children_map.remove(role_id) {
            for child_id in child_ids {
                self.parent_map.remove(&child_id);
            }
        }

        Ok(())
    }

    /// Check if setting a parent would create a circular dependency.
    fn would_create_cycle(&self, child_id: &str, proposed_parent_id: &str) -> bool {
        // If the proposed parent is the child itself, it's a cycle
        if child_id == proposed_parent_id {
            return true;
        }

        // Check if the proposed parent is already a descendant of the child
        let mut current = proposed_parent_id;
        while let Some(parent_id) = self.parent_map.get(current) {
            if parent_id == child_id {
                return true;
            }
            current = parent_id;
        }

        false
    }
}

impl Default for RoleHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

/// A role represents a collection of permissions that can be assigned to subjects.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Role {
    /// Unique identifier for the role.
    id: String,
    /// Human-readable name of the role.
    name: String,
    /// Optional description of the role.
    description: Option<String>,
    /// Permissions granted by this role.
    permissions: PermissionSet,
    /// Metadata associated with the role.
    metadata: HashMap<String, String>,
    /// Whether this role is active.
    active: bool,
}

impl Role {
    /// Create a new role with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description: None,
            permissions: PermissionSet::new(),
            metadata: HashMap::new(),
            active: true,
        }
    }

    /// Create a new role with a specific ID.
    pub fn with_id(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut role = Self::new(name);
        role.id = id.into();
        role
    }

    /// Get the role's unique identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the role's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the role's description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Get the role's description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Add a permission to this role.
    pub fn add_permission(mut self, permission: Permission) -> Self {
        self.permissions.add(permission);
        self
    }

    /// Add multiple permissions to this role.
    pub fn add_permissions(mut self, permissions: impl IntoIterator<Item = Permission>) -> Self {
        for permission in permissions {
            self.permissions.add(permission);
        }
        self
    }

    /// Remove a permission from this role.
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.permissions.remove(permission);
    }

    /// Check if this role has a specific permission.
    pub fn has_permission_exact(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Check if this role grants permission for an action on a resource type.
    pub fn has_permission(
        &self,
        action: &str,
        resource_type: &str,
        context: &HashMap<String, String>,
    ) -> bool {
        if !self.active {
            return false;
        }
        self.permissions.grants(action, resource_type, context)
    }

    /// Get all permissions granted by this role.
    pub fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    /// Set metadata for this role.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get metadata value for a key.
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Get all metadata.
    pub fn all_metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Set whether this role is active.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Check if this role is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this role.
    pub fn deactivate(mut self) -> Self {
        self.active = false;
        self
    }

    /// Merge permissions from another role into this one.
    pub fn merge_permissions(&mut self, other: &Role) {
        for permission in other.permissions() {
            self.permissions.add(permission.clone());
        }
    }

    // Optional hierarchy access methods (require hierarchy config to be enabled)

    /// Get the parent role ID if this role has a parent in the hierarchy.
    ///
    /// This method provides access to the direct parent relationship, enabling
    /// use cases like API responses, admin interfaces, and JWT token generation.
    ///
    /// Returns `None` if:
    /// - This role has no parent (it's a root role)
    /// - Hierarchy access is disabled in configuration
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let role = Role::new("junior_dev");
    /// if let Some(parent_id) = role.parent_role_id() {
    ///     println!("Parent role: {}", parent_id);
    /// }
    /// ```
    ///
    /// # Note
    /// This method returns `None` by default to maintain backward compatibility.
    /// The actual parent relationship is managed by the `RoleHierarchy` system.
    /// To use this feature, the role must be created through a system that
    /// tracks hierarchy relationships and enables hierarchy access.
    pub fn parent_role_id(&self) -> Option<&str> {
        // By default, roles don't track their parents directly
        // This is managed by RoleHierarchy and AsyncRoleSystem
        // Individual Role instances return None for backward compatibility
        None
    }

    /// Get the child role IDs if this role has children in the hierarchy.
    ///
    /// This method provides access to direct child relationships, useful for
    /// building admin interfaces, API responses, and permission visualization.
    ///
    /// Returns empty vector if:
    /// - This role has no children
    /// - Hierarchy access is disabled in configuration
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let role = Role::new("team_lead");
    /// let children = role.child_role_ids();
    /// for child_id in children {
    ///     println!("Child role: {}", child_id);
    /// }
    /// ```
    ///
    /// # Note
    /// This method returns an empty vector by default to maintain backward compatibility.
    /// The actual child relationships are managed by the `RoleHierarchy` system.
    /// To use this feature, the role must be created through a system that
    /// tracks hierarchy relationships and enables hierarchy access.
    pub fn child_role_ids(&self) -> Vec<&str> {
        // By default, roles don't track their children directly
        // This is managed by RoleHierarchy and AsyncRoleSystem
        // Individual Role instances return empty vector for backward compatibility
        Vec::new()
    }

    /// Check if this role is a root role (has no parent).
    ///
    /// A root role is one that sits at the top of a hierarchy branch
    /// and doesn't inherit from any other role.
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let admin_role = Role::new("admin");
    /// if admin_role.is_root_role() {
    ///     println!("This is a top-level role");
    /// }
    /// ```
    ///
    /// # Note
    /// Returns `true` by default since individual Role instances don't
    /// track hierarchy relationships. Use `RoleHierarchy` or `AsyncRoleSystem`
    /// for actual hierarchy-aware operations.
    pub fn is_root_role(&self) -> bool {
        self.parent_role_id().is_none()
    }

    /// Check if this role is a leaf role (has no children).
    ///
    /// A leaf role is one that doesn't have any roles inheriting from it.
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let intern_role = Role::new("intern");
    /// if intern_role.is_leaf_role() {
    ///     println!("This role has no children");
    /// }
    /// ```
    ///
    /// # Note
    /// Returns `true` by default since individual Role instances don't
    /// track hierarchy relationships. Use `RoleHierarchy` or `AsyncRoleSystem`
    /// for actual hierarchy-aware operations.
    pub fn is_leaf_role(&self) -> bool {
        self.child_role_ids().is_empty()
    }

    /// Get the depth of this role in the hierarchy.
    ///
    /// Root roles have depth 0, their children have depth 1, etc.
    /// This is useful for visualization and API responses.
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let role = Role::new("senior_dev");
    /// let depth = role.hierarchy_depth();
    /// println!("Role depth: {}", depth);
    /// ```
    ///
    /// # Note
    /// Returns `0` by default since individual Role instances don't
    /// track hierarchy relationships. Use `RoleHierarchy` or `AsyncRoleSystem`
    /// for actual hierarchy-aware depth calculation.
    pub fn hierarchy_depth(&self) -> usize {
        0
    }

    /// Get metadata about this role's position in the hierarchy.
    ///
    /// Returns a HashMap containing hierarchy-related metadata such as:
    /// - "parent_count": Number of ancestors
    /// - "child_count": Number of direct children
    /// - "descendant_count": Total number of descendants
    /// - "depth": Depth in hierarchy
    ///
    /// # Example
    /// ```rust
    /// use role_system::Role;
    ///
    /// let role = Role::new("manager");
    /// let hierarchy_meta = role.hierarchy_metadata();
    /// if let Some(depth) = hierarchy_meta.get("depth") {
    ///     println!("Hierarchy depth: {}", depth);
    /// }
    /// ```
    ///
    /// # Note
    /// Returns minimal metadata by default. Use `RoleHierarchy` or `AsyncRoleSystem`
    /// for complete hierarchy metadata.
    pub fn hierarchy_metadata(&self) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("depth".to_string(), "0".to_string());
        metadata.insert("parent_count".to_string(), "0".to_string());
        metadata.insert("child_count".to_string(), "0".to_string());
        metadata.insert("descendant_count".to_string(), "0".to_string());
        metadata.insert("is_root".to_string(), "true".to_string());
        metadata.insert("is_leaf".to_string(), "true".to_string());
        metadata
    }
}

/// A temporary role elevation for a subject.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct RoleElevation {
    /// The role being elevated to.
    role_name: String,
    /// When the elevation was created.
    #[cfg_attr(feature = "persistence", serde(with = "instant_serde"))]
    created_at: Instant,
    /// How long the elevation lasts (None for permanent).
    duration: Option<Duration>,
    /// Reason for the elevation.
    reason: Option<String>,
}

impl RoleElevation {
    /// Create a new role elevation.
    pub fn new(role_name: String, duration: Option<Duration>) -> Self {
        Self {
            role_name,
            created_at: Instant::now(),
            duration,
            reason: None,
        }
    }

    /// Create a role elevation with a reason.
    pub fn with_reason(role_name: String, duration: Option<Duration>, reason: String) -> Self {
        Self {
            role_name,
            created_at: Instant::now(),
            duration,
            reason: Some(reason),
        }
    }

    /// Get the role name being elevated to.
    pub fn role_name(&self) -> &str {
        &self.role_name
    }

    /// Get when the elevation was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get the duration of the elevation.
    pub fn duration(&self) -> Option<Duration> {
        self.duration
    }

    /// Get the reason for the elevation.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Check if the elevation has expired.
    pub fn is_expired(&self, now: Instant) -> bool {
        if let Some(duration) = self.duration {
            now.duration_since(self.created_at) > duration
        } else {
            false // Permanent elevation
        }
    }

    /// Get the time remaining for this elevation.
    pub fn time_remaining(&self, now: Instant) -> Option<Duration> {
        if let Some(duration) = self.duration {
            let elapsed = now.duration_since(self.created_at);
            if elapsed < duration {
                Some(duration - elapsed)
            } else {
                Some(Duration::ZERO)
            }
        } else {
            None // Permanent elevation
        }
    }
}

/// Builder for creating roles with a fluent API.
#[derive(Debug, Default)]
pub struct RoleBuilder {
    name: Option<String>,
    description: Option<String>,
    permissions: Vec<Permission>,
    metadata: HashMap<String, String>,
    active: bool,
}

impl RoleBuilder {
    /// Create a new role builder.
    pub fn new() -> Self {
        Self {
            active: true,
            ..Default::default()
        }
    }

    /// Set the role name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the role description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a permission to the role.
    pub fn permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Add multiple permissions to the role.
    pub fn permissions(mut self, permissions: impl IntoIterator<Item = Permission>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// Add permissions with fluent allow syntax.
    ///
    /// # Example
    /// ```rust
    /// use role_system::role::RoleBuilder;
    /// let role = RoleBuilder::new()
    ///     .name("admin")
    ///     .allow("users", ["create", "read", "update", "delete"])
    ///     .allow("roles", ["read", "assign"])
    ///     .build().unwrap();
    /// ```
    pub fn allow<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let resource = resource.into();
        for action in actions {
            self.permissions
                .push(Permission::new(action.into(), resource.clone()));
        }
        self
    }

    /// Add permissions with deny semantics (creates negative conditions).
    ///
    /// # Example
    /// ```rust
    /// use role_system::role::RoleBuilder;
    /// let role = RoleBuilder::new()
    ///     .name("restricted_admin")
    ///     .allow("users", ["read", "update"])
    ///     .deny("system", ["shutdown"])
    ///     .build().unwrap();
    /// ```
    pub fn deny<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let resource = resource.into();
        for action in actions {
            // Create a permission with a condition that always returns false
            let deny_permission =
                Permission::with_condition(action.into(), resource.clone(), |_| false);
            self.permissions.push(deny_permission);
        }
        self
    }

    /// Add permissions with conditional access.
    ///
    /// # Example
    /// ```rust
    /// use role_system::role::RoleBuilder;
    /// let role = RoleBuilder::new()
    ///     .name("user")
    ///     .allow_when("profile", ["update"], |ctx|
    ///         ctx.get("user_id") == ctx.get("target_id"))
    ///     .build().unwrap();
    /// ```
    pub fn allow_when<I, S, F>(
        mut self,
        resource: impl Into<String>,
        actions: I,
        condition: F,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        F: Fn(&std::collections::HashMap<String, String>) -> bool + Send + Sync + 'static + Clone,
    {
        let resource = resource.into();
        for action in actions {
            let conditional_permission =
                Permission::with_condition(action.into(), resource.clone(), condition.clone());
            self.permissions.push(conditional_permission);
        }
        self
    }

    /// Add metadata to the role.
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set whether the role is active.
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// Build the role.
    pub fn build(self) -> Result<Role> {
        let name = self
            .name
            .ok_or_else(|| Error::InvalidConfiguration("Role name is required".to_string()))?;

        let mut role = Role::new(name);

        if let Some(description) = self.description {
            role = role.with_description(description);
        }

        for permission in self.permissions {
            role = role.add_permission(permission);
        }

        for (key, value) in self.metadata {
            role = role.with_metadata(key, value);
        }

        role.set_active(self.active);

        Ok(role)
    }
}

// Helper module for serializing Instant with serde
#[cfg(feature = "persistence")]
mod instant_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(_instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert Instant to a duration since a reference point
        // Note: This is a simplified approach and may not work across process restarts
        let duration_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        duration_since_epoch.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _nanos = u128::deserialize(deserializer)?;
        // This is a simplified approach - in a real implementation you'd want
        // to store a reference point and calculate relative to that
        Ok(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Permission;

    #[test]
    fn test_role_creation() {
        let role = Role::new("admin")
            .with_description("Administrator role")
            .add_permission(Permission::new("read", "documents"))
            .add_permission(Permission::new("write", "documents"));

        assert_eq!(role.name(), "admin");
        assert_eq!(role.description(), Some("Administrator role"));
        assert_eq!(role.permissions().len(), 2);
        assert!(role.is_active());
    }

    #[test]
    fn test_role_permissions() {
        let role = Role::new("reader").add_permission(Permission::new("read", "documents"));

        let context = HashMap::new();
        assert!(role.has_permission("read", "documents", &context));
        assert!(!role.has_permission("write", "documents", &context));
    }

    #[test]
    fn test_role_builder() {
        let role = RoleBuilder::new()
            .name("test-role")
            .description("A test role")
            .permission(Permission::new("read", "documents"))
            .metadata("department", "IT")
            .active(true)
            .build()
            .unwrap();

        assert_eq!(role.name(), "test-role");
        assert_eq!(role.description(), Some("A test role"));
        assert_eq!(role.metadata("department"), Some("IT"));
        assert!(role.is_active());
    }

    #[test]
    fn test_role_elevation() {
        let elevation = RoleElevation::new("admin".to_string(), Some(Duration::from_secs(3600)));

        assert_eq!(elevation.role_name(), "admin");
        assert_eq!(elevation.duration(), Some(Duration::from_secs(3600)));
        assert!(!elevation.is_expired(Instant::now()));
    }

    #[test]
    fn test_inactive_role_permissions() {
        let mut role = Role::new("inactive").add_permission(Permission::new("read", "documents"));

        role.set_active(false);

        let context = HashMap::new();
        assert!(!role.has_permission("read", "documents", &context));
    }
}
