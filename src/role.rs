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
        let name = self.name.ok_or_else(|| {
            Error::InvalidConfiguration("Role name is required".to_string())
        })?;

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
        let role = Role::new("reader")
            .add_permission(Permission::new("read", "documents"));

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
        let mut role = Role::new("inactive")
            .add_permission(Permission::new("read", "documents"));
        
        role.set_active(false);
        
        let context = HashMap::new();
        assert!(!role.has_permission("read", "documents", &context));
    }
}
