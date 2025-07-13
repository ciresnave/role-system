//! Permission definitions and validation.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// A permission represents an action that can be performed on a resource type.
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Permission {
    /// The action being performed (e.g., "read", "write", "delete").
    action: String,
    /// The resource type this permission applies to (e.g., "documents", "users").
    resource_type: String,
    /// Optional conditional validator function.
    #[cfg_attr(feature = "persistence", serde(skip))]
    condition: Option<PermissionCondition>,
}

/// A condition that must be met for a permission to be granted.
pub type PermissionCondition = Arc<dyn Fn(&HashMap<String, String>) -> bool + Send + Sync>;

impl Permission {
    /// Create a new permission for an action on a resource type.
    pub fn new(action: impl Into<String>, resource_type: impl Into<String>) -> Self {
        let action = action.into();
        let resource_type = resource_type.into();
        
        if action.trim().is_empty() || resource_type.trim().is_empty() {
            panic!("Action and resource type cannot be empty");
        }
        
        // Check for null characters which are not allowed in permissions
        if action.contains('\0') || resource_type.contains('\0') {
            panic!("Action and resource type cannot contain null characters");
        }
        
        Self {
            action,
            resource_type,
            condition: None,
        }
    }

    /// Create a permission with a conditional validator.
    pub fn with_condition<F>(action: impl Into<String>, resource_type: impl Into<String>, condition: F) -> Self
    where
        F: Fn(&HashMap<String, String>) -> bool + Send + Sync + 'static,
    {
        let mut permission = Self::new(action, resource_type);
        permission.condition = Some(Arc::new(condition));
        permission
    }

    /// Create a wildcard permission that grants access to all actions on a resource type.
    pub fn wildcard(resource_type: impl Into<String>) -> Self {
        Self::new("*", resource_type)
    }

    /// Create a super-admin permission that grants access to everything.
    pub fn super_admin() -> Self {
        Self::new("*", "*")
    }

    /// Get the action this permission grants.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Get the resource type this permission applies to.
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// Check if this permission matches the given action and resource type.
    pub fn matches(&self, action: &str, resource_type: &str) -> bool {
        let action_match = self.action == "*" || self.action == action;
        let resource_match = self.resource_type == "*" || self.resource_type == resource_type;
        action_match && resource_match
    }

    /// Check if this permission is granted given the context.
    pub fn is_granted(&self, action: &str, resource_type: &str, context: &HashMap<String, String>) -> bool {
        if !self.matches(action, resource_type) {
            return false;
        }

        // Check conditional validator if present
        if let Some(condition) = &self.condition {
            condition(context)
        } else {
            true
        }
    }

    /// Parse a permission from a string format like "action:resource_type".
    pub fn parse(permission_str: &str) -> Result<Self> {
        let parts: Vec<&str> = permission_str.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidPermission(
                format!("Permission must be in format 'action:resource_type', got: '{permission_str}'")
            ));
        }

        let action = parts[0].trim();
        let resource_type = parts[1].trim();

        if action.is_empty() || resource_type.is_empty() {
            return Err(Error::InvalidPermission(
                format!("Action and resource type cannot be empty: '{permission_str}'")
            ));
        }

        // Check for null characters which are not allowed in permissions
        if action.contains('\0') || resource_type.contains('\0') {
            return Err(Error::InvalidPermission(
                format!("Action and resource type cannot contain null characters: '{permission_str}'")
            ));
        }

        Ok(Self::new(action, resource_type))
    }
}

impl std::fmt::Debug for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permission")
            .field("action", &self.action)
            .field("resource_type", &self.resource_type)
            .field("has_condition", &self.condition.is_some())
            .finish()
    }
}

impl Clone for Permission {
    fn clone(&self) -> Self {
        Self {
            action: self.action.clone(),
            resource_type: self.resource_type.clone(),
            condition: self.condition.clone(), // Now we can clone Arc
        }
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.action == other.action && self.resource_type == other.resource_type
        // Note: We don't compare conditions as they're function pointers
    }
}

impl Eq for Permission {}

impl std::hash::Hash for Permission {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.action.hash(state);
        self.resource_type.hash(state);
        // Note: We don't hash conditions as they're function pointers
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.action, self.resource_type)
    }
}

impl std::str::FromStr for Permission {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// A collection of permissions with utility methods.
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionSet {
    permissions: Vec<Permission>,
}

impl std::fmt::Debug for PermissionSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermissionSet")
            .field("permissions", &self.permissions)
            .field("count", &self.permissions.len())
            .finish()
    }
}

impl Clone for PermissionSet {
    fn clone(&self) -> Self {
        Self {
            permissions: self.permissions.clone(),
        }
    }
}

impl Default for PermissionSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionSet {
    /// Create a new empty permission set.
    pub fn new() -> Self {
        Self {
            permissions: Vec::new(),
        }
    }

    /// Add a permission to the set.
    pub fn add(&mut self, permission: Permission) {
        self.permissions.push(permission);
    }

    /// Remove a permission from the set.
    pub fn remove(&mut self, permission: &Permission) {
        self.permissions.retain(|p| p != permission);
    }

    /// Check if the set contains a specific permission.
    pub fn contains(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Check if any permission in the set grants the given action on the resource type.
    pub fn grants(&self, action: &str, resource_type: &str, context: &HashMap<String, String>) -> bool {
        self.permissions
            .iter()
            .any(|p| p.is_granted(action, resource_type, context))
    }

    /// Get all permissions in the set.
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// Get the number of permissions in the set.
    pub fn len(&self) -> usize {
        self.permissions.len()
    }

    /// Check if the permission set is empty.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    /// Merge another permission set into this one.
    pub fn merge(&mut self, other: PermissionSet) {
        for permission in other.permissions {
            if !self.contains(&permission) {
                self.add(permission);
            }
        }
    }
}

impl From<Vec<Permission>> for PermissionSet {
    fn from(permissions: Vec<Permission>) -> Self {
        Self { permissions }
    }
}

impl From<Permission> for PermissionSet {
    fn from(permission: Permission) -> Self {
        Self {
            permissions: vec![permission],
        }
    }
}

impl IntoIterator for PermissionSet {
    type Item = Permission;
    type IntoIter = std::vec::IntoIter<Permission>;

    fn into_iter(self) -> Self::IntoIter {
        self.permissions.into_iter()
    }
}

impl<'a> IntoIterator for &'a PermissionSet {
    type Item = &'a Permission;
    type IntoIter = std::slice::Iter<'a, Permission>;

    fn into_iter(self) -> Self::IntoIter {
        self.permissions.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_creation() {
        let permission = Permission::new("read", "documents");
        assert_eq!(permission.action(), "read");
        assert_eq!(permission.resource_type(), "documents");
    }

    #[test]
    fn test_permission_matching() {
        let permission = Permission::new("read", "documents");
        assert!(permission.matches("read", "documents"));
        assert!(!permission.matches("write", "documents"));
        assert!(!permission.matches("read", "users"));
    }

    #[test]
    fn test_wildcard_permission() {
        let permission = Permission::wildcard("documents");
        assert!(permission.matches("read", "documents"));
        assert!(permission.matches("write", "documents"));
        assert!(!permission.matches("read", "users"));
    }

    #[test]
    fn test_super_admin_permission() {
        let permission = Permission::super_admin();
        assert!(permission.matches("read", "documents"));
        assert!(permission.matches("write", "users"));
        assert!(permission.matches("delete", "anything"));
    }

    #[test]
    fn test_permission_parsing() {
        let permission = Permission::parse("read:documents").unwrap();
        assert_eq!(permission.action(), "read");
        assert_eq!(permission.resource_type(), "documents");

        assert!(Permission::parse("invalid").is_err());
        assert!(Permission::parse("read:").is_err());
        assert!(Permission::parse(":documents").is_err());
    }

    #[test]
    fn test_permission_set() {
        let mut set = PermissionSet::new();
        let perm1 = Permission::new("read", "documents");
        let perm2 = Permission::new("write", "documents");

        set.add(perm1.clone());
        set.add(perm2.clone());

        assert_eq!(set.len(), 2);
        assert!(set.contains(&perm1));
        assert!(set.contains(&perm2));

        let context = HashMap::new();
        assert!(set.grants("read", "documents", &context));
        assert!(set.grants("write", "documents", &context));
        assert!(!set.grants("delete", "documents", &context));
    }
}
