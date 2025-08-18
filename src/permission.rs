//! Permission definitions and validation with enhanced three-part format support.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// A permission represents an action that can be performed on a resource type.
///
/// Permissions follow the format "action:resource" or "action:resource:instance"
/// Examples:
/// - "read:documents" - Read any document
/// - "read:documents:doc123" - Read specific document doc123
/// - "admin:users" - Admin access to users
/// - "admin:users:user456" - Admin access to specific user
///
/// Special permissions:
/// - "*:*" grants all permissions (super admin)
/// - "action:*" grants all actions on any resource
/// - "*:resource" grants any action on a specific resource
/// - "action:resource:*" grants action on any instance of resource
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Permission {
    /// The action being performed (e.g., "read", "write", "delete").
    action: String,
    /// The resource type this permission applies to (e.g., "documents", "users").
    resource_type: String,
    /// Optional specific instance of the resource (e.g., "doc123", "user456").
    instance: Option<String>,
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

        // Use specialized permission validation that allows wildcards
        Self::validate_permission_field(&action, "action").expect("Invalid action in permission");
        Self::validate_permission_field(&resource_type, "resource_type")
            .expect("Invalid resource_type in permission");

        Self {
            action,
            resource_type,
            instance: None,
            condition: None,
        }
    }

    /// Try to create a new permission, returning an error if validation fails.
    pub fn try_new(action: impl Into<String>, resource_type: impl Into<String>) -> Result<Self> {
        let action = action.into();
        let resource_type = resource_type.into();

        // Use specialized permission validation that allows wildcards
        Self::validate_permission_field(&action, "action")?;
        Self::validate_permission_field(&resource_type, "resource_type")?;

        Ok(Self {
            action,
            resource_type,
            instance: None,
            condition: None,
        })
    }

    /// Create a new permission for an action on a specific resource instance.
    pub fn with_instance(
        action: impl Into<String>,
        resource_type: impl Into<String>,
        instance: impl Into<String>,
    ) -> Self {
        let mut permission = Self::new(action, resource_type);
        let instance = instance.into();

        Self::validate_permission_field(&instance, "instance")
            .expect("Invalid instance in permission");

        permission.instance = Some(instance.to_owned());
        permission
    }

    /// Create a permission with a conditional validator.
    pub fn with_condition<F>(
        action: impl Into<String>,
        resource_type: impl Into<String>,
        condition: F,
    ) -> Self
    where
        F: Fn(&HashMap<String, String>) -> bool + Send + Sync + 'static,
    {
        let mut permission = Self::new(action, resource_type);
        permission.condition = Some(Arc::new(condition));
        permission
    }

    /// Create a permission with both instance and condition.
    pub fn with_instance_and_condition<F>(
        action: impl Into<String>,
        resource_type: impl Into<String>,
        instance: impl Into<String>,
        condition: F,
    ) -> Self
    where
        F: Fn(&HashMap<String, String>) -> bool + Send + Sync + 'static,
    {
        let mut permission = Self::with_instance(action, resource_type, instance);
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

    /// Get the specific instance this permission applies to, if any.
    pub fn instance(&self) -> Option<&str> {
        self.instance.as_deref()
    }

    /// Check if this permission matches the given action and resource type.
    /// For backward compatibility, this doesn't consider instances.
    pub fn matches(&self, action: &str, resource_type: &str) -> bool {
        let action_match = self.action == "*" || self.action == action;
        let resource_match = self.resource_type == "*" || self.resource_type == resource_type;
        action_match && resource_match
    }

    /// Check if this permission matches the given action, resource type, and optional instance.
    pub fn matches_with_instance(
        &self,
        action: &str,
        resource_type: &str,
        instance: Option<&str>,
    ) -> bool {
        let action_match = self.action == "*" || self.action == action;
        let resource_match = self.resource_type == "*" || self.resource_type == resource_type;

        let instance_match = match (&self.instance, instance) {
            (None, _) => true, // Permission without instance matches any instance
            (Some(perm_inst), Some(req_inst)) => perm_inst == "*" || perm_inst == req_inst,
            (Some(_), None) => false, // Permission with instance doesn't match request without instance
        };

        action_match && resource_match && instance_match
    }

    /// Check if this permission implies another permission.
    /// A permission implies another if it grants equal or greater access.
    ///
    /// Examples:
    /// - "read:documents" implies "read:documents:doc123"
    /// - "admin:*" implies "admin:users"
    /// - "*:*" implies any permission
    /// - "read:documents:*" implies "read:documents:doc123"
    pub fn implies(&self, other: &Permission) -> bool {
        // Check action implication
        let action_implies = self.action == "*" || self.action == other.action;

        // Check resource implication
        let resource_implies =
            self.resource_type == "*" || self.resource_type == other.resource_type;

        // Check instance implication
        let instance_implies = match (&self.instance, &other.instance) {
            (None, _) => true,        // No instance restriction implies any instance
            (Some(_), None) => false, // Instance-specific doesn't imply general
            (Some(self_inst), Some(other_inst)) => self_inst == "*" || self_inst == other_inst,
        };

        action_implies && resource_implies && instance_implies
    }

    /// Check if this permission is granted given the context.
    pub fn is_granted(
        &self,
        action: &str,
        resource_type: &str,
        context: &HashMap<String, String>,
    ) -> bool {
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

    /// Parse a permission from a string format like "action:resource_type" or "action:resource_type:instance".
    pub fn parse(permission_str: &str) -> Result<Self> {
        let parts: Vec<&str> = permission_str.split(':').collect();

        match parts.len() {
            2 => {
                let action = parts[0].trim();
                let resource_type = parts[1].trim();

                Self::validate_permission_field(action, "action")?;
                Self::validate_permission_field(resource_type, "resource_type")?;

                Ok(Self::new(action, resource_type))
            }
            3 => {
                let action = parts[0].trim();
                let resource_type = parts[1].trim();
                let instance = parts[2].trim();

                Self::validate_permission_field(action, "action")?;
                Self::validate_permission_field(resource_type, "resource_type")?;
                Self::validate_permission_field(instance, "instance")?;

                Ok(Self::with_instance(action, resource_type, instance))
            }
            _ => Err(Error::InvalidPermission(format!(
                "Permission must be in format 'action:resource_type' or 'action:resource_type:instance', got: '{permission_str}'"
            ))),
        }
    }

    /// Validate permission field allowing wildcards and other permission-specific characters.
    fn validate_permission_field(value: &str, field_name: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "cannot be empty".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        if value.len() > 255 {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "exceeds maximum length of 255 characters".to_string(),
                invalid_value: Some(format!("{}...", &value[..50])),
            });
        }

        // Allow wildcards and alphanumeric characters, hyphens, underscores
        // But reject dangerous control characters and certain symbols
        if value
            .chars()
            .any(|c| c.is_control() || "'\";{}[]\\<>".contains(c))
        {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "contains invalid characters".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        // Still check for path traversal attempts
        if value.contains("..") || value.contains('\0') {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "contains path traversal sequences".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        Ok(())
    }
}

impl std::fmt::Debug for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permission")
            .field("action", &self.action)
            .field("resource_type", &self.resource_type)
            .field("instance", &self.instance)
            .field("has_condition", &self.condition.is_some())
            .finish()
    }
}

impl Clone for Permission {
    fn clone(&self) -> Self {
        Self {
            action: self.action.clone(),
            resource_type: self.resource_type.clone(),
            instance: self.instance.clone(),
            condition: self.condition.clone(), // Now we can clone Arc
        }
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.action == other.action
            && self.resource_type == other.resource_type
            && self.instance == other.instance
        // Note: We don't compare conditions as they're function pointers
    }
}

impl Eq for Permission {}

impl std::hash::Hash for Permission {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.action.hash(state);
        self.resource_type.hash(state);
        self.instance.hash(state);
        // Note: We don't hash conditions as they're function pointers
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.instance {
            Some(instance) => write!(f, "{}:{}:{}", self.action, self.resource_type, instance),
            None => write!(f, "{}:{}", self.action, self.resource_type),
        }
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
    pub fn grants(
        &self,
        action: &str,
        resource_type: &str,
        context: &HashMap<String, String>,
    ) -> bool {
        self.permissions
            .iter()
            .any(|p| p.is_granted(action, resource_type, context))
    }

    /// Check if any permission in the set grants the given action on the resource type and instance.
    pub fn grants_with_instance(
        &self,
        action: &str,
        resource_type: &str,
        instance: Option<&str>,
        context: &HashMap<String, String>,
    ) -> bool {
        self.permissions.iter().any(|p| {
            p.matches_with_instance(action, resource_type, instance)
                && (p.condition.is_none() || p.condition.as_ref().unwrap()(context))
        })
    }

    /// Check if any permission in the set implies the given permission.
    pub fn implies(&self, permission: &Permission) -> bool {
        self.permissions.iter().any(|p| p.implies(permission))
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
        assert_eq!(permission.instance(), None);
    }

    #[test]
    fn test_permission_with_instance() {
        let permission = Permission::with_instance("read", "documents", "doc123");
        assert_eq!(permission.action(), "read");
        assert_eq!(permission.resource_type(), "documents");
        assert_eq!(permission.instance(), Some("doc123"));
    }

    #[test]
    fn test_permission_matching() {
        let permission = Permission::new("read", "documents");
        assert!(permission.matches("read", "documents"));
        assert!(!permission.matches("write", "documents"));
        assert!(!permission.matches("read", "users"));
    }

    #[test]
    fn test_permission_matching_with_instance() {
        let permission = Permission::with_instance("read", "documents", "doc123");

        // Should match exact instance
        assert!(permission.matches_with_instance("read", "documents", Some("doc123")));

        // Should not match different instance
        assert!(!permission.matches_with_instance("read", "documents", Some("doc456")));

        // Should not match when no instance provided
        assert!(!permission.matches_with_instance("read", "documents", None));

        // General permission should match any instance
        let general_permission = Permission::new("read", "documents");
        assert!(general_permission.matches_with_instance("read", "documents", Some("doc123")));
        assert!(general_permission.matches_with_instance("read", "documents", None));
    }

    #[test]
    fn test_permission_implication() {
        let general = Permission::new("read", "documents");
        let specific = Permission::with_instance("read", "documents", "doc123");

        // General should imply specific
        assert!(general.implies(&specific));

        // Specific should not imply general
        assert!(!specific.implies(&general));

        // Same permission should imply itself
        assert!(general.implies(&general));
        assert!(specific.implies(&specific));

        // Wildcard tests
        let wildcard_action = Permission::new("*", "documents");
        let wildcard_resource = Permission::new("read", "*");
        let super_admin = Permission::super_admin();

        assert!(wildcard_action.implies(&general));
        assert!(wildcard_resource.implies(&general));
        assert!(super_admin.implies(&general));
        assert!(super_admin.implies(&specific));
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
        // Two-part format
        let permission = Permission::parse("read:documents").unwrap();
        assert_eq!(permission.action(), "read");
        assert_eq!(permission.resource_type(), "documents");
        assert_eq!(permission.instance(), None);

        // Three-part format
        let permission = Permission::parse("read:documents:doc123").unwrap();
        assert_eq!(permission.action(), "read");
        assert_eq!(permission.resource_type(), "documents");
        assert_eq!(permission.instance(), Some("doc123"));

        // Error cases
        assert!(Permission::parse("invalid").is_err());
        assert!(Permission::parse("read:").is_err());
        assert!(Permission::parse(":documents").is_err());
        assert!(Permission::parse("read:documents:").is_err());
        assert!(Permission::parse("read:documents:instance:extra").is_err());
    }

    #[test]
    fn test_permission_display() {
        let permission = Permission::new("read", "documents");
        assert_eq!(permission.to_string(), "read:documents");

        let permission_with_instance = Permission::with_instance("read", "documents", "doc123");
        assert_eq!(
            permission_with_instance.to_string(),
            "read:documents:doc123"
        );
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

    #[test]
    fn test_permission_set_with_instances() {
        let mut set = PermissionSet::new();
        let general_perm = Permission::new("read", "documents");
        let specific_perm = Permission::with_instance("write", "documents", "doc123");

        set.add(general_perm);
        set.add(specific_perm);

        let context = HashMap::new();

        // General permission should work for any instance
        assert!(set.grants_with_instance("read", "documents", Some("doc123"), &context));
        assert!(set.grants_with_instance("read", "documents", Some("doc456"), &context));
        assert!(set.grants_with_instance("read", "documents", None, &context));

        // Specific permission should only work for that instance
        assert!(set.grants_with_instance("write", "documents", Some("doc123"), &context));
        assert!(!set.grants_with_instance("write", "documents", Some("doc456"), &context));
        assert!(!set.grants_with_instance("write", "documents", None, &context));
    }

    #[test]
    fn test_permission_set_implication() {
        let mut set = PermissionSet::new();
        let general_perm = Permission::new("read", "documents");
        let admin_perm = Permission::new("admin", "*");

        set.add(general_perm);
        set.add(admin_perm);

        let specific_perm = Permission::with_instance("read", "documents", "doc123");
        let admin_users_perm = Permission::new("admin", "users");

        assert!(set.implies(&specific_perm));
        assert!(set.implies(&admin_users_perm));
    }
}
