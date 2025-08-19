//! Resource definitions for access control.

use crate::error::Error;
use std::collections::HashMap;

/// A resource represents something that can be accessed or acted upon.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Resource {
    /// Unique identifier for the resource.
    id: String,
    /// Type of resource (e.g., "document", "user", "project").
    resource_type: String,
    /// Optional name for the resource.
    name: Option<String>,
    /// Additional attributes for the resource.
    attributes: HashMap<String, String>,
    /// Hierarchical path for the resource (e.g., "/projects/web-app/documents/readme.md").
    path: Option<String>,
}

impl Resource {
    /// Create a new resource with validation.
    ///
    /// # Errors
    ///
    /// Returns a `ValidationError` if the ID or resource type contains path traversal
    /// sequences or null characters.
    pub fn new_checked(
        id: impl Into<String>,
        resource_type: impl Into<String>,
    ) -> Result<Self, Error> {
        let id = id.into();
        let resource_type = resource_type.into();

        // Validate resource ID for path traversal attempts
        if id.contains("..") || id.contains('\0') {
            return Err(Error::ValidationError {
                field: "id".to_string(),
                reason: "Resource ID cannot contain path traversal sequences or null characters"
                    .to_string(),
                invalid_value: Some(id),
            });
        }

        // Validate resource type for path traversal attempts
        if resource_type.contains("..") || resource_type.contains('\0') {
            return Err(Error::ValidationError {
                field: "resource_type".to_string(),
                reason: "Resource type cannot contain path traversal sequences or null characters"
                    .to_string(),
                invalid_value: Some(resource_type),
            });
        }

        Ok(Self {
            id,
            resource_type,
            name: None,
            attributes: HashMap::new(),
            path: None,
        })
    }

    /// Create a new resource.
    ///
    /// # Panics
    ///
    /// This method panics if the ID or resource type contains path traversal
    /// sequences or null characters. For non-panicking validation, use `new_checked`.
    pub fn new(id: impl Into<String>, resource_type: impl Into<String>) -> Self {
        match Self::new_checked(id, resource_type) {
            Ok(resource) => resource,
            Err(e) => panic!("Resource validation failed: {}", e),
        }
    }

    /// Get the resource's unique identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the resource type.
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// Set the resource name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the resource name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set the resource name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Set the resource path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Get the resource path.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Set the resource path.
    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = Some(path.into());
    }

    /// Add an attribute to the resource.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Set an attribute on the resource.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Get an attribute value.
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Get all attributes.
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// Remove an attribute.
    pub fn remove_attribute(&mut self, key: &str) -> Option<String> {
        self.attributes.remove(key)
    }

    /// Check if the resource has a specific attribute.
    pub fn has_attribute(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Get the effective name for display purposes.
    pub fn effective_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }

    /// Check if this resource matches a pattern.
    /// Patterns can include wildcards (*) and hierarchical matching.
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        // Exact match
        if pattern == self.id || pattern == self.resource_type {
            return true;
        }

        // Type wildcard (e.g., "documents/*")
        if let Some(type_prefix) = pattern.strip_suffix("/*")
            && self.resource_type == type_prefix
        {
            return true;
        }

        // Path matching
        if let Some(resource_path) = &self.path
            && self.matches_path_pattern(resource_path, pattern)
        {
            return true;
        }

        false
    }

    /// Check if the resource is within a specific parent path.
    pub fn is_under_path(&self, parent_path: &str) -> bool {
        if let Some(resource_path) = &self.path {
            resource_path.starts_with(parent_path)
        } else {
            false
        }
    }

    /// Get the parent path of this resource.
    pub fn parent_path(&self) -> Option<String> {
        self.path
            .as_ref()
            .and_then(|p| p.rfind('/').map(|i| p[..i].to_string()))
    }

    fn matches_path_pattern(&self, path: &str, pattern: &str) -> bool {
        // Simple glob-style matching
        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                return path.starts_with(prefix) && path.ends_with(suffix);
            }
        }

        path == pattern
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.name, &self.path) {
            (Some(name), Some(path)) => write!(
                f,
                "{} ({}:{} at {})",
                name, self.resource_type, self.id, path
            ),
            (Some(name), None) => write!(f, "{} ({}:{})", name, self.resource_type, self.id),
            (None, Some(path)) => write!(f, "{}:{} at {}", self.resource_type, self.id, path),
            (None, None) => write!(f, "{}:{}", self.resource_type, self.id),
        }
    }
}

/// Builder for creating resources with a fluent API.
#[derive(Debug, Default)]
pub struct ResourceBuilder {
    id: Option<String>,
    resource_type: Option<String>,
    name: Option<String>,
    path: Option<String>,
    attributes: HashMap<String, String>,
}

impl ResourceBuilder {
    /// Create a new resource builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the resource ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the resource type.
    pub fn resource_type(mut self, resource_type: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self
    }

    /// Set the resource name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the resource path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Add an attribute.
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Build the resource.
    pub fn build(self) -> Result<Resource, String> {
        let id = self.id.ok_or("Resource ID is required")?;
        let resource_type = self.resource_type.ok_or("Resource type is required")?;

        let mut resource = Resource::new(id, resource_type);

        if let Some(name) = self.name {
            resource = resource.with_name(name);
        }

        if let Some(path) = self.path {
            resource = resource.with_path(path);
        }

        for (key, value) in self.attributes {
            resource = resource.with_attribute(key, value);
        }

        Ok(resource)
    }
}

/// Common resource types for convenience.
pub mod types {
    use super::Resource;

    /// Create a document resource.
    pub fn document(id: impl Into<String>) -> Resource {
        Resource::new(id, "document")
    }

    /// Create a user resource.
    pub fn user(id: impl Into<String>) -> Resource {
        Resource::new(id, "user")
    }

    /// Create a project resource.
    pub fn project(id: impl Into<String>) -> Resource {
        Resource::new(id, "project")
    }

    /// Create a file resource.
    pub fn file(id: impl Into<String>) -> Resource {
        Resource::new(id, "file")
    }

    /// Create a database resource.
    pub fn database(id: impl Into<String>) -> Resource {
        Resource::new(id, "database")
    }

    /// Create an API endpoint resource.
    pub fn api_endpoint(id: impl Into<String>) -> Resource {
        Resource::new(id, "api_endpoint")
    }
}

#[cfg(test)]
mod tests {
    use super::types::*;
    use super::*;

    #[test]
    fn test_resource_creation() {
        let resource = Resource::new("doc123", "document")
            .with_name("My Document")
            .with_path("/projects/web-app/docs/readme.md")
            .with_attribute("owner", "john@example.com")
            .with_attribute("created", "2024-01-01");

        assert_eq!(resource.id(), "doc123");
        assert_eq!(resource.resource_type(), "document");
        assert_eq!(resource.name(), Some("My Document"));
        assert_eq!(resource.path(), Some("/projects/web-app/docs/readme.md"));
        assert_eq!(resource.attribute("owner"), Some("john@example.com"));
        assert_eq!(resource.effective_name(), "My Document");
    }

    #[test]
    fn test_resource_pattern_matching() {
        let resource =
            Resource::new("doc1", "document").with_path("/projects/web-app/docs/readme.md");

        assert!(resource.matches_pattern("*"));
        assert!(resource.matches_pattern("doc1"));
        assert!(resource.matches_pattern("document"));
        assert!(resource.matches_pattern("document/*"));
        assert!(!resource.matches_pattern("user"));
        assert!(!resource.matches_pattern("users/*"));
    }

    #[test]
    fn test_resource_path_operations() {
        let resource =
            Resource::new("doc1", "document").with_path("/projects/web-app/docs/readme.md");

        assert!(resource.is_under_path("/projects"));
        assert!(resource.is_under_path("/projects/web-app"));
        assert!(!resource.is_under_path("/other"));

        assert_eq!(
            resource.parent_path(),
            Some("/projects/web-app/docs".to_string())
        );
    }

    #[test]
    fn test_resource_builder() {
        let resource = ResourceBuilder::new()
            .id("test-id")
            .resource_type("test-type")
            .name("Test Resource")
            .path("/test/path")
            .attribute("key", "value")
            .build()
            .unwrap();

        assert_eq!(resource.id(), "test-id");
        assert_eq!(resource.resource_type(), "test-type");
        assert_eq!(resource.name(), Some("Test Resource"));
        assert_eq!(resource.path(), Some("/test/path"));
        assert_eq!(resource.attribute("key"), Some("value"));
    }

    #[test]
    fn test_common_resource_types() {
        let doc = document("doc1");
        let user_res = user("user1");
        let proj = project("proj1");

        assert_eq!(doc.resource_type(), "document");
        assert_eq!(user_res.resource_type(), "user");
        assert_eq!(proj.resource_type(), "project");
    }

    #[test]
    fn test_resource_effective_name() {
        let named_resource = Resource::new("r1", "type").with_name("Named Resource");
        let unnamed_resource = Resource::new("r2", "type");

        assert_eq!(named_resource.effective_name(), "Named Resource");
        assert_eq!(unnamed_resource.effective_name(), "r2");
    }
}
