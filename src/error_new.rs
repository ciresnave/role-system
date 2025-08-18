//! Error types for the role system.

use std::collections::HashMap;
use thiserror::Error;

/// Recovery suggestion for handling errors.
#[derive(Debug, Clone)]
pub struct RecoverySuggestion {
    pub message: String,
    pub suggested_actions: Vec<String>,
    pub documentation_link: Option<String>,
}

impl RecoverySuggestion {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            suggested_actions: Vec::new(),
            documentation_link: None,
        }
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.suggested_actions.push(action.into());
        self
    }

    pub fn with_documentation(mut self, link: impl Into<String>) -> Self {
        self.documentation_link = Some(link.into());
        self
    }
}

/// Details for permission denied errors.
#[derive(Debug, Clone)]
pub struct PermissionDeniedDetails {
    pub action: String,
    pub resource: String,
    pub subject: String,
    pub required_permissions: Vec<String>,
    pub suggested_roles: Vec<String>,
    pub recovery: Option<RecoverySuggestion>,
}

impl std::fmt::Display for PermissionDeniedDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Permission denied: {} on {} for {}",
            self.action, self.resource, self.subject
        )
    }
}

/// The main error type for role system operations.
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// Role with the given name already exists.
    #[error("Role '{0}' already exists")]
    RoleAlreadyExists(String),

    /// Role with the given name was not found.
    #[error("Role '{0}' not found")]
    RoleNotFound(String),

    /// Subject with the given ID was not found.
    #[error("Subject '{0}' not found")]
    SubjectNotFound(String),

    /// Permission was denied for the requested operation.
    #[error("{0}")]
    PermissionDenied(Box<PermissionDeniedDetails>),

    /// Circular dependency detected in role hierarchy.
    #[error("Circular dependency detected in role hierarchy involving '{0}'")]
    CircularDependency(String),

    /// Invalid permission format.
    #[error("Invalid permission format: {0}")]
    InvalidPermission(String),

    /// Invalid resource format.
    #[error("Invalid resource format: {0}")]
    InvalidResource(String),

    /// Role elevation has expired.
    #[error("Role elevation for subject '{0}' has expired")]
    ElevationExpired(String),

    /// Maximum role hierarchy depth exceeded.
    #[error("Maximum role hierarchy depth exceeded (max: {0})")]
    MaxDepthExceeded(usize),

    /// Serialization error.
    #[cfg(feature = "persistence")]
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Storage operation failed.
    #[error("Storage operation failed: {0}")]
    Storage(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Enhanced role operation error with context.
    #[error("Role operation failed: {operation} on role '{role}' - {reason}")]
    RoleOperationFailed {
        operation: String,
        role: String,
        reason: String,
    },

    /// Permission operation error with detailed context.
    #[error(
        "Permission operation failed: {operation} for subject '{subject}' on resource '{resource}' - {reason}"
    )]
    PermissionOperationFailed {
        operation: String,
        subject: String,
        resource: String,
        reason: String,
        context: Box<HashMap<String, String>>,
    },

    /// Validation error with field-specific information.
    #[error("Validation failed for field '{field}': {reason}")]
    ValidationError {
        field: String,
        reason: String,
        invalid_value: Option<String>,
    },

    /// Rate limiting error.
    #[error("Rate limit exceeded for subject '{subject}': {limit} operations per {window}")]
    RateLimitExceeded {
        subject: String,
        limit: u64,
        window: String,
    },

    /// Concurrency conflict error.
    #[error("Concurrency conflict: {operation} failed due to concurrent modification")]
    ConcurrencyConflict {
        operation: String,
        resource_id: String,
    },

    /// Authentication error.
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed {
        reason: String,
        subject_id: Option<String>,
    },

    /// Authorization error with detailed context.
    #[error(
        "Authorization failed: subject '{subject}' lacks permission '{permission}' for resource '{resource}'"
    )]
    AuthorizationFailed {
        subject: String,
        permission: String,
        resource: String,
        required_roles: Vec<String>,
    },
}

/// Result type alias for role system operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Helper trait for adding context to errors.
pub trait ErrorContext<T> {
    /// Add context to an error.
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;

    /// Add role operation context.
    fn with_role_context(self, operation: &str, role: &str, reason: &str) -> Result<T>;

    /// Add permission operation context.
    fn with_permission_context(
        self,
        operation: &str,
        subject: &str,
        resource: &str,
        reason: &str,
        context: HashMap<String, String>,
    ) -> Result<T>;
}

impl<T> ErrorContext<T> for Result<T> {
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| match e {
            Error::Storage(msg) => Error::Storage(format!("{}: {}", f(), msg)),
            other => other,
        })
    }

    fn with_role_context(self, operation: &str, role: &str, reason: &str) -> Result<T> {
        self.map_err(|_| Error::RoleOperationFailed {
            operation: operation.to_string(),
            role: role.to_string(),
            reason: reason.to_string(),
        })
    }

    fn with_permission_context(
        self,
        operation: &str,
        subject: &str,
        resource: &str,
        reason: &str,
        context: HashMap<String, String>,
    ) -> Result<T> {
        self.map_err(|_| Error::PermissionOperationFailed {
            operation: operation.to_string(),
            subject: subject.to_string(),
            resource: resource.to_string(),
            reason: reason.to_string(),
            context: Box::new(context),
        })
    }
}

/// Validation helper functions.
pub mod validation {
    use super::*;

    /// Validate an identifier (role name, subject ID, etc.).
    pub fn validate_identifier(value: &str, field_name: &str) -> Result<()> {
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

        // Check for dangerous characters
        if value.contains(|c: char| c.is_control() || "'\";--/*<>{}[]\\".contains(c)) {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "contains invalid characters".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        // Check for path traversal attempts
        if value.contains("..") || value.contains('\0') {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "contains path traversal sequences".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        Ok(())
    }

    /// Validate a resource path.
    pub fn validate_resource_path(path: &str) -> Result<()> {
        if path.is_empty() {
            return Ok(()); // Empty path is allowed
        }

        if !path.starts_with('/') {
            return Err(Error::ValidationError {
                field: "resource_path".to_string(),
                reason: "must start with '/'".to_string(),
                invalid_value: Some(path.to_string()),
            });
        }

        // Check for path traversal
        if path.contains("../") || path.contains("..\\") {
            return Err(Error::ValidationError {
                field: "resource_path".to_string(),
                reason: "contains path traversal sequences".to_string(),
                invalid_value: Some(path.to_string()),
            });
        }

        Ok(())
    }
}

