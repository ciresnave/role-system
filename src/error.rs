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

impl Error {
    /// Validates an identifier (role name, subject ID, etc.) for security.
    pub fn validate_identifier(value: &str, field_name: &str) -> Result<()> {
        if value.is_empty() {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "cannot be empty".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        if value.len() > 256 {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "too long (maximum 256 characters)".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        // Check for dangerous characters that could indicate injection attacks
        let dangerous_chars = [';', '\'', '"', '\\', '\0', '\n', '\r'];
        let dangerous_sequences = ["--", "/*", "*/", "<", ">", "{", "}", "[", "]"];

        for &ch in &dangerous_chars {
            if value.contains(ch) {
                return Err(Error::ValidationError {
                    field: field_name.to_string(),
                    reason: "contains invalid characters".to_string(),
                    invalid_value: Some(value.to_string()),
                });
            }
        }

        for &seq in &dangerous_sequences {
            if value.contains(seq) {
                return Err(Error::ValidationError {
                    field: field_name.to_string(),
                    reason: "contains invalid characters".to_string(),
                    invalid_value: Some(value.to_string()),
                });
            }
        }

        // Check for potential path traversal
        if value.contains("..") {
            return Err(Error::ValidationError {
                field: field_name.to_string(),
                reason: "potential path traversal detected".to_string(),
                invalid_value: Some(value.to_string()),
            });
        }

        Ok(())
    }

    /// Validates a resource path for security.
    pub fn validate_resource_path(path: &str) -> Result<()> {
        // Empty path is allowed (means "any resource")
        if path.is_empty() {
            return Ok(());
        }

        // Must start with /
        if !path.starts_with('/') {
            return Err(Error::ValidationError {
                field: "resource_path".to_string(),
                reason: "must start with '/' or be empty".to_string(),
                invalid_value: Some(path.to_string()),
            });
        }

        // Check for path traversal attempts
        if path.contains("../") || path.contains("..\\") {
            return Err(Error::ValidationError {
                field: "resource_path".to_string(),
                reason: "path traversal detected".to_string(),
                invalid_value: Some(path.to_string()),
            });
        }

        // Check for null bytes
        if path.contains('\0') {
            return Err(Error::ValidationError {
                field: "resource_path".to_string(),
                reason: "null byte detected".to_string(),
                invalid_value: Some(path.to_string()),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_suggestion_creation() {
        let suggestion = RecoverySuggestion::new("Permission denied")
            .with_action("Assign the 'admin' role to the user")
            .with_action("Check if the resource exists")
            .with_documentation("https://docs.example.com/permissions");

        assert_eq!(suggestion.message, "Permission denied");
        assert_eq!(suggestion.suggested_actions.len(), 2);
        assert_eq!(
            suggestion.suggested_actions[0],
            "Assign the 'admin' role to the user"
        );
        assert_eq!(
            suggestion.suggested_actions[1],
            "Check if the resource exists"
        );
        assert_eq!(
            suggestion.documentation_link,
            Some("https://docs.example.com/permissions".to_string())
        );
    }

    #[test]
    fn test_permission_denied_details_display() {
        let details = PermissionDeniedDetails {
            action: "delete".to_string(),
            resource: "document.txt".to_string(),
            subject: "alice".to_string(),
            required_permissions: vec!["delete:documents".to_string()],
            suggested_roles: vec!["admin".to_string(), "editor".to_string()],
            recovery: Some(RecoverySuggestion::new("Assign appropriate role")),
        };

        let display = format!("{}", details);
        assert!(display.contains("Permission denied"));
        assert!(display.contains("delete"));
        assert!(display.contains("document.txt"));
        assert!(display.contains("alice"));
    }

    #[test]
    fn test_permission_denied_error_creation() {
        let details = PermissionDeniedDetails {
            action: "read".to_string(),
            resource: "secret.txt".to_string(),
            subject: "bob".to_string(),
            required_permissions: vec!["read:secrets".to_string()],
            suggested_roles: vec!["security_admin".to_string()],
            recovery: Some(
                RecoverySuggestion::new("User needs security clearance")
                    .with_action("Contact security administrator")
                    .with_documentation("https://docs.example.com/security"),
            ),
        };

        let error = Error::PermissionDenied(Box::new(details));

        match error {
            Error::PermissionDenied(d) => {
                assert_eq!(d.action, "read");
                assert_eq!(d.resource, "secret.txt");
                assert_eq!(d.subject, "bob");
                assert!(d.recovery.is_some());
                assert_eq!(
                    d.recovery.unwrap().suggested_actions[0],
                    "Contact security administrator"
                );
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_validation_error_formatting() {
        let error = Error::ValidationError {
            field: "username".to_string(),
            reason: "contains invalid characters".to_string(),
            invalid_value: Some("user@name!".to_string()),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Validation failed"));
        assert!(error_string.contains("username"));
        assert!(error_string.contains("invalid characters"));
    }

    #[test]
    fn test_security_validation_basic() {
        // Valid inputs should pass
        assert!(Error::validate_identifier("valid_user", "username").is_ok());
        assert!(Error::validate_identifier("role123", "role").is_ok());
        assert!(Error::validate_identifier("resource_name", "resource").is_ok());
    }

    #[test]
    fn test_security_validation_empty_input() {
        let result = Error::validate_identifier("", "field");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ValidationError { field, reason, .. } => {
                assert_eq!(field, "field");
                assert!(reason.contains("cannot be empty"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_security_validation_invalid_characters() {
        let test_cases = vec![
            "user;name",    // semicolon
            "user'name",    // single quote
            "user\"name",   // double quote
            "user--name",   // double dash
            "user/*name",   // comment sequence
            "user<script>", // HTML/script tag
            "user{name}",   // braces
            "user[name]",   // brackets
            "user\\name",   // backslash
        ];

        for test_case in test_cases {
            let result = Error::validate_identifier(test_case, "field");
            assert!(result.is_err(), "Should reject: {}", test_case);
            match result.unwrap_err() {
                Error::ValidationError { reason, .. } => {
                    assert!(reason.contains("invalid characters"));
                }
                _ => panic!("Expected ValidationError for: {}", test_case),
            }
        }
    }

    #[test]
    fn test_resource_path_validation_valid() {
        assert!(Error::validate_resource_path("").is_ok()); // Empty is allowed
        assert!(Error::validate_resource_path("/documents").is_ok());
        assert!(Error::validate_resource_path("/documents/file.txt").is_ok());
        assert!(Error::validate_resource_path("/api/v1/users").is_ok());
    }

    #[test]
    fn test_comprehensive_error_scenarios() {
        // Test all error variants can be created and formatted
        let errors = vec![
            Error::RoleNotFound("admin".to_string()),
            Error::RoleAlreadyExists("user".to_string()),
            Error::SubjectNotFound("alice".to_string()),
            Error::CircularDependency("role cycle detected".to_string()),
            Error::ValidationError {
                field: "username".to_string(),
                reason: "invalid format".to_string(),
                invalid_value: Some("test@user".to_string()),
            },
            Error::Storage("connection failed".to_string()),
            Error::InvalidConfiguration("missing config".to_string()),
            Error::RateLimitExceeded {
                subject: "user123".to_string(),
                limit: 100,
                window: "1 minute".to_string(),
            },
            Error::ConcurrencyConflict {
                operation: "role_assignment".to_string(),
                resource_id: "role_123".to_string(),
            },
        ];

        for error in errors {
            // Ensure all errors can be formatted
            let error_string = format!("{}", error);
            assert!(!error_string.is_empty());

            // Ensure all errors can be debugged
            let debug_string = format!("{:?}", error);
            assert!(!debug_string.is_empty());
        }
    }

    #[test]
    fn test_enhanced_error_context_integration() {
        // Test creating a complex permission denied error with full context
        let recovery = RecoverySuggestion::new("User needs additional permissions")
            .with_action("Assign the 'documents_admin' role")
            .with_action("Verify the document exists")
            .with_action("Check if the user's access has expired")
            .with_documentation("https://docs.company.com/rbac/troubleshooting");

        let details = PermissionDeniedDetails {
            action: "delete".to_string(),
            resource: "/documents/confidential/report.pdf".to_string(),
            subject: "employee_123".to_string(),
            required_permissions: vec![
                "delete:documents".to_string(),
                "access:confidential".to_string(),
            ],
            suggested_roles: vec![
                "documents_admin".to_string(),
                "confidential_access".to_string(),
            ],
            recovery: Some(recovery),
        };

        let error = Error::PermissionDenied(Box::new(details));

        // Verify all components are present
        match &error {
            Error::PermissionDenied(d) => {
                assert_eq!(d.action, "delete");
                assert_eq!(d.resource, "/documents/confidential/report.pdf");
                assert_eq!(d.subject, "employee_123");
                assert_eq!(d.required_permissions.len(), 2);
                assert_eq!(d.suggested_roles.len(), 2);
                assert!(d.recovery.is_some());

                let recovery = d.recovery.as_ref().unwrap();
                assert_eq!(recovery.suggested_actions.len(), 3);
                assert!(recovery.documentation_link.is_some());
            }
            _ => panic!("Expected PermissionDenied"),
        }

        // Verify error message is comprehensive
        let error_message = format!("{}", error);
        assert!(error_message.contains("Permission denied"));
        assert!(error_message.contains("delete"));
        assert!(error_message.contains("confidential"));
    }

    #[test]
    fn test_role_operation_failed_error() {
        let error = Error::RoleOperationFailed {
            operation: "assign".to_string(),
            role: "admin".to_string(),
            reason: "circular dependency detected".to_string(),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Role operation failed"));
        assert!(error_string.contains("assign"));
        assert!(error_string.contains("admin"));
        assert!(error_string.contains("circular dependency"));
    }

    #[test]
    fn test_permission_operation_failed_error() {
        let mut context = HashMap::new();
        context.insert("user_group".to_string(), "employees".to_string());
        context.insert("resource_owner".to_string(), "security_team".to_string());

        let error = Error::PermissionOperationFailed {
            operation: "check".to_string(),
            subject: "alice".to_string(),
            resource: "classified_document".to_string(),
            reason: "insufficient clearance level".to_string(),
            context: Box::new(context),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Permission operation failed"));
        assert!(error_string.contains("check"));
        assert!(error_string.contains("alice"));
        assert!(error_string.contains("classified_document"));
        assert!(error_string.contains("insufficient clearance"));
    }

    #[test]
    fn test_rate_limit_exceeded_error() {
        let error = Error::RateLimitExceeded {
            subject: "user123".to_string(),
            limit: 100,
            window: "1 minute".to_string(),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Rate limit exceeded"));
        assert!(error_string.contains("user123"));
        assert!(error_string.contains("100"));
        assert!(error_string.contains("1 minute"));
    }

    #[test]
    fn test_concurrency_conflict_error() {
        let error = Error::ConcurrencyConflict {
            operation: "role_assignment".to_string(),
            resource_id: "role_123".to_string(),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Concurrency conflict"));
        assert!(error_string.contains("role_assignment"));
        assert!(error_string.contains("concurrent modification"));
    }

    #[test]
    fn test_authentication_failed_error() {
        let error = Error::AuthenticationFailed {
            reason: "invalid credentials".to_string(),
            subject_id: Some("user123".to_string()),
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Authentication failed"));
        assert!(error_string.contains("invalid credentials"));
    }

    #[test]
    fn test_authorization_failed_error() {
        let error = Error::AuthorizationFailed {
            subject: "alice".to_string(),
            permission: "delete:documents".to_string(),
            resource: "confidential.txt".to_string(),
            required_roles: vec!["admin".to_string(), "editor".to_string()],
        };

        let error_string = format!("{}", error);
        assert!(error_string.contains("Authorization failed"));
        assert!(error_string.contains("alice"));
        assert!(error_string.contains("delete:documents"));
        assert!(error_string.contains("confidential.txt"));
    }
}
