use std::collections::HashMap;
use std::fmt;

/// Represents all possible errors that can occur in the role system.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Role with the specified name was not found.
    RoleNotFound(String),

    /// Attempted to create a role that already exists.
    RoleAlreadyExists(String),

    /// Subject (user/entity) with the specified ID was not found.
    SubjectNotFound(String),

    /// A circular dependency was detected in role hierarchies.
    CircularDependency(String),

    /// Permission was denied for the requested operation.
    PermissionDenied(Box<PermissionDeniedDetails>),

    /// Validation failed for provided input.
    ValidationError {
        field: String,
        reason: String,
        invalid_value: Option<String>,
    },

    /// Storage backend error.
    Storage(String),

    /// Invalid configuration provided.
    InvalidConfiguration(String),
}

/// Detailed information about a permission denial.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionDeniedDetails {
    /// The action that was attempted.
    pub action: String,

    /// The resource that was accessed.
    pub resource: String,

    /// The subject (user/entity) that attempted the action.
    pub subject: String,

    /// The permissions that would be required for this action.
    pub required_permissions: Vec<String>,

    /// Suggested roles that would grant the required permissions.
    pub suggested_roles: Vec<String>,

    /// Recovery suggestions for resolving the permission issue.
    pub recovery: Option<RecoverySuggestion>,
}

/// Provides suggestions for recovering from an error.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoverySuggestion {
    /// Human-readable message describing the issue.
    pub message: String,

    /// List of suggested actions to resolve the issue.
    pub suggested_actions: Vec<String>,

    /// Optional link to documentation.
    pub documentation_link: Option<String>,
}

impl RecoverySuggestion {
    /// Creates a new recovery suggestion with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            suggested_actions: Vec::new(),
            documentation_link: None,
        }
    }

    /// Adds a suggested action to resolve the issue.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.suggested_actions.push(action.into());
        self
    }

    /// Adds a link to relevant documentation.
    pub fn with_documentation(mut self, link: impl Into<String>) -> Self {
        self.documentation_link = Some(link.into());
        self
    }
}

impl fmt::Display for PermissionDeniedDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Permission denied: {} cannot {} on {}",
            self.subject, self.action, self.resource
        )?;

        if !self.required_permissions.is_empty() {
            write!(
                f,
                "\nRequired permissions: {}",
                self.required_permissions.join(", ")
            )?;
        }

        if !self.suggested_roles.is_empty() {
            write!(f, "\nSuggested roles: {}", self.suggested_roles.join(", "))?;
        }

        if let Some(recovery) = &self.recovery {
            write!(f, "\n\nRecovery suggestions:")?;
            write!(f, "\n{}", recovery.message)?;
            for action in &recovery.suggested_actions {
                write!(f, "\n  - {}", action)?;
            }
            if let Some(doc_link) = &recovery.documentation_link {
                write!(f, "\n\nFor more information: {}", doc_link)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RoleNotFound(role) => write!(f, "Role '{}' not found", role),
            Error::RoleAlreadyExists(role) => write!(f, "Role '{}' already exists", role),
            Error::SubjectNotFound(subject) => write!(f, "Subject '{}' not found", subject),
            Error::CircularDependency(msg) => write!(f, "Circular dependency detected: {}", msg),
            Error::PermissionDenied(details) => write!(f, "{}", details),
            Error::ValidationError {
                field,
                reason,
                invalid_value,
            } => {
                write!(f, "Validation failed for field '{}': {}", field, reason)?;
                if let Some(value) = invalid_value {
                    write!(f, " (invalid value: '{}')", value)?;
                }
                Ok(())
            }
            Error::Storage(msg) => write!(f, "Storage error: {}", msg),
            Error::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Validates an identifier (role name, subject ID, etc.) for security.
    pub fn validate_identifier(value: &str, field_name: &str) -> Result<(), Error> {
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
    pub fn validate_resource_path(path: &str) -> Result<(), Error> {
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

/// Result type alias for the role system.
pub type Result<T> = std::result::Result<T, Error>;

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
}
