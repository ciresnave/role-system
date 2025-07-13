//! Error types for the role system.

use thiserror::Error;

/// The main error type for role system operations.
#[derive(Error, Debug)]
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
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

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
}

/// Result type alias for role system operations.
pub type Result<T> = std::result::Result<T, Error>;
