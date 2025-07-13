//! # Role System
//!
//! A flexible and powerful role-based access control (RBAC) library for Rust applications.
//! 
//! This crate provides a complete framework for defining roles, permissions, and access policies 
//! with support for dynamic role management, hierarchical roles, and fine-grained permission checking.
//!
//! ## Features
//!
//! - Hierarchical role definitions and inheritance
//! - Fine-grained permission control
//! - Dynamic role management at runtime
//! - Role assignment to users, groups, or resources
//! - Conditional permissions based on context
//! - Permission caching for performance
//! - Custom permission validators
//! - Serializable role definitions
//! - Audit logging of permission checks
//! - Integration with authentication systems
//! - Thread-safe implementation
//! - Support for temporary role elevation
//! - Role constraints (time-based, location-based, etc.)
//!
//! ## Quick Start
//!
//! ```rust
//! use role_system::{RoleSystem, Role, Permission, Subject, Resource};
//! 
//! // Initialize the role system
//! let mut role_system = RoleSystem::new();
//! 
//! // Define permissions
//! let read_docs = Permission::new("read", "documents");
//! let write_docs = Permission::new("write", "documents");
//! 
//! // Define roles with permissions
//! let reader = Role::new("reader").add_permission(read_docs.clone());
//! let writer = Role::new("writer")
//!     .add_permission(read_docs.clone())
//!     .add_permission(write_docs.clone());
//! 
//! // Register roles
//! role_system.register_role(reader)?;
//! role_system.register_role(writer)?;
//! 
//! // Assign roles to subjects
//! let user = Subject::new("user1");
//! role_system.assign_role(&user, "reader")?;
//! 
//! // Check permissions
//! let document = Resource::new("doc1", "documents");
//! let can_read = role_system.check_permission(&user, "read", &document)?;
//! 
//! assert!(can_read);
//! # Ok::<(), role_system::Error>(())
//! ```
//!
//! ## Audit Logging
//!
//! When the `audit` feature is enabled, Role System logs important security events 
//! using the standard Rust logging framework. To enable logging:
//!
//! ```rust
//! use role_system::init_audit_logger;
//!
//! // Initialize logging (must be called early in program execution)
//! init_audit_logger();
//!
//! // Configure log level through RUST_LOG environment variable:
//! // RUST_LOG=info,role_system=debug
//! ```
//!
//! The following events are logged:
//! - Role registration and updates
//! - Role hierarchy changes
//! - Role assignments and removals
//! - Permission checks (at debug level)
//! - Security-relevant errors
//!

#[cfg(feature = "audit")]
pub fn init_audit_logger() {
    env_logger::init();
}

pub mod core;
pub mod error;
pub mod permission;
pub mod resource;
pub mod role;
pub mod storage;
pub mod subject;

#[cfg(feature = "async")]
pub mod async_support;

// Re-export main types for convenience
pub use crate::{
    core::{RoleSystem, AccessResult},
    error::Error,
    permission::Permission,
    resource::Resource,
    role::Role,
    subject::Subject,
};

pub type Result<T> = std::result::Result<T, Error>;
