//! # Role System
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

pub mod app_type;
pub mod auth_context;
pub mod batch;
pub mod cache;
pub mod context_integration;
pub mod core;
pub mod database;
pub mod error;

// Testing and fuzzing
#[cfg(test)]
pub mod fuzz;

pub mod health;
pub mod hierarchy;
pub mod macros;
pub mod metrics;
pub mod performance;
pub mod permission;
pub mod property_tests;
pub mod query;
pub mod rate_limit;
pub mod resource;
pub mod role;
pub mod storage;
pub mod subject;
pub mod telemetry;
pub mod temporal;

#[cfg(feature = "async")]
pub mod async_support;

// Re-export main types for convenience
pub use crate::{
    app_type::ApplicationType,
    auth_context::{AuthenticationContext, JwtContext, SessionContext},
    batch::{BatchConfig, BatchOperations, BatchPermissionCheck, BatchResult, BatchRoleAssignment},
    context_integration::ContextualPermissions,
    core::{AccessResult, RoleSystem, RoleSystemConfig},
    error::Error,
    hierarchy::{
        HierarchyConfig, HierarchyConfigBuilder, RelationshipType, RoleHierarchyTree, RoleNode,
        RoleRelationship,
    },
    permission::Permission,
    resource::Resource,
    role::Role,
    storage::MemoryStorage,
    subject::Subject,
};

#[cfg(feature = "async")]
pub use crate::async_support::AsyncRoleSystem;
