//! Core role system implementation.
//!
//! This module contains the main implementation of the role-based access control system.
//! It provides the central `RoleSystem` struct which manages roles, permissions, subjects,
//! and resources, along with all access control operations.
//!
//! # Architecture
//!
//! The role system is built around these key components:
//!
//! - **Roles**: Named entities with assigned permissions
//! - **Permissions**: Grant access to perform actions on resource types
//! - **Subjects**: Users, services, or other entities that are assigned roles
//! - **Resources**: Objects that are protected by permissions
//! - **Storage**: Backend for persisting roles and other entities
//!
//! # Thread Safety
//!
//! The implementation uses `DashMap` for concurrent access to internal data structures,
//! making it thread-safe for use in multi-threaded applications.
//!
//! # Caching
//!
//! Permission checks are cached to improve performance for repeated access checks,
//! with configurable cache TTL and invalidation on role changes.

#[cfg(feature = "audit")]
use log::{info, warn};

use crate::{
    app_type::ApplicationType,
    error::{Error, Result},
    metrics::{MetricsProvider, RoleSystemMetrics},
    permission::Permission,
    resource::Resource,
    role::{Role, RoleElevation},
    storage::{MemoryStorage, Storage},
    subject::Subject,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The result of an access check.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult {
    /// Access is granted.
    Granted,
    /// Access is denied with a reason.
    Denied(String),
}

impl AccessResult {
    /// Returns true if access was granted.
    pub fn is_granted(&self) -> bool {
        matches!(self, AccessResult::Granted)
    }

    /// Returns true if access was denied.
    pub fn is_denied(&self) -> bool {
        !self.is_granted()
    }

    /// Returns the denial reason if access was denied.
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            AccessResult::Denied(reason) => Some(reason),
            AccessResult::Granted => None,
        }
    }
}

impl From<bool> for AccessResult {
    fn from(granted: bool) -> Self {
        if granted {
            AccessResult::Granted
        } else {
            AccessResult::Denied("Access denied".to_string())
        }
    }
}

/// Configuration for the role system.
#[derive(Debug, Clone)]
pub struct RoleSystemConfig {
    /// Maximum depth for role hierarchy traversal.
    pub max_hierarchy_depth: usize,
    /// Whether to enable permission caching.
    pub enable_caching: bool,
    /// Cache TTL in seconds.
    pub cache_ttl_seconds: u64,
    /// Whether to enable audit logging.
    pub enable_audit: bool,
}

impl Default for RoleSystemConfig {
    fn default() -> Self {
        Self {
            max_hierarchy_depth: 10,
            enable_caching: true,
            cache_ttl_seconds: 300, // 5 minutes
            enable_audit: true,
        }
    }
}

/// Cached permissions for a user with last updated timestamp.
#[derive(Debug, Clone)]
pub struct UserPermissions {
    /// The computed permission results
    pub computed_permissions: HashMap<String, AccessResult>,
    /// When the permissions were last updated
    pub last_updated: DateTime<Utc>,
}

impl UserPermissions {
    /// Create new user permissions cache
    pub fn new(permissions: HashMap<String, AccessResult>) -> Self {
        Self {
            computed_permissions: permissions,
            last_updated: Utc::now(),
        }
    }

    /// Check if the cache entry is expired based on TTL
    pub fn is_expired(&self, ttl_seconds: u64) -> bool {
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(ttl_seconds as i64);
        now.signed_duration_since(self.last_updated) > ttl
    }
}

/// The main role-based access control system.
pub struct RoleSystem<S = MemoryStorage>
where
    S: Storage,
{
    storage: S,
    config: RoleSystemConfig,
    // Role hierarchy: child -> parents
    role_hierarchy: DashMap<String, HashSet<String>>,
    // Subject role assignments
    subject_roles: DashMap<String, HashSet<String>>,
    // Temporary role elevations
    role_elevations: DashMap<String, Vec<RoleElevation>>,
    // Permission cache: (subject_id, permission_key) -> (UserPermissions)
    permission_cache: DashMap<(String, String), UserPermissions>,
    // Metrics collection
    metrics: Arc<RoleSystemMetrics>,
}

impl RoleSystem<MemoryStorage> {
    /// Create a new role system with default configuration and memory storage.
    pub fn new() -> Self {
        Self::with_config(RoleSystemConfig::default())
    }

    /// Create a new role system with custom configuration and memory storage.
    pub fn with_config(config: RoleSystemConfig) -> Self {
        Self {
            storage: MemoryStorage::new(),
            config,
            role_hierarchy: DashMap::new(),
            subject_roles: DashMap::new(),
            role_elevations: DashMap::new(),
            permission_cache: DashMap::new(),
            metrics: Arc::new(RoleSystemMetrics::new()),
        }
    }
}

impl<S> MetricsProvider for RoleSystem<S>
where
    S: Storage,
{
    fn metrics(&self) -> &RoleSystemMetrics {
        &self.metrics
    }
}

impl<S> RoleSystem<S>
where
    S: Storage,
{
    /// Create a new role system with custom storage.
    pub fn with_storage(storage: S, config: RoleSystemConfig) -> Self {
        Self {
            storage,
            config,
            role_hierarchy: DashMap::new(),
            subject_roles: DashMap::new(),
            role_elevations: DashMap::new(),
            permission_cache: DashMap::new(),
            metrics: Arc::new(RoleSystemMetrics::new()),
        }
    }

    /// Register a new role in the system.
    pub fn register_role(&mut self, role: Role) -> Result<()> {
        let role_name = role.name().to_string();

        if self.storage.role_exists(&role_name)? {
            return Err(Error::RoleAlreadyExists(role_name));
        }

        self.storage.store_role(role)?;

        #[cfg(feature = "audit")]
        info!("Role '{role_name}' registered");

        Ok(())
    }

    /// Get a role by name.
    pub fn get_role(&self, name: &str) -> Result<Option<Role>> {
        self.storage.get_role(name)
    }

    /// Update an existing role.
    pub fn update_role(&mut self, role: Role) -> Result<()> {
        let role_name = role.name().to_string();

        if !self.storage.role_exists(&role_name)? {
            return Err(Error::RoleNotFound(role_name));
        }

        self.storage.update_role(role)?;

        // Clear permission cache for all subjects with this role
        self.clear_role_cache(&role_name);

        #[cfg(feature = "audit")]
        info!("Role '{role_name}' updated");

        Ok(())
    }

    /// Add role inheritance (child inherits from parent).
    pub fn add_role_inheritance(&mut self, child: &str, parent: &str) -> Result<()> {
        // Check that both roles exist
        if !self.storage.role_exists(child)? {
            return Err(Error::RoleNotFound(child.to_string()));
        }
        if !self.storage.role_exists(parent)? {
            return Err(Error::RoleNotFound(parent.to_string()));
        }

        // Check for circular dependencies
        if self.would_create_cycle(child, parent)? {
            return Err(Error::CircularDependency(child.to_string()));
        }

        // Check if adding this inheritance would exceed the maximum depth
        if self.would_exceed_max_depth(child, parent)? {
            return Err(Error::MaxDepthExceeded(self.config.max_hierarchy_depth));
        }

        self.role_hierarchy
            .entry(child.to_string())
            .or_default()
            .insert(parent.to_string());

        #[cfg(feature = "audit")]
        info!("Role inheritance added: '{child}' inherits from '{parent}'");

        Ok(())
    }

    /// Remove role inheritance.
    pub fn remove_role_inheritance(&mut self, child: &str, parent: &str) -> Result<()> {
        if let Some(mut parents) = self.role_hierarchy.get_mut(child) {
            parents.remove(parent);
            if parents.is_empty() {
                drop(parents);
                self.role_hierarchy.remove(child);
            }
        }

        #[cfg(feature = "audit")]
        info!("Role inheritance removed: '{child}' no longer inherits from '{parent}'");

        Ok(())
    }

    /// Assign a role to a subject.
    pub fn assign_role(&mut self, subject: &Subject, role_name: &str) -> Result<()> {
        if !self.storage.role_exists(role_name)? {
            self.metrics.record_error("RoleNotFound");
            return Err(Error::RoleNotFound(role_name.to_string()));
        }

        self.subject_roles
            .entry(subject.id().to_string())
            .or_default()
            .insert(role_name.to_string());

        // Clear permission cache for this subject
        self.clear_subject_cache(subject.id());

        // Record metrics
        self.metrics.record_role_assignment(subject.id());

        #[cfg(feature = "audit")]
        info!(
            "Role '{}' assigned to subject '{}'",
            role_name,
            subject.id()
        );

        Ok(())
    }

    /// Remove a role from a subject.
    pub fn remove_role(&mut self, subject: &Subject, role_name: &str) -> Result<()> {
        if let Some(mut roles) = self.subject_roles.get_mut(subject.id()) {
            roles.remove(role_name);
            if roles.is_empty() {
                drop(roles);
                self.subject_roles.remove(subject.id());
            }
        }

        // Clear permission cache for this subject
        self.clear_subject_cache(subject.id());

        // Record metrics
        self.metrics.record_role_removal(subject.id());

        #[cfg(feature = "audit")]
        info!(
            "Role '{}' removed from subject '{}'",
            role_name,
            subject.id()
        );

        Ok(())
    }

    /// Temporarily elevate a subject's role.
    pub fn elevate_role(
        &mut self,
        subject: &Subject,
        role_name: &str,
        duration: Option<Duration>,
    ) -> Result<()> {
        if !self.storage.role_exists(role_name)? {
            self.metrics.record_error("RoleNotFound");
            return Err(Error::RoleNotFound(role_name.to_string()));
        }

        let elevation = RoleElevation::new(role_name.to_string(), duration);

        self.role_elevations
            .entry(subject.id().to_string())
            .or_default()
            .push(elevation);

        // Clear permission cache for this subject
        self.clear_subject_cache(subject.id());

        // Record metrics
        self.metrics.record_role_elevation(subject.id());

        #[cfg(feature = "audit")]
        info!(
            "Role '{}' elevated for subject '{}' with duration {:?}",
            role_name,
            subject.id(),
            duration
        );

        Ok(())
    }

    /// Check if a subject has a specific permission on a resource.
    pub fn check_permission(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
    ) -> Result<bool> {
        self.check_permission_with_context(subject, action, resource, &HashMap::new())
    }

    /// Check permission with additional context.
    pub fn check_permission_with_context(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
        context: &HashMap<String, String>,
    ) -> Result<bool> {
        let _timer = self.start_timer("permission_check");

        // Create cache key that includes context hash for conditional permissions
        let context_hash = if context.is_empty() {
            String::new()
        } else {
            // Create a simple hash of the context for caching
            let mut sorted_context: Vec<_> = context.iter().collect();
            sorted_context.sort_by_key(|(k, _)| *k);
            format!("{sorted_context:?}")
        };

        // Simplified cache key
        let permission_key = format!("{}:{}:{}", action, resource.id(), context_hash);
        let cache_key = (subject.id().to_string(), permission_key);

        // Check cache first
        if self.config.enable_caching {
            if let Some(entry) = self.permission_cache.get(&cache_key) {
                let permissions = entry.value();

                // Check if cache entry is still valid based on TTL
                let cache_still_valid = !permissions.is_expired(self.config.cache_ttl_seconds);

                // Additionally check if any role elevations have been applied since cache entry was created
                // For simplicity, we assume all elevations are valid and don't check timestamps
                let elevations_still_valid = true;

                if cache_still_valid && elevations_still_valid {
                    // Return the cached result for the specific permission
                    if let Some(result) = permissions.computed_permissions.get(action) {
                        self.metrics.record_cache_hit();
                        return Ok(result.is_granted());
                    }
                }
            }
            self.metrics.record_cache_miss();
        }

        let result = self.check_permission_internal(subject, action, resource, context)?;

        // Cache the result
        if self.config.enable_caching {
            // Get existing permissions or create new
            let mut user_permissions = if let Some(existing) = self.permission_cache.get(&cache_key)
            {
                existing.value().clone()
            } else {
                UserPermissions::new(HashMap::new())
            };

            // Update the permission
            user_permissions
                .computed_permissions
                .insert(action.to_string(), result.into());
            user_permissions.last_updated = Utc::now();

            // Insert back into cache
            self.permission_cache.insert(cache_key, user_permissions);
        }

        #[cfg(feature = "audit")]
        {
            let granted = result;
            if granted {
                info!(
                    "Permission GRANTED for subject '{}', action '{}', resource '{}'",
                    subject.id(),
                    action,
                    resource.id()
                );
            } else {
                warn!(
                    "Permission DENIED for subject '{}', action '{}', resource '{}'",
                    subject.id(),
                    action,
                    resource.id()
                );
            }
        }

        Ok(result)
    }
    /// Get all roles assigned to a subject (including inherited roles).
    pub fn get_subject_roles(&self, subject: &Subject) -> Result<HashSet<String>> {
        let mut all_roles = HashSet::new();

        // Get directly assigned roles
        if let Some(direct_roles) = self.subject_roles.get(subject.id()) {
            for role in direct_roles.iter() {
                all_roles.insert(role.clone());
                // Get inherited roles
                self.collect_inherited_roles(role, &mut all_roles, 0)?;
            }
        }

        // Get elevated roles
        if let Some(elevations) = self.role_elevations.get(subject.id()) {
            let now = Instant::now();
            for elevation in elevations.iter() {
                if !elevation.is_expired(now) {
                    all_roles.insert(elevation.role_name().to_string());
                    self.collect_inherited_roles(elevation.role_name(), &mut all_roles, 0)?;
                }
            }
        }

        Ok(all_roles)
    }

    /// Creates standard roles commonly used in applications.
    ///
    /// This method creates the following roles:
    /// - admin: Full system access
    /// - editor: Create and edit content
    /// - viewer: Read-only access
    /// - guest: Limited read access
    pub fn create_standard_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating standard roles: admin, editor, viewer, guest");

        // Admin role with full access
        let admin_role = Role::new("admin")
            .with_description("Full system access")
            .add_permission(Permission::super_admin());

        // Editor role with edit permissions
        let editor_role = Role::new("editor")
            .with_description("Create and edit content")
            .add_permission(Permission::new("create", "*"))
            .add_permission(Permission::new("read", "*"))
            .add_permission(Permission::new("update", "*"))
            .add_permission(Permission::new("delete", "*"));

        // Viewer role with read-only permissions
        let viewer_role = Role::new("viewer")
            .with_description("Read-only access")
            .add_permission(Permission::new("read", "*"));

        // Guest role with limited read permissions
        let guest_role = Role::new("guest")
            .with_description("Limited read access")
            .add_permission(Permission::new("read", "public"));

        // Register the roles
        self.register_role(admin_role)?;
        self.register_role(editor_role)?;
        self.register_role(viewer_role)?;
        self.register_role(guest_role)?;

        Ok(())
    }
    // ApplicationType enum is defined at the module level

    /// Creates roles appropriate for specific application types.
    pub fn create_application_roles(&mut self, app_type: ApplicationType) -> Result<()> {
        match app_type {
            ApplicationType::WebApp => self.create_web_app_roles()?,
            ApplicationType::ApiService => self.create_api_service_roles()?,
            ApplicationType::Cms => self.create_cms_roles()?,
            ApplicationType::Ecommerce => self.create_ecommerce_roles()?,
            ApplicationType::AdminDashboard => self.create_admin_dashboard_roles()?,
        }

        Ok(())
    }

    // Private helper methods for specific application types
    fn create_web_app_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating web application roles");

        // User role
        let user_role = Role::new("user")
            .with_description("Standard authenticated user")
            .add_permission(Permission::new("read", "content"))
            .add_permission(Permission::new("read", "profile"))
            .add_permission(Permission::new("update", "profile:self"));

        // Premium user role
        let premium_role = Role::new("premium_user")
            .with_description("Premium tier user with extra access")
            .add_permission(Permission::new("read", "content"))
            .add_permission(Permission::new("read", "profile"))
            .add_permission(Permission::new("update", "profile:self"))
            .add_permission(Permission::new("read", "premium_content"));

        // Moderator role
        let moderator_role = Role::new("moderator")
            .with_description("Content moderation capabilities")
            .add_permission(Permission::new("read", "*"))
            .add_permission(Permission::new("update", "content"))
            .add_permission(Permission::new("delete", "content"));

        self.register_role(user_role)?;
        self.register_role(premium_role)?;
        self.register_role(moderator_role)?;

        // Also create standard roles
        self.create_standard_roles()?;

        Ok(())
    }

    fn create_api_service_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating API service roles");

        // Service role
        let service_role = Role::new("service")
            .with_description("Service-to-service API access")
            .add_permission(Permission::new("read", "api"))
            .add_permission(Permission::new("create", "api"));

        // Consumer role
        let consumer_role = Role::new("consumer")
            .with_description("API consumer with read access")
            .add_permission(Permission::new("read", "api"));

        // System role
        let system_role = Role::new("system")
            .with_description("Internal system operations")
            .add_permission(Permission::new("*", "system"));

        self.register_role(service_role)?;
        self.register_role(consumer_role)?;
        self.register_role(system_role)?;

        // Also create standard roles
        self.create_standard_roles()?;

        Ok(())
    }

    fn create_cms_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating CMS roles");

        // Author role
        let author_role = Role::new("author")
            .with_description("Content creator")
            .add_permission(Permission::new("create", "content"))
            .add_permission(Permission::new("read", "content"))
            .add_permission(Permission::new("update", "content:own"))
            .add_permission(Permission::new("delete", "content:own"));

        // Publisher role
        let publisher_role = Role::new("publisher")
            .with_description("Content publisher")
            .add_permission(Permission::new("read", "content"))
            .add_permission(Permission::new("update", "content"))
            .add_permission(Permission::new("publish", "content"));

        self.register_role(author_role)?;
        self.register_role(publisher_role)?;

        // Also create standard roles
        self.create_standard_roles()?;

        Ok(())
    }

    fn create_ecommerce_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating e-commerce roles");

        // Customer role
        let customer_role = Role::new("customer")
            .with_description("Shopping customer")
            .add_permission(Permission::new("read", "product"))
            .add_permission(Permission::new("create", "order"))
            .add_permission(Permission::new("read", "order:own"));

        // Vendor role
        let vendor_role = Role::new("vendor")
            .with_description("Product vendor")
            .add_permission(Permission::new("create", "product"))
            .add_permission(Permission::new("read", "product:own"))
            .add_permission(Permission::new("update", "product:own"))
            .add_permission(Permission::new("delete", "product:own"))
            .add_permission(Permission::new("read", "order:for_products"));

        self.register_role(customer_role)?;
        self.register_role(vendor_role)?;

        // Also create standard roles
        self.create_standard_roles()?;

        Ok(())
    }

    fn create_admin_dashboard_roles(&mut self) -> Result<()> {
        #[cfg(feature = "audit")]
        info!("Creating admin dashboard roles");

        // Support role
        let support_role = Role::new("support")
            .with_description("Customer support staff")
            .add_permission(Permission::new("read", "*"))
            .add_permission(Permission::new("update", "user:status"));

        // Analytics role
        let analytics_role = Role::new("analytics")
            .with_description("Data analysis")
            .add_permission(Permission::new("read", "*"))
            .add_permission(Permission::new("export", "data"));

        self.register_role(support_role)?;
        self.register_role(analytics_role)?;

        // Also create standard roles
        self.create_standard_roles()?;

        Ok(())
    }

    // Internal implementation

    fn check_permission_internal(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
        context: &HashMap<String, String>,
    ) -> Result<bool> {
        let subject_roles = self.get_subject_roles(subject)?;

        for role_name in subject_roles {
            if let Some(role) = self.storage.get_role(&role_name)?
                && role.has_permission(action, resource.resource_type(), context)
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn collect_inherited_roles(
        &self,
        role_name: &str,
        collected: &mut HashSet<String>,
        depth: usize,
    ) -> Result<()> {
        if depth >= self.config.max_hierarchy_depth {
            return Err(Error::MaxDepthExceeded(self.config.max_hierarchy_depth));
        }

        if let Some(parents) = self.role_hierarchy.get(role_name) {
            for parent in parents.iter() {
                if collected.insert(parent.clone()) {
                    self.collect_inherited_roles(parent, collected, depth + 1)?;
                }
            }
        }

        Ok(())
    }

    fn would_create_cycle(&self, child: &str, parent: &str) -> Result<bool> {
        let mut visited = HashSet::new();
        self.has_path(parent, child, &mut visited, 0)
    }

    fn would_exceed_max_depth(&self, child: &str, parent: &str) -> Result<bool> {
        // Calculate the depth from the child downwards (how many levels inherit from child)
        let child_downward_depth = self.calculate_downward_depth(child)?;
        // Calculate the depth from the parent upwards (how many levels parent inherits from)
        let parent_upward_depth = self.calculate_upward_depth(parent)?;

        // If child inherits from parent, the total depth would be:
        // parent_upward_depth + 1 (for the new link) + child_downward_depth
        let total_depth = parent_upward_depth + 1 + child_downward_depth;

        Ok(total_depth > self.config.max_hierarchy_depth)
    }

    fn calculate_downward_depth(&self, role_name: &str) -> Result<usize> {
        let mut max_depth = 0;
        let mut visited = HashSet::new();
        self.calculate_downward_depth_recursive(role_name, &mut visited, 0, &mut max_depth)?;
        Ok(max_depth)
    }

    fn calculate_downward_depth_recursive(
        &self,
        role_name: &str,
        visited: &mut HashSet<String>,
        current_depth: usize,
        max_depth: &mut usize,
    ) -> Result<()> {
        if current_depth > self.config.max_hierarchy_depth {
            return Err(Error::MaxDepthExceeded(self.config.max_hierarchy_depth));
        }

        if !visited.insert(role_name.to_string()) {
            return Ok(()); // Already visited
        }

        *max_depth = std::cmp::max(*max_depth, current_depth);

        // Find all roles that inherit from this role
        for entry in self.role_hierarchy.iter() {
            let (child, parents) = (entry.key(), entry.value());
            if parents.contains(role_name) {
                self.calculate_downward_depth_recursive(
                    child,
                    visited,
                    current_depth + 1,
                    max_depth,
                )?;
            }
        }

        Ok(())
    }

    fn calculate_upward_depth(&self, role_name: &str) -> Result<usize> {
        let mut max_depth = 0;
        let mut visited = HashSet::new();
        self.calculate_upward_depth_recursive(role_name, &mut visited, 0, &mut max_depth)?;
        Ok(max_depth)
    }

    fn calculate_upward_depth_recursive(
        &self,
        role_name: &str,
        visited: &mut HashSet<String>,
        current_depth: usize,
        max_depth: &mut usize,
    ) -> Result<()> {
        if current_depth > self.config.max_hierarchy_depth {
            return Err(Error::MaxDepthExceeded(self.config.max_hierarchy_depth));
        }

        if !visited.insert(role_name.to_string()) {
            return Ok(()); // Already visited
        }

        *max_depth = std::cmp::max(*max_depth, current_depth);

        if let Some(parents) = self.role_hierarchy.get(role_name) {
            for parent in parents.iter() {
                self.calculate_upward_depth_recursive(
                    parent,
                    visited,
                    current_depth + 1,
                    max_depth,
                )?;
            }
        }

        Ok(())
    }

    fn has_path(
        &self,
        from: &str,
        to: &str,
        visited: &mut HashSet<String>,
        depth: usize,
    ) -> Result<bool> {
        if depth >= self.config.max_hierarchy_depth {
            return Err(Error::MaxDepthExceeded(self.config.max_hierarchy_depth));
        }

        if from == to {
            return Ok(true);
        }

        if !visited.insert(from.to_string()) {
            return Ok(false); // Already visited
        }

        if let Some(parents) = self.role_hierarchy.get(from) {
            for parent in parents.iter() {
                if self.has_path(parent, to, visited, depth + 1)? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn clear_subject_cache(&self, subject_id: &str) {
        if !self.config.enable_caching {
            return;
        }

        let keys_to_remove: Vec<_> = self
            .permission_cache
            .iter()
            .filter(|entry| entry.key().0 == subject_id)
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.permission_cache.remove(&key);
        }
    }

    fn clear_role_cache(&self, _role_name: &str) {
        if !self.config.enable_caching {
            return;
        }

        // We need to clear cache for all subjects that have this role
        // This is a simplified approach - in a real implementation you might
        // want to track role assignments more efficiently
        self.permission_cache.clear();
    }
}

impl<S: Storage> RoleSystem<S> {
    /// Get access to the internal storage backend (for query operations).
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get access to the subject roles mapping (for query operations).
    pub fn subject_roles(&self) -> &DashMap<String, HashSet<String>> {
        &self.subject_roles
    }

    /// Get access to the role hierarchy mapping (for query operations).
    pub fn role_hierarchy(&self) -> &DashMap<String, HashSet<String>> {
        &self.role_hierarchy
    }

    /// Get access to the configuration (for query operations).
    pub fn config(&self) -> &RoleSystemConfig {
        &self.config
    }
}

// Enhanced API Extensions
impl<S: Storage> RoleSystem<S> {
    /// Assign multiple roles to a subject in a single operation.
    pub fn assign_roles<I>(&mut self, subject: &Subject, roles: I) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        for role in roles {
            self.assign_role(subject, role.as_ref())?;
        }
        Ok(())
    }

    /// Remove multiple roles from a subject in a single operation.
    pub fn remove_roles<I>(&mut self, subject: &Subject, roles: I) -> Result<()>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        for role in roles {
            self.remove_role(subject, role.as_ref())?;
        }
        Ok(())
    }

    /// Check multiple permissions for a subject in a single operation.
    pub fn check_permissions_batch(
        &self,
        subject: &Subject,
        permissions: &[(&str, &Resource)],
    ) -> Result<Vec<(String, String, bool)>> {
        permissions
            .iter()
            .map(|(action, resource)| {
                let result = self.check_permission(subject, action, resource)?;
                Ok((action.to_string(), resource.id().to_string(), result))
            })
            .collect()
    }

    /// Bulk role assignment with validation.
    pub fn bulk_assign_roles(
        &mut self,
        assignments: &[(Subject, Vec<String>)],
    ) -> Result<Vec<Result<()>>> {
        let mut results = Vec::new();

        for (subject, roles) in assignments {
            let role_refs: Vec<&str> = roles.iter().map(|s| s.as_str()).collect();
            let result = self.assign_roles(subject, role_refs);
            results.push(result);
        }

        Ok(results)
    }

    /// Get detailed permission summary for a subject.
    pub fn get_permission_summary(&self, subject: &Subject) -> Result<PermissionSummary> {
        let roles = self.get_subject_roles(subject)?;
        let mut permissions = Vec::new();

        for role_name in &roles {
            if let Some(role) = self.storage.get_role(role_name)? {
                for permission in role.permissions().permissions() {
                    permissions.push(permission.clone());
                }
            }
        }

        let effective_permissions_count = permissions.len();

        Ok(PermissionSummary {
            subject_id: subject.id().to_string(),
            roles: roles.into_iter().collect(),
            permissions,
            effective_permissions_count,
        })
    }
}

/// Summary of a subject's permissions and roles.
#[derive(Debug, Clone)]
pub struct PermissionSummary {
    pub subject_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
    pub effective_permissions_count: usize,
}

impl<S> Default for RoleSystem<S>
where
    S: Storage + Default,
{
    fn default() -> Self {
        Self::with_storage(S::default(), RoleSystemConfig::default())
    }
}
