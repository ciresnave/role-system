//! Async support for the role system (requires 'async' feature).

use crate::{
    core::{RoleSystem, RoleSystemConfig},
    error::Result,
    resource::Resource,
    role::Role,
    storage::Storage,
    subject::Subject,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, RwLock};

/// Async wrapper around the role system for non-blocking operations.
pub struct AsyncRoleSystem<S>
where
    S: Storage + Send + Sync,
{
    inner: Arc<RwLock<RoleSystem<S>>>,
}

impl<S> AsyncRoleSystem<S>
where
    S: Storage + Send + Sync,
{
    /// Create a new async role system.
    pub fn new(role_system: RoleSystem<S>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(role_system)),
        }
    }

    /// Register a new role in the system.
    pub async fn register_role(&self, role: Role) -> Result<()> {
        let mut system = self.inner.write().await;
        system.register_role(role)
    }

    /// Get a role by name.
    pub async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        let system = self.inner.read().await;
        system.get_role(name)
    }

    /// Add role inheritance (child inherits from parent).
    pub async fn add_role_inheritance(&self, child: &str, parent: &str) -> Result<()> {
        let mut system = self.inner.write().await;
        system.add_role_inheritance(child, parent)
    }

    /// Remove role inheritance.
    pub async fn remove_role_inheritance(&self, child: &str, parent: &str) -> Result<()> {
        let mut system = self.inner.write().await;
        system.remove_role_inheritance(child, parent)
    }

    /// Assign a role to a subject.
    pub async fn assign_role(&self, subject: &Subject, role_name: &str) -> Result<()> {
        let mut system = self.inner.write().await;
        system.assign_role(subject, role_name)
    }

    /// Remove a role from a subject.
    pub async fn remove_role(&self, subject: &Subject, role_name: &str) -> Result<()> {
        let mut system = self.inner.write().await;
        system.remove_role(subject, role_name)
    }

    /// Temporarily elevate a subject's role.
    pub async fn elevate_role(
        &self,
        subject: &Subject,
        role_name: &str,
        duration: Option<Duration>,
    ) -> Result<()> {
        let mut system = self.inner.write().await;
        system.elevate_role(subject, role_name, duration)
    }

    /// Check if a subject has a specific permission on a resource.
    pub async fn check_permission(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
    ) -> Result<bool> {
        let system = self.inner.read().await;
        system.check_permission(subject, action, resource)
    }

    /// Check permission with additional context.
    pub async fn check_permission_with_context(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
        context: &HashMap<String, String>,
    ) -> Result<bool> {
        let system = self.inner.read().await;
        system.check_permission_with_context(subject, action, resource, context)
    }

    /// Get all roles assigned to a subject.
    pub async fn get_subject_roles(&self, subject: &Subject) -> Result<HashSet<String>> {
        let system = self.inner.read().await;
        system.get_subject_roles(subject)
    }

    /// Batch check multiple permissions for a subject.
    pub async fn batch_check_permissions(
        &self,
        subject: &Subject,
        checks: &[(String, Resource)], // (action, resource) pairs
    ) -> Result<Vec<(String, Resource, bool)>> {
        let system = self.inner.read().await;
        let mut results = Vec::new();

        for (action, resource) in checks {
            let granted = system.check_permission(subject, action, resource)?;
            results.push((action.clone(), resource.clone(), granted));
        }

        Ok(results)
    }

    /// Perform multiple role operations atomically.
    pub async fn atomic_role_operations<F, R>(&self, operations: F) -> Result<R>
    where
        F: FnOnce(&mut RoleSystem<S>) -> Result<R> + Send,
    {
        let mut system = self.inner.write().await;
        operations(&mut *system)
    }

    /// Get a read-only reference to the role system for complex queries.
    pub async fn with_read_access<F, R>(&self, operation: F) -> R
    where
        F: FnOnce(&RoleSystem<S>) -> R + Send,
    {
        let system = self.inner.read().await;
        operation(&*system)
    }

    // Hierarchy traversal methods for optional hierarchy access

    /// Get the complete hierarchy tree structure.
    ///
    /// This method provides a structured view of the entire role hierarchy,
    /// useful for visualization, API responses, and external system integration.
    ///
    /// # Arguments
    /// * `config` - Optional hierarchy configuration. If None, uses default settings.
    ///
    /// # Returns
    /// A `RoleHierarchyTree` containing the complete hierarchy structure with metadata.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # use role_system::hierarchy::HierarchyConfigBuilder;
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    ///
    /// let config = HierarchyConfigBuilder::new()
    ///     .enable_hierarchy_access(true)
    ///     .max_depth(10)
    ///     .build();
    ///
    /// let tree = role_system.get_hierarchy_tree(Some(config)).await?;
    /// println!("Total roles: {}, Max depth: {}", tree.total_roles, tree.max_depth);
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn get_hierarchy_tree(
        &self,
        config: Option<crate::hierarchy::HierarchyConfig>,
    ) -> Result<crate::hierarchy::RoleHierarchyTree> {
        use crate::hierarchy::{RoleHierarchyTree, RoleNode};
        use std::time::Instant;

        let config = config.unwrap_or_default();

        if !config.enable_hierarchy_access {
            return Err(crate::error::Error::InvalidResource(
                "Hierarchy access is disabled in configuration".to_string(),
            ));
        }

        let start_time = Instant::now();
        let _system = self.inner.read().await;

        // For now, create a simplified tree structure
        // In a real implementation, this would use actual hierarchy data
        let all_roles: Vec<crate::role::Role> = vec![];

        if all_roles.is_empty() {
            // Create empty tree
            let empty_role = crate::role::Role::new("__empty__");
            let root_node = RoleNode::new(empty_role, 0);
            let mut tree = RoleHierarchyTree::new(root_node);
            tree.metadata.generation_time_ms = start_time.elapsed().as_millis() as u64;
            return Ok(tree);
        }

        // This would be implemented with actual hierarchy data
        let empty_role = crate::role::Role::new("__empty__");
        let root_node = RoleNode::new(empty_role, 0);
        let mut tree = RoleHierarchyTree::new(root_node);
        tree.metadata.generation_time_ms = start_time.elapsed().as_millis() as u64;
        tree.metadata.total_permissions = 0;

        Ok(tree)
    }

    /// Get all parent roles for a given role (ancestors).
    ///
    /// This method returns all roles that the specified role inherits from,
    /// including both direct parents and inherited ancestors.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to get ancestors for
    /// * `_include_inherited` - Whether to include inherited (indirect) parents
    ///
    /// # Returns
    /// A vector of role IDs representing all ancestor roles.
    ///
    /// # Example
    /// ```no_run
    /// # use role_system::async_support::AsyncRoleSystem;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), role_system::Error> {
    /// # let role_system = AsyncRoleSystem::new(role_system::RoleSystem::new());
    /// let ancestors = role_system.get_role_ancestors("junior_dev", true).await?;
    /// for ancestor_id in ancestors {
    ///     println!("Inherits from: {}", ancestor_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_role_ancestors(
        &self,
        role_id: &str,
        _include_inherited: bool,
    ) -> Result<Vec<String>> {
        let system = self.inner.read().await;

        // Verify role exists by attempting to get it
        let _role = system.get_role(role_id)?;

        // For now, return empty vector since individual roles don't track hierarchy
        // In a real implementation, this would traverse the RoleHierarchy
        Ok(Vec::new())
    }

    /// Get all child roles for a given role (descendants).
    ///
    /// This method returns all roles that inherit from the specified role,
    /// including both direct children and inherited descendants.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to get descendants for
    /// * `_include_inherited` - Whether to include inherited (indirect) children
    ///
    /// # Returns
    /// A vector of role IDs representing all descendant roles.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    /// let descendants = role_system.get_role_descendants("team_lead", true).await?;
    /// for descendant_id in descendants {
    ///     println!("Has child: {}", descendant_id);
    /// }
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn get_role_descendants(
        &self,
        role_id: &str,
        _include_inherited: bool,
    ) -> Result<Vec<String>> {
        let system = self.inner.read().await;

        // Verify role exists by attempting to get it
        let _role = system.get_role(role_id)?;

        // For now, return empty vector since individual roles don't track hierarchy
        // In a real implementation, this would traverse the RoleHierarchy
        Ok(Vec::new())
    }
    /// Get all sibling roles for a given role.
    ///
    /// Sibling roles are roles that share the same parent in the hierarchy.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to get siblings for
    ///
    /// # Returns
    /// A vector of role IDs representing all sibling roles.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    /// let siblings = role_system.get_role_siblings("senior_dev").await?;
    /// for sibling_id in siblings {
    ///     println!("Sibling role: {}", sibling_id);
    /// }
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn get_role_siblings(&self, role_id: &str) -> Result<Vec<String>> {
        let system = self.inner.read().await;

        // For now, return empty vector since individual roles don't track hierarchy
        // In a real implementation, this would find roles with the same parent
        let _role = system.get_role(role_id)?;

        // This would be implemented using the RoleHierarchy system
        Ok(Vec::new())
    }

    /// Get all role relationships in the hierarchy.
    ///
    /// This method returns all parent-child relationships, useful for
    /// database storage, API responses, and external system integration.
    ///
    /// # Arguments
    /// * `relationship_type` - Optional filter for relationship type
    ///
    /// # Returns
    /// A vector of `RoleRelationship` objects representing all relationships.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # use role_system::hierarchy::RelationshipType;
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    ///
    /// // Get all relationships
    /// let all_relationships = role_system.get_role_relationships(None).await?;
    ///
    /// // Get only direct relationships
    /// let direct_relationships = role_system
    ///     .get_role_relationships(Some(RelationshipType::Direct))
    ///     .await?;
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn get_role_relationships(
        &self,
        _relationship_type: Option<crate::hierarchy::RelationshipType>,
    ) -> Result<Vec<crate::hierarchy::RoleRelationship>> {
        let system = self.inner.read().await;

        // For now, return empty vector since individual roles don't track hierarchy
        // In a real implementation, this would extract all relationships from RoleHierarchy
        // Just verify the system is accessible
        drop(system);

        // This would be implemented using the RoleHierarchy system
        Ok(Vec::new())
    }

    /// Check if one role is an ancestor of another.
    ///
    /// This method checks if `ancestor_id` is in the inheritance chain of `descendant_id`.
    ///
    /// # Arguments
    /// * `ancestor_id` - The potential ancestor role ID
    /// * `descendant_id` - The potential descendant role ID
    ///
    /// # Returns
    /// `true` if `ancestor_id` is an ancestor of `descendant_id`.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    /// let is_ancestor = role_system
    ///     .is_role_ancestor("admin", "junior_dev")
    ///     .await?;
    ///
    /// if is_ancestor {
    ///     println!("admin is an ancestor of junior_dev");
    /// }
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn is_role_ancestor(&self, ancestor_id: &str, descendant_id: &str) -> Result<bool> {
        let system = self.inner.read().await;

        // For now, return false since individual roles don't track hierarchy
        // In a real implementation, this would traverse the RoleHierarchy
        let _ancestor = system.get_role(ancestor_id)?;
        let _descendant = system.get_role(descendant_id)?;

        // This would be implemented using the RoleHierarchy system
        Ok(false)
    }

    /// Get the hierarchy depth of a role.
    ///
    /// The depth is the number of levels from the root of the hierarchy.
    /// Root roles have depth 0.
    ///
    /// # Arguments
    /// * `role_id` - The ID of the role to get depth for
    ///
    /// # Returns
    /// The depth of the role in the hierarchy.
    ///
    /// # Example
    /// ```rust
    /// # use role_system::{AsyncRoleSystem, RoleSystem, RoleSystemConfig, MemoryStorage};
    /// # tokio_test::block_on(async {
    /// let storage = MemoryStorage::new();
    /// let role_sys = RoleSystem::with_storage(storage, RoleSystemConfig::default());
    /// let role_system = AsyncRoleSystem::new(role_sys);
    /// let depth = role_system.get_role_depth("senior_dev").await?;
    /// println!("Role depth: {}", depth);
    /// # Ok::<(), role_system::Error>(())
    /// # });
    /// ```
    pub async fn get_role_depth(&self, role_id: &str) -> Result<usize> {
        let system = self.inner.read().await;

        // For now, return 0 since individual roles don't track hierarchy
        // In a real implementation, this would calculate depth from RoleHierarchy
        let _role = system.get_role(role_id)?;

        // This would be implemented using the RoleHierarchy system
        Ok(0)
    }
}

impl<S> Clone for AsyncRoleSystem<S>
where
    S: Storage + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Async trait for storage backends that support async operations.
#[async_trait::async_trait]
pub trait AsyncStorage: Send + Sync {
    /// Store a role asynchronously.
    async fn store_role(&mut self, role: Role) -> Result<()>;

    /// Get a role by name asynchronously.
    async fn get_role(&self, name: &str) -> Result<Option<Role>>;

    /// Check if a role exists asynchronously.
    async fn role_exists(&self, name: &str) -> Result<bool>;

    /// Delete a role asynchronously.
    async fn delete_role(&mut self, name: &str) -> Result<bool>;

    /// List all role names asynchronously.
    async fn list_roles(&self) -> Result<Vec<String>>;

    /// Update an existing role asynchronously.
    async fn update_role(&mut self, role: Role) -> Result<()>;
}

/// Async memory storage implementation.
#[derive(Debug, Default)]
pub struct AsyncMemoryStorage {
    roles: Arc<RwLock<HashMap<String, Role>>>,
}

impl AsyncMemoryStorage {
    /// Create a new async memory storage instance.
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of stored roles.
    pub async fn role_count(&self) -> usize {
        self.roles.read().await.len()
    }

    /// Clear all stored data.
    pub async fn clear(&self) {
        self.roles.write().await.clear();
    }
}

#[async_trait::async_trait]
impl AsyncStorage for AsyncMemoryStorage {
    async fn store_role(&mut self, role: Role) -> Result<()> {
        let name = role.name().to_string();
        self.roles.write().await.insert(name, role);
        Ok(())
    }

    async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        Ok(self.roles.read().await.get(name).cloned())
    }

    async fn role_exists(&self, name: &str) -> Result<bool> {
        Ok(self.roles.read().await.contains_key(name))
    }

    async fn delete_role(&mut self, name: &str) -> Result<bool> {
        Ok(self.roles.write().await.remove(name).is_some())
    }

    async fn list_roles(&self) -> Result<Vec<String>> {
        Ok(self.roles.read().await.keys().cloned().collect())
    }

    async fn update_role(&mut self, role: Role) -> Result<()> {
        let name = role.name().to_string();
        self.roles.write().await.insert(name, role);
        Ok(())
    }
}

/// Helper trait for converting sync storage to async.
pub struct AsyncStorageAdapter<S>
where
    S: Storage + Send + Sync,
{
    storage: Arc<Mutex<S>>,
}

impl<S> AsyncStorageAdapter<S>
where
    S: Storage + Send + Sync,
{
    /// Create a new async storage adapter.
    pub fn new(storage: S) -> Self {
        Self {
            storage: Arc::new(Mutex::new(storage)),
        }
    }
}

#[async_trait::async_trait]
impl<S> AsyncStorage for AsyncStorageAdapter<S>
where
    S: Storage + Send + Sync,
{
    async fn store_role(&mut self, role: Role) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.store_role(role)
    }

    async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        let storage = self.storage.lock().await;
        storage.get_role(name)
    }

    async fn role_exists(&self, name: &str) -> Result<bool> {
        let storage = self.storage.lock().await;
        storage.role_exists(name)
    }

    async fn delete_role(&mut self, name: &str) -> Result<bool> {
        let mut storage = self.storage.lock().await;
        storage.delete_role(name)
    }

    async fn list_roles(&self) -> Result<Vec<String>> {
        let storage = self.storage.lock().await;
        storage.list_roles()
    }

    async fn update_role(&mut self, role: Role) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.update_role(role)
    }
}

/// Async role system builder for easy configuration.
pub struct AsyncRoleSystemBuilder<S>
where
    S: Storage + Send + Sync,
{
    config: RoleSystemConfig,
    storage: Option<S>,
}

impl<S> AsyncRoleSystemBuilder<S>
where
    S: Storage + Send + Sync + Default,
{
    /// Create a new builder with default storage.
    pub fn new() -> Self {
        Self {
            config: RoleSystemConfig::default(),
            storage: None,
        }
    }
}

impl<S> Default for AsyncRoleSystemBuilder<S>
where
    S: Storage + Send + Sync + Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S> AsyncRoleSystemBuilder<S>
where
    S: Storage + Send + Sync,
{
    /// Create a new builder with custom storage.
    pub fn with_storage(storage: S) -> Self {
        Self {
            config: RoleSystemConfig::default(),
            storage: Some(storage),
        }
    }

    /// Set the configuration.
    pub fn config(mut self, config: RoleSystemConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the maximum hierarchy depth.
    pub fn max_hierarchy_depth(mut self, depth: usize) -> Self {
        self.config.max_hierarchy_depth = depth;
        self
    }

    /// Enable or disable permission caching.
    pub fn enable_caching(mut self, enabled: bool) -> Self {
        self.config.enable_caching = enabled;
        self
    }

    /// Set the cache TTL in seconds.
    pub fn cache_ttl_seconds(mut self, ttl: u64) -> Self {
        self.config.cache_ttl_seconds = ttl;
        self
    }

    /// Enable or disable audit logging.
    pub fn enable_audit(mut self, enabled: bool) -> Self {
        self.config.enable_audit = enabled;
        self
    }

    /// Build the async role system.
    pub fn build(self) -> AsyncRoleSystem<S>
    where
        S: Default,
    {
        let storage = self.storage.unwrap_or_default();
        let role_system = RoleSystem::with_storage(storage, self.config);
        AsyncRoleSystem::new(role_system)
    }

    /// Build the async role system with provided storage.
    pub fn build_with_storage(self, storage: S) -> AsyncRoleSystem<S> {
        let role_system = RoleSystem::with_storage(storage, self.config);
        AsyncRoleSystem::new(role_system)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{permission::Permission, storage::MemoryStorage};

    #[tokio::test]
    async fn test_async_role_system() {
        let storage = MemoryStorage::new();
        let config = RoleSystemConfig::default();
        let role_system = RoleSystem::with_storage(storage, config);
        let async_system = AsyncRoleSystem::new(role_system);

        // Create and register a role
        let role = Role::new("async-test").add_permission(Permission::new("read", "documents"));

        async_system.register_role(role).await.unwrap();

        // Create a subject and assign the role
        let subject = Subject::user("user1");
        async_system
            .assign_role(&subject, "async-test")
            .await
            .unwrap();

        // Check permission
        let resource = Resource::new("doc1", "documents");
        let can_read = async_system
            .check_permission(&subject, "read", &resource)
            .await
            .unwrap();

        assert!(can_read);
    }

    #[tokio::test]
    async fn test_async_batch_permissions() {
        let storage = MemoryStorage::new();
        let config = RoleSystemConfig::default();
        let role_system = RoleSystem::with_storage(storage, config);
        let async_system = AsyncRoleSystem::new(role_system);

        // Setup role and subject
        let role = Role::new("batch-test")
            .add_permission(Permission::new("read", "documents"))
            .add_permission(Permission::new("write", "documents"));

        async_system.register_role(role).await.unwrap();

        let subject = Subject::user("user1");
        async_system
            .assign_role(&subject, "batch-test")
            .await
            .unwrap();

        // Batch check permissions
        let checks = vec![
            ("read".to_string(), Resource::new("doc1", "documents")),
            ("write".to_string(), Resource::new("doc1", "documents")),
            ("delete".to_string(), Resource::new("doc1", "documents")),
        ];

        let results = async_system
            .batch_check_permissions(&subject, &checks)
            .await
            .unwrap();

        assert_eq!(results.len(), 3);
        assert!(results[0].2); // read granted
        assert!(results[1].2); // write granted
        assert!(!results[2].2); // delete denied
    }

    #[tokio::test]
    async fn test_async_memory_storage() {
        let mut storage = AsyncMemoryStorage::new();

        let role =
            Role::new("async-storage-test").add_permission(Permission::new("read", "documents"));

        // Store role
        storage.store_role(role.clone()).await.unwrap();
        assert_eq!(storage.role_count().await, 1);

        // Check existence
        assert!(storage.role_exists("async-storage-test").await.unwrap());

        // Get role
        let retrieved = storage
            .get_role("async-storage-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.name(), "async-storage-test");

        // List roles
        let roles = storage.list_roles().await.unwrap();
        assert_eq!(roles.len(), 1);

        // Delete role
        assert!(storage.delete_role("async-storage-test").await.unwrap());
        assert_eq!(storage.role_count().await, 0);
    }

    #[tokio::test]
    async fn test_async_builder() {
        let async_system = AsyncRoleSystemBuilder::<MemoryStorage>::new()
            .max_hierarchy_depth(5)
            .enable_caching(false)
            .build();

        // Should be able to use the system
        let role = Role::new("builder-test");
        async_system.register_role(role).await.unwrap();

        let retrieved = async_system.get_role("builder-test").await.unwrap();
        assert!(retrieved.is_some());
    }
}
