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
use tokio::sync::{RwLock, Mutex};

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
        let role = Role::new("async-test")
            .add_permission(Permission::new("read", "documents"));
        
        async_system.register_role(role).await.unwrap();

        // Create a subject and assign the role
        let subject = Subject::user("user1");
        async_system.assign_role(&subject, "async-test").await.unwrap();

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
        async_system.assign_role(&subject, "batch-test").await.unwrap();

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
        
        let role = Role::new("async-storage-test")
            .add_permission(Permission::new("read", "documents"));
        
        // Store role
        storage.store_role(role.clone()).await.unwrap();
        assert_eq!(storage.role_count().await, 1);
        
        // Check existence
        assert!(storage.role_exists("async-storage-test").await.unwrap());
        
        // Get role
        let retrieved = storage.get_role("async-storage-test").await.unwrap().unwrap();
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
