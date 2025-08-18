//! Storage abstractions for persisting role system data.

use crate::{error::Result, role::Role};
use dashmap::DashMap;
use std::sync::Arc;

/// Trait for storing and retrieving role system data.
pub trait Storage: Send + Sync {
    /// Store a role.
    fn store_role(&mut self, role: Role) -> Result<()>;

    /// Get a role by name.
    fn get_role(&self, name: &str) -> Result<Option<Role>>;

    /// Check if a role exists.
    fn role_exists(&self, name: &str) -> Result<bool>;

    /// Delete a role.
    fn delete_role(&mut self, name: &str) -> Result<bool>;

    /// List all role names.
    fn list_roles(&self) -> Result<Vec<String>>;

    /// Update an existing role.
    fn update_role(&mut self, role: Role) -> Result<()>;
}

/// In-memory storage implementation using DashMap for thread safety.
#[derive(Debug, Default, Clone)]
pub struct MemoryStorage {
    roles: Arc<DashMap<String, Role>>,
}

impl MemoryStorage {
    /// Create a new memory storage instance.
    pub fn new() -> Self {
        Self {
            roles: Arc::new(DashMap::new()),
        }
    }

    /// Get the number of stored roles.
    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    /// Clear all stored data.
    pub fn clear(&mut self) {
        self.roles.clear();
    }
}

impl Storage for MemoryStorage {
    fn store_role(&mut self, role: Role) -> Result<()> {
        let name = role.name().to_string();
        self.roles.insert(name, role);
        Ok(())
    }

    fn get_role(&self, name: &str) -> Result<Option<Role>> {
        Ok(self.roles.get(name).map(|r| r.clone()))
    }

    fn role_exists(&self, name: &str) -> Result<bool> {
        Ok(self.roles.contains_key(name))
    }

    fn delete_role(&mut self, name: &str) -> Result<bool> {
        Ok(self.roles.remove(name).is_some())
    }

    fn list_roles(&self) -> Result<Vec<String>> {
        Ok(self.roles.iter().map(|entry| entry.key().clone()).collect())
    }

    fn update_role(&mut self, role: Role) -> Result<()> {
        let name = role.name().to_string();
        self.roles.insert(name, role);
        Ok(())
    }
}

/// File-based storage implementation (requires persistence feature).
#[cfg(feature = "persistence")]
pub mod file_storage {
    use super::*;
    use crate::error::Error;
    use std::{
        collections::HashMap,
        fs::{File, OpenOptions},
        io::{BufReader, BufWriter},
        path::{Path, PathBuf},
        sync::RwLock,
    };

    /// File-based storage that persists roles to JSON files.
    #[derive(Debug)]
    pub struct FileStorage {
        storage_path: PathBuf,
        roles: Arc<RwLock<HashMap<String, Role>>>,
    }

    impl FileStorage {
        /// Create a new file storage instance.
        pub fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
            let storage_path = storage_path.as_ref().to_path_buf();

            // Create directory if it doesn't exist
            if let Some(parent) = storage_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Storage(format!("Failed to create storage directory: {}", e))
                })?;
            }

            let mut storage = Self {
                storage_path,
                roles: Arc::new(RwLock::new(HashMap::new())),
            };

            // Load existing data if the file exists
            storage.load_from_disk()?;

            Ok(storage)
        }

        /// Load roles from disk.
        fn load_from_disk(&mut self) -> Result<()> {
            if !self.storage_path.exists() {
                return Ok(());
            }

            let file = File::open(&self.storage_path)
                .map_err(|e| Error::Storage(format!("Failed to open storage file: {}", e)))?;

            let reader = BufReader::new(file);
            let roles: HashMap<String, Role> = serde_json::from_reader(reader)?;

            *self.roles.write().unwrap() = roles;
            Ok(())
        }

        /// Save roles to disk.
        fn save_to_disk(&self) -> Result<()> {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&self.storage_path)
                .map_err(|e| Error::Storage(format!("Failed to create storage file: {}", e)))?;

            let writer = BufWriter::new(file);
            let roles = self.roles.read().unwrap();
            serde_json::to_writer_pretty(writer, &*roles)?;
            Ok(())
        }

        /// Get the storage file path.
        pub fn storage_path(&self) -> &Path {
            &self.storage_path
        }

        /// Get the number of stored roles.
        pub fn role_count(&self) -> usize {
            self.roles.read().unwrap().len()
        }
    }

    impl Storage for FileStorage {
        fn store_role(&mut self, role: Role) -> Result<()> {
            let name = role.name().to_string();
            self.roles.write().unwrap().insert(name, role);
            self.save_to_disk()
        }

        fn get_role(&self, name: &str) -> Result<Option<Role>> {
            Ok(self.roles.read().unwrap().get(name).cloned())
        }

        fn role_exists(&self, name: &str) -> Result<bool> {
            Ok(self.roles.read().unwrap().contains_key(name))
        }

        fn delete_role(&mut self, name: &str) -> Result<bool> {
            let removed = self.roles.write().unwrap().remove(name).is_some();
            if removed {
                self.save_to_disk()?;
            }
            Ok(removed)
        }

        fn list_roles(&self) -> Result<Vec<String>> {
            Ok(self.roles.read().unwrap().keys().cloned().collect())
        }

        fn update_role(&mut self, role: Role) -> Result<()> {
            let name = role.name().to_string();
            self.roles.write().unwrap().insert(name, role);
            self.save_to_disk()
        }
    }
}

#[cfg(feature = "persistence")]
pub use file_storage::FileStorage;

/// Composite storage that can combine multiple storage backends.
pub struct CompositeStorage {
    primary: Box<dyn Storage>,
    secondary: Option<Box<dyn Storage>>,
}

impl CompositeStorage {
    /// Create a new composite storage with primary storage.
    pub fn new(primary: Box<dyn Storage>) -> Self {
        Self {
            primary,
            secondary: None,
        }
    }

    /// Add a secondary storage backend.
    pub fn with_secondary(mut self, secondary: Box<dyn Storage>) -> Self {
        self.secondary = Some(secondary);
        self
    }
}

impl Storage for CompositeStorage {
    fn store_role(&mut self, role: Role) -> Result<()> {
        // Store in primary first
        self.primary.store_role(role.clone())?;

        // Then store in secondary if available
        if let Some(secondary) = &mut self.secondary {
            secondary.store_role(role)?;
        }

        Ok(())
    }

    fn get_role(&self, name: &str) -> Result<Option<Role>> {
        // Try primary first
        match self.primary.get_role(name)? {
            Some(role) => Ok(Some(role)),
            None => {
                // Fallback to secondary
                if let Some(secondary) = &self.secondary {
                    secondary.get_role(name)
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn role_exists(&self, name: &str) -> Result<bool> {
        if self.primary.role_exists(name)? {
            Ok(true)
        } else if let Some(secondary) = &self.secondary {
            secondary.role_exists(name)
        } else {
            Ok(false)
        }
    }

    fn delete_role(&mut self, name: &str) -> Result<bool> {
        let mut deleted = false;

        if self.primary.delete_role(name)? {
            deleted = true;
        }

        if let Some(secondary) = &mut self.secondary
            && secondary.delete_role(name)?
        {
            deleted = true;
        }

        Ok(deleted)
    }

    fn list_roles(&self) -> Result<Vec<String>> {
        let mut roles = self.primary.list_roles()?;

        if let Some(secondary) = &self.secondary {
            let secondary_roles = secondary.list_roles()?;
            for role in secondary_roles {
                if !roles.contains(&role) {
                    roles.push(role);
                }
            }
        }

        roles.sort();
        Ok(roles)
    }

    fn update_role(&mut self, role: Role) -> Result<()> {
        self.primary.update_role(role.clone())?;

        if let Some(secondary) = &mut self.secondary {
            secondary.update_role(role)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{permission::Permission, role::Role};

    #[test]
    fn test_memory_storage() {
        let mut storage = MemoryStorage::new();

        let role = Role::new("test-role").add_permission(Permission::new("read", "documents"));

        // Store role
        storage.store_role(role.clone()).unwrap();
        assert_eq!(storage.role_count(), 1);

        // Check existence
        assert!(storage.role_exists("test-role").unwrap());
        assert!(!storage.role_exists("non-existent").unwrap());

        // Get role
        let retrieved = storage.get_role("test-role").unwrap().unwrap();
        assert_eq!(retrieved.name(), "test-role");

        // List roles
        let roles = storage.list_roles().unwrap();
        assert_eq!(roles.len(), 1);
        assert!(roles.contains(&"test-role".to_string()));

        // Delete role
        assert!(storage.delete_role("test-role").unwrap());
        assert!(!storage.role_exists("test-role").unwrap());
        assert_eq!(storage.role_count(), 0);
    }

    #[cfg(feature = "persistence")]
    #[test]
    fn test_file_storage() {
        use std::env;

        let temp_dir = env::temp_dir();
        let storage_path = temp_dir.join("test_roles.json");

        // Clean up any existing file
        let _ = std::fs::remove_file(&storage_path);

        {
            let mut storage = FileStorage::new(&storage_path).unwrap();

            let role =
                Role::new("file-test-role").add_permission(Permission::new("read", "documents"));

            // Store role
            storage.store_role(role.clone()).unwrap();
            assert_eq!(storage.role_count(), 1);

            // Verify file was created
            assert!(storage_path.exists());
        }

        // Create new storage instance to test persistence
        {
            let storage = FileStorage::new(&storage_path).unwrap();
            assert_eq!(storage.role_count(), 1);

            let retrieved = storage.get_role("file-test-role").unwrap().unwrap();
            assert_eq!(retrieved.name(), "file-test-role");
        }

        // Clean up
        let _ = std::fs::remove_file(&storage_path);
    }

    #[test]
    fn test_composite_storage() {
        let primary = Box::new(MemoryStorage::new());
        let secondary = Box::new(MemoryStorage::new());

        let mut storage = CompositeStorage::new(primary).with_secondary(secondary);

        let role = Role::new("composite-test").add_permission(Permission::new("read", "documents"));

        // Store in both
        storage.store_role(role.clone()).unwrap();

        // Should be able to retrieve
        let retrieved = storage.get_role("composite-test").unwrap().unwrap();
        assert_eq!(retrieved.name(), "composite-test");

        // Should appear in list
        let roles = storage.list_roles().unwrap();
        assert!(roles.contains(&"composite-test".to_string()));
    }
}
