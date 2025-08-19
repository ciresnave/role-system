//! Database storage backend for the role system.

#[cfg(feature = "database")]
use crate::{
    error::{Error, Result},
    role::Role,
    storage::Storage,
};

#[cfg(not(feature = "database"))]
use crate::error::Error;

#[cfg(feature = "database")]
use sqlx::{PgPool, Row};

#[cfg(feature = "database")]
/// PostgreSQL storage backend for the role system.
pub struct DatabaseStorage {
    pool: PgPool,
    table_prefix: String,
}

#[cfg(feature = "database")]
impl DatabaseStorage {
    /// Create a new database storage backend.
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| Error::Storage(format!("Database connection failed: {}", e)))?;

        let storage = Self {
            pool,
            table_prefix: "rbac_".to_string(),
        };

        // Initialize database schema
        storage.initialize_schema().await?;

        Ok(storage)
    }

    /// Create a new database storage backend with custom table prefix.
    pub async fn new_with_prefix(database_url: &str, table_prefix: String) -> Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| Error::Storage(format!("Database connection failed: {}", e)))?;

        let storage = Self { pool, table_prefix };

        // Initialize database schema
        storage.initialize_schema().await?;

        Ok(storage)
    }

    /// Initialize the database schema.
    async fn initialize_schema(&self) -> Result<()> {
        let roles_table = format!("{}roles", self.table_prefix);
        let role_permissions_table = format!("{}role_permissions", self.table_prefix);
        let subjects_table = format!("{}subjects", self.table_prefix);
        let subject_roles_table = format!("{}subject_roles", self.table_prefix);

        // Create roles table
        let create_roles = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                name VARCHAR(255) PRIMARY KEY,
                description TEXT,
                active BOOLEAN NOT NULL DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
            roles_table
        );

        // Create role permissions table
        let create_role_permissions = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id SERIAL PRIMARY KEY,
                role_name VARCHAR(255) NOT NULL REFERENCES {}(name) ON DELETE CASCADE,
                action VARCHAR(255) NOT NULL,
                resource_type VARCHAR(255) NOT NULL,
                instance_id VARCHAR(255),
                condition_json JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(role_name, action, resource_type, instance_id)
            )
            "#,
            role_permissions_table, roles_table
        );

        // Create subjects table
        let create_subjects = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id VARCHAR(255) PRIMARY KEY,
                subject_type VARCHAR(50) NOT NULL,
                display_name VARCHAR(255),
                metadata JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
            subjects_table
        );

        // Create subject roles table
        let create_subject_roles = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id SERIAL PRIMARY KEY,
                subject_id VARCHAR(255) NOT NULL REFERENCES {}(id) ON DELETE CASCADE,
                role_name VARCHAR(255) NOT NULL REFERENCES {}(name) ON DELETE CASCADE,
                assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                assigned_by VARCHAR(255),
                UNIQUE(subject_id, role_name)
            )
            "#,
            subject_roles_table, subjects_table, roles_table
        );

        // Execute schema creation
        sqlx::query(&create_roles)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to create roles table: {}", e)))?;

        sqlx::query(&create_role_permissions)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                Error::Storage(format!("Failed to create role_permissions table: {}", e))
            })?;

        sqlx::query(&create_subjects)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to create subjects table: {}", e)))?;

        sqlx::query(&create_subject_roles)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to create subject_roles table: {}", e)))?;

        Ok(())
    }

    /// Get the roles table name.
    fn roles_table(&self) -> String {
        format!("{}roles", self.table_prefix)
    }

    /// Get the role permissions table name.
    fn role_permissions_table(&self) -> String {
        format!("{}role_permissions", self.table_prefix)
    }

    /// Get the subjects table name.
    #[allow(dead_code)]
    fn subjects_table(&self) -> String {
        format!("{}subjects", self.table_prefix)
    }

    /// Get the subject roles table name.
    #[allow(dead_code)]
    fn subject_roles_table(&self) -> String {
        format!("{}subject_roles", self.table_prefix)
    }

    /// Store role permissions in the database.
    async fn store_role_permissions(&self, role_name: &str, role: &Role) -> Result<()> {
        let table = self.role_permissions_table();

        // Delete existing permissions for this role
        let delete_query = format!("DELETE FROM {} WHERE role_name = $1", table);
        sqlx::query(&delete_query)
            .bind(role_name)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to delete old permissions: {}", e)))?;

        // Insert new permissions
        for permission in role.permissions().permissions() {
            let insert_query = format!(
                "INSERT INTO {} (role_name, action, resource_type, instance_id) VALUES ($1, $2, $3, $4)",
                table
            );

            sqlx::query(&insert_query)
                .bind(role_name)
                .bind(permission.action())
                .bind(permission.resource_type())
                .bind(permission.instance())
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Storage(format!("Failed to insert permission: {}", e)))?;
        }

        Ok(())
    }

    /// Load role permissions from the database.
    async fn load_role_permissions(
        &self,
        role_name: &str,
    ) -> Result<Vec<crate::permission::Permission>> {
        let table = self.role_permissions_table();
        let query = format!(
            "SELECT action, resource_type, instance_id FROM {} WHERE role_name = $1",
            table
        );

        let rows = sqlx::query(&query)
            .bind(role_name)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to load permissions: {}", e)))?;

        let mut permissions = Vec::new();
        for row in rows {
            let action: String = row.get("action");
            let resource_type: String = row.get("resource_type");
            let instance_id: Option<String> = row.get("instance_id");

            let permission = if let Some(instance) = instance_id {
                crate::permission::Permission::with_instance(action, resource_type, instance)
            } else {
                crate::permission::Permission::new(action, resource_type)
            };

            permissions.push(permission);
        }

        Ok(permissions)
    }

    /// Store a role in the database (async implementation).
    pub async fn store_role_async(&mut self, role: Role) -> Result<()> {
        let roles_table = self.roles_table();

        // Start a transaction
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Storage(format!("Failed to start transaction: {}", e)))?;

        // Insert or update role
        let upsert_query = format!(
            r#"
            INSERT INTO {} (name, description, active, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                active = EXCLUDED.active,
                updated_at = NOW()
            "#,
            roles_table
        );

        sqlx::query(&upsert_query)
            .bind(role.name())
            .bind(role.description())
            .bind(role.is_active())
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Storage(format!("Failed to store role: {}", e)))?;

        // Store permissions
        self.store_role_permissions(role.name(), &role).await?;

        // Commit transaction
        tx.commit()
            .await
            .map_err(|e| Error::Storage(format!("Failed to commit transaction: {}", e)))?;

        Ok(())
    }

    /// Get a role from the database (async implementation).
    pub async fn get_role_async(&self, name: &str) -> Result<Option<Role>> {
        let roles_table = self.roles_table();
        let query = format!(
            "SELECT name, description, active FROM {} WHERE name = $1 AND active = true",
            roles_table
        );

        let row = sqlx::query(&query)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to get role: {}", e)))?;

        if let Some(row) = row {
            let role_name: String = row.get("name");
            let description: Option<String> = row.get("description");
            let is_active: bool = row.get("active");

            let mut role = Role::new(role_name);
            if let Some(desc) = description {
                role = role.with_description(desc);
            }
            if !is_active {
                role = role.deactivate();
            }

            // Load permissions
            let permissions = self.load_role_permissions(name).await?;
            for permission in permissions {
                role = role.add_permission(permission);
            }

            Ok(Some(role))
        } else {
            Ok(None)
        }
    }

    /// Delete a role from the database (async implementation).
    pub async fn delete_role_async(&mut self, name: &str) -> Result<bool> {
        let roles_table = self.roles_table();

        // Soft delete by setting active = false
        let update_query = format!(
            "UPDATE {} SET active = false, updated_at = NOW() WHERE name = $1 AND active = true",
            roles_table
        );

        let result = sqlx::query(&update_query)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to delete role: {}", e)))?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a role exists in the database (async implementation).
    pub async fn role_exists_async(&self, name: &str) -> Result<bool> {
        let roles_table = self.roles_table();
        let query = format!(
            "SELECT 1 FROM {} WHERE name = $1 AND active = true LIMIT 1",
            roles_table
        );

        let row = sqlx::query(&query)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to check role existence: {}", e)))?;

        Ok(row.is_some())
    }

    /// List all roles in the database (async implementation).
    pub async fn list_roles_async(&self) -> Result<Vec<String>> {
        let roles_table = self.roles_table();
        let query = format!(
            "SELECT name FROM {} WHERE active = true ORDER BY name",
            roles_table
        );

        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to list roles: {}", e)))?;

        let roles: Vec<String> = rows.into_iter().map(|row| row.get("name")).collect();
        Ok(roles)
    }

    /// Get the number of roles in the database (async implementation).
    pub async fn role_count_async(&self) -> Result<usize> {
        let roles_table = self.roles_table();
        let query = format!(
            "SELECT COUNT(*) as count FROM {} WHERE active = true",
            roles_table
        );

        let row = sqlx::query(&query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Storage(format!("Failed to count roles: {}", e)))?;

        let count: i64 = row.get("count");
        Ok(count as usize)
    }
}

#[cfg(feature = "database")]
impl Storage for DatabaseStorage {
    fn store_role(&mut self, _role: Role) -> Result<()> {
        Err(Error::Storage(
            "Use store_role_async for database storage".to_string(),
        ))
    }

    fn get_role(&self, _name: &str) -> Result<Option<Role>> {
        Err(Error::Storage(
            "Use get_role_async for database storage".to_string(),
        ))
    }

    fn role_exists(&self, _name: &str) -> Result<bool> {
        Err(Error::Storage(
            "Use role_exists_async for database storage".to_string(),
        ))
    }

    fn delete_role(&mut self, _name: &str) -> Result<bool> {
        Err(Error::Storage(
            "Use delete_role_async for database storage".to_string(),
        ))
    }

    fn list_roles(&self) -> Result<Vec<String>> {
        Err(Error::Storage(
            "Use list_roles_async for database storage".to_string(),
        ))
    }

    fn update_role(&mut self, role: Role) -> Result<()> {
        // For database storage, update is the same as store
        self.store_role(role)
    }

    fn role_count(&self) -> usize {
        // For database storage, this should use the async method
        // Return 0 as a placeholder since we can't use async here
        0
    }
}

#[cfg(feature = "database")]
impl DatabaseStorage {
    /// Perform a health check on the database connection.
    pub async fn health_check(&self) -> Result<bool> {
        let result = sqlx::query("SELECT 1").fetch_optional(&self.pool).await;

        match result {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(_) => Ok(false),
        }
    }

    /// Get database connection statistics.
    pub fn connection_stats(&self) -> DatabaseStats {
        DatabaseStats {
            active_connections: self.pool.size() as usize,
            idle_connections: self.pool.num_idle(),
            max_connections: self.pool.options().get_max_connections() as usize,
        }
    }

    /// Close all database connections.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[cfg(feature = "database")]
/// Database connection statistics.
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub active_connections: usize,
    pub idle_connections: usize,
    pub max_connections: usize,
}

#[cfg(not(feature = "database"))]
/// Placeholder when database feature is not enabled.
pub struct DatabaseStorage;

#[cfg(not(feature = "database"))]
impl DatabaseStorage {
    /// Create a new database storage (disabled).
    pub async fn new(_database_url: &str) -> std::result::Result<Self, Error> {
        Err(Error::Storage(
            "Database storage not available. Enable 'database' feature.".to_string(),
        ))
    }
}

#[cfg(all(test, feature = "database"))]
mod tests {
    use super::*;
    use crate::{permission::Permission, role::Role};

    // Note: These tests require a running PostgreSQL database
    // and the DATABASE_URL environment variable to be set

    async fn setup_test_db() -> DatabaseStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:password@localhost/rbac_test".to_string());

        DatabaseStorage::new(&database_url)
            .await
            .expect("Failed to setup test database")
    }

    #[tokio::test]
    #[ignore] // Ignore by default since it requires a database
    async fn test_database_storage_role_operations() {
        let mut storage = setup_test_db().await;

        let role = Role::new("test_role")
            .with_description("Test role for database storage")
            .add_permission(Permission::new("read", "documents"))
            .add_permission(Permission::new("write", "documents"));

        // Store role
        storage.store_role_async(role.clone()).await.unwrap();

        // Check existence
        assert!(storage.role_exists_async("test_role").await.unwrap());

        // Get role
        let retrieved = storage.get_role_async("test_role").await.unwrap().unwrap();
        assert_eq!(retrieved.name(), "test_role");
        assert_eq!(
            retrieved.description(),
            Some("Test role for database storage")
        );
        assert_eq!(retrieved.permissions().permissions().len(), 2);

        // List roles
        let roles = storage.list_roles_async().await.unwrap();
        assert!(roles.contains(&"test_role".to_string()));

        // Delete role
        assert!(storage.delete_role_async("test_role").await.unwrap());
        assert!(!storage.role_exists_async("test_role").await.unwrap());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since it requires a database
    async fn test_database_health_check() {
        let storage = setup_test_db().await;
        assert!(storage.health_check().await.unwrap());
    }
}
