//! Batch operations API for high-performance bulk operations

use crate::{Error, Permission, Resource, Role, RoleSystem, Subject};

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchResult<T> {
    /// Successful operations with their results
    pub successes: Vec<(usize, T)>,
    /// Failed operations with their errors
    pub failures: Vec<(usize, Error)>,
}

impl<T> BatchResult<T> {
    /// Create a new empty batch result
    pub fn new() -> Self {
        Self {
            successes: Vec::new(),
            failures: Vec::new(),
        }
    }

    /// Add a successful result
    pub fn add_success(&mut self, index: usize, result: T) {
        self.successes.push((index, result));
    }

    /// Add a failed result
    pub fn add_failure(&mut self, index: usize, error: Error) {
        self.failures.push((index, error));
    }

    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.successes.len() + self.failures.len();
        if total == 0 {
            return 0.0;
        }
        (self.successes.len() as f64 / total as f64) * 100.0
    }

    /// Check if all operations succeeded
    pub fn all_succeeded(&self) -> bool {
        self.failures.is_empty()
    }

    /// Get total number of operations
    pub fn total_operations(&self) -> usize {
        self.successes.len() + self.failures.len()
    }
}

impl<T> Default for BatchResult<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch permission check request
#[derive(Debug, Clone)]
pub struct BatchPermissionCheck {
    pub subject: Subject,
    pub permission: Permission,
    pub resource: Resource,
}

impl BatchPermissionCheck {
    /// Create a new batch permission check
    pub fn new(subject: Subject, permission: Permission, resource: Resource) -> Self {
        Self {
            subject,
            permission,
            resource,
        }
    }
}

/// Batch role assignment request
#[derive(Debug, Clone)]
pub struct BatchRoleAssignment {
    pub subject: Subject,
    pub role: Role,
    pub assign: bool, // true for assign, false for revoke
}

impl BatchRoleAssignment {
    /// Create a new batch role assignment
    pub fn new_assignment(subject: Subject, role: Role) -> Self {
        Self {
            subject,
            role,
            assign: true,
        }
    }

    /// Create a new batch role revocation
    pub fn new_revocation(subject: Subject, role: Role) -> Self {
        Self {
            subject,
            role,
            assign: false,
        }
    }
}

/// Batch operations configuration
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of operations to process concurrently
    pub max_concurrency: usize,
    /// Whether to stop on first failure or continue processing
    pub fail_fast: bool,
    /// Timeout for the entire batch operation (in milliseconds)
    pub timeout_ms: Option<u64>,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_concurrency: num_cpus::get().max(1),
            fail_fast: false,
            timeout_ms: None,
        }
    }
}

/// Extension trait for RoleSystem to support batch operations
pub trait BatchOperations {
    /// Perform batch permission checks
    fn batch_check_permissions(
        &self,
        checks: Vec<BatchPermissionCheck>,
    ) -> Result<BatchResult<bool>, Error>;

    /// Perform batch role assignments and revocations (requires mutable access)
    fn batch_role_operations(
        &mut self,
        operations: Vec<BatchRoleAssignment>,
    ) -> Result<BatchResult<()>, Error>;
}

impl BatchOperations for RoleSystem {
    fn batch_check_permissions(
        &self,
        checks: Vec<BatchPermissionCheck>,
    ) -> Result<BatchResult<bool>, Error> {
        let mut result = BatchResult::new();

        for (i, check) in checks.iter().enumerate() {
            match self.check_permission(&check.subject, check.permission.action(), &check.resource)
            {
                Ok(allowed) => result.add_success(i, allowed),
                Err(error) => result.add_failure(i, error),
            }
        }

        Ok(result)
    }

    fn batch_role_operations(
        &mut self,
        operations: Vec<BatchRoleAssignment>,
    ) -> Result<BatchResult<()>, Error> {
        let mut result = BatchResult::new();

        for (i, operation) in operations.iter().enumerate() {
            let op_result = if operation.assign {
                self.assign_role(&operation.subject, operation.role.name())
            } else {
                self.remove_role(&operation.subject, operation.role.name())
            };

            match op_result {
                Ok(()) => result.add_success(i, ()),
                Err(error) => result.add_failure(i, error),
            }
        }

        Ok(result)
    }
}
