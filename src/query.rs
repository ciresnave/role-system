//! Query interface for the role system.
//!
//! This module provides a high-level query API for analyzing and inspecting
//! the role system state. It offers complex queries for finding subjects,
//! roles, permissions, and generating statistics.

use crate::{
    core::RoleSystem, error::Result, permission::Permission, storage::Storage, subject::Subject,
};
use std::collections::{HashMap, HashSet};

/// Query interface for role system analysis.
pub struct RoleQuery<'a, S: Storage> {
    system: &'a RoleSystem<S>,
}

/// Trait for providing query capabilities.
pub trait RoleSystemQuery<S: Storage> {
    /// Get a query interface for this role system.
    fn query(&self) -> RoleQuery<'_, S>;
}

impl<S: Storage> RoleSystemQuery<S> for RoleSystem<S> {
    fn query(&self) -> RoleQuery<'_, S> {
        RoleQuery { system: self }
    }
}

impl<'a, S: Storage> RoleQuery<'a, S> {
    /// Find all subjects that have the specified role.
    pub fn find_subjects_with_role(&self, role_name: &str) -> Result<Vec<String>> {
        let mut subjects = Vec::new();

        for entry in self.system.subject_roles() {
            let (subject_id, roles) = (entry.key(), entry.value());
            if roles.contains(role_name) {
                subjects.push(subject_id.clone());
            }
        }

        Ok(subjects)
    }

    /// Find all subjects that have any of the specified roles.
    pub fn subjects_with_any_role(&self, role_names: &[&str]) -> Result<Vec<String>> {
        let mut subjects = Vec::new();
        let role_set: HashSet<&str> = role_names.iter().copied().collect();

        for entry in self.system.subject_roles() {
            let (subject_id, roles) = (entry.key(), entry.value());
            if roles.iter().any(|role| role_set.contains(role.as_str())) {
                subjects.push(subject_id.clone());
            }
        }

        Ok(subjects)
    }

    /// Find all subjects that have all of the specified roles.
    pub fn subjects_with_all_roles(&self, role_names: &[&str]) -> Result<Vec<String>> {
        let mut subjects = Vec::new();
        let role_set: HashSet<&str> = role_names.iter().copied().collect();

        for entry in self.system.subject_roles() {
            let (subject_id, roles) = (entry.key(), entry.value());
            let subject_role_set: HashSet<&str> = roles.iter().map(|s| s.as_str()).collect();
            if role_set.is_subset(&subject_role_set) {
                subjects.push(subject_id.clone());
            }
        }

        Ok(subjects)
    }

    /// Get all effective permissions for a subject.
    pub fn effective_permissions(&self, subject: &Subject) -> Result<Vec<Permission>> {
        let mut permissions = Vec::new();
        let subject_roles = self.system.get_subject_roles(subject)?;

        for role_name in subject_roles {
            if let Some(role) = self.system.get_role(&role_name)? {
                for permission in role.permissions().permissions() {
                    if !permissions.contains(permission) {
                        permissions.push(permission.clone());
                    }
                }
            }
        }

        Ok(permissions)
    }

    /// Find all roles that contain a specific permission.
    pub fn roles_with_permission(&self, permission: &Permission) -> Result<Vec<String>> {
        let mut matching_roles = Vec::new();
        let role_names = self.system.storage().list_roles()?;

        for role_name in role_names {
            if let Some(role) = self.system.storage().get_role(&role_name)?
                && role.permissions().permissions().contains(permission)
            {
                matching_roles.push(role_name);
            }
        }

        Ok(matching_roles)
    }

    /// Get role hierarchy information.
    pub fn role_hierarchy(&self) -> HashMap<String, Vec<String>> {
        let mut hierarchy = HashMap::new();

        for entry in self.system.role_hierarchy() {
            let (child, parents) = (entry.key(), entry.value());
            hierarchy.insert(child.clone(), parents.iter().cloned().collect());
        }

        hierarchy
    }

    /// Find all parent roles of a given role.
    pub fn parent_roles(&self, child_role: &str) -> Vec<String> {
        if let Some(parents) = self.system.role_hierarchy().get(child_role) {
            parents.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Find all child roles of a given role.
    pub fn child_roles(&self, parent_role: &str) -> Vec<String> {
        let mut children = Vec::new();

        for entry in self.system.role_hierarchy() {
            let (child, parents) = (entry.key(), entry.value());
            if parents.contains(parent_role) {
                children.push(child.clone());
            }
        }

        children
    }

    /// Generate system statistics.
    pub fn system_statistics(&self) -> Result<SystemStatistics> {
        let roles = self.system.storage().list_roles()?;
        let mut total_permissions = 0;

        for role_name in &roles {
            if let Some(role) = self.system.storage().get_role(role_name)? {
                total_permissions += role.permissions().permissions().len();
            }
        }

        // Calculate unique subjects
        let mut unique_subjects = HashSet::new();
        for entry in self.system.subject_roles() {
            unique_subjects.insert(entry.key().clone());
        }

        Ok(SystemStatistics {
            total_roles: roles.len(),
            total_permissions,
            total_subjects: unique_subjects.len(),
            total_role_assignments: self.count_role_assignments()?,
        })
    }

    /// Get permission coverage statistics.
    pub fn permission_coverage(&self, subjects: &[Subject]) -> Result<PermissionCoverage> {
        let mut permission_counts: HashMap<String, usize> = HashMap::new();

        for subject in subjects {
            let permissions = self.effective_permissions(subject)?;
            for permission in permissions {
                let perm_str = format!("{}:{}", permission.action(), permission.resource_type());
                *permission_counts.entry(perm_str).or_insert(0) += 1;
            }
        }

        let all_roles = self.system.storage().list_roles()?;
        let mut total_possible_permissions = 0;

        for role_name in &all_roles {
            if let Some(role) = self.system.storage().get_role(role_name)? {
                total_possible_permissions += role.permissions().permissions().len();
            }
        }

        Ok(PermissionCoverage {
            permission_usage: permission_counts,
            total_possible_permissions,
            subjects_analyzed: subjects.len(),
        })
    }

    /// Find unused roles (roles with no subjects assigned).
    pub fn unused_roles(&self) -> Result<Vec<String>> {
        let all_roles = self.system.storage().list_roles()?;
        let mut used_roles = HashSet::new();

        for entry in self.system.subject_roles() {
            for role in entry.value().iter() {
                used_roles.insert(role.clone());
            }
        }

        Ok(all_roles
            .into_iter()
            .filter(|role| !used_roles.contains(role))
            .collect())
    }

    /// Get the maximum depth of the role hierarchy.
    pub fn max_hierarchy_depth(&self) -> Result<usize> {
        let roles = self.system.storage().list_roles()?;
        let mut max_depth = 0;

        for role_name in roles {
            let depth = self.calculate_role_depth(&role_name, &mut HashSet::new(), 0)?;
            max_depth = max_depth.max(depth);
        }

        Ok(max_depth)
    }

    /// Calculate the depth of a specific role in the hierarchy.
    fn calculate_role_depth(
        &self,
        role: &str,
        visited: &mut HashSet<String>,
        current_depth: usize,
    ) -> Result<usize> {
        if current_depth >= self.system.config().max_hierarchy_depth {
            return Ok(current_depth);
        }

        if !visited.insert(role.to_string()) {
            return Ok(current_depth); // Cycle detected
        }

        let mut max_child_depth = current_depth;

        if let Some(parents) = self.system.role_hierarchy().get(role) {
            for parent in parents.iter() {
                let parent_depth = self.calculate_role_depth(parent, visited, current_depth + 1)?;
                max_child_depth = max_child_depth.max(parent_depth);
            }
        }

        visited.remove(role);
        Ok(max_child_depth)
    }

    /// Count total role assignments across all subjects.
    fn count_role_assignments(&self) -> Result<usize> {
        let mut total = 0;
        for entry in self.system.subject_roles() {
            total += entry.value().len();
        }
        Ok(total)
    }
}

/// System-wide statistics.
#[derive(Debug, Clone)]
pub struct SystemStatistics {
    /// Total number of roles defined.
    pub total_roles: usize,
    /// Total number of permissions across all roles.
    pub total_permissions: usize,
    /// Total number of subjects with role assignments.
    pub total_subjects: usize,
    /// Total number of role assignments.
    pub total_role_assignments: usize,
}

/// Permission coverage analysis.
#[derive(Debug, Clone)]
pub struct PermissionCoverage {
    /// How many subjects have each permission.
    pub permission_usage: HashMap<String, usize>,
    /// Total number of unique permissions available.
    pub total_possible_permissions: usize,
    /// Number of subjects analyzed.
    pub subjects_analyzed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::RoleSystem, permission::Permission, role::Role, storage::MemoryStorage,
        subject::Subject,
    };

    #[test]
    fn test_query_interface() {
        let mut system = RoleSystem::<MemoryStorage>::new();

        // Create test data
        let admin_role = Role::new("admin")
            .add_permission(Permission::new("read", "documents"))
            .add_permission(Permission::new("write", "documents"));

        let user_role = Role::new("user").add_permission(Permission::new("read", "documents"));

        system.register_role(admin_role).unwrap();
        system.register_role(user_role).unwrap();

        let admin_user = Subject::user("admin1");
        let regular_user = Subject::user("user1");

        system.assign_role(&admin_user, "admin").unwrap();
        system.assign_role(&regular_user, "user").unwrap();

        // Test queries
        let query = system.query();

        let admin_subjects = query.find_subjects_with_role("admin").unwrap();
        assert_eq!(admin_subjects.len(), 1);
        assert!(admin_subjects.contains(&"admin1".to_string()));

        let user_subjects = query.find_subjects_with_role("user").unwrap();
        assert_eq!(user_subjects.len(), 1);
        assert!(user_subjects.contains(&"user1".to_string()));

        let read_permission = Permission::new("read", "documents");
        let roles_with_read = query.roles_with_permission(&read_permission).unwrap();
        assert_eq!(roles_with_read.len(), 2);
        assert!(roles_with_read.contains(&"admin".to_string()));
        assert!(roles_with_read.contains(&"user".to_string()));

        let stats = query.system_statistics().unwrap();
        assert_eq!(stats.total_roles, 2);
        assert_eq!(stats.total_subjects, 2);
        assert_eq!(stats.total_role_assignments, 2);
    }

    #[test]
    fn test_permission_coverage() {
        let mut system = RoleSystem::<MemoryStorage>::new();

        let role = Role::new("test").add_permission(Permission::new("read", "docs"));

        system.register_role(role).unwrap();

        let user = Subject::user("test_user");
        system.assign_role(&user, "test").unwrap();

        let query = system.query();
        let coverage = query.permission_coverage(&[user]).unwrap();

        assert_eq!(coverage.subjects_analyzed, 1);
        assert!(coverage.permission_usage.contains_key("read:docs"));
    }

    #[test]
    fn test_hierarchy_queries() {
        let mut system = RoleSystem::<MemoryStorage>::new();

        let parent_role = Role::new("parent");
        let child_role = Role::new("child");

        system.register_role(parent_role).unwrap();
        system.register_role(child_role).unwrap();
        system.add_role_inheritance("child", "parent").unwrap();

        let query = system.query();

        let parents = query.parent_roles("child");
        assert_eq!(parents.len(), 1);
        assert!(parents.contains(&"parent".to_string()));

        let children = query.child_roles("parent");
        assert_eq!(children.len(), 1);
        assert!(children.contains(&"child".to_string()));
    }
}
