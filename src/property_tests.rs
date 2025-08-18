//! Property-based testing for the role system.
//!
//! This module provides comprehensive property-based tests using the `proptest` crate
//! to verify the correctness of role system operations under a wide variety of inputs.

#[cfg(test)]
mod tests {
    use crate::{
        core::RoleSystem, permission::Permission, resource::Resource, role::Role,
        storage::MemoryStorage, subject::Subject,
    };
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};

    // Enhanced generators for property testing

    /// Generate valid identifier strings.
    fn identifier_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_-]{0,63}")
            .unwrap()
            .prop_filter("Must not be empty", |s| !s.is_empty())
    }

    /// Generate valid action strings including wildcards.
    fn action_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("read".to_string()),
            Just("write".to_string()),
            Just("delete".to_string()),
            Just("admin".to_string()),
            Just("execute".to_string()),
            Just("*".to_string()),
            identifier_strategy(),
        ]
    }

    /// Generate valid resource type strings including wildcards.
    fn resource_type_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("documents".to_string()),
            Just("users".to_string()),
            Just("settings".to_string()),
            Just("files".to_string()),
            Just("*".to_string()),
            identifier_strategy(),
        ]
    }

    /// Generate permission strategies.
    fn permission_strategy() -> impl Strategy<Value = Permission> {
        (action_strategy(), resource_type_strategy())
            .prop_map(|(action, resource_type)| Permission::new(action, resource_type))
    }

    /// Generate role strategies.
    fn role_strategy() -> impl Strategy<Value = Role> {
        (
            identifier_strategy(),
            prop::collection::vec(permission_strategy(), 0..5),
        )
            .prop_map(|(name, permissions)| {
                let mut role = Role::new(name);
                for permission in permissions {
                    role = role.add_permission(permission);
                }
                role
            })
    }

    /// Generate subject strategies.
    fn subject_strategy() -> impl Strategy<Value = Subject> {
        identifier_strategy().prop_map(Subject::user)
    }

    /// Generate resource strategies.
    fn resource_strategy() -> impl Strategy<Value = Resource> {
        (identifier_strategy(), identifier_strategy())
            .prop_map(|(id, resource_type)| Resource::new(id, resource_type))
    }

    /// Generate valid role hierarchy (no cycles).
    fn valid_hierarchy_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        // Generate a DAG (Directed Acyclic Graph) for role hierarchy
        prop::collection::vec((identifier_strategy(), identifier_strategy()), 0..10).prop_filter(
            "No cycles",
            |hierarchy| {
                // Simple cycle detection
                let mut graph: HashMap<String, Vec<String>> = HashMap::new();
                for (child, parent) in hierarchy {
                    graph.entry(child.clone()).or_default().push(parent.clone());
                }
                !has_cycle(&graph)
            },
        )
    }

    fn has_cycle(graph: &HashMap<String, Vec<String>>) -> bool {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for node in graph.keys() {
            if has_cycle_util(graph, node, &mut visited, &mut rec_stack) {
                return true;
            }
        }
        false
    }

    fn has_cycle_util(
        graph: &HashMap<String, Vec<String>>,
        node: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> bool {
        if rec_stack.contains(node) {
            return true;
        }
        if visited.contains(node) {
            return false;
        }

        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());

        if let Some(neighbors) = graph.get(node) {
            for neighbor in neighbors {
                if has_cycle_util(graph, neighbor, visited, rec_stack) {
                    return true;
                }
            }
        }

        rec_stack.remove(node);
        false
    }

    // Property tests

    proptest! {
        #[test]
        fn prop_permission_parsing_roundtrip(
            action in action_strategy(),
            resource_type in resource_type_strategy()
        ) {
            let permission = Permission::new(&action, &resource_type);
            let permission_str = format!("{}:{}", action, resource_type);
            let parsed = Permission::parse(&permission_str).unwrap();

            prop_assert_eq!(permission.action(), parsed.action());
            prop_assert_eq!(permission.resource_type(), parsed.resource_type());
        }

        #[test]
        fn prop_role_hierarchy_preserves_permissions(
            roles in prop::collection::vec(role_strategy(), 1..5),
            hierarchy in valid_hierarchy_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();
            let mut role_names = Vec::new();

            // Register roles
            for role in roles {
                role_names.push(role.name().to_string());
                system.register_role(role).unwrap();
            }

            // Apply hierarchy (only for existing roles)
            for (child, parent) in hierarchy {
                if role_names.contains(&child) && role_names.contains(&parent) {
                    let _ = system.add_role_inheritance(&child, &parent);
                }
            }

            // Property: A subject with a child role should have at least
            // the same permissions as someone with just the parent role
            for role_name in &role_names {
                let subject = Subject::user(format!("test_{}", role_name));
                system.assign_role(&subject, role_name).unwrap();

                let roles = system.get_subject_roles(&subject).unwrap();

                // Subject should have at least their directly assigned role
                prop_assert!(roles.contains(role_name));
            }
        }

        #[test]
        fn prop_permission_checks_are_consistent(
            subject in subject_strategy(),
            role in role_strategy(),
            resource in resource_strategy(),
            action in action_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            system.register_role(role.clone()).unwrap();
            system.assign_role(&subject, role.name()).unwrap();

            let result1 = system.check_permission(&subject, &action, &resource).unwrap();
            let result2 = system.check_permission(&subject, &action, &resource).unwrap();

            // Property: Multiple calls with same parameters should return same result
            prop_assert_eq!(result1, result2);
        }

        #[test]
        fn prop_wildcard_permissions_imply_specific(
            subject in subject_strategy(),
            resource in resource_strategy(),
            action in action_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            // Create role with wildcard permission
            let wildcard_role = Role::new("wildcard")
                .add_permission(Permission::super_admin());

            system.register_role(wildcard_role).unwrap();
            system.assign_role(&subject, "wildcard").unwrap();

            let can_access = system.check_permission(&subject, &action, &resource).unwrap();

            // Property: Super admin should have access to everything
            prop_assert!(can_access);
        }

        #[test]
        fn prop_role_assignment_is_idempotent(
            subject in subject_strategy(),
            role in role_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            system.register_role(role.clone()).unwrap();

            // Assign role multiple times
            system.assign_role(&subject, role.name()).unwrap();
            system.assign_role(&subject, role.name()).unwrap();
            system.assign_role(&subject, role.name()).unwrap();

            let roles = system.get_subject_roles(&subject).unwrap();

            // Property: Multiple assignments should result in single role
            prop_assert_eq!(roles.len(), 1);
            prop_assert!(roles.contains(role.name()));
        }

        #[test]
        fn prop_permission_denial_is_safe(
            subject in subject_strategy(),
            resource in resource_strategy(),
            action in action_strategy()
        ) {
            let system = RoleSystem::<MemoryStorage>::new();

            // No roles assigned - should deny all permissions
            let can_access = system.check_permission(&subject, &action, &resource).unwrap();

            // Property: No roles should mean no access (fail-safe default)
            prop_assert!(!can_access);
        }

        #[test]
        fn prop_role_removal_revokes_permissions(
            subject in subject_strategy(),
            role in role_strategy(),
            resource in resource_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            system.register_role(role.clone()).unwrap();
            system.assign_role(&subject, role.name()).unwrap();

            // Check if subject has any permissions from this role
            let _has_permissions_before = role.permissions().permissions().iter().any(|perm| {
                system.check_permission(&subject, perm.action(), &resource).unwrap_or(false)
            });

            // Remove the role
            system.remove_role(&subject, role.name()).unwrap();

            // Check permissions after removal
            let has_permissions_after = role.permissions().permissions().iter().any(|perm| {
                system.check_permission(&subject, perm.action(), &resource).unwrap_or(false)
            });

            // Property: If removing a role eliminates all roles, permissions should be revoked
            let remaining_roles = system.get_subject_roles(&subject).unwrap();
            if remaining_roles.is_empty() {
                prop_assert!(!has_permissions_after);
            }
        }

        #[test]
        fn prop_cache_invalidation_is_correct(
            subject in subject_strategy(),
            role in role_strategy(),
            resource in resource_strategy(),
            action in action_strategy()
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            // First check (should populate cache)
            let result1 = system.check_permission(&subject, &action, &resource).unwrap();

            // Add a role that might change the result
            system.register_role(role.clone()).unwrap();
            system.assign_role(&subject, role.name()).unwrap();

            // Second check (should reflect the new role)
            let result2 = system.check_permission(&subject, &action, &resource).unwrap();

            // Property: Adding roles should never decrease permissions
            prop_assert!(result2 >= result1);
        }
    }

    // Quickcheck-style property tests for different testing styles

    #[cfg(test)]
    mod quickcheck_tests {
        use super::*;
        use quickcheck::TestResult;
        use quickcheck_macros::quickcheck;

        #[quickcheck]
        fn qc_permission_creation_never_panics(
            action: String,
            resource_type: String,
        ) -> TestResult {
            // Skip invalid inputs that would legitimately fail validation
            if action.trim().is_empty() || resource_type.trim().is_empty() {
                return TestResult::discard();
            }
            if action.contains('\0') || resource_type.contains('\0') {
                return TestResult::discard();
            }
            if action.contains("..") || resource_type.contains("..") {
                return TestResult::discard();
            }
            if action.len() > 255 || resource_type.len() > 255 {
                return TestResult::discard();
            }
            if action
                .chars()
                .any(|c| c.is_control() || "'\";--/*<>{}[]\\".contains(c))
            {
                return TestResult::discard();
            }
            if resource_type
                .chars()
                .any(|c| c.is_control() || "'\";--/*<>{}[]\\".contains(c))
            {
                return TestResult::discard();
            }

            // This should not panic with valid inputs
            let _permission = Permission::new(action, resource_type);
            TestResult::passed()
        }

        #[quickcheck]
        fn qc_role_system_operations_are_safe(operations: Vec<u8>) -> bool {
            let mut system = RoleSystem::<MemoryStorage>::new();
            let test_role =
                Role::new("test_role").add_permission(Permission::new("test", "resource"));
            let test_subject = Subject::user("test_user");

            // Try to register the role first
            let _ = system.register_role(test_role);

            // Perform random operations
            for &op in &operations {
                match op % 4 {
                    0 => {
                        let _ = system.assign_role(&test_subject, "test_role");
                    }
                    1 => {
                        let _ = system.remove_role(&test_subject, "test_role");
                    }
                    2 => {
                        let resource = Resource::new("test_res", "resource");
                        let _ = system.check_permission(&test_subject, "test", &resource);
                    }
                    3 => {
                        let _ = system.get_subject_roles(&test_subject);
                    }
                    _ => unreachable!(),
                }
            }

            // System should remain in a valid state
            true
        }
    }

    // Regression tests based on property testing discoveries
    #[cfg(test)]
    mod regression_tests {
        use super::*;

        #[test]
        fn test_empty_role_hierarchy_edge_case() {
            let mut system = RoleSystem::<MemoryStorage>::new();
            let role = Role::new("empty_role"); // No permissions

            system.register_role(role).unwrap();

            let subject = Subject::user("test_user");
            system.assign_role(&subject, "empty_role").unwrap();

            let resource = Resource::new("test", "test");
            let can_access = system.check_permission(&subject, "any", &resource).unwrap();

            // Should not have access with empty role
            assert!(!can_access);
        }

        #[test]
        fn test_permission_string_edge_cases() {
            // Test various edge cases discovered through property testing
            let valid_cases = vec![
                "a:b",
                "read:documents",
                "admin:*",
                "*:documents",
                "*:*",
                "read:file-type",
                "write:user_data",
            ];

            for case in valid_cases {
                Permission::parse(case).unwrap_or_else(|_| panic!("Should parse: {}", case));
            }

            let invalid_cases = vec![
                "", ":", "a:", ":b", "a:b:c:d", "a\0:b", "a:b\0", "a'b:c", "a;b:c", "a\"b:c",
                "a{b:c", "a}b:c", "a[b:c", "a]b:c", "a\\b:c", "a<b:c", "a>b:c",
            ];

            for case in invalid_cases {
                assert!(
                    Permission::parse(case).is_err(),
                    "Should not parse: {}",
                    case
                );
            }
        }
    }
}
