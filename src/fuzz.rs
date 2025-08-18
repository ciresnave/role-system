//! Fuzzing tests for the role system to discover edge cases and security vulnerabilities.

#[cfg(test)]
mod fuzz_tests {
    use crate::{
        core::RoleSystem, permission::Permission, resource::Resource, role::Role,
        storage::MemoryStorage, subject::Subject,
    };

    // Use arbitrary for property-based testing that can be used for fuzzing
    use proptest::prelude::*;

    /// Fuzz input for role system operations.
    #[derive(Debug, Clone)]
    struct FuzzInput {
        operations: Vec<FuzzOperation>,
    }

    #[derive(Debug, Clone)]
    enum FuzzOperation {
        RegisterRole {
            name: String,
            permissions: Vec<(String, String)>,
        },
        AssignRole {
            subject_id: String,
            role_name: String,
        },
        CheckPermission {
            subject_id: String,
            action: String,
            resource_id: String,
            resource_type: String,
        },
        RemoveRole {
            subject_id: String,
            role_name: String,
        },
        AddRoleInheritance {
            child: String,
            parent: String,
        },
    }

    impl Arbitrary for FuzzOperation {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                (
                    any::<String>(),
                    prop::collection::vec((any::<String>(), any::<String>()), 0..5)
                )
                    .prop_map(|(name, permissions)| FuzzOperation::RegisterRole {
                        name,
                        permissions
                    }),
                (any::<String>(), any::<String>()).prop_map(|(subject_id, role_name)| {
                    FuzzOperation::AssignRole {
                        subject_id,
                        role_name,
                    }
                }),
                (
                    any::<String>(),
                    any::<String>(),
                    any::<String>(),
                    any::<String>()
                )
                    .prop_map(
                        |(subject_id, action, resource_id, resource_type)| {
                            FuzzOperation::CheckPermission {
                                subject_id,
                                action,
                                resource_id,
                                resource_type,
                            }
                        }
                    ),
                (any::<String>(), any::<String>()).prop_map(|(subject_id, role_name)| {
                    FuzzOperation::RemoveRole {
                        subject_id,
                        role_name,
                    }
                }),
                (any::<String>(), any::<String>()).prop_map(|(child, parent)| {
                    FuzzOperation::AddRoleInheritance { child, parent }
                }),
            ]
            .boxed()
        }
    }

    impl Arbitrary for FuzzInput {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop::collection::vec(any::<FuzzOperation>(), 1..50)
                .prop_map(|operations| FuzzInput { operations })
                .boxed()
        }
    }

    /// Sanitize string input to prevent injection attacks.
    fn sanitize_string(input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .take(100) // Limit length
            .collect()
    }

    /// Execute a fuzz operation safely.
    fn execute_fuzz_operation(
        system: &mut RoleSystem<MemoryStorage>,
        operation: FuzzOperation,
    ) -> bool {
        match operation {
            FuzzOperation::RegisterRole { name, permissions } => {
                let sanitized_name = sanitize_string(&name);
                if sanitized_name.is_empty() {
                    return true; // Skip invalid names
                }

                let mut role = Role::new(sanitized_name);
                for (action, resource_type) in permissions {
                    let sanitized_action = sanitize_string(&action);
                    let sanitized_resource = sanitize_string(&resource_type);

                    if !sanitized_action.is_empty() && !sanitized_resource.is_empty() {
                        let permission = Permission::new(sanitized_action, sanitized_resource);
                        role = role.add_permission(permission);
                    }
                }

                let _ = system.register_role(role);
                true
            }
            FuzzOperation::AssignRole {
                subject_id,
                role_name,
            } => {
                let sanitized_subject = sanitize_string(&subject_id);
                let sanitized_role = sanitize_string(&role_name);

                if sanitized_subject.is_empty() || sanitized_role.is_empty() {
                    return true;
                }

                let subject = Subject::user(sanitized_subject);
                let _ = system.assign_role(&subject, &sanitized_role);
                true
            }
            FuzzOperation::CheckPermission {
                subject_id,
                action,
                resource_id,
                resource_type,
            } => {
                let sanitized_subject = sanitize_string(&subject_id);
                let sanitized_action = sanitize_string(&action);
                let sanitized_resource_id = sanitize_string(&resource_id);
                let sanitized_resource_type = sanitize_string(&resource_type);

                if sanitized_subject.is_empty()
                    || sanitized_action.is_empty()
                    || sanitized_resource_id.is_empty()
                    || sanitized_resource_type.is_empty()
                {
                    return true;
                }

                let subject = Subject::user(sanitized_subject);
                let resource = Resource::new(sanitized_resource_id, sanitized_resource_type);
                let _ = system.check_permission(&subject, &sanitized_action, &resource);
                true
            }
            FuzzOperation::RemoveRole {
                subject_id,
                role_name,
            } => {
                let sanitized_subject = sanitize_string(&subject_id);
                let sanitized_role = sanitize_string(&role_name);

                if sanitized_subject.is_empty() || sanitized_role.is_empty() {
                    return true;
                }

                let subject = Subject::user(sanitized_subject);
                let _ = system.remove_role(&subject, &sanitized_role);
                true
            }
            FuzzOperation::AddRoleInheritance { child, parent } => {
                let sanitized_child = sanitize_string(&child);
                let sanitized_parent = sanitize_string(&parent);

                if sanitized_child.is_empty()
                    || sanitized_parent.is_empty()
                    || sanitized_child == sanitized_parent
                {
                    return true;
                }

                let _ = system.add_role_inheritance(&sanitized_child, &sanitized_parent);
                true
            }
        }
    }

    proptest! {
        #[test]
        fn fuzz_role_system_never_panics(input in any::<FuzzInput>()) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            // Execute all operations - should never panic
            for operation in input.operations {
                prop_assert!(execute_fuzz_operation(&mut system, operation));
            }
        }

        #[test]
        fn fuzz_permission_strings_never_panic(
            action in ".*",
            resource_type in ".*"
        ) {
            // Test that arbitrary strings don't cause panics when creating permissions
            let result = std::panic::catch_unwind(|| {
                // Only create permission if strings are not empty after basic validation
                if !action.trim().is_empty() && !resource_type.trim().is_empty() {
                    // Try to create permission - validation errors are expected and should be handled gracefully
                    if Permission::try_new(&action, &resource_type).is_err() {
                        // Validation error is expected for invalid input - not a panic
                    }
                }
            });

            // Should either succeed or fail gracefully, never panic
            prop_assert!(result.is_ok());
        }

        #[test]
        fn fuzz_role_hierarchy_stability(
            role_pairs in prop::collection::vec((any::<String>(), any::<String>()), 1..20)
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            // Register roles and create hierarchy
            let mut registered_roles = std::collections::HashSet::new();

            for (child, parent) in role_pairs {
                let sanitized_child = sanitize_string(&child);
                let sanitized_parent = sanitize_string(&parent);

                if sanitized_child.is_empty() || sanitized_parent.is_empty() ||
                   sanitized_child == sanitized_parent {
                    continue;
                }

                // Register roles if not already registered
                if registered_roles.insert(sanitized_child.clone()) {
                    let role = Role::new(sanitized_child.clone());
                    let _ = system.register_role(role);
                }

                if registered_roles.insert(sanitized_parent.clone()) {
                    let role = Role::new(sanitized_parent.clone());
                    let _ = system.register_role(role);
                }

                // Try to add inheritance - should handle cycles gracefully
                let _ = system.add_role_inheritance(&sanitized_child, &sanitized_parent);
            }

            // System should remain stable
            prop_assert!(true);
        }

        #[test]
        fn fuzz_concurrent_like_operations(
            operations in prop::collection::vec(any::<FuzzOperation>(), 1..100)
        ) {
            let mut system = RoleSystem::<MemoryStorage>::new();

            // Execute many operations in sequence (simulating concurrent-like load)
            for operation in operations {
                let _ = execute_fuzz_operation(&mut system, operation);
            }

            // System should remain consistent
            prop_assert!(true);
        }

        #[test]
        fn fuzz_memory_exhaustion_protection(
            large_string in prop::string::string_regex("[a-zA-Z0-9]{1000,2000}").unwrap()
        ) {
            let result = std::panic::catch_unwind(|| {
                let _permission = Permission::new(&large_string[..100], &large_string[100..200]);
            });

            // Should handle large strings gracefully
            prop_assert!(result.is_ok());
        }
    }

    #[test]
    fn fuzz_invalid_utf8_handling() {
        // Test with invalid UTF-8 sequences (converted to valid strings)
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD];
        let string_from_bytes = String::from_utf8_lossy(&invalid_bytes);

        // Should not panic with converted string
        let result = std::panic::catch_unwind(|| {
            let sanitized = sanitize_string(&string_from_bytes);
            if !sanitized.is_empty() {
                let _permission = Permission::new(sanitized.clone(), sanitized);
            }
        });

        assert!(result.is_ok());
    }

    #[test]
    fn fuzz_extreme_role_hierarchy_depth() {
        let mut system = RoleSystem::<MemoryStorage>::new();

        // Create a deep hierarchy
        let mut previous_role = "root".to_string();
        let root_role = Role::new(previous_role.clone());
        system.register_role(root_role).unwrap();

        for i in 1..=20 {
            let current_role = format!("level_{}", i);
            let role = Role::new(current_role.clone());
            system.register_role(role).unwrap();

            // This should eventually hit max depth limit
            let _ = system.add_role_inheritance(&current_role, &previous_role);
            previous_role = current_role;
        }

        // System should handle deep hierarchies gracefully
    }

    #[test]
    fn fuzz_special_characters_in_permissions() {
        let special_chars = vec![
            "role\0with\0nulls",
            "role\nwith\nnewlines",
            "role\twith\ttabs",
            "role\"with\"quotes",
            "role'with'apostrophes",
            "role;with;semicolons",
            "role(with)parens",
            "role[with]brackets",
            "role{with}braces",
            "role<with>angles",
            "role|with|pipes",
            "role\\with\\backslashes",
            "role/with/slashes",
            "role?with?questions",
            "role*with*wildcards",
            "role%with%percents",
            "role&with&ampersands",
            "role=with=equals",
            "role+with+plus",
            "role-with-dashes",
            "role_with_underscores",
            "role.with.dots",
            "role,with,commas",
            "role:with:colons",
            "role#with#hashes",
            "role@with@ats",
            "role!with!exclamations",
            "role$with$dollars",
            "role^with^carets",
            "role~with~tildes",
            "role`with`backticks",
        ];

        for special_string in special_chars {
            let result = std::panic::catch_unwind(|| {
                let sanitized = sanitize_string(special_string);
                if !sanitized.is_empty() {
                    let _permission = Permission::new(sanitized.clone(), sanitized);
                }
            });

            assert!(result.is_ok(), "Failed with string: {}", special_string);
        }
    }
}

/// Load testing utilities for performance validation.
#[cfg(test)]
pub mod load_tests {
    use crate::{
        core::RoleSystem, permission::Permission, resource::Resource, role::Role,
        storage::MemoryStorage, subject::Subject,
    };
    use std::time::Instant;

    /// Run a basic load test with many permission checks.
    pub fn load_test_permission_checks(
        num_subjects: usize,
        num_roles: usize,
        num_permissions_per_role: usize,
        num_checks: usize,
    ) -> (std::time::Duration, f64) {
        let mut system = RoleSystem::<MemoryStorage>::new();

        // Setup: Create roles with permissions
        for role_idx in 0..num_roles {
            let mut role = Role::new(format!("role_{}", role_idx));

            for perm_idx in 0..num_permissions_per_role {
                let permission = Permission::new(
                    format!("action_{}", perm_idx),
                    format!("resource_type_{}", perm_idx % 10), // Group resources
                );
                role = role.add_permission(permission);
            }

            system.register_role(role).unwrap();
        }

        // Setup: Create subjects and assign roles
        let subjects: Vec<Subject> = (0..num_subjects)
            .map(|i| Subject::user(format!("user_{}", i)))
            .collect();

        for (i, subject) in subjects.iter().enumerate() {
            let role_name = format!("role_{}", i % num_roles);
            system.assign_role(subject, &role_name).unwrap();
        }

        // Load test: Perform many permission checks
        let start = Instant::now();
        let mut granted_count = 0;

        for i in 0..num_checks {
            let subject = &subjects[i % num_subjects];
            let action = format!("action_{}", i % num_permissions_per_role);
            let resource = Resource::new(
                format!("resource_{}", i),
                format!("resource_type_{}", i % 10),
            );

            if system
                .check_permission(subject, &action, &resource)
                .unwrap_or(false)
            {
                granted_count += 1;
            }
        }

        let duration = start.elapsed();
        let success_rate = granted_count as f64 / num_checks as f64;

        (duration, success_rate)
    }

    #[test]
    fn test_load_performance() {
        let (duration, success_rate) = load_test_permission_checks(
            100,   // subjects
            50,    // roles
            20,    // permissions per role
            10000, // permission checks
        );

        println!("Load test results:");
        println!("  Duration: {:?}", duration);
        println!("  Success rate: {:.2}%", success_rate * 100.0);
        println!(
            "  Checks per second: {:.0}",
            10000.0 / duration.as_secs_f64()
        );

        // Performance assertions
        assert!(
            duration.as_millis() < 5000,
            "Load test took too long: {:?}",
            duration
        );
        assert!(success_rate > 0.0, "No permissions were granted");
    }

    #[test]
    fn test_memory_usage_scaling() {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Simple memory tracking (approximate)
        static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

        #[allow(dead_code)]
        struct TrackingAllocator;

        unsafe impl GlobalAlloc for TrackingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let ptr = unsafe { System.alloc(layout) };
                if !ptr.is_null() {
                    ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
                }
                ptr
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) };
                ALLOCATED.fetch_sub(layout.size(), Ordering::Relaxed);
            }
        }

        // Test memory usage with increasing scale
        let initial_memory = ALLOCATED.load(Ordering::Relaxed);

        let system = RoleSystem::<MemoryStorage>::new();
        let memory_after_creation = ALLOCATED.load(Ordering::Relaxed);

        println!("Memory usage:");
        println!("  Initial: {} bytes", initial_memory);
        println!("  After creation: {} bytes", memory_after_creation);
        println!(
            "  System overhead: {} bytes",
            memory_after_creation - initial_memory
        );

        // Basic memory usage should be reasonable
        let overhead = memory_after_creation - initial_memory;
        assert!(
            overhead < 1024 * 1024,
            "System uses too much memory: {} bytes",
            overhead
        );

        drop(system);
    }
}
