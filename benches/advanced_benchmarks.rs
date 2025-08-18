//! Advanced benchmarking utilities for performance testing and optimization.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use role_system::{
    core::RoleSystem, permission::Permission, resource::Resource, role::Role,
    storage::MemoryStorage, subject::Subject,
};
use std::hint::black_box;

/// Setup a role system with a given number of roles and permissions.
fn setup_role_system(
    num_roles: usize,
    num_permissions_per_role: usize,
) -> RoleSystem<MemoryStorage> {
    let mut system = RoleSystem::<MemoryStorage>::new();

    for role_idx in 0..num_roles {
        let mut role = Role::new(format!("role_{}", role_idx));

        for perm_idx in 0..num_permissions_per_role {
            let permission = Permission::new(
                format!("action_{}", perm_idx),
                format!("resource_type_{}", perm_idx % 10),
            );
            role = role.add_permission(permission);
        }

        system.register_role(role).unwrap();
    }

    system
}

/// Setup subjects with role assignments.
fn setup_subjects_with_roles(
    system: &mut RoleSystem<MemoryStorage>,
    num_subjects: usize,
    num_roles: usize,
) -> Vec<Subject> {
    let subjects: Vec<Subject> = (0..num_subjects)
        .map(|i| Subject::user(format!("user_{}", i)))
        .collect();

    for (i, subject) in subjects.iter().enumerate() {
        let role_name = format!("role_{}", i % num_roles);
        system.assign_role(subject, &role_name).unwrap();
    }

    subjects
}

/// Benchmark permission checking performance.
fn bench_permission_checks(c: &mut Criterion) {
    let mut group = c.benchmark_group("permission_checks");

    // Test different scales
    let scales = vec![
        (10, 5),   // 10 roles, 5 permissions each
        (50, 10),  // 50 roles, 10 permissions each
        (100, 20), // 100 roles, 20 permissions each
        (500, 50), // 500 roles, 50 permissions each
    ];

    for (num_roles, num_permissions) in scales {
        let mut system = setup_role_system(num_roles, num_permissions);
        let subjects = setup_subjects_with_roles(&mut system, 100, num_roles);

        let resource = Resource::new("test_resource".to_string(), "test_type".to_string());

        group.bench_with_input(
            BenchmarkId::new(
                "single_check",
                format!("{}r_{}p", num_roles, num_permissions),
            ),
            &(&system, &subjects[0], &resource),
            |b, (system, subject, resource)| {
                b.iter(|| {
                    black_box(system.check_permission(
                        black_box(subject),
                        black_box("action_1"),
                        black_box(resource),
                    ))
                })
            },
        );
    }

    group.finish();
}

/// Benchmark batch operations performance.
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");

    let mut system = setup_role_system(100, 20);
    let subjects = setup_subjects_with_roles(&mut system, 1000, 100);

    // Benchmark batch role assignments
    group.bench_function("batch_assign_roles", |b| {
        b.iter(|| {
            let assignments: Vec<_> = (0..50)
                .map(|i| (subjects[i].clone(), vec!["role_1".to_string()]))
                .collect();

            black_box(system.bulk_assign_roles(black_box(&assignments)))
        })
    });

    // Benchmark batch permission checks
    group.bench_function("batch_permission_checks", |b| {
        b.iter(|| {
            let resources: Vec<_> = (0..50)
                .map(|i| Resource::new(format!("resource_{}", i), "test_type".to_string()))
                .collect();
            let checks: Vec<_> = resources
                .iter()
                .map(|resource| ("action_1", resource))
                .collect();

            black_box(system.check_permissions_batch(black_box(&subjects[0]), black_box(&checks)))
        })
    });

    group.finish();
}

/// Benchmark storage backend performance.
fn bench_storage_backends(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_backends");

    // Memory storage benchmark
    group.bench_function("memory_storage_role_registration", |b| {
        b.iter(|| {
            let mut system = RoleSystem::<MemoryStorage>::new();
            let role = Role::new("test_role".to_string())
                .add_permission(Permission::new("read".to_string(), "document".to_string()));

            black_box(system.register_role(black_box(role)))
        })
    });

    group.finish();
}

/// Benchmark role hierarchy traversal.
fn bench_role_hierarchy(c: &mut Criterion) {
    let mut group = c.benchmark_group("role_hierarchy");

    // Create a system with deep role hierarchy
    let mut system = RoleSystem::<MemoryStorage>::new();

    // Create a hierarchy: admin -> manager -> supervisor -> employee -> intern
    let hierarchy = vec![
        ("admin", vec!["manager"]),
        ("manager", vec!["supervisor"]),
        ("supervisor", vec!["employee"]),
        ("employee", vec!["intern"]),
        ("intern", vec![]),
    ];

    for (role_name, child_roles) in &hierarchy {
        let mut role = Role::new(role_name.to_string());
        role = role.add_permission(Permission::new(
            format!("{}_action", role_name),
            "resource".to_string(),
        ));
        system.register_role(role).unwrap();

        for child in child_roles {
            system.add_role_inheritance(child, role_name).unwrap();
        }
    }

    let subject = Subject::user("test_user".to_string());
    system.assign_role(&subject, "intern").unwrap();

    let resource = Resource::new("test_resource".to_string(), "resource".to_string());

    group.bench_function("hierarchy_permission_check", |b| {
        b.iter(|| {
            // Should check inherited permissions from intern -> employee -> supervisor -> manager -> admin
            black_box(system.check_permission(
                black_box(&subject),
                black_box("admin_action"),
                black_box(&resource),
            ))
        })
    });

    group.finish();
}

/// Benchmark concurrent-like operations.
fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");

    let mut system = setup_role_system(100, 20);
    let subjects = setup_subjects_with_roles(&mut system, 1000, 100);

    // Simulate concurrent permission checks
    group.bench_function("simulated_concurrent_checks", |b| {
        b.iter(|| {
            let mut results = Vec::with_capacity(100);

            for i in 0..100 {
                let subject = &subjects[i % subjects.len()];
                let resource = Resource::new(format!("resource_{}", i), "test_type".to_string());

                let result = system.check_permission(subject, "action_1", &resource);
                results.push(black_box(result));
            }

            black_box(results)
        })
    });

    // Simulate mixed read/write operations
    group.bench_function("mixed_read_write_operations", |b| {
        b.iter(|| {
            let mut operations = Vec::new();

            for i in 0..50 {
                // Read operation
                let subject = &subjects[i % subjects.len()];
                let resource = Resource::new(format!("resource_{}", i), "test_type".to_string());
                let check_result = system.check_permission(subject, "action_1", &resource);
                operations.push(("read", black_box(check_result)));

                // Write operation (role assignment)
                if i % 10 == 0 {
                    let assign_result = system.assign_role(subject, "role_1");
                    operations.push(("write", black_box(assign_result.map(|_| true))));
                }
            }

            black_box(operations)
        })
    });

    group.finish();
}

/// Benchmark string operations and memory usage.
fn bench_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_operations");

    // Test permission creation with different string patterns
    let string_patterns = vec![
        ("short", "read"),
        ("medium", "user:profile:update"),
        (
            "long",
            "organization:department:team:project:document:version:read",
        ),
        ("uuid_like", "550e8400-e29b-41d4-a716-446655440000"),
    ];

    for (name, pattern) in string_patterns {
        group.bench_with_input(
            BenchmarkId::new("permission_creation", name),
            &pattern,
            |b, pattern| {
                b.iter(|| {
                    black_box(Permission::new(
                        black_box(pattern.to_string()),
                        black_box("resource_type".to_string()),
                    ))
                })
            },
        );
    }

    // Test string comparison performance in permission checking
    let permission = Permission::new("test_action".to_string(), "test_resource".to_string());

    group.bench_function("string_equality_check", |b| {
        b.iter(|| {
            let action = "test_action";
            let resource_type = "test_resource";

            black_box(permission.action() == action && permission.resource_type() == resource_type)
        })
    });

    group.finish();
}

/// Benchmark memory allocation patterns.
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");

    // Test role creation and destruction
    group.bench_function("role_lifecycle", |b| {
        b.iter(|| {
            let mut role = Role::new("test_role".to_string());

            for i in 0..10 {
                let permission =
                    Permission::new(format!("action_{}", i), format!("resource_{}", i));
                role = role.add_permission(permission);
            }

            black_box(role)
        })
    });

    // Test system creation and population
    group.bench_function("system_population", |b| {
        b.iter(|| {
            let mut system = RoleSystem::<MemoryStorage>::new();

            for i in 0..10 {
                let role = Role::new(format!("role_{}", i)).add_permission(Permission::new(
                    format!("action_{}", i),
                    "resource".to_string(),
                ));

                system.register_role(role).unwrap();

                let subject = Subject::user(format!("user_{}", i));
                system
                    .assign_role(&subject, &format!("role_{}", i))
                    .unwrap();
            }

            black_box(system)
        })
    });

    group.finish();
}

/// Benchmark cache performance (if caching is implemented).
fn bench_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_performance");

    let mut system = setup_role_system(100, 20);
    let subjects = setup_subjects_with_roles(&mut system, 100, 100);

    let resource = Resource::new("cached_resource".to_string(), "cached_type".to_string());

    // Warm up cache
    for subject in &subjects {
        let _ = system.check_permission(subject, "action_1", &resource);
    }

    group.bench_function("cached_permission_check", |b| {
        b.iter(|| {
            let subject = &subjects[0]; // Same subject for cache hit
            black_box(system.check_permission(
                black_box(subject),
                black_box("action_1"),
                black_box(&resource),
            ))
        })
    });

    group.bench_function("cache_miss_permission_check", |b| {
        let mut counter = 0;
        b.iter(|| {
            let subject = &subjects[counter % subjects.len()];
            counter += 1;

            let resource = Resource::new(format!("resource_{}", counter), "type".to_string());

            black_box(system.check_permission(
                black_box(subject),
                black_box("action_1"),
                black_box(&resource),
            ))
        })
    });

    group.finish();
}

// Group all benchmarks together
criterion_group!(
    benches,
    bench_permission_checks,
    bench_batch_operations,
    bench_storage_backends,
    bench_role_hierarchy,
    bench_concurrent_operations,
    bench_string_operations,
    bench_memory_patterns,
    bench_cache_performance
);

criterion_main!(benches);

#[cfg(test)]
mod benchmark_tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_benchmark_setup() {
        // Verify benchmark setup functions work correctly
        let _system = setup_role_system(10, 5);
        // Basic smoke test that setup works
        assert!(true);
    }

    #[test]
    fn test_benchmark_scalability() {
        // Test that benchmarks can handle different scales
        let scales = vec![(10, 5), (100, 20), (1000, 50)];

        for (num_roles, num_permissions) in scales {
            let _system = setup_role_system(num_roles, num_permissions);
            // Basic smoke test that setup works at scale
            assert!(true);
        }
    }
}
