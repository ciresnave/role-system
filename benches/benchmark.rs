use criterion::{criterion_group, criterion_main, Criterion};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::hint::black_box;
use std::sync::Arc;

fn bench_permission_check(c: &mut Criterion) {
    let mut system = RoleSystem::new();
    let role = Role::new("role")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("write", "documents"));
    
    system.register_role(role).unwrap();
    let subject = Subject::new("user");
    system.assign_role(&subject, "role").unwrap();
    let resource = Resource::new("doc1", "documents");

    c.bench_function("permission_check", |b| {
        b.iter(|| {
            black_box(system.check_permission(&subject, "read", &resource).unwrap())
        })
    });
}

fn bench_role_inheritance(c: &mut Criterion) {
    let mut system = RoleSystem::new();
    
    // Create a deep role hierarchy
    let roles = ["role1", "role2", "role3", "role4", "role5"];
    for role in roles.iter() {
        system.register_role(Role::new(*role)).unwrap();
    }
    
    // Set up inheritance chain
    for i in 1..roles.len() {
        system.add_role_inheritance(roles[i], roles[i-1]).unwrap();
    }

    let subject = Subject::new("user");
    system.assign_role(&subject, roles.last().unwrap()).unwrap();
    let resource = Resource::new("doc1", "documents");

    c.bench_function("role_inheritance", |b| {
        b.iter(|| {
            black_box(system.check_permission(&subject, "read", &resource).unwrap())
        })
    });
}

fn bench_conditional_permission(c: &mut Criterion) {
    let mut system = RoleSystem::new();
    let permission = Permission::with_condition("read", "documents", |ctx| {
        ctx.get("time") == Some(&"business_hours".to_string()) &&
        ctx.get("location") == Some(&"office".to_string())
    });
    
    let role = Role::new("role").add_permission(permission);
    system.register_role(role).unwrap();
    
    let subject = Subject::new("user");
    system.assign_role(&subject, "role").unwrap();
    let resource = Resource::new("doc1", "documents");
    
    let mut context = std::collections::HashMap::new();
    context.insert("time".to_string(), "business_hours".to_string());
    context.insert("location".to_string(), "office".to_string());

    c.bench_function("conditional_permission", |b| {
        b.iter(|| {
            black_box(system.check_permission(&subject, "read", &resource).unwrap())
        })
    });
}

fn bench_concurrent_access(c: &mut Criterion) {
    let mut system = RoleSystem::new();
    let role = Role::new("role").add_permission(Permission::new("read", "documents"));
    system.register_role(role).unwrap();
    
    let subject = Subject::new("user");
    system.assign_role(&subject, "role").unwrap();
    let resource = Resource::new("doc1", "documents");
    
    // We'll simulate concurrency with Arc cloning for the benchmark
    let system = Arc::new(system);
    
    c.bench_function("concurrent_access", |b| {
        b.iter(|| {
            let sys = Arc::clone(&system);
            let sub = subject.clone();
            let res = resource.clone();
            black_box(sys.check_permission(&sub, "read", &res).unwrap())
        })
    });
}

fn bench_role_assignment(c: &mut Criterion) {
    let mut system = RoleSystem::new();
    let role = Role::new("role");
    system.register_role(role).unwrap();
    let subject = Subject::new("user");

    c.bench_function("role_assignment", |b| {
        b.iter(|| {
            system.assign_role(&subject, "role").unwrap();
            system.remove_role(&subject, "role").unwrap();
        })
    });
}

fn bench_resource_pattern_matching(c: &mut Criterion) {
    let resource = Resource::new("doc1", "documents")
        .with_path("/projects/web-app/docs/readme.md");

    c.bench_function("resource_pattern_matching", |b| {
        b.iter(|| {
            black_box(
                resource.matches_pattern("documents/*") &&
                resource.matches_pattern("*") &&
                resource.matches_pattern("doc1") &&
                !resource.matches_pattern("invalid")
            )
        })
    });
}

criterion_group!(
    benches,
    bench_permission_check,
    bench_role_inheritance,
    bench_conditional_permission,
    bench_concurrent_access,
    bench_role_assignment,
    bench_resource_pattern_matching
);
criterion_main!(benches);
