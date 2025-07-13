#![feature(test)]

extern crate test;

use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use test::Bencher;

#[bench]
fn bench_permission_check(b: &mut Bencher) {
    let mut system = RoleSystem::new();
    let role = Role::new("role")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("write", "documents"));
    
    system.register_role(role).unwrap();
    let subject = Subject::new("user");
    system.assign_role(&subject, "role").unwrap();
    let resource = Resource::new("doc1", "documents");

    b.iter(|| {
        system.check_permission(&subject, "read", &resource).unwrap()
    });
}

#[bench]
fn bench_role_inheritance(b: &mut Bencher) {
    let mut system = RoleSystem::new();
    
    // Create a deep role hierarchy
    let roles = ["role1", "role2", "role3", "role4", "role5"];
    for role in roles.iter() {
        system.register_role(Role::new(role)).unwrap();
    }
    
    // Set up inheritance chain
    for i in 1..roles.len() {
        system.add_role_inheritance(roles[i], roles[i-1]).unwrap();
    }

    let subject = Subject::new("user");
    system.assign_role(&subject, roles.last().unwrap()).unwrap();
    let resource = Resource::new("doc1", "documents");

    b.iter(|| {
        system.check_permission(&subject, "read", &resource).unwrap()
    });
}

#[bench]
fn bench_conditional_permission(b: &mut Bencher) {
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

    b.iter(|| {
        system.check_permission_with_context(&subject, "read", &resource, &context).unwrap()
    });
}

#[bench]
fn bench_concurrent_access(b: &mut Bencher) {
    use std::sync::Arc;
    use std::thread;
    
    let system = Arc::new(RoleSystem::new());
    let role = Role::new("role").add_permission(Permission::new("read", "documents"));
    Arc::clone(&system).register_role(role).unwrap();
    
    let subject = Subject::new("user");
    Arc::clone(&system).assign_role(&subject, "role").unwrap();
    let resource = Resource::new("doc1", "documents");
    
    b.iter(|| {
        let sys = Arc::clone(&system);
        let sub = subject.clone();
        let res = resource.clone();
        thread::spawn(move || {
            sys.check_permission(&sub, "read", &res).unwrap()
        }).join().unwrap()
    });
}

#[bench]
fn bench_role_assignment(b: &mut Bencher) {
    let mut system = RoleSystem::new();
    let role = Role::new("role");
    system.register_role(role).unwrap();
    let subject = Subject::new("user");

    b.iter(|| {
        system.assign_role(&subject, "role").unwrap();
        system.remove_role(&subject, "role").unwrap();
    });
}

#[bench]
fn bench_resource_pattern_matching(b: &mut Bencher) {
    let resource = Resource::new("doc1", "documents")
        .with_path("/projects/web-app/docs/readme.md");

    b.iter(|| {
        resource.matches_pattern("documents/*") &&
        resource.matches_pattern("*") &&
        resource.matches_pattern("doc1") &&
        !resource.matches_pattern("invalid")
    });
}
