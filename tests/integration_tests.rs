//! Integration tests for the role system.

use role_system::{
    core::{RoleSystem, RoleSystemConfig},
    permission::Permission,
    resource::Resource,
    role::{Role, RoleBuilder},
    storage::MemoryStorage,
    subject::Subject,
    Error,
};
use std::{collections::HashMap, time::Duration};

#[test]
fn test_basic_role_assignment_and_permission_check() {
    let mut system = RoleSystem::new();

    // Create permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");

    // Create roles
    let reader = Role::new("reader").add_permission(read_docs.clone());
    let writer = Role::new("writer")
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());

    // Register roles
    system.register_role(reader).unwrap();
    system.register_role(writer).unwrap();

    // Create subjects
    let user1 = Subject::user("user1");
    let user2 = Subject::user("user2");

    // Assign roles
    system.assign_role(&user1, "reader").unwrap();
    system.assign_role(&user2, "writer").unwrap();

    // Create resource
    let document = Resource::new("doc1", "documents");

    // Test permissions
    assert!(system.check_permission(&user1, "read", &document).unwrap());
    assert!(!system.check_permission(&user1, "write", &document).unwrap());
    assert!(system.check_permission(&user2, "read", &document).unwrap());
    assert!(system.check_permission(&user2, "write", &document).unwrap());
}

#[test]
fn test_role_hierarchy() {
    let mut system = RoleSystem::new();

    // Create permissions
    let read_perm = Permission::new("read", "documents");
    let write_perm = Permission::new("write", "documents");
    let admin_perm = Permission::new("admin", "*");

    // Create roles
    let reader = Role::new("reader").add_permission(read_perm);
    let writer = Role::new("writer").add_permission(write_perm);
    let admin = Role::new("admin").add_permission(admin_perm);

    // Register roles
    system.register_role(reader).unwrap();
    system.register_role(writer).unwrap();
    system.register_role(admin).unwrap();

    // Set up hierarchy: admin -> writer -> reader
    system.add_role_inheritance("writer", "reader").unwrap();
    system.add_role_inheritance("admin", "writer").unwrap();

    // Create subject and assign base role
    let user = Subject::user("admin_user");
    system.assign_role(&user, "admin").unwrap();

    // Create resource
    let document = Resource::new("doc1", "documents");

    // Admin should have all permissions through inheritance
    assert!(system.check_permission(&user, "read", &document).unwrap());
    assert!(system.check_permission(&user, "write", &document).unwrap());
    assert!(system.check_permission(&user, "admin", &document).unwrap());
}

#[test]
fn test_role_elevation() {
    let mut system = RoleSystem::new();

    // Create roles
    let user_role = Role::new("user").add_permission(Permission::new("read", "documents"));
    let admin_role = Role::new("admin").add_permission(Permission::new("admin", "*"));

    system.register_role(user_role).unwrap();
    system.register_role(admin_role).unwrap();

    // Create subject
    let user = Subject::user("temp_admin");
    system.assign_role(&user, "user").unwrap();

    let document = Resource::new("doc1", "documents");

    // Initially, user can only read
    assert!(system.check_permission(&user, "read", &document).unwrap());
    assert!(!system.check_permission(&user, "admin", &document).unwrap());

    // Elevate to admin for 1 hour
    system
        .elevate_role(&user, "admin", Some(Duration::from_secs(3600)))
        .unwrap();

    // Now user should have admin permissions
    assert!(system.check_permission(&user, "read", &document).unwrap());
    assert!(system.check_permission(&user, "admin", &document).unwrap());
}

#[test]
fn test_conditional_permissions() {
    let mut system = RoleSystem::new();

    // Create a permission with condition
    let conditional_perm = Permission::with_condition("print", "documents", |context| {
        context.get("time") == Some(&"business_hours".to_string())
            && context.get("location") == Some(&"office".to_string())
    });

    let role = Role::new("office_worker").add_permission(conditional_perm);
    system.register_role(role).unwrap();

    let user = Subject::user("worker");
    system.assign_role(&user, "office_worker").unwrap();

    let document = Resource::new("doc1", "documents");

    // Test with correct context
    let mut context = HashMap::new();
    context.insert("time".to_string(), "business_hours".to_string());
    context.insert("location".to_string(), "office".to_string());

    assert!(system
        .check_permission_with_context(&user, "print", &document, &context)
        .unwrap());

    // Test with incorrect context
    context.insert("location".to_string(), "home".to_string());
    assert!(!system
        .check_permission_with_context(&user, "print", &document, &context)
        .unwrap());
}

#[test]
fn test_wildcard_permissions() {
    let mut system = RoleSystem::new();

    // Create admin with wildcard permissions
    let admin = Role::new("super_admin").add_permission(Permission::super_admin());
    system.register_role(admin).unwrap();

    let user = Subject::user("super_user");
    system.assign_role(&user, "super_admin").unwrap();

    // Test various resources and actions
    let doc = Resource::new("doc1", "documents");
    let user_res = Resource::new("user1", "users");
    let project = Resource::new("proj1", "projects");

    // Super admin should have access to everything
    assert!(system.check_permission(&user, "read", &doc).unwrap());
    assert!(system.check_permission(&user, "write", &doc).unwrap());
    assert!(system.check_permission(&user, "delete", &doc).unwrap());
    assert!(system.check_permission(&user, "manage", &user_res).unwrap());
    assert!(system.check_permission(&user, "create", &project).unwrap());
}

#[test]
fn test_multiple_role_assignment() {
    let mut system = RoleSystem::new();

    // Create different roles
    let doc_reader = Role::new("doc_reader").add_permission(Permission::new("read", "documents"));
    let user_manager = Role::new("user_manager").add_permission(Permission::new("manage", "users"));
    let project_lead = Role::new("project_lead").add_permission(Permission::new("lead", "projects"));

    system.register_role(doc_reader).unwrap();
    system.register_role(user_manager).unwrap();
    system.register_role(project_lead).unwrap();

    // Assign multiple roles to one user
    let user = Subject::user("multi_role_user");
    system.assign_role(&user, "doc_reader").unwrap();
    system.assign_role(&user, "user_manager").unwrap();
    system.assign_role(&user, "project_lead").unwrap();

    // Test permissions from all roles
    let doc = Resource::new("doc1", "documents");
    let user_res = Resource::new("user1", "users");
    let project = Resource::new("proj1", "projects");

    assert!(system.check_permission(&user, "read", &doc).unwrap());
    assert!(system.check_permission(&user, "manage", &user_res).unwrap());
    assert!(system.check_permission(&user, "lead", &project).unwrap());
    
    // Should not have permissions not granted by any role
    assert!(!system.check_permission(&user, "write", &doc).unwrap());
}

#[test]
fn test_error_conditions() {
    let mut system = RoleSystem::new();

    let user = Subject::user("test_user");

    // Test assigning non-existent role
    assert!(matches!(
        system.assign_role(&user, "non_existent"),
        Err(Error::RoleNotFound(_))
    ));

    // Test duplicate role registration
    let role = Role::new("duplicate");
    system.register_role(role.clone()).unwrap();
    assert!(matches!(
        system.register_role(role),
        Err(Error::RoleAlreadyExists(_))
    ));

    // Test circular dependency
    let role1 = Role::new("role1");
    let role2 = Role::new("role2");
    system.register_role(role1).unwrap();
    system.register_role(role2).unwrap();

    system.add_role_inheritance("role1", "role2").unwrap();
    assert!(matches!(
        system.add_role_inheritance("role2", "role1"),
        Err(Error::CircularDependency(_))
    ));
}

#[test]
fn test_role_builder() {
    let role = RoleBuilder::new()
        .name("complex_role")
        .description("A complex role with multiple permissions")
        .permission(Permission::new("read", "documents"))
        .permission(Permission::new("write", "documents"))
        .metadata("department", "Engineering")
        .metadata("level", "senior")
        .active(true)
        .build()
        .unwrap();

    assert_eq!(role.name(), "complex_role");
    assert_eq!(role.description(), Some("A complex role with multiple permissions"));
    assert_eq!(role.permissions().len(), 2);
    assert_eq!(role.metadata("department"), Some("Engineering"));
    assert_eq!(role.metadata("level"), Some("senior"));
    assert!(role.is_active());

    let mut system = RoleSystem::new();
    system.register_role(role).unwrap();

    let user = Subject::user("test_user");
    system.assign_role(&user, "complex_role").unwrap();

    let doc = Resource::new("doc1", "documents");
    assert!(system.check_permission(&user, "read", &doc).unwrap());
    assert!(system.check_permission(&user, "write", &doc).unwrap());
}

#[test]
fn test_subject_types() {
    let mut system = RoleSystem::new();

    let role = Role::new("service_role").add_permission(Permission::new("api", "endpoints"));
    system.register_role(role).unwrap();

    // Test different subject types
    let user = Subject::user("user1");
    let group = Subject::group("group1");
    let service = Subject::service("service1");
    let device = Subject::device("device1");

    system.assign_role(&user, "service_role").unwrap();
    system.assign_role(&group, "service_role").unwrap();
    system.assign_role(&service, "service_role").unwrap();
    system.assign_role(&device, "service_role").unwrap();

    let endpoint = Resource::new("api1", "endpoints");

    // All subject types should work the same way
    assert!(system.check_permission(&user, "api", &endpoint).unwrap());
    assert!(system.check_permission(&group, "api", &endpoint).unwrap());
    assert!(system.check_permission(&service, "api", &endpoint).unwrap());
    assert!(system.check_permission(&device, "api", &endpoint).unwrap());
}

#[test]
fn test_resource_pattern_matching() {
    let mut system = RoleSystem::new();

    // Create role with wildcard permission for documents
    let role = Role::new("doc_admin").add_permission(Permission::wildcard("documents"));
    system.register_role(role).unwrap();

    let user = Subject::user("doc_user");
    system.assign_role(&user, "doc_admin").unwrap();

    // Test various document resources
    let readme = Resource::new("readme", "documents").with_path("/project/README.md");
    let spec = Resource::new("spec", "documents").with_path("/project/docs/spec.md");

    // Should have all permissions on documents
    assert!(system.check_permission(&user, "read", &readme).unwrap());
    assert!(system.check_permission(&user, "write", &readme).unwrap());
    assert!(system.check_permission(&user, "delete", &readme).unwrap());
    assert!(system.check_permission(&user, "read", &spec).unwrap());
    assert!(system.check_permission(&user, "write", &spec).unwrap());

    // Should not have permissions on other resource types
    let user_res = Resource::new("user1", "users");
    assert!(!system.check_permission(&user, "read", &user_res).unwrap());
}

#[test]
fn test_configuration() {
    let config = RoleSystemConfig {
        max_hierarchy_depth: 3,
        enable_caching: false,
        cache_ttl_seconds: 60,
        enable_audit: false,
    };

    let storage = MemoryStorage::new();
    let mut system = RoleSystem::with_storage(storage, config);

    // Create a deep hierarchy that exceeds the limit
    for i in 0..5 {
        let role = Role::new(format!("role{}", i));
        system.register_role(role).unwrap();
    }

    // Create hierarchy: role4 -> role3 -> role2 -> role1 -> role0
    system.add_role_inheritance("role1", "role0").unwrap();
    system.add_role_inheritance("role2", "role1").unwrap();
    system.add_role_inheritance("role3", "role2").unwrap();
    
    // This should fail due to max depth
    assert!(matches!(
        system.add_role_inheritance("role4", "role3"),
        Err(Error::MaxDepthExceeded(_))
    ));
}

#[cfg(feature = "async")]
mod async_tests {
    use super::*;
    use role_system::async_support::{AsyncRoleSystem, AsyncRoleSystemBuilder};

    #[tokio::test]
    async fn test_async_basic_operations() {
        let role_system = RoleSystem::new();
        let async_system = AsyncRoleSystem::new(role_system);

        // Create and register role
        let role = Role::new("async_test").add_permission(Permission::new("read", "documents"));
        async_system.register_role(role).await.unwrap();

        // Create subject and assign role
        let user = Subject::user("async_user");
        async_system.assign_role(&user, "async_test").await.unwrap();

        // Check permission
        let doc = Resource::new("doc1", "documents");
        let can_read = async_system.check_permission(&user, "read", &doc).await.unwrap();
        assert!(can_read);
    }

    #[tokio::test]
    async fn test_async_builder() {
        let async_system = AsyncRoleSystemBuilder::<MemoryStorage>::new()
            .max_hierarchy_depth(5)
            .enable_caching(true)
            .cache_ttl_seconds(300)
            .build();

        let role = Role::new("builder_test");
        async_system.register_role(role).await.unwrap();

        let retrieved = async_system.get_role("builder_test").await.unwrap();
        assert!(retrieved.is_some());
    }
}
