//! Integration tests for middleware examples
//! 
//! These tests verify that the middleware examples compile and work correctly
//! with the role system.

use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::collections::HashMap;

#[tokio::test]
async fn test_basic_role_system_setup() {
    let mut system = RoleSystem::new();
    
    // Setup roles similar to middleware examples
    let admin = Role::new("admin")
        .add_permission(Permission::super_admin());
    
    let editor = Role::new("editor")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("write", "documents"));
    
    let user = Role::new("user")
        .add_permission(Permission::new("read", "documents"));
    
    system.register_role(admin).unwrap();
    system.register_role(editor).unwrap();
    system.register_role(user).unwrap();
    
    // Setup hierarchy
    system.add_role_inheritance("editor", "user").unwrap();
    system.add_role_inheritance("admin", "editor").unwrap();
    
    // Test user assignments
    let admin_user = Subject::user("admin-user");
    let editor_user = Subject::user("editor-user");
    let regular_user = Subject::user("regular-user");
    
    system.assign_role(&admin_user, "admin").unwrap();
    system.assign_role(&editor_user, "editor").unwrap();
    system.assign_role(&regular_user, "user").unwrap();
    
    // Test permissions
    let document = Resource::new("doc1", "documents");
    
    // Admin should have all permissions
    assert!(system.check_permission(&admin_user, "read", &document).unwrap());
    assert!(system.check_permission(&admin_user, "write", &document).unwrap());
    assert!(system.check_permission(&admin_user, "delete", &document).unwrap());
    
    // Editor should have read/write but not delete
    assert!(system.check_permission(&editor_user, "read", &document).unwrap());
    assert!(system.check_permission(&editor_user, "write", &document).unwrap());
    assert!(!system.check_permission(&editor_user, "delete", &document).unwrap());
    
    // Regular user should only have read
    assert!(system.check_permission(&regular_user, "read", &document).unwrap());
    assert!(!system.check_permission(&regular_user, "write", &document).unwrap());
    assert!(!system.check_permission(&regular_user, "delete", &document).unwrap());
}

#[tokio::test]
async fn test_conditional_permissions() {
    let mut system = RoleSystem::new();
    
    // Create conditional permission similar to middleware examples
    let business_hours_permission = Permission::with_condition("print", "documents", |context| {
        context.get("time") == Some(&"business_hours".to_string()) &&
        context.get("location") == Some(&"office".to_string())
    });
    
    let office_worker = Role::new("office_worker")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(business_hours_permission);
    
    system.register_role(office_worker).unwrap();
    
    let worker = Subject::user("worker");
    system.assign_role(&worker, "office_worker").unwrap();
    
    let document = Resource::new("report.pdf", "documents");
    
    // Test with correct context
    let mut valid_context = HashMap::new();
    valid_context.insert("time".to_string(), "business_hours".to_string());
    valid_context.insert("location".to_string(), "office".to_string());
    
    assert!(system.check_permission_with_context(
        &worker, "print", &document, &valid_context
    ).unwrap());
    
    // Test with invalid context
    let mut invalid_context = HashMap::new();
    invalid_context.insert("time".to_string(), "after_hours".to_string());
    invalid_context.insert("location".to_string(), "home".to_string());
    
    assert!(!system.check_permission_with_context(
        &worker, "print", &document, &invalid_context
    ).unwrap());
}

#[tokio::test]
async fn test_api_resource_permissions() {
    let mut system = RoleSystem::new();
    
    // Setup API-specific permissions like in middleware examples
    let api_user = Role::new("api_user")
        .add_permission(Permission::new("access", "api"));
    
    let api_admin = Role::new("api_admin")
        .add_permission(Permission::new("access", "api"))
        .add_permission(Permission::new("admin", "api"));
    
    system.register_role(api_user).unwrap();
    system.register_role(api_admin).unwrap();
    
    let user = Subject::user("api-user");
    let admin = Subject::user("api-admin");
    
    system.assign_role(&user, "api_user").unwrap();
    system.assign_role(&admin, "api_admin").unwrap();
    
    let api_resource = Resource::new("endpoint", "api");
    
    // Both should have API access
    assert!(system.check_permission(&user, "access", &api_resource).unwrap());
    assert!(system.check_permission(&admin, "access", &api_resource).unwrap());
    
    // Only admin should have admin access
    assert!(!system.check_permission(&user, "admin", &api_resource).unwrap());
    assert!(system.check_permission(&admin, "admin", &api_resource).unwrap());
}

#[tokio::test]
async fn test_multi_tenant_like_permissions() {
    let mut system = RoleSystem::new();
    
    // Test tenant-like isolation using resource context
    let tenant_admin = Role::new("tenant_admin")
        .add_permission(Permission::new("manage", "tenant_resources"));
    
    system.register_role(tenant_admin).unwrap();
    
    let admin_tenant_a = Subject::user("admin-tenant-a");
    let admin_tenant_b = Subject::user("admin-tenant-b");
    
    system.assign_role(&admin_tenant_a, "tenant_admin").unwrap();
    system.assign_role(&admin_tenant_b, "tenant_admin").unwrap();
    
    // Create tenant-specific resources
    let resource_a = Resource::new("resource-1", "tenant_resources")
        .with_metadata("tenant", "tenant-a");
    let resource_b = Resource::new("resource-2", "tenant_resources")
        .with_metadata("tenant", "tenant-b");
    
    // Both should be able to manage tenant resources in general
    assert!(system.check_permission(&admin_tenant_a, "manage", &resource_a).unwrap());
    assert!(system.check_permission(&admin_tenant_b, "manage", &resource_b).unwrap());
    
    // This test shows the basic permission check works
    // In a real multi-tenant system, you'd implement tenant isolation
    // through custom permission conditions or resource matching
}

#[tokio::test]
async fn test_role_elevation_like_middleware() {
    let mut system = RoleSystem::new();
    
    // Setup roles for elevation testing
    let user_role = Role::new("user")
        .add_permission(Permission::new("read", "documents"));
    
    let admin_role = Role::new("admin")
        .add_permission(Permission::new("admin", "*"));
    
    system.register_role(user_role).unwrap();
    system.register_role(admin_role).unwrap();
    
    let user = Subject::user("elevate-test-user");
    system.assign_role(&user, "user").unwrap();
    
    let document = Resource::new("doc1", "documents");
    let system_resource = Resource::new("system", "*");
    
    // Initially, user can only read
    assert!(system.check_permission(&user, "read", &document).unwrap());
    assert!(!system.check_permission(&user, "admin", &system_resource).unwrap());
    
    // Elevate to admin temporarily
    system.elevate_role(&user, "admin", Some(std::time::Duration::from_secs(3600))).unwrap();
    
    // Now user should have admin permissions
    assert!(system.check_permission(&user, "read", &document).unwrap());
    assert!(system.check_permission(&user, "admin", &system_resource).unwrap());
}

#[test]
fn test_middleware_example_permissions() {
    // Test the permission patterns used in middleware examples
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    let admin_all = Permission::new("admin", "*");
    let super_admin = Permission::super_admin();
    
    // Verify permission properties
    assert_eq!(read_docs.action(), "read");
    assert_eq!(read_docs.resource_type(), "documents");
    
    assert_eq!(write_docs.action(), "write");
    assert_eq!(write_docs.resource_type(), "documents");
    
    assert_eq!(admin_all.action(), "admin");
    assert_eq!(admin_all.resource_type(), "*");
    
    // Super admin should match any action/resource
    let context = HashMap::new();
    assert!(super_admin.is_granted("any_action", "any_resource", &context));
    assert!(super_admin.is_granted("delete", "sensitive_data", &context));
}
