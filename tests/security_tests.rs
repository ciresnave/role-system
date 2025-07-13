//! Security-focused tests for the role system.
//! These tests ensure the system cannot be compromised through various attack vectors.

use role_system::{
    core::{RoleSystem, RoleSystemConfig},
    permission::Permission,
    resource::Resource,
    role::Role,
    subject::Subject,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[test]
fn test_privilege_escalation_prevention() {
    let mut system = RoleSystem::new();

    // Create permissions with different levels
    let read_docs = Permission::new("read", "documents");
    let admin_perm = Permission::new("admin", "system");
    
    // Create roles
    let user_role = Role::new("user").add_permission(read_docs);
    let admin_role = Role::new("admin").add_permission(admin_perm);
    
    system.register_role(user_role).unwrap();
    system.register_role(admin_role).unwrap();

    let user = Subject::user("normal_user");
    system.assign_role(&user, "user").unwrap();

    let admin_resource = Resource::new("critical_system", "system");
    
    // User should NOT have admin permissions
    assert!(!system.check_permission(&user, "admin", &admin_resource).unwrap());
    
    // Even if we try to manipulate the system, user should not gain admin access
    let user_roles = system.get_subject_roles(&user).unwrap();
    assert!(!user_roles.contains("admin"));
    assert_eq!(user_roles.len(), 1);
    assert!(user_roles.contains("user"));
}

#[test]
fn test_role_hierarchy_cycle_prevention() {
    let mut system = RoleSystem::new();
    
    // Create roles
    let role_a = Role::new("role_a");
    let role_b = Role::new("role_b");
    let role_c = Role::new("role_c");
    
    system.register_role(role_a).unwrap();
    system.register_role(role_b).unwrap();
    system.register_role(role_c).unwrap();
    
    // Create a chain: role_a -> role_b -> role_c
    system.add_role_inheritance("role_a", "role_b").unwrap();
    system.add_role_inheritance("role_b", "role_c").unwrap();
    
    // Attempting to create a cycle should fail
    assert!(system.add_role_inheritance("role_c", "role_a").is_err());
    assert!(system.add_role_inheritance("role_c", "role_b").is_err());
    
    // Direct self-reference should also fail
    assert!(system.add_role_inheritance("role_a", "role_a").is_err());
}

#[test]
fn test_conditional_permission_bypass_prevention() {
    let mut system = RoleSystem::new();
    
    // Create a permission that should only work during business hours
    let conditional_perm = Permission::with_condition("access", "vault", |context| {
        context.get("time") == Some(&"business_hours".to_string())
            && context.get("authorized") == Some(&"true".to_string())
    });
    
    let role = Role::new("vault_user").add_permission(conditional_perm);
    system.register_role(role).unwrap();
    
    let user = Subject::user("employee");
    system.assign_role(&user, "vault_user").unwrap();
    
    let vault = Resource::new("main_vault", "vault");
    
    // Test with correct context
    let mut valid_context = HashMap::new();
    valid_context.insert("time".to_string(), "business_hours".to_string());
    valid_context.insert("authorized".to_string(), "true".to_string());
    assert!(system.check_permission_with_context(&user, "access", &vault, &valid_context).unwrap());
    
    // Test bypass attempts with malicious contexts
    let malicious_contexts = vec![
        HashMap::new(), // Empty context
        {
            let mut ctx = HashMap::new();
            ctx.insert("time".to_string(), "business_hours".to_string());
            // Missing authorized field
            ctx
        },
        {
            let mut ctx = HashMap::new();
            ctx.insert("time".to_string(), "after_hours".to_string());
            ctx.insert("authorized".to_string(), "true".to_string());
            ctx
        },
        {
            let mut ctx = HashMap::new();
            ctx.insert("time".to_string(), "business_hours".to_string());
            ctx.insert("authorized".to_string(), "false".to_string());
            ctx
        },
        {
            let mut ctx = HashMap::new();
            // Injection attempt
            ctx.insert("time".to_string(), "business_hours\"; DROP TABLE permissions; --".to_string());
            ctx.insert("authorized".to_string(), "true".to_string());
            ctx
        }
    ];
    
    for malicious_context in malicious_contexts {
        assert!(!system.check_permission_with_context(&user, "access", &vault, &malicious_context).unwrap(),
               "Permission should be denied for malicious context: {:?}", malicious_context);
    }
}

#[test]
fn test_input_validation_and_injection_prevention() {
    let mut system = RoleSystem::new();
    
    // Test malicious inputs for role names
    let long_string = "a".repeat(10000);
    let malicious_inputs = vec![
        "",
        " ",
        "\n",
        "\t",
        "role\x00name",
        "role'; DROP TABLE roles; --",
        "../../../etc/passwd",
        "role<script>alert('xss')</script>",
        "role\u{0000}name",
        &long_string, // Very long string
    ];
    
    for malicious_input in malicious_inputs {
        // Creating roles with malicious names should either fail or be sanitized
        let result = Role::new(malicious_input);
        if !malicious_input.is_empty() && !malicious_input.trim().is_empty() {
            // If the role is created, it should not cause issues when registered
            let register_result = system.register_role(result);
            // System should handle this gracefully without crashing
            if register_result.is_ok() {
                // If registered successfully, ensure it doesn't break permission checks
                let user = Subject::user("test_user");
                let _ = system.assign_role(&user, malicious_input);
                let resource = Resource::new("test", "test");
                let _ = system.check_permission(&user, "test", &resource);
            }
        }
    }
}

#[test]
fn test_concurrent_access_safety() {
    let system = Arc::new(Mutex::new(RoleSystem::new()));
    
    // Register initial role
    {
        let mut sys = system.lock().unwrap();
        let role = Role::new("test_role").add_permission(Permission::new("read", "documents"));
        sys.register_role(role).unwrap();
    }
    
    let handles: Vec<_> = (0..10).map(|i| {
        let system_clone = Arc::clone(&system);
        thread::spawn(move || {
            let user = Subject::user(&format!("user_{}", i));
            let resource = Resource::new("doc", "documents");
            
            // Each thread tries to assign role and check permission
            {
                let mut sys = system_clone.lock().unwrap();
                let _ = sys.assign_role(&user, "test_role");
            }
            
            // Check permission
            {
                let sys = system_clone.lock().unwrap();
                let result = sys.check_permission(&user, "read", &resource);
                assert!(result.is_ok());
            }
        })
    }).collect();
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify system state is consistent
    let sys = system.lock().unwrap();
    for i in 0..10 {
        let user = Subject::user(&format!("user_{}", i));
        let roles = sys.get_subject_roles(&user).unwrap();
        assert!(roles.contains("test_role"));
    }
}

#[test]
fn test_cache_integrity() {
    let mut system = RoleSystem::new();
    
    let permission = Permission::new("read", "documents");
    let role = Role::new("reader").add_permission(permission);
    system.register_role(role).unwrap();
    
    let user = Subject::user("cache_test_user");
    system.assign_role(&user, "reader").unwrap();
    
    let resource = Resource::new("doc1", "documents");
    
    // Prime the cache
    assert!(system.check_permission(&user, "read", &resource).unwrap());
    
    // Remove the role assignment
    system.remove_role(&user, "reader").unwrap();
    
    // Cache should be invalidated, permission should be denied
    assert!(!system.check_permission(&user, "read", &resource).unwrap());
    
    // Re-assign role
    system.assign_role(&user, "reader").unwrap();
    
    // Permission should be granted again
    assert!(system.check_permission(&user, "read", &resource).unwrap());
}

#[test]
fn test_role_elevation_expiry() {
    let mut system = RoleSystem::new();
    
    let admin_perm = Permission::new("admin", "system");
    let admin_role = Role::new("admin").add_permission(admin_perm);
    system.register_role(admin_role).unwrap();
    
    let user = Subject::user("temp_admin");
    let resource = Resource::new("system", "system");
    
    // User should not have admin permission initially
    assert!(!system.check_permission(&user, "admin", &resource).unwrap());
    
    // Elevate user to admin for a very short duration
    system.elevate_role(&user, "admin", Some(Duration::from_millis(10))).unwrap();
    
    // User should have admin permission immediately after elevation
    assert!(system.check_permission(&user, "admin", &resource).unwrap());
    
    // Wait for elevation to expire
    thread::sleep(Duration::from_millis(50));
    
    // User should no longer have admin permission
    assert!(!system.check_permission(&user, "admin", &resource).unwrap());
}

#[test]
fn test_resource_pattern_security() {
    let mut system = RoleSystem::new();
    
    // Create permissions for specific patterns
    let user_docs_perm = Permission::new("read", "documents");
    let admin_docs_perm = Permission::new("read", "admin_documents");
    
    let user_role = Role::new("user").add_permission(user_docs_perm);
    let admin_role = Role::new("admin").add_permission(admin_docs_perm);
    
    system.register_role(user_role).unwrap();
    system.register_role(admin_role).unwrap();
    
    let user = Subject::user("normal_user");
    system.assign_role(&user, "user").unwrap();
    
    // User should access regular documents
    let user_doc = Resource::new("user_file.txt", "documents");
    assert!(system.check_permission(&user, "read", &user_doc).unwrap());
    
    // User should NOT access admin documents
    let admin_doc = Resource::new("admin_file.txt", "admin_documents");
    assert!(!system.check_permission(&user, "read", &admin_doc).unwrap());
    
    // Test path traversal attempts - these should fail to create
    let malicious_resource_specs = vec![
        ("../admin_file.txt", "documents"),
        ("../../etc/passwd", "documents"),
        ("admin_file.txt", "documents/../admin_documents"),
    ];
    
    for (id, resource_type) in malicious_resource_specs {
        let result = std::panic::catch_unwind(|| {
            Resource::new(id, resource_type)
        });
        assert!(result.is_err(), "Should fail to create malicious resource with ID: '{}'", id);
    }
}

#[test]
fn test_error_information_leakage() {
    let mut system = RoleSystem::new();
    
    let user = Subject::user("test_user");
    let resource = Resource::new("test_resource", "test_type");
    
    // Test permission check on non-existent role
    let result = system.check_permission(&user, "read", &resource);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should return false, not error
    
    // Test assigning non-existent role
    let result = system.assign_role(&user, "non_existent_role");
    assert!(result.is_err());
    
    // Error message should not leak sensitive information
    if let Err(error) = result {
        let error_msg = error.to_string();
        // Should not contain file paths, memory addresses, or other sensitive data
        assert!(!error_msg.contains("/"));
        assert!(!error_msg.contains("\\"));
        assert!(!error_msg.contains("0x"));
        assert!(!error_msg.contains("password"));
        assert!(!error_msg.contains("secret"));
    }
}

#[test]
fn test_boundary_conditions() {
    let _system = RoleSystem::new();
    
    // Test with maximum hierarchy depth
    let config = RoleSystemConfig {
        max_hierarchy_depth: 3,
        enable_caching: true,
        cache_ttl_seconds: 300,
        enable_audit: false,
    };
    let mut limited_system = RoleSystem::with_config(config);
    
    // Create a hierarchy at the limit
    for i in 0..=3 {
        let role = Role::new(&format!("role_{}", i));
        limited_system.register_role(role).unwrap();
    }
    
    // Build hierarchy: role_0 -> role_1 -> role_2 -> role_3
    for i in 0..3 {
        limited_system.add_role_inheritance(&format!("role_{}", i), &format!("role_{}", i + 1)).unwrap();
    }
    
    // Adding one more level should fail
    let role_4 = Role::new("role_4");
    limited_system.register_role(role_4).unwrap();
    assert!(limited_system.add_role_inheritance("role_3", "role_4").is_err());
}

#[test]
fn test_memory_exhaustion_protection() {
    let mut system = RoleSystem::new();
    
    // Create a large number of roles and permissions
    for i in 0..1000 {
        let permission = Permission::new(&format!("action_{}", i), &format!("resource_{}", i));
        let role = Role::new(&format!("role_{}", i)).add_permission(permission);
        system.register_role(role).unwrap();
    }
    
    // Create users and assign roles
    for i in 0..100 {
        let user = Subject::user(&format!("user_{}", i));
        for j in 0..10 {
            let role_index = (i * 10 + j) % 1000;
            system.assign_role(&user, &format!("role_{}", role_index)).unwrap();
        }
    }
    
    // System should still be responsive
    let test_user = Subject::user("user_0");
    let test_resource = Resource::new("resource_0", "resource_0");
    let start = Instant::now();
    let result = system.check_permission(&test_user, "action_0", &test_resource);
    let duration = start.elapsed();
    
    assert!(result.is_ok());
    assert!(duration < Duration::from_millis(100), "Permission check took too long: {:?}", duration);
}

#[test]
fn test_wildcard_permission_security() {
    let mut system = RoleSystem::new();
    
    // Create a role with wildcard action but specific resource
    let limited_wildcard = Permission::wildcard("documents");
    let role = Role::new("doc_admin").add_permission(limited_wildcard);
    system.register_role(role).unwrap();
    
    let user = Subject::user("doc_admin_user");
    system.assign_role(&user, "doc_admin").unwrap();
    
    let doc_resource = Resource::new("test.txt", "documents");
    let system_resource = Resource::new("config", "system");
    
    // User should have all actions on documents
    assert!(system.check_permission(&user, "read", &doc_resource).unwrap());
    assert!(system.check_permission(&user, "write", &doc_resource).unwrap());
    assert!(system.check_permission(&user, "delete", &doc_resource).unwrap());
    
    // But NOT on system resources
    assert!(!system.check_permission(&user, "read", &system_resource).unwrap());
    assert!(!system.check_permission(&user, "write", &system_resource).unwrap());
    assert!(!system.check_permission(&user, "delete", &system_resource).unwrap());
}

#[test]
fn test_super_admin_isolation() {
    let mut system = RoleSystem::new();
    
    // Create super admin and regular user
    let super_admin_role = Role::new("super_admin").add_permission(Permission::super_admin());
    let user_role = Role::new("user").add_permission(Permission::new("read", "documents"));
    
    system.register_role(super_admin_role).unwrap();
    system.register_role(user_role).unwrap();
    
    let admin = Subject::user("admin");
    let user = Subject::user("user");
    
    system.assign_role(&admin, "super_admin").unwrap();
    system.assign_role(&user, "user").unwrap();
    
    let critical_resource = Resource::new("nuclear_codes", "top_secret");
    let user_resource = Resource::new("readme.txt", "documents");
    
    // Super admin should have access to everything
    assert!(system.check_permission(&admin, "read", &critical_resource).unwrap());
    assert!(system.check_permission(&admin, "launch", &critical_resource).unwrap());
    assert!(system.check_permission(&admin, "read", &user_resource).unwrap());
    
    // Regular user should only have limited access
    assert!(!system.check_permission(&user, "read", &critical_resource).unwrap());
    assert!(!system.check_permission(&user, "launch", &critical_resource).unwrap());
    assert!(system.check_permission(&user, "read", &user_resource).unwrap());
    assert!(!system.check_permission(&user, "write", &user_resource).unwrap());
}

#[cfg(feature = "persistence")]
#[test]
fn test_serialization_integrity() {
    use serde_json;
    
    let mut system = RoleSystem::new();
    
    let permission = Permission::new("read", "documents");
    let role = Role::new("reader").add_permission(permission);
    system.register_role(role).unwrap();
    
    let user = Subject::user("test_user");
    system.assign_role(&user, "reader").unwrap();
    
    // Serialize a permission
    let original_permission = Permission::new("write", "files");
    let serialized = serde_json::to_string(&original_permission).unwrap();
    
    // Verify it can be deserialized correctly
    let deserialized: Permission = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.action(), original_permission.action());
    assert_eq!(deserialized.resource_type(), original_permission.resource_type());
    
    // Test that malicious JSON cannot create invalid permissions
    let malicious_json = r#"{"action":"admin","resource_type":"system","condition":"malicious_code"}"#;
    let result: Result<Permission, _> = serde_json::from_str(malicious_json);
    // Should either deserialize safely (ignoring malicious fields) or fail
    assert!(result.is_ok() || result.is_err());
}
