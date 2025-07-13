//! Edge case tests for permission-specific security scenarios.

use role_system::permission::{Permission, PermissionSet};
use std::collections::HashMap;

#[test]
fn test_permission_edge_cases() {
    // Test empty string handling
    let result = std::panic::catch_unwind(|| {
        Permission::new("", "documents")
    });
    assert!(result.is_err(), "Empty action should panic");
    
    let result = std::panic::catch_unwind(|| {
        Permission::new("read", "")
    });
    assert!(result.is_err(), "Empty resource type should panic");
    
    // Test whitespace-only strings
    let result = std::panic::catch_unwind(|| {
        Permission::new(" ", "documents")
    });
    assert!(result.is_err(), "Whitespace-only action should panic");
    
    let result = std::panic::catch_unwind(|| {
        Permission::new("read", " ")
    });
    assert!(result.is_err(), "Whitespace-only resource type should panic");
}

#[test]
fn test_permission_parsing_security() {
    // Test various malformed permission strings that should fail
    let malformed_permissions = vec![
        "",
        ":",
        "action:",
        ":resource",
        "action:resource:extra",
        "action:resource:extra:parts",
        " : ",
        "\n:\t",
        "action\u{0000}:resource",
        "action:resource\u{0000}",
    ];
    
    for malformed in malformed_permissions {
        let result = Permission::parse(malformed);
        assert!(result.is_err(), "Should fail to parse: '{}'", malformed);
    }
    
    // Test that valid permissions parse correctly
    let valid_permissions = vec![
        "action:resource",
        "read:documents", 
        "write:files",
    ];
    
    for valid in valid_permissions {
        let result = Permission::parse(valid);
        assert!(result.is_ok(), "Should successfully parse: '{}'", valid);
    }
}

#[test]
fn test_unicode_and_special_characters() {
    // Test with Unicode characters
    let unicode_permission = Permission::new("читать", "документы");
    assert_eq!(unicode_permission.action(), "читать");
    assert_eq!(unicode_permission.resource_type(), "документы");
    
    // Test with emojis
    let emoji_permission = Permission::new("🔒", "🗂️");
    assert_eq!(emoji_permission.action(), "🔒");
    assert_eq!(emoji_permission.resource_type(), "🗂️");
    
    // Test with special characters that might be used in injection attacks
    let special_chars = vec!["<script>", "'; DROP TABLE", "../..", "\n\r\t"];
    for special in special_chars {
        let permission = Permission::new(format!("action_{}", special), format!("resource_{}", special));
        // Should not crash or cause issues
        assert!(permission.matches(&format!("action_{}", special), &format!("resource_{}", special)));
    }
}

#[test]
fn test_conditional_permission_edge_cases() {
    // Test conditional permission with always-false condition
    let never_permission = Permission::with_condition("read", "documents", |_| false);
    let context = HashMap::new();
    assert!(!never_permission.is_granted("read", "documents", &context));
    
    // Test conditional permission with always-true condition
    let always_permission = Permission::with_condition("read", "documents", |_| true);
    assert!(always_permission.is_granted("read", "documents", &context));
    
    // Test conditional permission that panics (removed this test as it's not safe to test panicking closures)
}

#[test]
fn test_conditional_permission_context_manipulation() {
    let permission = Permission::with_condition("access", "vault", |context| {
        // Check for specific key-value pairs
        context.get("user_level") == Some(&"admin".to_string()) &&
        context.get("time_of_day") == Some(&"business_hours".to_string())
    });
    
    // Test with correct context
    let mut valid_context = HashMap::new();
    valid_context.insert("user_level".to_string(), "admin".to_string());
    valid_context.insert("time_of_day".to_string(), "business_hours".to_string());
    assert!(permission.is_granted("access", "vault", &valid_context));
    
    // Test context manipulation attempts
    let manipulation_attempts = vec![
        {
            let mut ctx = HashMap::new();
            ctx.insert("user_level".to_string(), "ADMIN".to_string()); // Case manipulation
            ctx.insert("time_of_day".to_string(), "business_hours".to_string());
            ctx
        },
        {
            let mut ctx = HashMap::new();
            ctx.insert("user_level".to_string(), " admin ".to_string()); // Whitespace
            ctx.insert("time_of_day".to_string(), "business_hours".to_string());
            ctx
        },
        {
            let mut ctx = HashMap::new();
            ctx.insert("user_level".to_string(), "admin\x00".to_string()); // Null byte
            ctx.insert("time_of_day".to_string(), "business_hours".to_string());
            ctx
        },
    ];
    
    for attempt in manipulation_attempts {
        assert!(!permission.is_granted("access", "vault", &attempt),
               "Should reject context manipulation: {:?}", attempt);
    }
    
    // Test that extra keys don't affect the result (this should pass)
    let mut context_with_extra_keys = HashMap::new();
    context_with_extra_keys.insert("user_level".to_string(), "admin".to_string());
    context_with_extra_keys.insert("time_of_day".to_string(), "business_hours".to_string());
    context_with_extra_keys.insert("__proto__".to_string(), "admin".to_string()); // Extra key
    context_with_extra_keys.insert("extra_field".to_string(), "value".to_string());
    
    // This should pass because the condition only checks for the specific keys
    assert!(permission.is_granted("access", "vault", &context_with_extra_keys),
           "Should allow access with extra keys if core conditions are met");
}

#[test]
fn test_permission_set_security() {
    let mut permission_set = PermissionSet::new();
    
    // Add permissions
    let read_perm = Permission::new("read", "documents");
    let write_perm = Permission::new("write", "documents");
    let _admin_perm = Permission::new("admin", "system"); // Not used in this test
    
    permission_set.add(read_perm.clone());
    permission_set.add(write_perm.clone());
    
    // Verify isolation - admin permission should not be granted
    let context = HashMap::new();
    assert!(permission_set.grants("read", "documents", &context));
    assert!(permission_set.grants("write", "documents", &context));
    assert!(!permission_set.grants("admin", "system", &context));
    
    // Test that removing a permission actually removes it
    permission_set.remove(&read_perm);
    assert!(!permission_set.grants("read", "documents", &context));
    assert!(permission_set.grants("write", "documents", &context));
}

#[test]
fn test_permission_clone_security() {
    // Test that cloning conditional permissions preserves security
    let original = Permission::with_condition("access", "secure_area", |context| {
        context.get("clearance_level") == Some(&"top_secret".to_string())
    });
    
    let cloned = original.clone();
    
    let mut valid_context = HashMap::new();
    valid_context.insert("clearance_level".to_string(), "top_secret".to_string());
    
    let mut invalid_context = HashMap::new();
    invalid_context.insert("clearance_level".to_string(), "confidential".to_string());
    
    // Both original and clone should behave identically
    assert!(original.is_granted("access", "secure_area", &valid_context));
    assert!(cloned.is_granted("access", "secure_area", &valid_context));
    
    assert!(!original.is_granted("access", "secure_area", &invalid_context));
    assert!(!cloned.is_granted("access", "secure_area", &invalid_context));
}

#[test]
fn test_permission_equality_security() {
    let perm1 = Permission::new("read", "documents");
    let perm2 = Permission::new("read", "documents");
    let perm3 = Permission::new("write", "documents");
    
    // Basic equality
    assert_eq!(perm1, perm2);
    assert_ne!(perm1, perm3);
    
    // Conditional permissions with same action/resource should be equal
    // even if they have different conditions (for security isolation)
    let cond_perm1 = Permission::with_condition("read", "documents", |_| true);
    let cond_perm2 = Permission::with_condition("read", "documents", |_| false);
    
    assert_eq!(cond_perm1, cond_perm2);
    assert_eq!(cond_perm1, perm1); // Should equal non-conditional version too
}

#[test]
fn test_permission_hash_security() {
    use std::collections::HashSet;
    
    let mut permission_set = HashSet::new();
    
    let perm1 = Permission::new("read", "documents");
    let perm2 = Permission::new("read", "documents");
    let cond_perm = Permission::with_condition("read", "documents", |_| true);
    
    permission_set.insert(perm1);
    
    // Duplicate permission should not be added
    assert!(!permission_set.insert(perm2));
    
    // Conditional permission with same action/resource should not be added
    assert!(!permission_set.insert(cond_perm));
    
    assert_eq!(permission_set.len(), 1);
}

#[test]
fn test_large_permission_sets() {
    let mut large_set = PermissionSet::new();
    
    // Add a large number of permissions
    for i in 0..10000 {
        let permission = Permission::new(format!("action_{}", i), format!("resource_{}", i % 100));
        large_set.add(permission);
    }
    
    assert_eq!(large_set.len(), 10000);
    
    // Permission checking should still be efficient
    let context = HashMap::new();
    let start = std::time::Instant::now();
    
    // Test checking for existing and non-existing permissions
    assert!(large_set.grants("action_5000", "resource_0", &context));
    assert!(!large_set.grants("non_existent_action", "resource_0", &context));
    
    let duration = start.elapsed();
    assert!(duration < std::time::Duration::from_millis(100), 
           "Permission check took too long: {:?}", duration);
}

#[test]
fn test_wildcard_permission_precedence() {
    let mut permission_set = PermissionSet::new();
    
    // Add specific permission first
    let specific_perm = Permission::new("read", "documents");
    permission_set.add(specific_perm);
    
    // Add wildcard permission
    let wildcard_perm = Permission::wildcard("documents");
    permission_set.add(wildcard_perm);
    
    let context = HashMap::new();
    
    // Both read and write should be granted due to wildcard
    assert!(permission_set.grants("read", "documents", &context));
    assert!(permission_set.grants("write", "documents", &context));
    assert!(permission_set.grants("delete", "documents", &context));
    
    // But not for other resource types
    assert!(!permission_set.grants("read", "users", &context));
}

#[test]
fn test_super_admin_permission_isolation() {
    let mut permission_set = PermissionSet::new();
    
    // Add regular permissions
    let read_perm = Permission::new("read", "documents");
    permission_set.add(read_perm);
    
    // Super admin permission should grant everything
    let super_admin = Permission::super_admin();
    let mut admin_set = PermissionSet::new();
    admin_set.add(super_admin);
    
    let context = HashMap::new();
    
    // Regular set should not grant admin actions
    assert!(!permission_set.grants("admin", "system", &context));
    assert!(!permission_set.grants("delete", "users", &context));
    
    // Admin set should grant everything
    assert!(admin_set.grants("admin", "system", &context));
    assert!(admin_set.grants("delete", "users", &context));
    assert!(admin_set.grants("read", "documents", &context));
    assert!(admin_set.grants("any_action", "any_resource", &context));
}
