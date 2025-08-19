/// Comprehensive example showcasing role-system v1.1.0 features.
///
/// This example demonstrates:
/// - Enhanced Permission constructors (with_context, with_scope, conditional)
/// - Fluent RoleBuilder API (allow, deny, allow_when)
/// - Declarative role macros (define_role!, define_roles!)
/// - Role hierarchy with inheritance
/// - Conditional permissions with context-dependent access
use role_system::{
    define_role, define_roles, permission,
    permission::{ConditionalPermissionBuilder, Permission},
    role::{RoleBuilder, RoleHierarchy},
};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Role System v1.1.0 Enhanced Features Demo ===\n");

    // 1. Enhanced Permission Constructors
    println!("1. Enhanced Permission Constructors:");

    let basic_permission = Permission::new("read", "documents");
    println!("   Basic: {:?}", basic_permission);

    let scoped_permissions = Permission::with_scope("documents", "read", vec!["public", "shared"]);
    println!(
        "   Scoped: {} permissions generated",
        scoped_permissions.len()
    );

    let context_permission = Permission::with_context("profile", "update", Some("owner_only"));
    println!("   Context: {:?}", context_permission);

    let conditional_permission = Permission::conditional("secure_area", "access")
        .when(|ctx| ctx.get("clearance_level") == Some(&"top_secret".to_string()))
        .build();
    println!("   Conditional: created\n");

    // 2. Conditional Permission Builder
    println!("2. Conditional Permission Builder:");

    let complex_permission = ConditionalPermissionBuilder::new("system", "admin_access")
        .when(|ctx| ctx.get("role") == Some(&"admin".to_string()))
        .or_when(|ctx| ctx.get("emergency") == Some(&"true".to_string()))
        .build();

    // Demonstrate usage with different contexts
    let mut admin_ctx = HashMap::new();
    admin_ctx.insert("role".to_string(), "admin".to_string());

    let mut emergency_ctx = HashMap::new();
    emergency_ctx.insert("emergency".to_string(), "true".to_string());

    let empty_ctx = HashMap::new();

    println!("   Complex conditional access:");
    println!(
        "     Admin context: {}",
        complex_permission.is_granted("admin_access", "system", &admin_ctx)
    );
    println!(
        "     Emergency context: {}",
        complex_permission.is_granted("admin_access", "system", &emergency_ctx)
    );
    println!(
        "     Empty context: {}\n",
        complex_permission.is_granted("admin_access", "system", &empty_ctx)
    );

    // 3. Fluent RoleBuilder API
    println!("3. Fluent RoleBuilder API:");

    let admin_role = RoleBuilder::new()
        .name("admin")
        .description("System administrator with full access")
        .allow("users", ["create", "read", "update", "delete"])
        .allow("system", ["configure", "monitor", "backup"])
        .deny("system", ["format"]) // Even admins can't format
        .allow_when("sensitive_data", ["access"], |ctx| {
            ctx.get("two_factor_auth") == Some(&"enabled".to_string())
        })
        .build()?;

    println!(
        "   Admin role: {} with {} permissions",
        admin_role.name(),
        admin_role.permissions().len()
    );

    // 4. Declarative Role Macros
    println!("\n4. Declarative Role Macros:");

    let editor_role = define_role!(editor {
        posts: ["create", "read", "update"],
        media: ["upload", "organize"],
        comments: ["moderate"]
    });
    println!(
        "   Editor role: {} with {} permissions",
        editor_role.name(),
        editor_role.permissions().len()
    );

    let all_roles = define_roles! {
        viewer {
            posts: ["read"],
            comments: ["read"]
        },

        moderator {
            posts: ["read", "feature"],
            comments: ["read", "moderate", "delete"],
            users: ["warn", "timeout"]
        }
    };
    println!("   Bulk created {} roles", all_roles.len());

    // 5. Role Hierarchy with Inheritance
    println!("\n5. Role Hierarchy with Inheritance:");

    let mut hierarchy = RoleHierarchy::new();

    // Add roles to hierarchy
    hierarchy.add_role(admin_role.clone())?;
    hierarchy.add_role(editor_role.clone())?;
    hierarchy.add_role(all_roles["viewer"].clone())?;
    hierarchy.add_role(all_roles["moderator"].clone())?;

    // Set up hierarchy using role IDs: admin -> moderator -> editor -> viewer
    let admin_id = admin_role.id();
    let editor_id = editor_role.id();
    let viewer_id = all_roles["viewer"].id();
    let moderator_id = all_roles["moderator"].id();

    hierarchy.set_parent(moderator_id, admin_id)?;
    hierarchy.set_parent(editor_id, moderator_id)?;
    hierarchy.set_parent(viewer_id, editor_id)?;

    // Check effective permissions (including inherited)
    let viewer_permissions = hierarchy.get_effective_permissions(viewer_id)?;
    println!(
        "   Viewer effective permissions: {} (including inherited)",
        viewer_permissions.len()
    );

    let admin_permissions = hierarchy.get_effective_permissions(admin_id)?;
    println!(
        "   Admin effective permissions: {}",
        admin_permissions.len()
    );

    // 6. Context-Dependent Permission Checking
    println!("\n6. Context-Dependent Permission Checking:");

    let mut user_context = HashMap::new();
    user_context.insert("user_id".to_string(), "user123".to_string());
    user_context.insert("clearance_level".to_string(), "confidential".to_string());

    let mut admin_context = HashMap::new();
    admin_context.insert("two_factor_auth".to_string(), "enabled".to_string());
    admin_context.insert("clearance_level".to_string(), "top_secret".to_string());

    // Test permissions with different contexts
    println!(
        "   User can read documents: {}",
        basic_permission.is_granted("read", "documents", &user_context)
    );

    println!(
        "   User can access secure area: {}",
        conditional_permission.is_granted("access", "secure_area", &user_context)
    );

    println!(
        "   Admin can access secure area: {}",
        conditional_permission.is_granted("access", "secure_area", &admin_context)
    );

    // 7. Macro-Generated Permissions
    println!("\n7. Macro-Generated Permissions:");

    let single_perm = permission!("files", "read");
    let multi_perms = permission!("api", ["get", "post", "put", "delete"]);

    println!("   Single permission: {:?}", single_perm);
    println!("   Multiple permissions: {} generated", multi_perms.len());

    println!("\n=== Demo Complete ===");
    println!("Role System v1.1.0 provides enhanced ergonomics while maintaining");
    println!("backward compatibility with existing v1.0.x codebases.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_features_integration() {
        // Test that all enhanced features work together
        let role = RoleBuilder::new()
            .name("test_role")
            .allow("resource", ["action1", "action2"])
            .deny("resource", ["forbidden"])
            .build()
            .expect("Failed to build role");

        assert_eq!(role.name(), "test_role");
        assert_eq!(role.permissions().len(), 3); // 2 allow + 1 deny
    }

    #[test]
    fn test_hierarchy_inheritance() {
        let mut hierarchy = RoleHierarchy::new();

        let parent = define_role!(parent {
            resource: ["action1", "action2"]
        });

        let child = define_role!(child {
            resource: ["action3"]
        });

        let parent_id = parent.id().to_string();
        let child_id = child.id().to_string();

        hierarchy.add_role(parent).expect("Failed to add parent");
        hierarchy.add_role(child).expect("Failed to add child");
        hierarchy
            .set_parent(&child_id, &parent_id)
            .expect("Failed to set parent");

        let effective = hierarchy
            .get_effective_permissions(&child_id)
            .expect("Failed to get effective permissions");

        assert_eq!(effective.len(), 3); // 2 inherited + 1 own
    }

    #[test]
    fn test_conditional_permissions() {
        let perm = Permission::conditional("resource", "access")
            .when(|ctx| ctx.get("authorized") == Some(&"true".to_string()))
            .build();

        let mut valid_context = HashMap::new();
        valid_context.insert("authorized".to_string(), "true".to_string());

        let invalid_context = HashMap::new();

        assert!(perm.is_granted("access", "resource", &valid_context));
        assert!(!perm.is_granted("access", "resource", &invalid_context));
    }
}
