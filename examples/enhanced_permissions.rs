use role_system::{RoleSystem, Permission, Subject, Role, Resource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Enhanced Permission System Demo - Three-Part Format & Implication Logic");
    println!("==============================================================================");
    
    let mut rbac = RoleSystem::new();
    
    // Demo 1: Three-Part Permission Format
    println!("\n📋 Demo 1: Three-Part Permission Format");
    println!("-----------------------------------------");
    
    // Traditional two-part permissions (still supported)
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    
    // New three-part permissions with specific instances
    let read_doc123 = Permission::with_instance("read", "documents", "doc123");
    let edit_doc123 = Permission::with_instance("edit", "documents", "doc123");
    let delete_file456 = Permission::with_instance("delete", "files", "file456");
    
    println!("✓ Two-part: {}", read_docs);
    println!("✓ Two-part: {}", write_docs);
    println!("✓ Three-part: {}", read_doc123);
    println!("✓ Three-part: {}", edit_doc123);
    println!("✓ Three-part: {}", delete_file456);
    
    // Demo 2: Permission Parsing
    println!("\n📋 Demo 2: Enhanced Permission Parsing");
    println!("----------------------------------------");
    
    let permissions = vec![
        "read:documents",           // Traditional format
        "read:documents:doc123",    // New instance-specific format
        "admin:users:user456",      // Admin access to specific user
        "*:*",                      // Super admin
        "edit:projects:*",          // Edit any project
    ];
    
    for perm_str in permissions {
        match Permission::parse(perm_str) {
            Ok(permission) => {
                println!("✓ Parsed '{}' -> Action: '{}', Resource: '{}', Instance: {:?}", 
                    perm_str, 
                    permission.action(), 
                    permission.resource_type(),
                    permission.instance()
                );
            }
            Err(e) => println!("✗ Failed to parse '{}': {}", perm_str, e),
        }
    }
    
    // Demo 3: Permission Implication Logic
    println!("\n📋 Demo 3: Permission Implication Logic");
    println!("----------------------------------------");
    
    let general_read = Permission::new("read", "documents");
    let specific_read = Permission::with_instance("read", "documents", "doc123");
    let admin_all = Permission::super_admin();
    let admin_docs = Permission::new("admin", "documents");
    let edit_any_doc = Permission::with_instance("edit", "documents", "*");
    let edit_specific = Permission::with_instance("edit", "documents", "doc789");
    
    let implications = vec![
        (&general_read, &specific_read, "General read implies specific read"),
        (&admin_all, &general_read, "Super admin implies general read"),
        (&admin_all, &specific_read, "Super admin implies specific read"),
        (&admin_docs, &general_read, "Admin docs implies general read"),
        (&edit_any_doc, &edit_specific, "Edit any doc implies edit specific doc"),
        (&specific_read, &general_read, "Specific does NOT imply general"),
    ];
    
    for (perm1, perm2, description) in implications {
        let implies = perm1.implies(perm2);
        println!("{} '{}' → '{}': {}", 
            if implies { "✓" } else { "✗" },
            perm1, 
            perm2, 
            description
        );
    }
    
    // Demo 4: Real-World Multi-Tenant Scenario
    println!("\n📋 Demo 4: Multi-Tenant Document Management System");
    println!("---------------------------------------------------");
    
    // Create roles with instance-specific permissions
    let admin_role = Role::new("admin")
        .add_permission(Permission::super_admin());
    
    let tenant_admin = Role::new("tenant_admin")
        .add_permission(Permission::with_instance("admin", "documents", "tenant_123"))
        .add_permission(Permission::with_instance("read", "users", "*"));
    
    let document_editor = Role::new("doc_editor")
        .add_permission(Permission::with_instance("read", "documents", "doc_456"))
        .add_permission(Permission::with_instance("edit", "documents", "doc_456"));
    
    let viewer = Role::new("viewer")
        .add_permission(Permission::new("read", "documents"));
    
    // Add roles to the system
    rbac.register_role(admin_role)?;
    rbac.register_role(tenant_admin)?;
    rbac.register_role(document_editor)?;
    rbac.register_role(viewer)?;
    
    // Create users
    let super_admin = Subject::user("super_admin");
    let tenant_admin_user = Subject::user("tenant_admin_user");
    let editor_user = Subject::user("editor_user");
    let viewer_user = Subject::user("viewer_user");
    
    // Assign roles
    rbac.assign_role(&super_admin, "admin")?;
    rbac.assign_role(&tenant_admin_user, "tenant_admin")?;
    rbac.assign_role(&editor_user, "doc_editor")?;
    rbac.assign_role(&viewer_user, "viewer")?;
    
    // Test permissions
    println!("\n🔐 Permission Tests:");
    
    let test_cases = vec![
        (&super_admin, "read", "documents", Some("any_doc"), "Super admin can read any document"),
        (&super_admin, "delete", "system", None, "Super admin can delete system resources"),
        (&tenant_admin_user, "admin", "documents", Some("tenant_123"), "Tenant admin can admin their documents"),
        (&tenant_admin_user, "admin", "documents", Some("tenant_456"), "Tenant admin CANNOT admin other tenant's documents"),
        (&editor_user, "edit", "documents", Some("doc_456"), "Editor can edit assigned document"),
        (&editor_user, "edit", "documents", Some("doc_789"), "Editor CANNOT edit other documents"),
        (&viewer_user, "read", "documents", Some("any_doc"), "Viewer can read any document"),
        (&viewer_user, "edit", "documents", Some("any_doc"), "Viewer CANNOT edit documents"),
    ];
    
    for (subject, action, resource, instance, description) in test_cases {
        let has_permission = if let Some(inst) = instance {
            let resource_obj = Resource::new(inst, resource);
            rbac.check_permission(subject, action, &resource_obj).unwrap_or(false)
        } else {
            let resource_obj = Resource::new("default", resource);
            rbac.check_permission(subject, action, &resource_obj).unwrap_or(false)
        };
        
        println!("{} {}: {} ({}:{}{})", 
            if has_permission { "✅" } else { "❌" },
            subject.effective_name(),
            description,
            action,
            resource,
            instance.map(|i| format!(":{}", i)).unwrap_or_default()
        );
    }
    
    // Demo 5: Instance Wildcard Permissions
    println!("\n📋 Demo 5: Instance Wildcard Permissions");
    println!("------------------------------------------");
    
    let project_manager = Role::new("project_manager")
        .add_permission(Permission::with_instance("read", "projects", "*"))
        .add_permission(Permission::with_instance("edit", "projects", "*"));
    
    rbac.register_role(project_manager)?;
    
    let pm_user = Subject::user("project_manager_user");
    rbac.assign_role(&pm_user, "project_manager")?;
    
    let wildcard_tests = vec![
        ("read", "projects", "project_1"),
        ("read", "projects", "project_2"),
        ("edit", "projects", "project_1"),
        ("delete", "projects", "project_1"), // Should fail
    ];
    
    for (action, resource, instance) in wildcard_tests {
        let resource_obj = Resource::new(instance, resource);
        let has_perm = rbac.check_permission(&pm_user, action, &resource_obj).unwrap_or(false);
        println!("{} Project Manager can {}: {}:{}:{}", 
            if has_perm { "✅" } else { "❌" },
            if has_perm { "perform" } else { "NOT perform" },
            action, resource, instance
        );
    }
    
    println!("\n🎉 Enhanced Permission System Demo Complete!");
    println!("\nKey Features Demonstrated:");
    println!("• Three-part permission format (action:resource:instance)");
    println!("• Enhanced permission implication logic");
    println!("• Instance-specific access control");
    println!("• Wildcard instance permissions");
    println!("• Multi-tenant security patterns");
    println!("• Backward compatibility with two-part format");
    
    Ok(())
}