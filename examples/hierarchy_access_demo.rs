/// Comprehensive example demonstrating optional hierarchy access methods.
///
/// This example shows how to use the new hierarchy features introduced in v1.1.0
/// that enable real-world integration scenarios like API responses, admin interfaces,
/// JWT token generation, and database storage integration.
use role_system::{
    Error, Permission, Role,
    async_support::AsyncRoleSystem,
    hierarchy::{HierarchyConfigBuilder, RoleHierarchyTree},
    storage::MemoryStorage,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    println!("=== Role System v1.1.0 - Optional Hierarchy Access Demo ===\n");

    // Initialize role system
    let storage = MemoryStorage::new();
    let system = role_system::RoleSystem::with_storage(storage, Default::default());
    let async_system = AsyncRoleSystem::new(system);

    // Create roles with permissions
    println!("1. Creating roles with enhanced permissions...");

    let admin = Role::new("admin")
        .with_description("System administrator with full access")
        .add_permission(Permission::new("*", "*"))
        .with_metadata("level", "5")
        .with_metadata("department", "IT");

    let manager = Role::new("manager")
        .with_description("Team manager with elevated privileges")
        .add_permission(Permission::new("read", "reports"))
        .add_permission(Permission::new("write", "reports"))
        .add_permission(Permission::new("manage", "team"))
        .with_metadata("level", "4")
        .with_metadata("department", "Operations");

    let developer = Role::new("developer")
        .with_description("Software developer with code access")
        .add_permission(Permission::new("read", "code"))
        .add_permission(Permission::new("write", "code"))
        .add_permission(Permission::new("deploy", "staging"))
        .with_metadata("level", "3")
        .with_metadata("department", "Engineering");

    let intern = Role::new("intern")
        .with_description("Intern with limited access")
        .add_permission(Permission::new("read", "documentation"))
        .with_metadata("level", "1")
        .with_metadata("department", "Various");

    // Register roles
    async_system.register_role(admin).await?;
    async_system.register_role(manager).await?;
    async_system.register_role(developer).await?;
    async_system.register_role(intern).await?;

    println!("✓ Created 4 roles: admin, manager, developer, intern\n");

    // Demonstrate Role hierarchy access methods
    println!("2. Testing Role hierarchy access methods...");

    // Get individual role and test hierarchy methods
    if let Some(admin_role) = async_system.get_role("admin").await? {
        println!("Admin role hierarchy info:");
        println!("  - Parent role ID: {:?}", admin_role.parent_role_id());
        println!("  - Child role IDs: {:?}", admin_role.child_role_ids());
        println!("  - Is root role: {}", admin_role.is_root_role());
        println!("  - Is leaf role: {}", admin_role.is_leaf_role());
        println!("  - Hierarchy depth: {}", admin_role.hierarchy_depth());

        let hierarchy_meta = admin_role.hierarchy_metadata();
        println!("  - Hierarchy metadata:");
        for (key, value) in &hierarchy_meta {
            println!("    * {}: {}", key, value);
        }
    }
    println!();

    // Demonstrate AsyncRoleSystem hierarchy traversal methods
    println!("3. Testing AsyncRoleSystem hierarchy traversal methods...");

    // Configure hierarchy access
    let hierarchy_config = HierarchyConfigBuilder::new()
        .enable_hierarchy_access(true)
        .max_depth(10)
        .max_traversal_size(100)
        .enable_caching(true)
        .include_permission_counts(true)
        .build();

    println!("Hierarchy configuration:");
    println!(
        "  - Hierarchy access enabled: {}",
        hierarchy_config.enable_hierarchy_access
    );
    println!("  - Max depth: {}", hierarchy_config.max_hierarchy_depth);
    println!(
        "  - Max traversal size: {}",
        hierarchy_config.max_traversal_size
    );
    println!("  - Caching enabled: {}", hierarchy_config.cache_hierarchy);
    println!();

    // Get hierarchy tree
    println!("4. Getting hierarchy tree structure...");
    match async_system
        .get_hierarchy_tree(Some(hierarchy_config))
        .await
    {
        Ok(tree) => {
            display_hierarchy_tree(&tree);
        }
        Err(e) => {
            println!("Error getting hierarchy tree: {}", e);
        }
    }

    // Test role relationships
    println!("5. Testing role relationship queries...");

    let test_roles = ["admin", "manager", "developer", "intern"];

    for role_id in &test_roles {
        println!("Role: {}", role_id);

        // Get ancestors
        match async_system.get_role_ancestors(role_id, true).await {
            Ok(ancestors) => {
                println!("  - Ancestors: {:?}", ancestors);
            }
            Err(e) => {
                println!("  - Error getting ancestors: {}", e);
            }
        }

        // Get descendants
        match async_system.get_role_descendants(role_id, true).await {
            Ok(descendants) => {
                println!("  - Descendants: {:?}", descendants);
            }
            Err(e) => {
                println!("  - Error getting descendants: {}", e);
            }
        }

        // Get siblings
        match async_system.get_role_siblings(role_id).await {
            Ok(siblings) => {
                println!("  - Siblings: {:?}", siblings);
            }
            Err(e) => {
                println!("  - Error getting siblings: {}", e);
            }
        }

        // Get hierarchy depth
        match async_system.get_role_depth(role_id).await {
            Ok(depth) => {
                println!("  - Hierarchy depth: {}", depth);
            }
            Err(e) => {
                println!("  - Error getting depth: {}", e);
            }
        }

        println!();
    }

    // Test ancestor relationships
    println!("6. Testing ancestor relationship checks...");

    let relationship_tests = [
        ("admin", "manager"),
        ("manager", "developer"),
        ("developer", "intern"),
        ("admin", "intern"),
    ];

    for (ancestor, descendant) in &relationship_tests {
        match async_system.is_role_ancestor(ancestor, descendant).await {
            Ok(is_ancestor) => {
                println!(
                    "  - Is '{}' an ancestor of '{}'? {}",
                    ancestor, descendant, is_ancestor
                );
            }
            Err(e) => {
                println!("  - Error checking ancestor relationship: {}", e);
            }
        }
    }
    println!();

    // Get all role relationships
    println!("7. Getting all role relationships...");
    match async_system.get_role_relationships(None).await {
        Ok(relationships) => {
            if relationships.is_empty() {
                println!("  - No explicit relationships found (roles are independent)");
                println!("  - In a real hierarchy, this would show parent-child relationships");
            } else {
                for relationship in &relationships {
                    println!(
                        "  - {} -> {} ({:?})",
                        relationship.parent_role_id,
                        relationship.child_role_id,
                        relationship.relationship_type
                    );
                }
            }
        }
        Err(e) => {
            println!("  - Error getting relationships: {}", e);
        }
    }
    println!();

    // Demonstrate backward compatibility
    println!("8. Demonstrating backward compatibility...");

    // Test with hierarchy access disabled
    let disabled_config = HierarchyConfigBuilder::new()
        .enable_hierarchy_access(false)
        .build();

    match async_system.get_hierarchy_tree(Some(disabled_config)).await {
        Ok(_) => {
            println!("  - Unexpected: should have failed with disabled hierarchy access");
        }
        Err(e) => {
            println!(
                "  ✓ Correctly rejected hierarchy access when disabled: {}",
                e
            );
        }
    }

    // Individual Role methods maintain backward compatibility
    if let Some(role) = async_system.get_role("developer").await? {
        println!("  ✓ Individual role hierarchy methods return default values:");
        println!(
            "    - Parent: {:?} (None for backward compatibility)",
            role.parent_role_id()
        );
        println!(
            "    - Children: {:?} (Empty for backward compatibility)",
            role.child_role_ids()
        );
        println!("    - Is root: {} (True by default)", role.is_root_role());
        println!("    - Is leaf: {} (True by default)", role.is_leaf_role());
        println!("    - Depth: {} (0 by default)", role.hierarchy_depth());
    }
    println!();

    // Demonstrate real-world use cases
    println!("9. Real-world integration examples...");

    demonstrate_api_response_generation(&async_system).await?;
    demonstrate_jwt_claims_generation(&async_system).await?;
    demonstrate_admin_interface_data(&async_system).await?;

    println!("=== Demo Complete ===");
    println!("This demonstrates the new optional hierarchy access methods that enable:");
    println!("  ✓ API response generation with role metadata");
    println!("  ✓ JWT token claims with hierarchy information");
    println!("  ✓ Admin interface role management");
    println!("  ✓ Database integration with structured relationships");
    println!("  ✓ Backward compatibility with existing code");
    println!("  ✓ Configuration-controlled access to hierarchy features");

    Ok(())
}

/// Display hierarchy tree structure in a readable format.
fn display_hierarchy_tree(tree: &RoleHierarchyTree) {
    println!("Hierarchy Tree Structure:");
    println!("  - Total roles: {}", tree.total_roles);
    println!("  - Max depth: {}", tree.max_depth);
    println!("  - Schema version: {}", tree.metadata.schema_version);
    println!("  - Total permissions: {}", tree.metadata.total_permissions);
    println!(
        "  - Generation time: {}ms",
        tree.metadata.generation_time_ms
    );

    println!("  - Root node:");
    display_role_node(&tree.root, "    ");
    println!();
}

/// Recursively display role node structure.
fn display_role_node(node: &role_system::hierarchy::RoleNode, indent: &str) {
    println!(
        "{}Role: {} (depth: {}, descendants: {})",
        indent,
        node.role.name(),
        node.depth,
        node.descendant_count
    );

    for child in &node.children {
        display_role_node(child, &format!("{}  ", indent));
    }
}

/// Demonstrate API response generation using hierarchy methods.
async fn demonstrate_api_response_generation(
    system: &AsyncRoleSystem<MemoryStorage>,
) -> Result<(), Error> {
    println!("  API Response Generation:");

    if let Some(role) = system.get_role("manager").await? {
        // Simulate generating API response with role hierarchy information
        let api_response = serde_json::json!({
            "role": {
                "id": role.id(),
                "name": role.name(),
                "description": role.description(),
                "active": role.is_active(),
                "metadata": role.all_metadata(),
                "hierarchy": {
                    "parent": role.parent_role_id(),
                    "children": role.child_role_ids(),
                    "depth": role.hierarchy_depth(),
                    "is_root": role.is_root_role(),
                    "is_leaf": role.is_leaf_role()
                },
                "permissions": role.permissions().len()
            }
        });

        println!(
            "    Generated API response: {}",
            serde_json::to_string_pretty(&api_response)
                .unwrap_or_else(|_| "Error serializing".to_string())
        );
    }

    Ok(())
}

/// Demonstrate JWT claims generation with hierarchy information.
async fn demonstrate_jwt_claims_generation(
    system: &AsyncRoleSystem<MemoryStorage>,
) -> Result<(), Error> {
    println!("  JWT Claims Generation:");

    if let Some(role) = system.get_role("developer").await? {
        // Simulate generating JWT claims with hierarchy metadata
        let jwt_claims = serde_json::json!({
            "sub": "user123",
            "roles": [role.name()],
            "role_metadata": {
                "level": role.metadata("level"),
                "department": role.metadata("department"),
                "hierarchy_depth": role.hierarchy_depth(),
                "is_privileged": !role.is_leaf_role()
            },
            "iat": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 3600
        });

        println!(
            "    Generated JWT claims: {}",
            serde_json::to_string_pretty(&jwt_claims)
                .unwrap_or_else(|_| "Error serializing".to_string())
        );
    }

    Ok(())
}

/// Demonstrate admin interface data preparation.
async fn demonstrate_admin_interface_data(
    system: &AsyncRoleSystem<MemoryStorage>,
) -> Result<(), Error> {
    println!("  Admin Interface Data:");

    // Simulate preparing data for an admin interface
    let config = HierarchyConfigBuilder::new()
        .enable_hierarchy_access(true)
        .build();

    match system.get_hierarchy_tree(Some(config)).await {
        Ok(tree) => {
            let admin_data = serde_json::json!({
                "dashboard": {
                    "total_roles": tree.total_roles,
                    "max_hierarchy_depth": tree.max_depth,
                    "total_permissions": tree.metadata.total_permissions,
                    "hierarchy_health": {
                        "generation_time_ms": tree.metadata.generation_time_ms,
                        "schema_version": tree.metadata.schema_version
                    }
                },
                "role_tree": {
                    "root": {
                        "name": tree.root.role.name(),
                        "depth": tree.root.depth,
                        "children_count": tree.root.children.len(),
                        "descendant_count": tree.root.descendant_count
                    }
                }
            });

            println!(
                "    Generated admin dashboard data: {}",
                serde_json::to_string_pretty(&admin_data)
                    .unwrap_or_else(|_| "Error serializing".to_string())
            );
        }
        Err(e) => {
            println!("    Error generating admin data: {}", e);
        }
    }

    Ok(())
}
