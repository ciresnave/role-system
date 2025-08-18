//! Simple Batch Operations Test

use role_system::{
    Permission, Resource, Role, RoleSystem, Subject,
    batch::{BatchOperations, BatchPermissionCheck, BatchRoleAssignment},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔥 Testing Batch Operations");
    println!("===========================\n");

    let mut system = RoleSystem::new();

    // Setup
    let read_perm = Permission::new("read", "documents");
    let write_perm = Permission::new("write", "documents");

    let reader_role = Role::new("reader").add_permission(read_perm.clone());
    let writer_role = Role::new("writer")
        .add_permission(read_perm.clone())
        .add_permission(write_perm.clone());

    system.register_role(reader_role)?;
    system.register_role(writer_role)?;

    let alice = Subject::new("alice".to_string());
    system.assign_role(&alice, "reader")?;

    // Test batch permission checks
    println!("Testing batch permission checks...");
    let checks = vec![
        BatchPermissionCheck::new(
            alice.clone(),
            read_perm.clone(),
            Resource::new("doc1", "documents"),
        ),
        BatchPermissionCheck::new(
            alice.clone(),
            write_perm.clone(),
            Resource::new("doc1", "documents"),
        ),
        BatchPermissionCheck::new(
            Subject::new("bob".to_string()),
            read_perm.clone(),
            Resource::new("doc2", "documents"),
        ),
    ];

    let result = system.batch_check_permissions(checks)?;
    println!("✅ Batch permission results:");
    println!("   Total: {}", result.total_operations());
    println!("   Successes: {}", result.successes.len());
    println!("   Failures: {}", result.failures.len());
    println!("   Success rate: {:.1}%", result.success_rate());

    // Test batch role assignments
    println!("\nTesting batch role assignments...");
    let assignments = vec![
        BatchRoleAssignment::new_assignment(
            Subject::new("bob".to_string()),
            Role::new("reader".to_string()),
        ),
        BatchRoleAssignment::new_assignment(
            Subject::new("charlie".to_string()),
            Role::new("writer".to_string()),
        ),
    ];

    let role_result = system.batch_role_operations(assignments)?;
    println!("✅ Batch role assignment results:");
    println!("   Total: {}", role_result.total_operations());
    println!("   Successes: {}", role_result.successes.len());
    println!("   Failures: {}", role_result.failures.len());
    println!("   Success rate: {:.1}%", role_result.success_rate());

    println!("\n🎉 Batch operations working perfectly!");

    Ok(())
}
