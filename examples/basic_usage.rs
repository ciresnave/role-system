//! Example demonstrating the role system API as shown in the documentation.

use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize audit logging
    #[cfg(feature = "audit")]
    role_system::init_audit_logger();

    // Initialize the role system
    let mut role_system = RoleSystem::new();
    
    // Define some permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    let _delete_docs = Permission::new("delete", "documents"); // Prefix with underscore
    let admin_all = Permission::new("admin", "*");
    
    // Define roles with permissions
    let reader = Role::new("reader")
        .add_permission(read_docs.clone());
        
    let writer = Role::new("writer")
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());
        
    let admin = Role::new("admin")
        .add_permission(admin_all.clone());
    
    // Register roles
    role_system.register_role(reader)?;
    role_system.register_role(writer)?;
    role_system.register_role(admin)?;
    
    // Create hierarchical roles
    role_system.add_role_inheritance("admin", "writer")?;
    role_system.add_role_inheritance("writer", "reader")?;
    
    // Assign roles to subjects
    let user1 = Subject::new("user1");
    let user2 = Subject::new("user2");
    let user3 = Subject::new("user3");
    
    role_system.assign_role(&user1, "reader")?;
    role_system.assign_role(&user2, "writer")?;
    role_system.assign_role(&user3, "admin")?;
    
    // Define a resource
    let document = Resource::new("document1", "documents");
    
    // Check permissions
    let can_user1_read = role_system.check_permission(&user1, "read", &document)?;
    let can_user1_write = role_system.check_permission(&user1, "write", &document)?;
    let can_user2_write = role_system.check_permission(&user2, "write", &document)?;
    let can_user3_delete = role_system.check_permission(&user3, "delete", &document)?;
    
    println!("User1 can read: {}", can_user1_read);
    println!("User1 can write: {}", can_user1_write);
    println!("User2 can write: {}", can_user2_write);
    println!("User3 can delete: {}", can_user3_delete);
    
    // Add context-based permissions
    let mut context = HashMap::new();
    context.insert("time".to_string(), "business_hours".to_string());
    context.insert("location".to_string(), "office".to_string());
    
    // Create a conditional permission
    let conditional_print = Permission::with_condition("print", "documents", move |ctx| {
        ctx.get("time") == Some(&"business_hours".to_string()) && 
        ctx.get("location") == Some(&"office".to_string())
    });
    
    // Add the conditional permission to reader role
    let mut updated_reader = role_system.get_role("reader")?.unwrap();
    updated_reader = updated_reader.add_permission(conditional_print);
    role_system.update_role(updated_reader)?;
    
    // Check with context
    let can_user1_print = role_system.check_permission_with_context(
        &user1, "print", &document, &context
    )?;
    
    println!("User1 can print during business hours: {}", can_user1_print);
    
    // Temporarily elevate a user's role
    role_system.elevate_role(&user1, "writer", Some(std::time::Duration::from_secs(3600)))?;
    
    // Now user1 can write
    let can_user1_write_after = role_system.check_permission(&user1, "write", &document)?;
    println!("User1 can write after elevation: {}", can_user1_write_after);
    
    Ok(())
}

// Since we don't have update_role method in our current implementation,
// let's create a version that works with our current API
#[allow(dead_code)]
fn create_updated_role_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut role_system = RoleSystem::new();
    
    // Create permissions
    let read_docs = Permission::new("read", "documents");
    let print_docs = Permission::with_condition("print", "documents", |ctx| {
        ctx.get("time") == Some(&"business_hours".to_string()) && 
        ctx.get("location") == Some(&"office".to_string())
    });
    
    // Create reader role with both permissions
    let reader = Role::new("reader")
        .add_permission(read_docs)
        .add_permission(print_docs);
    
    role_system.register_role(reader)?;
    
    let user = Subject::new("user1");
    role_system.assign_role(&user, "reader")?;
    
    let document = Resource::new("document1", "documents");
    
    // Test context-based permission
    let mut context = HashMap::new();
    context.insert("time".to_string(), "business_hours".to_string());
    context.insert("location".to_string(), "office".to_string());
    
    let can_print = role_system.check_permission_with_context(
        &user, "print", &document, &context
    )?;
    
    println!("User can print with proper context: {}", can_print);
    
    // Test without proper context
    context.insert("location".to_string(), "home".to_string());
    let can_print_home = role_system.check_permission_with_context(
        &user, "print", &document, &context
    )?;
    
    println!("User can print from home: {}", can_print_home);
    
    Ok(())
}
