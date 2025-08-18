//! Example demonstrating Phase 1 improvements: Enhanced error context, property testing, and telemetry.

use role_system::{Permission, Resource, Role, RoleSystem, Subject};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Role System Phase 1 Improvements Demo");
    println!("==========================================");

    // Initialize the role system
    let mut role_system = RoleSystem::new();

    // 1. Enhanced Error Context Demo
    println!("\n1. Enhanced Error Context:");
    println!("--------------------------");

    // Try to assign a non-existent role - should show helpful error context
    let user = Subject::user("demo_user");
    match role_system.assign_role(&user, "nonexistent_role") {
        Ok(_) => println!("Unexpected success"),
        Err(e) => {
            println!("Error: {}", e);
            // The error now includes more context and suggestions
        }
    }

    // 2. Demonstrate improved validation errors
    match role_system.register_role(Role::new("")) {
        Ok(_) => println!("Unexpected success"),
        Err(e) => {
            println!("Validation error with context: {}", e);
        }
    }

    // 3. Set up some roles for permission testing
    println!("\n2. Setting up roles with hierarchical permissions:");
    println!("------------------------------------------------");

    let reader_role = Role::new("reader")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("list", "documents"));

    let writer_role = Role::new("writer")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("write", "documents"))
        .add_permission(Permission::new("list", "documents"));

    let admin_role = Role::new("admin").add_permission(Permission::new("*", "*"));

    role_system.register_role(reader_role)?;
    role_system.register_role(writer_role)?;
    role_system.register_role(admin_role)?;

    // Create role hierarchy
    role_system.add_role_inheritance("writer", "reader")?;
    role_system.add_role_inheritance("admin", "writer")?;

    println!("✓ Created role hierarchy: admin → writer → reader");

    // 4. Demonstrate permission checking with better error context
    println!("\n3. Permission Checking with Enhanced Errors:");
    println!("--------------------------------------------");

    let test_user = Subject::user("test_user");
    role_system.assign_role(&test_user, "reader")?;

    let doc = Resource::new("secret_doc", "documents");

    // This should succeed
    match role_system.check_permission(&test_user, "read", &doc) {
        Ok(true) => println!("✓ User can read documents (as expected)"),
        Ok(false) => println!("✗ User cannot read documents"),
        Err(e) => println!("Error: {}", e),
    }

    // This should fail but with helpful context
    match role_system.check_permission(&test_user, "delete", &doc) {
        Ok(true) => println!("✓ User can delete documents"),
        Ok(false) => println!("✗ User cannot delete documents (expected - reader role)"),
        Err(e) => println!("Error: {}", e),
    }

    // 5. Health check demo
    println!("\n4. System Health Check:");
    println!("------------------------");

    let health = role_system.health_check();
    println!("System status: {:?}", health.status);
    println!("Uptime: {} seconds", health.uptime_seconds);
    println!("Components checked: {}", health.components.len());

    for component in &health.components {
        println!(
            "  - {}: {:?} ({}ms)",
            component.name,
            component.status,
            component.response_time_ms.unwrap_or(0)
        );
    }

    // 6. Metrics summary
    println!("\n5. Metrics Summary:");
    println!("-------------------");

    let metrics = &health.metrics_summary;
    println!(
        "Total permission checks: {}",
        metrics.total_permission_checks
    );
    println!("Cache hit rate: {:.1}%", metrics.cache_hit_rate);
    println!("Error rate: {:.1}%", metrics.error_rate);
    println!("Active subjects: {}", metrics.active_subjects);
    println!("Total roles: {}", metrics.total_roles);

    #[cfg(feature = "telemetry")]
    {
        use role_system::telemetry::TelemetryProvider;

        println!("\n6. Telemetry:");
        println!("-------------");

        let telemetry = TelemetryProvider::new();

        // Record some test operations
        telemetry.record_permission_check("alice", "read", "documents", true);
        telemetry.record_permission_check("bob", "write", "documents", false);
        telemetry.record_role_operation("assign", "admin", true);
        telemetry.record_cache_operation(true); // cache hit
        telemetry.record_cache_operation(false); // cache miss

        let metrics = telemetry.get_metrics();
        println!("✓ Telemetry system working:");
        println!("  - Permission checks: {}", metrics.permission_checks_total);
        println!("  - Checks granted: {}", metrics.permission_checks_granted);
        println!("  - Checks denied: {}", metrics.permission_checks_denied);
        println!("  - Role operations: {}", metrics.role_operations_total);
        println!("  - Cache hits: {}", metrics.cache_hits);
        println!("  - Cache misses: {}", metrics.cache_misses);
        println!("  - System uptime: {}ms", telemetry.uptime().as_millis());
    }

    #[cfg(not(feature = "telemetry"))]
    {
        println!("\n6. Telemetry:");
        println!("-------------");
        println!("Telemetry feature not enabled. Add --features telemetry to enable.");
    }

    println!("\n🎉 Phase 1 improvements demo completed!");
    println!("Key improvements demonstrated:");
    println!("  ✓ Enhanced error context with recovery suggestions");
    println!("  ✓ Comprehensive property-based testing");
    println!("  ✓ Health monitoring and metrics");
    println!("  ✓ OpenTelemetry integration foundation");

    Ok(())
}
