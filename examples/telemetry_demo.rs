//! Comprehensive telemetry demonstration showing all observability features.

use role_system::telemetry::{InstrumentedOperation, TelemetryConfig, TelemetryProvider};
use role_system::{Permission, Resource, Role, RoleSystem, Subject};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Role System Telemetry Demo");
    println!("==============================\n");

    // 1. Basic telemetry setup
    println!("1. Telemetry Provider Setup:");
    println!("-----------------------------");

    let _telemetry = TelemetryProvider::new();
    println!("✓ Created telemetry provider with default config");

    // 2. Custom configuration
    println!("\n2. Custom Telemetry Configuration:");
    println!("-----------------------------------");

    let custom_config = TelemetryConfig {
        service_name: "demo-rbac-system".to_string(),
        service_version: "1.0.0".to_string(),
        detailed_tracking: true,
        enable_metrics: true,
        enable_error_tracking: true,
        enable_performance_tracking: true,
    };

    let custom_telemetry = TelemetryProvider::with_config(custom_config.clone());
    println!("✓ Created custom telemetry provider:");
    println!("  - Service: {}", custom_config.service_name);
    println!("  - Version: {}", custom_config.service_version);
    println!("  - Detailed tracking: {}", custom_config.detailed_tracking);
    println!("  - Metrics enabled: {}", custom_config.enable_metrics);
    println!(
        "  - Error tracking: {}",
        custom_config.enable_error_tracking
    );
    println!(
        "  - Performance tracking: {}",
        custom_config.enable_performance_tracking
    );

    // 3. Recording various operations
    println!("\n3. Recording Operations:");
    println!("------------------------");

    // Permission checks
    custom_telemetry.record_permission_check("alice", "read", "documents", true);
    custom_telemetry.record_permission_check("bob", "write", "documents", true);
    custom_telemetry.record_permission_check("charlie", "delete", "documents", false);
    custom_telemetry.record_permission_check("dave", "admin", "users", false);
    println!("✓ Recorded 4 permission checks (2 granted, 2 denied)");

    // Role operations
    custom_telemetry.record_role_operation("create", "editor", true);
    custom_telemetry.record_role_operation("assign", "admin", true);
    custom_telemetry.record_role_operation("revoke", "guest", true);
    custom_telemetry.record_role_operation("delete", "nonexistent", false);
    println!("✓ Recorded 4 role operations (3 successful, 1 failed)");

    // Cache operations
    for i in 0..10 {
        let hit = i % 3 != 0; // ~67% hit rate
        custom_telemetry.record_cache_operation(hit);
    }
    println!("✓ Recorded 10 cache operations (~67% hit rate)");

    // Performance tracking
    let durations = [
        Duration::from_micros(150),
        Duration::from_micros(200),
        Duration::from_micros(175),
        Duration::from_micros(300),
        Duration::from_micros(125),
    ];

    for (i, duration) in durations.iter().enumerate() {
        custom_telemetry.record_operation_duration(&format!("operation_{}", i), *duration);
    }
    println!("✓ Recorded 5 performance measurements");

    // 4. Error recording
    println!("\n4. Error Recording:");
    println!("-------------------");

    let fake_error = role_system::error::Error::RoleNotFound("nonexistent".to_string());

    custom_telemetry.record_permission_check_error("eve", "admin", "system", &fake_error);
    println!("✓ Recorded permission check error");

    // 5. Instrumented operations
    println!("\n5. Instrumented Operations:");
    println!("---------------------------");

    let mut operation = InstrumentedOperation::new("complex_permission_check");
    operation.set_attribute("user", "test_user");
    operation.set_attribute("resource", "sensitive_data");

    // Simulate some work
    std::thread::sleep(Duration::from_millis(10));

    let op_duration = operation.finish();
    custom_telemetry.record_operation_duration("complex_operation", op_duration);
    println!(
        "✓ Completed instrumented operation in {}ms",
        op_duration.as_millis()
    );

    // 6. Metrics collection and display
    println!("\n6. Metrics Summary:");
    println!("-------------------");

    let metrics = custom_telemetry.get_metrics();

    println!("Permission Checks:");
    println!("  - Total: {}", metrics.permission_checks_total);
    println!("  - Granted: {}", metrics.permission_checks_granted);
    println!("  - Denied: {}", metrics.permission_checks_denied);
    println!("  - Errors: {}", metrics.permission_check_errors);
    println!(
        "  - Success rate: {:.1}%",
        (metrics.permission_checks_granted as f64 / metrics.permission_checks_total as f64) * 100.0
    );

    println!("\nRole Operations:");
    println!("  - Total: {}", metrics.role_operations_total);
    println!("  - Errors: {}", metrics.role_operation_errors);
    println!(
        "  - Success rate: {:.1}%",
        ((metrics.role_operations_total - metrics.role_operation_errors) as f64
            / metrics.role_operations_total as f64)
            * 100.0
    );

    println!("\nCache Performance:");
    println!("  - Hits: {}", metrics.cache_hits);
    println!("  - Misses: {}", metrics.cache_misses);
    let total_cache_ops = metrics.cache_hits + metrics.cache_misses;
    if total_cache_ops > 0 {
        println!(
            "  - Hit rate: {:.1}%",
            (metrics.cache_hits as f64 / total_cache_ops as f64) * 100.0
        );
    }

    println!("\nPerformance:");
    println!(
        "  - Total operation time: {}ms",
        metrics.total_operation_time_ms
    );
    println!(
        "  - Average operation time: {:.2}ms",
        metrics.avg_permission_check_time_ms
    );

    println!("\nSystem:");
    println!("  - Uptime: {}ms", custom_telemetry.uptime().as_millis());

    // 7. Metrics reset demonstration
    println!("\n7. Metrics Reset:");
    println!("-----------------");

    println!(
        "Before reset - Total permission checks: {}",
        custom_telemetry.get_metrics().permission_checks_total
    );
    custom_telemetry.reset_metrics();
    println!(
        "After reset - Total permission checks: {}",
        custom_telemetry.get_metrics().permission_checks_total
    );
    println!("✓ Metrics successfully reset");

    // 8. Integration with role system
    println!("\n8. Integration Example:");
    println!("-----------------------");

    let mut role_system = RoleSystem::new();
    let integration_telemetry = TelemetryProvider::new();

    // Setup roles
    let admin_role = Role::new("admin").add_permission(Permission::new("*", "*"));
    role_system.register_role(admin_role)?;

    let admin_user = Subject::new("admin_user".to_string());
    role_system.assign_role(&admin_user, "admin")?;

    let resource = Resource::new("important_file", "documents");

    // Record permission check with telemetry
    let start = std::time::Instant::now();
    let permission_result = role_system.check_permission(&admin_user, "read", &resource);
    let duration = start.elapsed();

    match &permission_result {
        Ok(granted) => {
            integration_telemetry.record_permission_check(
                "admin_user",
                "read",
                "documents",
                *granted,
            );
            integration_telemetry.record_operation_duration("permission_check", duration);
        }
        Err(error) => {
            integration_telemetry.record_permission_check_error(
                "admin_user",
                "read",
                "documents",
                error,
            );
        }
    }

    println!("✓ Permission check: {:?}", permission_result);
    println!("✓ Telemetry recorded for permission check");

    let final_metrics = integration_telemetry.get_metrics();
    println!(
        "Final metrics - Permission checks: {}",
        final_metrics.permission_checks_total
    );

    println!("\n🎉 Telemetry demo completed!");
    println!("✨ Key telemetry features demonstrated:");
    println!("   • Comprehensive metrics collection");
    println!("   • Permission and role operation tracking");
    println!("   • Cache performance monitoring");
    println!("   • Error tracking and categorization");
    println!("   • Performance measurement");
    println!("   • Instrumented operations");
    println!("   • Real-time metrics reporting");
    println!("   • Integration with RBAC operations");

    Ok(())
}
