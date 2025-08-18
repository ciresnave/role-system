# Telemetry Usage Guide

This document explains how to properly use the telemetry features in the examples.

## Feature Flag Requirements

The telemetry functionality requires enabling the `telemetry` feature flag:

```bash
# To run examples with telemetry enabled
cargo run --example phase1_improvements --features telemetry
cargo run --example telemetry_demo --features telemetry

# To build with telemetry support
cargo build --features telemetry
```

## Import Pattern

When using telemetry in conditional compilation blocks, import the telemetry types inside the `#[cfg(feature = "telemetry")]` block to avoid unused import warnings:

```rust
#[cfg(feature = "telemetry")]
{
    use role_system::telemetry::TelemetryProvider;

    let telemetry = TelemetryProvider::new();
    // ... use telemetry
}
```

## Example Usage

### Basic Telemetry

```rust
use role_system::telemetry::TelemetryProvider;

let telemetry = TelemetryProvider::new();

// Record operations
telemetry.record_permission_check("alice", "read", "documents", true);
telemetry.record_role_operation("assign", "admin", true);
telemetry.record_cache_operation(true); // cache hit

// Get metrics
let metrics = telemetry.get_metrics();
println!("Permission checks: {}", metrics.permission_checks_total);
```

### Custom Configuration

```rust
use role_system::telemetry::{TelemetryProvider, TelemetryConfig};

let config = TelemetryConfig {
    service_name: "my-rbac-system".to_string(),
    service_version: "1.0.0".to_string(),
    detailed_tracking: true,
    enable_metrics: true,
    enable_error_tracking: true,
    enable_performance_tracking: true,
};

let telemetry = TelemetryProvider::with_config(config);
```

## Available Examples

1. **`phase1_improvements.rs`** - Shows basic integration with feature flag handling
2. **`telemetry_demo.rs`** - Comprehensive telemetry feature demonstration

Both examples work correctly with and without the telemetry feature enabled.
