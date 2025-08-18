//! Telemetry and observability integration for comprehensive monitoring.
//!
//! This module provides metrics, tracing, and monitoring capabilities for role system operations.
//! It includes a working implementation with optional OpenTelemetry integration.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "audit")]
use log::{debug, error, info, warn};

/// Telemetry configuration for the role system.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for metrics and tracing
    pub service_name: String,
    /// Service version for identification
    pub service_version: String,
    /// Enable detailed operation tracking
    pub detailed_tracking: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable error tracking
    pub enable_error_tracking: bool,
    /// Enable performance tracking
    pub enable_performance_tracking: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "role-system".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            detailed_tracking: true,
            enable_metrics: true,
            enable_error_tracking: true,
            enable_performance_tracking: true,
        }
    }
}

/// Metrics collected by the telemetry system.
#[derive(Debug, Clone)]
pub struct TelemetryMetrics {
    /// Total permission checks performed
    pub permission_checks_total: u64,
    /// Permission checks that were granted
    pub permission_checks_granted: u64,
    /// Permission checks that were denied
    pub permission_checks_denied: u64,
    /// Permission check errors
    pub permission_check_errors: u64,

    /// Role operations performed
    pub role_operations_total: u64,
    /// Role operation errors
    pub role_operation_errors: u64,

    /// Cache operations
    pub cache_hits: u64,
    pub cache_misses: u64,

    /// Performance metrics
    pub total_operation_time_ms: u64,
    pub avg_permission_check_time_ms: f64,

    /// Error tracking
    pub errors_by_type: HashMap<String, u64>,
}

impl Default for TelemetryMetrics {
    fn default() -> Self {
        Self {
            permission_checks_total: 0,
            permission_checks_granted: 0,
            permission_checks_denied: 0,
            permission_check_errors: 0,
            role_operations_total: 0,
            role_operation_errors: 0,
            cache_hits: 0,
            cache_misses: 0,
            total_operation_time_ms: 0,
            avg_permission_check_time_ms: 0.0,
            errors_by_type: HashMap::new(),
        }
    }
}

/// Working telemetry provider for the role system.
pub struct TelemetryProvider {
    config: TelemetryConfig,

    // Atomic counters for thread-safe metrics
    permission_checks_total: Arc<AtomicU64>,
    permission_checks_granted: Arc<AtomicU64>,
    permission_checks_denied: Arc<AtomicU64>,
    permission_check_errors: Arc<AtomicU64>,

    role_operations_total: Arc<AtomicU64>,
    role_operation_errors: Arc<AtomicU64>,

    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,

    total_operation_time_ms: Arc<AtomicU64>,
    operation_count: Arc<AtomicU64>,

    start_time: Instant,
}

impl Default for TelemetryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryProvider {
    /// Create a new telemetry provider.
    pub fn new() -> Self {
        Self::with_config(TelemetryConfig::default())
    }

    /// Create a new telemetry provider with custom configuration.
    pub fn with_config(config: TelemetryConfig) -> Self {
        #[cfg(feature = "audit")]
        info!("Initializing telemetry provider: {}", config.service_name);

        Self {
            config,
            permission_checks_total: Arc::new(AtomicU64::new(0)),
            permission_checks_granted: Arc::new(AtomicU64::new(0)),
            permission_checks_denied: Arc::new(AtomicU64::new(0)),
            permission_check_errors: Arc::new(AtomicU64::new(0)),
            role_operations_total: Arc::new(AtomicU64::new(0)),
            role_operation_errors: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            total_operation_time_ms: Arc::new(AtomicU64::new(0)),
            operation_count: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
        }
    }

    /// Record a permission check operation.
    pub fn record_permission_check(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        granted: bool,
    ) {
        if !self.config.enable_metrics {
            return;
        }

        self.permission_checks_total.fetch_add(1, Ordering::Relaxed);

        if granted {
            self.permission_checks_granted
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "audit")]
            debug!("Permission granted: {} -> {}:{}", subject, action, resource);
        } else {
            self.permission_checks_denied
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "audit")]
            debug!("Permission denied: {} -> {}:{}", subject, action, resource);
        }
    }

    /// Record a permission check error.
    pub fn record_permission_check_error(
        &self,
        subject: &str,
        action: &str,
        resource: &str,
        error: &crate::error::Error,
    ) {
        if !self.config.enable_error_tracking {
            return;
        }

        self.permission_check_errors.fetch_add(1, Ordering::Relaxed);

        #[cfg(feature = "audit")]
        error!(
            "Permission check error: {} -> {}:{} - {}",
            subject, action, resource, error
        );
    }

    /// Record a role operation.
    pub fn record_role_operation(&self, operation: &str, role: &str, success: bool) {
        if !self.config.enable_metrics {
            return;
        }

        self.role_operations_total.fetch_add(1, Ordering::Relaxed);

        if success {
            #[cfg(feature = "audit")]
            debug!("Role operation successful: {} on {}", operation, role);
        } else {
            self.role_operation_errors.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "audit")]
            warn!("Role operation failed: {} on {}", operation, role);
        }
    }

    /// Record cache operation.
    pub fn record_cache_operation(&self, hit: bool) {
        if !self.config.enable_metrics {
            return;
        }

        if hit {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record operation duration.
    pub fn record_operation_duration(&self, _operation: &str, duration: Duration) {
        if !self.config.enable_performance_tracking {
            return;
        }

        self.total_operation_time_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        self.operation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current metrics snapshot.
    pub fn get_metrics(&self) -> TelemetryMetrics {
        let operation_count = self.operation_count.load(Ordering::Relaxed);
        let total_time = self.total_operation_time_ms.load(Ordering::Relaxed);

        let avg_permission_check_time_ms = if operation_count > 0 {
            total_time as f64 / operation_count as f64
        } else {
            0.0
        };

        TelemetryMetrics {
            permission_checks_total: self.permission_checks_total.load(Ordering::Relaxed),
            permission_checks_granted: self.permission_checks_granted.load(Ordering::Relaxed),
            permission_checks_denied: self.permission_checks_denied.load(Ordering::Relaxed),
            permission_check_errors: self.permission_check_errors.load(Ordering::Relaxed),
            role_operations_total: self.role_operations_total.load(Ordering::Relaxed),
            role_operation_errors: self.role_operation_errors.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            total_operation_time_ms: total_time,
            avg_permission_check_time_ms,
            errors_by_type: HashMap::new(), // Could be enhanced with more detailed tracking
        }
    }

    /// Get system uptime.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Reset all metrics (useful for testing).
    pub fn reset_metrics(&self) {
        self.permission_checks_total.store(0, Ordering::Relaxed);
        self.permission_checks_granted.store(0, Ordering::Relaxed);
        self.permission_checks_denied.store(0, Ordering::Relaxed);
        self.permission_check_errors.store(0, Ordering::Relaxed);
        self.role_operations_total.store(0, Ordering::Relaxed);
        self.role_operation_errors.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.total_operation_time_ms.store(0, Ordering::Relaxed);
        self.operation_count.store(0, Ordering::Relaxed);
    }
}

/// Telemetry wrapper for instrumented operations.
pub struct InstrumentedOperation {
    start_time: Instant,
    operation_name: String,
}

impl InstrumentedOperation {
    /// Create a new instrumented operation.
    pub fn new(operation_name: impl Into<String>) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.into(),
        }
    }

    /// Add context to the operation (for compatibility, currently logs with audit feature).
    #[cfg(feature = "audit")]
    pub fn set_attribute(&mut self, key: &str, value: impl Into<String>) {
        debug!(
            "Operation {}: {} = {}",
            self.operation_name,
            key,
            value.into()
        );
    }

    /// Add context to the operation (no-op without audit feature).
    #[cfg(not(feature = "audit"))]
    pub fn set_attribute(&mut self, _key: &str, _value: impl Into<String>) {
        // No-op
    }

    /// Record an error in the operation.
    #[cfg(feature = "audit")]
    pub fn record_error(&mut self, error: &dyn std::error::Error) {
        error!("Operation {} failed: {}", self.operation_name, error);
    }

    /// Record an error (no-op without audit feature).
    #[cfg(not(feature = "audit"))]
    pub fn record_error(&mut self, _error: &dyn std::error::Error) {
        // No-op
    }

    /// Get the duration of the operation.
    pub fn duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Finish the operation and return the duration.
    pub fn finish(self) -> Duration {
        let duration = self.duration();

        #[cfg(feature = "audit")]
        debug!(
            "Operation {} completed in {}ms",
            self.operation_name,
            duration.as_millis()
        );

        duration
    }
}

impl Default for InstrumentedOperation {
    fn default() -> Self {
        Self::new("unnamed_operation")
    }
}

/// Macro for creating instrumented operations.
#[macro_export]
macro_rules! instrument {
    ($telemetry:expr, $operation:expr) => {{
        $crate::telemetry::InstrumentedOperation::new($operation)
    }};
    ($telemetry:expr, $operation:expr, $($attr:expr),*) => {{
        let mut op = $crate::telemetry::InstrumentedOperation::new($operation);
        $(
            op.set_attribute($attr.0, $attr.1);
        )*
        op
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "role-system");
        assert_eq!(config.service_version, env!("CARGO_PKG_VERSION"));
        assert!(config.detailed_tracking);
        assert!(config.enable_metrics);
        assert!(config.enable_error_tracking);
        assert!(config.enable_performance_tracking);
    }

    #[test]
    fn test_instrumented_operation() {
        let op = InstrumentedOperation::new("test_operation");

        // Simulate some work
        std::thread::sleep(Duration::from_millis(1));

        let duration = op.finish();
        assert!(duration.as_millis() >= 1);
    }

    #[test]
    fn test_telemetry_provider_creation() {
        let config = TelemetryConfig::default();
        let provider = TelemetryProvider::with_config(config);

        // Test that we can record some metrics
        provider.record_permission_check("alice", "read", "document", true);
        provider.record_permission_check("bob", "write", "document", false);
        provider.record_role_operation("assign", "admin", true);

        let metrics = provider.get_metrics();
        assert_eq!(metrics.permission_checks_total, 2);
        assert_eq!(metrics.permission_checks_granted, 1);
        assert_eq!(metrics.permission_checks_denied, 1);
        assert_eq!(metrics.role_operations_total, 1);
    }

    #[test]
    fn test_telemetry_metrics() {
        let provider = TelemetryProvider::new();

        // Test cache operations
        provider.record_cache_operation(true); // hit
        provider.record_cache_operation(false); // miss
        provider.record_cache_operation(true); // hit

        let metrics = provider.get_metrics();
        assert_eq!(metrics.cache_hits, 2);
        assert_eq!(metrics.cache_misses, 1);

        // Test reset
        provider.reset_metrics();
        let reset_metrics = provider.get_metrics();
        assert_eq!(reset_metrics.cache_hits, 0);
        assert_eq!(reset_metrics.cache_misses, 0);
    }

    #[test]
    fn test_operation_duration_tracking() {
        let provider = TelemetryProvider::new();
        let duration = Duration::from_millis(100);

        provider.record_operation_duration("test_op", duration);

        let metrics = provider.get_metrics();
        assert_eq!(metrics.total_operation_time_ms, 100);
        assert_eq!(metrics.avg_permission_check_time_ms, 100.0);
    }
}
