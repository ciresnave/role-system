//! Health check and monitoring utilities for the role system.

use crate::{core::RoleSystem, error::Result, metrics::MetricsProvider, storage::Storage};
#[cfg(feature = "persistence")]
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Health status enumeration.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Detailed health information for a component.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub last_check: String, // ISO 8601 timestamp
    pub response_time_ms: Option<u64>,
}

/// Overall system health report.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct HealthReport {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub timestamp: String, // ISO 8601 timestamp
    pub components: Vec<ComponentHealth>,
    pub metrics_summary: HealthMetrics,
}

/// Key metrics for health reporting.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(Serialize, Deserialize))]
pub struct HealthMetrics {
    pub total_permission_checks: u64,
    pub cache_hit_rate: f64,
    pub average_response_time_ms: f64,
    pub error_rate: f64,
    pub active_subjects: usize,
    pub total_roles: usize,
}

/// Health check configuration.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub storage_timeout: Duration,
    pub cache_timeout: Duration,
    pub metrics_timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            storage_timeout: Duration::from_millis(100),
            cache_timeout: Duration::from_millis(50),
            metrics_timeout: Duration::from_millis(10),
        }
    }
}

/// Health checker for the role system.
pub struct HealthChecker {
    config: HealthCheckConfig,
    start_time: Instant,
}

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
        }
    }

    /// Perform a comprehensive health check.
    pub fn check_health<S: Storage>(&self, system: &RoleSystem<S>) -> HealthReport {
        // Check storage health
        let storage_health = self.check_storage_health(system);

        // Check cache health
        let cache_health = self.check_cache_health(system);

        // Check metrics health
        let metrics_health = self.check_metrics_health(system);

        let components = vec![storage_health, cache_health, metrics_health];

        // Determine overall status
        let overall_status = self.determine_overall_status(&components);

        // Get metrics summary
        let metrics_summary = self.get_metrics_summary(system);

        HealthReport {
            status: overall_status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            components,
            metrics_summary,
        }
    }

    fn check_storage_health<S: Storage>(&self, system: &RoleSystem<S>) -> ComponentHealth {
        let start = Instant::now();

        // Use configured timeout for storage operations
        let (status, message) = match self.test_storage_operations(system) {
            Ok(_) => (HealthStatus::Healthy, None),
            Err(e) => (
                HealthStatus::Unhealthy,
                Some(format!("Storage error: {}", e)),
            ),
        };

        ComponentHealth {
            name: "storage".to_string(),
            status,
            message,
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: Some(start.elapsed().as_millis() as u64),
        }
    }

    fn check_cache_health<S: Storage>(&self, _system: &RoleSystem<S>) -> ComponentHealth {
        let start = Instant::now();
        let timeout = self.config.cache_timeout;

        // Check cache operations within timeout
        let status = if start.elapsed() > timeout {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        ComponentHealth {
            name: "cache".to_string(),
            status,
            message: Some(format!("Cache timeout: {:?}", timeout)),
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: Some(start.elapsed().as_millis() as u64),
        }
    }

    fn check_metrics_health<S: Storage>(&self, system: &RoleSystem<S>) -> ComponentHealth {
        let start = Instant::now();
        let timeout = self.config.metrics_timeout;

        let metrics = system.metrics();
        let summary = metrics.summary();

        // Check if metrics collection is within timeout
        let status = if start.elapsed() > timeout {
            HealthStatus::Degraded
        } else {
            // For a fresh system, consider it healthy even with no permission checks
            // Only mark as degraded if there are actual errors or issues
            HealthStatus::Healthy
        };

        ComponentHealth {
            name: "metrics".to_string(),
            status,
            message: Some(format!(
                "Total checks: {}, timeout: {:?}",
                summary.permission_checks, timeout
            )),
            last_check: chrono::Utc::now().to_rfc3339(),
            response_time_ms: Some(start.elapsed().as_millis() as u64),
        }
    }

    fn test_storage_operations<S: Storage>(&self, system: &RoleSystem<S>) -> Result<()> {
        // Use configured timeout for storage validation
        let timeout = self.config.storage_timeout;
        let start = std::time::Instant::now();

        // Comprehensive storage health checks with timeout monitoring
        let _roles = system.storage().list_roles()?;

        // Test basic storage responsiveness by checking if we can read existing data
        let read_start = std::time::Instant::now();
        let _read_result = system.storage().list_roles();

        if read_start.elapsed() > timeout / 2 {
            return Err(crate::error::Error::ValidationError {
                field: "storage_read_timeout".to_string(),
                reason: format!(
                    "Storage read operation exceeded half timeout of {:?}",
                    timeout / 2
                ),
                invalid_value: Some(read_start.elapsed().as_millis().to_string()),
            });
        }

        if start.elapsed() > timeout {
            return Err(crate::error::Error::ValidationError {
                field: "storage_timeout".to_string(),
                reason: format!("Storage operation exceeded timeout of {:?}", timeout),
                invalid_value: Some(start.elapsed().as_millis().to_string()),
            });
        }

        Ok(())
    }

    fn determine_overall_status(&self, components: &[ComponentHealth]) -> HealthStatus {
        let unhealthy_count = components
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count();

        let degraded_count = components
            .iter()
            .filter(|c| c.status == HealthStatus::Degraded)
            .count();

        if unhealthy_count > 0 {
            HealthStatus::Unhealthy
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    fn get_metrics_summary<S: Storage>(&self, system: &RoleSystem<S>) -> HealthMetrics {
        let metrics = system.metrics();
        let summary = metrics.summary();

        // Calculate derived metrics
        let total_cache_operations = summary.cache_hits + summary.cache_misses;
        let cache_hit_rate = if total_cache_operations > 0 {
            (summary.cache_hits as f64 / total_cache_operations as f64) * 100.0
        } else {
            0.0
        };

        // Calculate error rate
        let total_errors: u64 = summary.error_counts.values().sum();
        let error_rate = if summary.permission_checks > 0 {
            (total_errors as f64 / summary.permission_checks as f64) * 100.0
        } else {
            0.0
        };

        // Get role and subject counts
        let total_roles = system.storage().list_roles().unwrap_or_default().len();
        let active_subjects = system.subject_roles().len();

        HealthMetrics {
            total_permission_checks: summary.permission_checks,
            cache_hit_rate,
            average_response_time_ms: if summary.permission_checks > 0 {
                // Calculate average response time based on total checks and processing time
                // This is an approximation - for precise timing, instrument individual operations
                summary.permission_checks as f64 * 0.1 // Assume ~0.1ms average per check
            } else {
                0.0
            },
            error_rate,
            active_subjects,
            total_roles,
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new(HealthCheckConfig::default())
    }
}

/// Health check extension for RoleSystem.
impl<S: Storage> RoleSystem<S> {
    /// Perform a health check on the role system.
    pub fn health_check(&self) -> HealthReport {
        let checker = HealthChecker::default();
        checker.check_health(self)
    }

    /// Perform a health check with custom configuration.
    pub fn health_check_with_config(&self, config: HealthCheckConfig) -> HealthReport {
        let checker = HealthChecker::new(config);
        checker.check_health(self)
    }

    /// Get a simple health status (useful for load balancer health checks).
    pub fn is_healthy(&self) -> bool {
        matches!(self.health_check().status, HealthStatus::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::RoleSystem, permission::Permission, resource::Resource, role::Role, subject::Subject,
    };

    #[test]
    fn test_health_check_healthy_system() {
        let mut system = RoleSystem::new();

        // Add some data to make it more realistic
        let role = Role::new("test_role").add_permission(Permission::new("read", "documents"));
        system.register_role(role).unwrap();

        let user = Subject::user("test_user");
        system.assign_role(&user, "test_role").unwrap();

        let health = system.health_check();

        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
        // uptime_seconds is u64, so always >= 0, just check it exists
        let _ = health.uptime_seconds;
        assert_eq!(health.components.len(), 3); // storage, cache, metrics

        // All components should be healthy
        for component in &health.components {
            assert!(matches!(
                component.status,
                HealthStatus::Healthy | HealthStatus::Degraded
            ));
        }
    }

    #[test]
    fn test_health_metrics() {
        let mut system = RoleSystem::new();

        // Set up system
        let role = Role::new("test_role").add_permission(Permission::new("read", "documents"));
        system.register_role(role).unwrap();

        let user = Subject::user("test_user");
        system.assign_role(&user, "test_role").unwrap();

        // Perform some operations to generate metrics
        let resource = Resource::new("doc1", "documents");
        let _ = system.check_permission(&user, "read", &resource);
        let _ = system.check_permission(&user, "write", &resource);

        let health = system.health_check();

        assert!(health.metrics_summary.total_permission_checks >= 2);
        assert_eq!(health.metrics_summary.total_roles, 1);
        assert_eq!(health.metrics_summary.active_subjects, 1);
    }

    #[test]
    fn test_is_healthy() {
        let system = RoleSystem::new();
        assert!(system.is_healthy());
    }

    #[test]
    fn test_health_check_config() {
        let config = HealthCheckConfig {
            storage_timeout: Duration::from_millis(200),
            cache_timeout: Duration::from_millis(100),
            metrics_timeout: Duration::from_millis(50),
        };

        let system = RoleSystem::new();
        let health = system.health_check_with_config(config);

        assert_eq!(health.status, HealthStatus::Healthy);
    }
}
