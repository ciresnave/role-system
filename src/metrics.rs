//! Metrics collection for the role system.

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Metrics collector for role system operations.
#[derive(Debug, Clone)]
pub struct RoleSystemMetrics {
    /// Number of permission checks performed.
    pub permission_checks: Arc<AtomicU64>,
    /// Number of cache hits.
    pub cache_hits: Arc<AtomicU64>,
    /// Number of cache misses.
    pub cache_misses: Arc<AtomicU64>,
    /// Number of role assignments.
    pub role_assignments: Arc<AtomicU64>,
    /// Number of role removals.
    pub role_removals: Arc<AtomicU64>,
    /// Number of role elevations.
    pub role_elevations: Arc<AtomicU64>,
    /// Permission check durations (simplified histogram).
    pub permission_check_durations: Arc<DashMap<String, Duration>>,
    /// Error counts by type.
    pub error_counts: Arc<DashMap<String, AtomicU64>>,
    /// Subject activity counts.
    pub subject_activity: Arc<DashMap<String, AtomicU64>>,
}

impl Default for RoleSystemMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleSystemMetrics {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            permission_checks: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            role_assignments: Arc::new(AtomicU64::new(0)),
            role_removals: Arc::new(AtomicU64::new(0)),
            role_elevations: Arc::new(AtomicU64::new(0)),
            permission_check_durations: Arc::new(DashMap::new()),
            error_counts: Arc::new(DashMap::new()),
            subject_activity: Arc::new(DashMap::new()),
        }
    }

    /// Record a permission check.
    pub fn record_permission_check(&self, duration: Duration) {
        self.permission_checks.fetch_add(1, Ordering::Relaxed);

        // Simple bucketed histogram
        let bucket = self.duration_to_bucket(duration);
        self.permission_check_durations
            .entry(bucket)
            .and_modify(|existing| {
                if duration > *existing {
                    *existing = duration;
                }
            })
            .or_insert(duration);
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a role assignment.
    pub fn record_role_assignment(&self, subject_id: &str) {
        self.role_assignments.fetch_add(1, Ordering::Relaxed);
        self.record_subject_activity(subject_id);
    }

    /// Record a role removal.
    pub fn record_role_removal(&self, subject_id: &str) {
        self.role_removals.fetch_add(1, Ordering::Relaxed);
        self.record_subject_activity(subject_id);
    }

    /// Record a role elevation.
    pub fn record_role_elevation(&self, subject_id: &str) {
        self.role_elevations.fetch_add(1, Ordering::Relaxed);
        self.record_subject_activity(subject_id);
    }

    /// Record an error.
    pub fn record_error(&self, error_type: &str) {
        self.error_counts
            .entry(error_type.to_string())
            .and_modify(|count| {
                count.fetch_add(1, Ordering::Relaxed);
            })
            .or_insert_with(|| AtomicU64::new(1));
    }

    /// Record subject activity.
    pub fn record_subject_activity(&self, subject_id: &str) {
        self.subject_activity
            .entry(subject_id.to_string())
            .and_modify(|count| {
                count.fetch_add(1, Ordering::Relaxed);
            })
            .or_insert_with(|| AtomicU64::new(1));
    }

    /// Get cache hit ratio.
    pub fn cache_hit_ratio(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Get metrics summary.
    pub fn summary(&self) -> MetricsSummary {
        MetricsSummary {
            permission_checks: self.permission_checks.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_hit_ratio: self.cache_hit_ratio(),
            role_assignments: self.role_assignments.load(Ordering::Relaxed),
            role_removals: self.role_removals.load(Ordering::Relaxed),
            role_elevations: self.role_elevations.load(Ordering::Relaxed),
            error_counts: self
                .error_counts
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
                .collect(),
            active_subjects: self.subject_activity.len() as u64,
        }
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        self.permission_checks.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.role_assignments.store(0, Ordering::Relaxed);
        self.role_removals.store(0, Ordering::Relaxed);
        self.role_elevations.store(0, Ordering::Relaxed);
        self.permission_check_durations.clear();
        self.error_counts.clear();
        self.subject_activity.clear();
    }

    fn duration_to_bucket(&self, duration: Duration) -> String {
        let micros = duration.as_micros();
        match micros {
            0..=99 => "0-99μs".to_string(),
            100..=999 => "100-999μs".to_string(),
            1000..=9999 => "1-9ms".to_string(),
            10000..=99999 => "10-99ms".to_string(),
            100000..=999999 => "100-999ms".to_string(),
            _ => "1s+".to_string(),
        }
    }
}

/// Summary of metrics.
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub permission_checks: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_ratio: f64,
    pub role_assignments: u64,
    pub role_removals: u64,
    pub role_elevations: u64,
    pub error_counts: HashMap<String, u64>,
    pub active_subjects: u64,
}

/// Timer for measuring operation durations.
pub struct MetricsTimer {
    start: Instant,
    metrics: Arc<RoleSystemMetrics>,
    operation: String,
}

impl MetricsTimer {
    /// Create a new timer.
    pub fn new(metrics: Arc<RoleSystemMetrics>, operation: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            metrics,
            operation: operation.into(),
        }
    }
}

impl Drop for MetricsTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        if self.operation == "permission_check" {
            self.metrics.record_permission_check(duration);
        }
    }
}

/// Trait for components that can provide metrics.
pub trait MetricsProvider {
    /// Get the metrics instance.
    fn metrics(&self) -> &RoleSystemMetrics;

    /// Start a timer for an operation.
    fn start_timer(&self, operation: &str) -> MetricsTimer {
        MetricsTimer::new(Arc::new(self.metrics().clone()), operation.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_metrics_basic_operations() {
        let metrics = RoleSystemMetrics::new();

        // Test permission check recording
        metrics.record_permission_check(Duration::from_micros(500));
        assert_eq!(metrics.permission_checks.load(Ordering::Relaxed), 1);

        // Test cache hit/miss recording
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.cache_misses.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.cache_hit_ratio(), 0.5);

        // Test role operations
        metrics.record_role_assignment("user1");
        metrics.record_role_removal("user2");
        metrics.record_role_elevation("user3");
        assert_eq!(metrics.role_assignments.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.role_removals.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.role_elevations.load(Ordering::Relaxed), 1);

        // Test error recording
        metrics.record_error("ValidationError");
        metrics.record_error("ValidationError");
        assert_eq!(
            metrics
                .error_counts
                .get("ValidationError")
                .unwrap()
                .load(Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn test_metrics_summary() {
        let metrics = RoleSystemMetrics::new();

        metrics.record_permission_check(Duration::from_millis(1));
        metrics.record_cache_hit();
        metrics.record_role_assignment("user1");
        metrics.record_error("TestError");

        let summary = metrics.summary();
        assert_eq!(summary.permission_checks, 1);
        assert_eq!(summary.cache_hits, 1);
        assert_eq!(summary.role_assignments, 1);
        assert_eq!(summary.error_counts.get("TestError"), Some(&1));
        assert_eq!(summary.active_subjects, 1);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = RoleSystemMetrics::new();

        metrics.record_permission_check(Duration::from_millis(1));
        metrics.record_cache_hit();
        metrics.record_role_assignment("user1");

        metrics.reset();

        let summary = metrics.summary();
        assert_eq!(summary.permission_checks, 0);
        assert_eq!(summary.cache_hits, 0);
        assert_eq!(summary.role_assignments, 0);
        assert_eq!(summary.active_subjects, 0);
    }

    #[test]
    fn test_metrics_timer() {
        let metrics = Arc::new(RoleSystemMetrics::new());

        {
            let _timer = MetricsTimer::new(metrics.clone(), "permission_check");
            thread::sleep(StdDuration::from_millis(1));
        } // Timer drops here and records the duration

        assert_eq!(metrics.permission_checks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_duration_bucketing() {
        let metrics = RoleSystemMetrics::new();

        assert_eq!(
            metrics.duration_to_bucket(Duration::from_micros(50)),
            "0-99μs"
        );
        assert_eq!(
            metrics.duration_to_bucket(Duration::from_micros(500)),
            "100-999μs"
        );
        assert_eq!(
            metrics.duration_to_bucket(Duration::from_millis(5)),
            "1-9ms"
        );
        assert_eq!(
            metrics.duration_to_bucket(Duration::from_millis(50)),
            "10-99ms"
        );
        assert_eq!(
            metrics.duration_to_bucket(Duration::from_millis(500)),
            "100-999ms"
        );
        assert_eq!(metrics.duration_to_bucket(Duration::from_secs(2)), "1s+");
    }
}
