//! Rate limiting for role system operations.

use crate::error::{Error, Result};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of operations allowed in the time window.
    pub max_operations: u64,
    /// Time window for rate limiting.
    pub window_duration: Duration,
    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_operations: 1000,
            window_duration: Duration::from_secs(60),
            enabled: false,
        }
    }
}

/// Rate limiting window for tracking operations.
#[derive(Debug)]
struct RateLimitWindow {
    /// Number of operations in the current window.
    operations: AtomicU64,
    /// When the current window started.
    window_start: Instant,
    /// Configuration for this rate limiter.
    config: RateLimitConfig,
}

impl RateLimitWindow {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            operations: AtomicU64::new(0),
            window_start: Instant::now(),
            config,
        }
    }

    fn check_and_increment(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let now = Instant::now();

        // Reset window if expired
        if now.duration_since(self.window_start) >= self.config.window_duration {
            self.operations.store(0, Ordering::Relaxed);
            self.window_start = now;
        }

        let current_ops = self.operations.load(Ordering::Relaxed);

        if current_ops >= self.config.max_operations {
            return Err(Error::RateLimitExceeded {
                subject: "system".to_string(), // Will be overridden by caller
                limit: self.config.max_operations,
                window: format!("{:?}", self.config.window_duration),
            });
        }

        self.operations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn current_usage(&self) -> (u64, u64) {
        let current = self.operations.load(Ordering::Relaxed);
        (current, self.config.max_operations)
    }
}

/// Rate limiter for role system operations.
#[derive(Debug)]
pub struct RateLimiter {
    /// Rate limiting windows per subject.
    subject_windows: DashMap<String, RateLimitWindow>,
    /// Global rate limiting window.
    global_window: RateLimitWindow,
    /// Configuration for subject-specific rate limiting.
    subject_config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(global_config: RateLimitConfig, subject_config: RateLimitConfig) -> Self {
        Self {
            subject_windows: DashMap::new(),
            global_window: RateLimitWindow::new(global_config),
            subject_config,
        }
    }

    /// Check and record a permission check operation.
    pub fn check_permission_rate_limit(&mut self, subject_id: &str) -> Result<()> {
        // Check global rate limit first
        self.global_window
            .check_and_increment()
            .map_err(|_| Error::RateLimitExceeded {
                subject: "global".to_string(),
                limit: self.global_window.config.max_operations,
                window: format!("{:?}", self.global_window.config.window_duration),
            })?;

        // Check subject-specific rate limit
        if self.subject_config.enabled {
            let mut window = self
                .subject_windows
                .entry(subject_id.to_string())
                .or_insert_with(|| RateLimitWindow::new(self.subject_config.clone()));

            window
                .check_and_increment()
                .map_err(|_| Error::RateLimitExceeded {
                    subject: subject_id.to_string(),
                    limit: self.subject_config.max_operations,
                    window: format!("{:?}", self.subject_config.window_duration),
                })?;
        }

        Ok(())
    }

    /// Check rate limit for role assignment operations.
    pub fn check_role_assignment_rate_limit(&mut self, subject_id: &str) -> Result<()> {
        // Role assignments are typically less frequent, so use a stricter limit
        let role_config = RateLimitConfig {
            max_operations: self.subject_config.max_operations / 10,
            window_duration: self.subject_config.window_duration,
            enabled: self.subject_config.enabled,
        };

        if role_config.enabled {
            let mut window = self
                .subject_windows
                .entry(format!("role_assignment:{}", subject_id))
                .or_insert_with(|| RateLimitWindow::new(role_config.clone()));

            window
                .check_and_increment()
                .map_err(|_| Error::RateLimitExceeded {
                    subject: subject_id.to_string(),
                    limit: role_config.max_operations,
                    window: format!("{:?}", role_config.window_duration),
                })?;
        }

        Ok(())
    }

    /// Get current usage statistics.
    pub fn usage_stats(&self) -> RateLimitStats {
        let global_usage = self.global_window.current_usage();

        let mut subject_usage = Vec::new();
        for entry in self.subject_windows.iter() {
            let (subject, window) = (entry.key(), entry.value());
            let usage = window.current_usage();
            subject_usage.push((subject.clone(), usage.0, usage.1));
        }

        RateLimitStats {
            global_usage: global_usage.0,
            global_limit: global_usage.1,
            subject_usage,
        }
    }

    /// Reset rate limiting windows for a subject.
    pub fn reset_subject(&self, subject_id: &str) {
        self.subject_windows.remove(subject_id);
        self.subject_windows
            .remove(&format!("role_assignment:{}", subject_id));
    }

    /// Cleanup expired windows.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut expired_keys = Vec::new();

        for entry in self.subject_windows.iter() {
            let (key, window) = (entry.key(), entry.value());
            if now.duration_since(window.window_start) >= window.config.window_duration * 2 {
                expired_keys.push(key.clone());
            }
        }

        for key in expired_keys {
            self.subject_windows.remove(&key);
        }
    }
}

/// Rate limiting statistics.
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Current global usage.
    pub global_usage: u64,
    /// Global rate limit.
    pub global_limit: u64,
    /// Subject-specific usage: (subject_id, current_usage, limit).
    pub subject_usage: Vec<(String, u64, u64)>,
}

impl RateLimitStats {
    /// Get global usage percentage.
    pub fn global_usage_percentage(&self) -> f64 {
        if self.global_limit == 0 {
            0.0
        } else {
            (self.global_usage as f64 / self.global_limit as f64) * 100.0
        }
    }

    /// Get subjects approaching their rate limit (above threshold percentage).
    pub fn subjects_approaching_limit(&self, threshold_percentage: f64) -> Vec<String> {
        self.subject_usage
            .iter()
            .filter(|(_, current, limit)| {
                if *limit == 0 {
                    false
                } else {
                    let percentage = (*current as f64 / *limit as f64) * 100.0;
                    percentage >= threshold_percentage
                }
            })
            .map(|(subject, _, _)| subject.clone())
            .collect()
    }
}

/// Trait for components that support rate limiting.
pub trait RateLimited {
    /// Check if an operation is rate limited for a subject.
    fn is_rate_limited(&mut self, subject_id: &str, operation: &str) -> Result<()>;

    /// Get rate limiting statistics.
    fn rate_limit_stats(&self) -> RateLimitStats;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_rate_limit_basic() {
        let global_config = RateLimitConfig {
            max_operations: 5,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let subject_config = RateLimitConfig {
            max_operations: 3,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // Should allow first 3 operations for subject
        for _ in 0..3 {
            limiter.check_permission_rate_limit("user1").unwrap();
        }

        // 4th operation should fail
        assert!(limiter.check_permission_rate_limit("user1").is_err());
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let global_config = RateLimitConfig {
            max_operations: 100,
            window_duration: Duration::from_millis(100),
            enabled: true,
        };

        let subject_config = RateLimitConfig {
            max_operations: 2,
            window_duration: Duration::from_millis(100),
            enabled: true,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // Use up the limit
        limiter.check_permission_rate_limit("user1").unwrap();
        limiter.check_permission_rate_limit("user1").unwrap();
        assert!(limiter.check_permission_rate_limit("user1").is_err());

        // Wait for window to reset
        thread::sleep(StdDuration::from_millis(150));

        // Should work again
        limiter.check_permission_rate_limit("user1").unwrap();
    }

    #[test]
    fn test_rate_limit_disabled() {
        let global_config = RateLimitConfig {
            max_operations: 1,
            window_duration: Duration::from_secs(1),
            enabled: false,
        };

        let subject_config = RateLimitConfig {
            max_operations: 1,
            window_duration: Duration::from_secs(1),
            enabled: false,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // Should allow many operations when disabled
        for _ in 0..100 {
            limiter.check_permission_rate_limit("user1").unwrap();
        }
    }

    #[test]
    fn test_role_assignment_rate_limit() {
        let global_config = RateLimitConfig::default();

        let subject_config = RateLimitConfig {
            max_operations: 100,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // Role assignments have stricter limits (max_operations / 10)
        for _ in 0..10 {
            limiter.check_role_assignment_rate_limit("user1").unwrap();
        }

        // 11th operation should fail
        assert!(limiter.check_role_assignment_rate_limit("user1").is_err());
    }

    #[test]
    fn test_usage_stats() {
        let global_config = RateLimitConfig {
            max_operations: 10,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let subject_config = RateLimitConfig {
            max_operations: 5,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // Generate some usage
        limiter.check_permission_rate_limit("user1").unwrap();
        limiter.check_permission_rate_limit("user1").unwrap();
        limiter.check_permission_rate_limit("user2").unwrap();

        let stats = limiter.usage_stats();
        assert_eq!(stats.global_usage, 3);
        assert_eq!(stats.global_limit, 10);
        assert_eq!(stats.global_usage_percentage(), 30.0);

        // Should have entries for both users
        assert!(stats.subject_usage.iter().any(|(id, _, _)| id == "user1"));
        assert!(stats.subject_usage.iter().any(|(id, _, _)| id == "user2"));
    }

    #[test]
    fn test_subjects_approaching_limit() {
        let global_config = RateLimitConfig::default();

        let subject_config = RateLimitConfig {
            max_operations: 10,
            window_duration: Duration::from_secs(1),
            enabled: true,
        };

        let mut limiter = RateLimiter::new(global_config, subject_config);

        // User1 uses 9/10 (90%)
        for _ in 0..9 {
            limiter.check_permission_rate_limit("user1").unwrap();
        }

        // User2 uses 5/10 (50%)
        for _ in 0..5 {
            limiter.check_permission_rate_limit("user2").unwrap();
        }

        let stats = limiter.usage_stats();
        let approaching = stats.subjects_approaching_limit(80.0);

        assert!(approaching.contains(&"user1".to_string()));
        assert!(!approaching.contains(&"user2".to_string()));
    }
}
