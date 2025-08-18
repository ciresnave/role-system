//! Temporal and time-based permission management.

use crate::{
    error::{Error, Result},
    permission::Permission,
};
use chrono::{DateTime, Datelike, Duration, NaiveTime, Utc, Weekday};
use chrono_tz::Tz;
#[cfg(feature = "persistence")]
use serde::{Deserialize, Serialize};

/// Time-based permission that includes temporal constraints.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct TemporalPermission {
    /// The base permission
    permission: Permission,
    /// When this permission becomes valid
    valid_from: Option<DateTime<Utc>>,
    /// When this permission expires
    valid_until: Option<DateTime<Utc>>,
    /// Recurring schedule for this permission
    schedule: Option<Schedule>,
    /// Maximum usage count (for consumable permissions)
    max_usage: Option<u32>,
    /// Current usage count
    usage_count: u32,
}

/// Recurring schedule for permissions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule {
    /// Days of the week this permission is active
    weekdays: Vec<Weekday>,
    /// Start time each day (in UTC)
    start_time: NaiveTime,
    /// End time each day (in UTC)
    end_time: NaiveTime,
    /// Time zone for schedule interpretation
    timezone: String,
}

/// Time-based access control policy.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct TemporalPolicy {
    /// Policy name
    name: String,
    /// Description
    description: Option<String>,
    /// List of temporal permissions
    permissions: Vec<TemporalPermission>,
    /// Policy effective date
    effective_from: DateTime<Utc>,
    /// Policy expiration date
    expires_at: Option<DateTime<Utc>>,
}

impl TemporalPermission {
    /// Create a new temporal permission.
    pub fn new(permission: Permission) -> Self {
        Self {
            permission,
            valid_from: None,
            valid_until: None,
            schedule: None,
            max_usage: None,
            usage_count: 0,
        }
    }

    /// Set the valid from time.
    pub fn valid_from(mut self, from: DateTime<Utc>) -> Self {
        self.valid_from = Some(from);
        self
    }

    /// Set the valid until time.
    pub fn valid_until(mut self, until: DateTime<Utc>) -> Self {
        self.valid_until = Some(until);
        self
    }

    /// Set a recurring schedule.
    pub fn with_schedule(mut self, schedule: Schedule) -> Self {
        self.schedule = Some(schedule);
        self
    }

    /// Set maximum usage count.
    pub fn with_max_usage(mut self, max_usage: u32) -> Self {
        self.max_usage = Some(max_usage);
        self
    }

    /// Check if the permission is valid at the given time.
    pub fn is_valid_at(&self, time: DateTime<Utc>) -> bool {
        // Check absolute time bounds
        if let Some(from) = self.valid_from
            && time < from
        {
            return false;
        }

        if let Some(until) = self.valid_until
            && time > until
        {
            return false;
        }

        // Check usage limits
        if let Some(max_usage) = self.max_usage
            && self.usage_count >= max_usage
        {
            return false;
        }

        // Check recurring schedule
        if let Some(ref schedule) = self.schedule {
            return schedule.is_valid_at(time);
        }

        true
    }

    /// Check if the permission is currently valid.
    pub fn is_currently_valid(&self) -> bool {
        self.is_valid_at(Utc::now())
    }

    /// Record usage of this permission.
    pub fn record_usage(&mut self) -> Result<()> {
        if let Some(max_usage) = self.max_usage
            && self.usage_count >= max_usage
        {
            return Err(Error::ValidationError {
                field: "usage_limit".to_string(),
                reason: "Permission usage limit exceeded".to_string(),
                invalid_value: Some(self.usage_count.to_string()),
            });
        }

        self.usage_count += 1;
        Ok(())
    }

    /// Get the underlying permission.
    pub fn permission(&self) -> &Permission {
        &self.permission
    }

    /// Get usage statistics.
    pub fn usage_stats(&self) -> (u32, Option<u32>) {
        (self.usage_count, self.max_usage)
    }

    /// Get time until this permission becomes valid (if not yet valid).
    pub fn time_until_valid(&self) -> Option<Duration> {
        if let Some(valid_from) = self.valid_from {
            let now = Utc::now();
            if now < valid_from {
                return Some(valid_from - now);
            }
        }
        None
    }

    /// Get time until this permission expires.
    pub fn time_until_expiry(&self) -> Option<Duration> {
        if let Some(valid_until) = self.valid_until {
            let now = Utc::now();
            if now < valid_until {
                return Some(valid_until - now);
            }
        }
        None
    }
}

impl Schedule {
    /// Create a new schedule.
    pub fn new(
        weekdays: Vec<Weekday>,
        start_time: NaiveTime,
        end_time: NaiveTime,
        timezone: String,
    ) -> Self {
        Self {
            weekdays,
            start_time,
            end_time,
            timezone,
        }
    }

    /// Create a business hours schedule (Monday-Friday, 9 AM - 5 PM).
    pub fn business_hours(timezone: String) -> Self {
        use Weekday::*;
        Self::new(
            vec![Mon, Tue, Wed, Thu, Fri],
            NaiveTime::from_hms_opt(9, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(17, 0, 0).unwrap(),
            timezone,
        )
    }

    /// Create a 24/7 schedule.
    pub fn always(timezone: String) -> Self {
        use Weekday::*;
        Self::new(
            vec![Mon, Tue, Wed, Thu, Fri, Sat, Sun],
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(23, 59, 59).unwrap(),
            timezone,
        )
    }

    /// Create a weekend-only schedule.
    pub fn weekends(timezone: String) -> Self {
        use Weekday::*;
        Self::new(
            vec![Sat, Sun],
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            NaiveTime::from_hms_opt(23, 59, 59).unwrap(),
            timezone,
        )
    }

    /// Check if the schedule is valid at the given time.
    pub fn is_valid_at(&self, time: DateTime<Utc>) -> bool {
        // Convert UTC time to the target timezone using chrono-tz
        let target_tz: Tz = self.timezone.parse().unwrap_or(chrono_tz::UTC);
        let local_time = time.with_timezone(&target_tz);

        let weekday = local_time.weekday();
        if !self.weekdays.contains(&weekday) {
            return false;
        }

        let time_of_day = local_time.time();
        if self.start_time <= self.end_time {
            // Same day schedule
            time_of_day >= self.start_time && time_of_day <= self.end_time
        } else {
            // Overnight schedule (e.g., 22:00 - 06:00)
            time_of_day >= self.start_time || time_of_day <= self.end_time
        }
    }
}

impl TemporalPolicy {
    /// Create a new temporal policy.
    pub fn new(name: String, effective_from: DateTime<Utc>) -> Self {
        Self {
            name,
            description: None,
            permissions: Vec::new(),
            effective_from,
            expires_at: None,
        }
    }

    /// Get the policy name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the policy description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Set the policy description.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set the expiration time.
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add a temporal permission to this policy.
    pub fn add_permission(mut self, permission: TemporalPermission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Check if the policy is currently active.
    pub fn is_active(&self) -> bool {
        self.is_active_at(Utc::now())
    }

    /// Check if the policy is active at the given time.
    pub fn is_active_at(&self, time: DateTime<Utc>) -> bool {
        if time < self.effective_from {
            return false;
        }

        if let Some(expires_at) = self.expires_at
            && time > expires_at
        {
            return false;
        }

        true
    }

    /// Get all valid permissions at the current time.
    pub fn valid_permissions(&self) -> Vec<&Permission> {
        self.valid_permissions_at(Utc::now())
    }

    /// Get all valid permissions at the given time.
    pub fn valid_permissions_at(&self, time: DateTime<Utc>) -> Vec<&Permission> {
        if !self.is_active_at(time) {
            return Vec::new();
        }

        self.permissions
            .iter()
            .filter(|tp| tp.is_valid_at(time))
            .map(|tp| tp.permission())
            .collect()
    }

    /// Get policy statistics.
    pub fn stats(&self) -> PolicyStats {
        let total_permissions = self.permissions.len();
        let currently_valid = self.valid_permissions().len();
        let expired_permissions = self
            .permissions
            .iter()
            .filter(|tp| !tp.is_currently_valid())
            .count();

        PolicyStats {
            total_permissions,
            currently_valid,
            expired_permissions,
            is_active: self.is_active(),
        }
    }
}

/// Statistics for a temporal policy.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyStats {
    pub total_permissions: usize,
    pub currently_valid: usize,
    pub expired_permissions: usize,
    pub is_active: bool,
}

/// Builder for creating temporal permissions easily.
pub struct TemporalPermissionBuilder {
    permission: Permission,
}

impl TemporalPermissionBuilder {
    /// Create a new builder.
    pub fn new(action: &str, resource_type: &str) -> Self {
        Self {
            permission: Permission::new(action, resource_type),
        }
    }

    /// Set valid time range.
    pub fn valid_between(self, from: DateTime<Utc>, until: DateTime<Utc>) -> TemporalPermission {
        TemporalPermission::new(self.permission)
            .valid_from(from)
            .valid_until(until)
    }

    /// Set business hours schedule.
    pub fn business_hours(self, timezone: String) -> TemporalPermission {
        TemporalPermission::new(self.permission).with_schedule(Schedule::business_hours(timezone))
    }

    /// Set weekend schedule.
    pub fn weekends_only(self, timezone: String) -> TemporalPermission {
        TemporalPermission::new(self.permission).with_schedule(Schedule::weekends(timezone))
    }

    /// Set usage limit.
    pub fn with_usage_limit(self, max_usage: u32) -> TemporalPermission {
        TemporalPermission::new(self.permission).with_max_usage(max_usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_temporal_permission_time_bounds() {
        let permission = Permission::new("read", "documents");
        let now = Utc::now();
        let future = now + Duration::hours(1);
        let past = now - Duration::hours(1);

        let temp_perm = TemporalPermission::new(permission)
            .valid_from(past)
            .valid_until(future);

        assert!(temp_perm.is_valid_at(now));
        assert!(!temp_perm.is_valid_at(past - Duration::minutes(1)));
        assert!(!temp_perm.is_valid_at(future + Duration::minutes(1)));
    }

    #[test]
    fn test_usage_limits() {
        let permission = Permission::new("delete", "files");
        let mut temp_perm = TemporalPermission::new(permission).with_max_usage(2);

        assert!(temp_perm.is_currently_valid());

        temp_perm.record_usage().unwrap();
        assert!(temp_perm.is_currently_valid());

        temp_perm.record_usage().unwrap();
        assert!(!temp_perm.is_currently_valid());

        assert!(temp_perm.record_usage().is_err());
    }

    #[test]
    fn test_business_hours_schedule() {
        let schedule = Schedule::business_hours("UTC".to_string());

        // Monday 10 AM should be valid
        let monday_10am = Utc.with_ymd_and_hms(2024, 1, 1, 10, 0, 0).unwrap(); // Jan 1, 2024 was a Monday
        assert!(schedule.is_valid_at(monday_10am));

        // Saturday 10 AM should not be valid
        let saturday_10am = Utc.with_ymd_and_hms(2024, 1, 6, 10, 0, 0).unwrap(); // Jan 6, 2024 was a Saturday
        assert!(!schedule.is_valid_at(saturday_10am));

        // Monday 6 PM should not be valid (after business hours)
        let monday_6pm = Utc.with_ymd_and_hms(2024, 1, 1, 18, 0, 0).unwrap();
        assert!(!schedule.is_valid_at(monday_6pm));
    }

    #[test]
    fn test_temporal_policy() {
        let now = Utc::now();
        let permission = Permission::new("read", "documents");
        let temp_perm = TemporalPermission::new(permission)
            .valid_from(now - Duration::hours(1))
            .valid_until(now + Duration::hours(1));

        let policy = TemporalPolicy::new("test_policy".to_string(), now - Duration::hours(2))
            .add_permission(temp_perm);

        assert!(policy.is_active());
        assert_eq!(policy.valid_permissions().len(), 1);

        let stats = policy.stats();
        assert_eq!(stats.total_permissions, 1);
        assert_eq!(stats.currently_valid, 1);
        assert!(stats.is_active);
    }

    #[test]
    fn test_temporal_permission_builder() {
        let now = Utc::now();
        let temp_perm = TemporalPermissionBuilder::new("read", "documents")
            .valid_between(now, now + Duration::hours(2));

        assert!(temp_perm.is_currently_valid());
        assert_eq!(temp_perm.permission().action(), "read");
    }
}
