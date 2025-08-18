//! Fine-grained cache management for the role system.

use crate::{core::UserPermissions, metrics::RoleSystemMetrics};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Cache tag for organizing cache entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheTag {
    /// Cache entries for a specific subject.
    Subject(String),
    /// Cache entries involving a specific role.
    Role(String),
    /// Cache entries for a specific resource type.
    ResourceType(String),
    /// Cache entries for a specific action.
    Action(String),
    /// Cache entries with context dependencies.
    ContextDependent,
}

/// Cache entry with metadata for invalidation.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached user permissions.
    pub permissions: UserPermissions,
    /// Tags associated with this cache entry.
    pub tags: HashSet<CacheTag>,
    /// When the entry was created.
    pub created_at: DateTime<Utc>,
}

impl CacheEntry {
    /// Create a new cache entry.
    pub fn new(permissions: UserPermissions, tags: HashSet<CacheTag>) -> Self {
        Self {
            permissions,
            tags,
            created_at: Utc::now(),
        }
    }

    /// Check if the entry has a specific tag.
    pub fn has_tag(&self, tag: &CacheTag) -> bool {
        self.tags.contains(tag)
    }

    /// Check if the entry is expired based on TTL.
    pub fn is_expired(&self, ttl_seconds: u64) -> bool {
        self.permissions.is_expired(ttl_seconds)
    }
}

/// Advanced cache manager with fine-grained invalidation.
#[derive(Debug)]
pub struct CacheManager {
    /// Main cache storage: (subject_id, permission_key) -> CacheEntry
    cache: DashMap<(String, String), CacheEntry>,
    /// Tag index: CacheTag -> Set of cache keys
    tag_index: DashMap<CacheTag, HashSet<(String, String)>>,
    /// Metrics for cache operations
    metrics: Arc<RoleSystemMetrics>,
}

impl CacheManager {
    /// Create a new cache manager.
    pub fn new(metrics: Arc<RoleSystemMetrics>) -> Self {
        Self {
            cache: DashMap::new(),
            tag_index: DashMap::new(),
            metrics,
        }
    }

    /// Insert a cache entry with tags.
    pub fn insert(
        &self,
        key: (String, String),
        permissions: UserPermissions,
        tags: HashSet<CacheTag>,
    ) {
        let entry = CacheEntry::new(permissions, tags.clone());

        // Insert into main cache
        self.cache.insert(key.clone(), entry);

        // Update tag index
        for tag in tags {
            self.tag_index.entry(tag).or_default().insert(key.clone());
        }
    }

    /// Get a cache entry if it exists and is valid.
    pub fn get(&self, key: &(String, String), ttl_seconds: u64) -> Option<UserPermissions> {
        if let Some(entry) = self.cache.get(key) {
            if !entry.is_expired(ttl_seconds) {
                self.metrics.record_cache_hit();
                return Some(entry.permissions.clone());
            } else {
                // Remove expired entry
                drop(entry);
                self.remove_expired_entry(key);
            }
        }

        self.metrics.record_cache_miss();
        None
    }

    /// Invalidate cache entries by tag.
    pub fn invalidate_by_tag(&self, tag: &CacheTag) {
        if let Some(keys) = self.tag_index.get(tag) {
            let keys_to_remove: Vec<_> = keys.iter().cloned().collect();
            drop(keys); // Release the lock

            for key in keys_to_remove {
                self.remove_entry(&key);
            }
        }
    }

    /// Invalidate cache entries for a specific subject.
    pub fn invalidate_subject(&self, subject_id: &str) {
        self.invalidate_by_tag(&CacheTag::Subject(subject_id.to_string()));
    }

    /// Invalidate cache entries involving a specific role.
    pub fn invalidate_role(&self, role_name: &str) {
        self.invalidate_by_tag(&CacheTag::Role(role_name.to_string()));
    }

    /// Invalidate cache entries for a specific resource type.
    pub fn invalidate_resource_type(&self, resource_type: &str) {
        self.invalidate_by_tag(&CacheTag::ResourceType(resource_type.to_string()));
    }

    /// Invalidate all context-dependent cache entries.
    pub fn invalidate_context_dependent(&self) {
        self.invalidate_by_tag(&CacheTag::ContextDependent);
    }

    /// Remove expired entries.
    pub fn cleanup_expired(&self, ttl_seconds: u64) {
        let expired_keys: Vec<_> = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired(ttl_seconds))
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired_keys {
            self.remove_expired_entry(&key);
        }
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let total_entries = self.cache.len();
        let tag_count = self.tag_index.len();

        let mut tags_per_entry = 0;
        for entry in self.cache.iter() {
            tags_per_entry += entry.value().tags.len();
        }

        let avg_tags_per_entry = if total_entries > 0 {
            tags_per_entry as f64 / total_entries as f64
        } else {
            0.0
        };

        CacheStats {
            total_entries,
            tag_count,
            avg_tags_per_entry,
        }
    }

    /// Clear all cache entries.
    pub fn clear(&self) {
        self.cache.clear();
        self.tag_index.clear();
    }

    /// Generate cache tags for a permission check.
    pub fn generate_tags(
        subject_id: &str,
        action: &str,
        resource_type: &str,
        roles: &[String],
        has_context: bool,
    ) -> HashSet<CacheTag> {
        let mut tags = HashSet::new();

        // Subject tag
        tags.insert(CacheTag::Subject(subject_id.to_string()));

        // Action tag
        tags.insert(CacheTag::Action(action.to_string()));

        // Resource type tag
        tags.insert(CacheTag::ResourceType(resource_type.to_string()));

        // Role tags
        for role in roles {
            tags.insert(CacheTag::Role(role.clone()));
        }

        // Context dependency tag
        if has_context {
            tags.insert(CacheTag::ContextDependent);
        }

        tags
    }

    // Private helper methods

    fn remove_entry(&self, key: &(String, String)) {
        if let Some((_, entry)) = self.cache.remove(key) {
            // Remove from tag index
            for tag in &entry.tags {
                if let Some(mut keys) = self.tag_index.get_mut(tag) {
                    keys.remove(key);
                    if keys.is_empty() {
                        drop(keys);
                        self.tag_index.remove(tag);
                    }
                }
            }
        }
    }

    fn remove_expired_entry(&self, key: &(String, String)) {
        self.remove_entry(key);
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cache entries.
    pub total_entries: usize,
    /// Number of unique tags.
    pub tag_count: usize,
    /// Average number of tags per entry.
    pub avg_tags_per_entry: f64,
}

/// Trait for components that can provide cache invalidation.
pub trait CacheInvalidation {
    /// Invalidate cache entries for a subject.
    fn invalidate_subject_cache(&self, subject_id: &str);

    /// Invalidate cache entries for a role.
    fn invalidate_role_cache(&self, role_name: &str);

    /// Invalidate cache entries for a resource type.
    fn invalidate_resource_type_cache(&self, resource_type: &str);

    /// Cleanup expired cache entries.
    fn cleanup_expired_cache(&self, ttl_seconds: u64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::RoleSystemMetrics;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_cache_manager_basic_operations() {
        let metrics = Arc::new(RoleSystemMetrics::new());
        let cache = CacheManager::new(metrics.clone());

        let key = ("user1".to_string(), "read:documents".to_string());
        let mut permissions_map = HashMap::new();
        permissions_map.insert("read".to_string(), crate::core::AccessResult::Granted);
        let permissions = UserPermissions::new(permissions_map);

        let mut tags = HashSet::new();
        tags.insert(CacheTag::Subject("user1".to_string()));
        tags.insert(CacheTag::Action("read".to_string()));
        tags.insert(CacheTag::ResourceType("documents".to_string()));

        // Insert entry
        cache.insert(key.clone(), permissions.clone(), tags);

        // Retrieve entry
        let retrieved = cache.get(&key, 300).unwrap();
        assert_eq!(
            retrieved.computed_permissions.len(),
            permissions.computed_permissions.len()
        );

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.tag_count, 3);
    }

    #[test]
    fn test_cache_invalidation_by_tag() {
        let metrics = Arc::new(RoleSystemMetrics::new());
        let cache = CacheManager::new(metrics);

        let key1 = ("user1".to_string(), "read:documents".to_string());
        let key2 = ("user2".to_string(), "read:documents".to_string());

        let permissions = UserPermissions::new(HashMap::new());

        let mut tags1 = HashSet::new();
        tags1.insert(CacheTag::Subject("user1".to_string()));
        tags1.insert(CacheTag::ResourceType("documents".to_string()));

        let mut tags2 = HashSet::new();
        tags2.insert(CacheTag::Subject("user2".to_string()));
        tags2.insert(CacheTag::ResourceType("documents".to_string()));

        cache.insert(key1.clone(), permissions.clone(), tags1);
        cache.insert(key2.clone(), permissions.clone(), tags2);

        assert_eq!(cache.stats().total_entries, 2);

        // Invalidate by resource type - should remove both entries
        cache.invalidate_resource_type("documents");

        assert_eq!(cache.stats().total_entries, 0);
    }

    #[test]
    fn test_cache_tag_generation() {
        let tags = CacheManager::generate_tags(
            "user1",
            "read",
            "documents",
            &["reader".to_string(), "user".to_string()],
            true,
        );

        assert!(tags.contains(&CacheTag::Subject("user1".to_string())));
        assert!(tags.contains(&CacheTag::Action("read".to_string())));
        assert!(tags.contains(&CacheTag::ResourceType("documents".to_string())));
        assert!(tags.contains(&CacheTag::Role("reader".to_string())));
        assert!(tags.contains(&CacheTag::Role("user".to_string())));
        assert!(tags.contains(&CacheTag::ContextDependent));
    }

    #[test]
    fn test_expired_cache_cleanup() {
        let metrics = Arc::new(RoleSystemMetrics::new());
        let cache = CacheManager::new(metrics);

        let key = ("user1".to_string(), "read:documents".to_string());

        // Create an expired permissions object
        let mut permissions_map = HashMap::new();
        permissions_map.insert("read".to_string(), crate::core::AccessResult::Granted);
        let mut permissions = UserPermissions::new(permissions_map);
        permissions.last_updated = Utc::now() - chrono::Duration::seconds(400); // Older than typical TTL

        let tags = HashSet::new();
        cache.insert(key.clone(), permissions, tags);

        assert_eq!(cache.stats().total_entries, 1);

        // Cleanup with TTL of 300 seconds - should remove the expired entry
        cache.cleanup_expired(300);

        assert_eq!(cache.stats().total_entries, 0);
    }
}
