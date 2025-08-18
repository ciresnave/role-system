//! Performance optimization utilities for the role system.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Mutex;

/// String pool for reducing allocations in hot paths.
pub struct StringPool {
    pool: Mutex<VecDeque<String>>,
    max_size: usize,
}

impl StringPool {
    /// Create a new string pool with the specified maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
        }
    }

    /// Get a string from the pool, or create a new one if the pool is empty.
    pub fn get_string(&self) -> String {
        self.pool.lock().unwrap().pop_front().unwrap_or_default()
    }

    /// Return a string to the pool after clearing it.
    pub fn return_string(&self, mut s: String) {
        s.clear();
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push_back(s);
        }
    }

    /// Get the current pool size.
    pub fn pool_size(&self) -> usize {
        self.pool.lock().unwrap().len()
    }

    /// Clear the entire pool.
    pub fn clear(&self) {
        self.pool.lock().unwrap().clear();
    }
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new(100) // Default pool size
    }
}

/// Optimized cache key that uses Cow for conditional cloning.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey<'a> {
    pub subject_id: Cow<'a, str>,
    pub permission_key: Cow<'a, str>,
}

impl<'a> CacheKey<'a> {
    /// Create a new cache key with borrowed strings.
    pub fn borrowed(subject_id: &'a str, permission_key: &'a str) -> Self {
        Self {
            subject_id: Cow::Borrowed(subject_id),
            permission_key: Cow::Borrowed(permission_key),
        }
    }

    /// Create a new cache key with owned strings.
    pub fn owned(subject_id: String, permission_key: String) -> Self {
        Self {
            subject_id: Cow::Owned(subject_id),
            permission_key: Cow::Owned(permission_key),
        }
    }

    /// Convert to owned cache key.
    pub fn into_owned(self) -> CacheKey<'static> {
        CacheKey {
            subject_id: Cow::Owned(self.subject_id.into_owned()),
            permission_key: Cow::Owned(self.permission_key.into_owned()),
        }
    }
}

/// Memory pool for frequently allocated objects.
pub struct ObjectPool<T> {
    pool: Mutex<VecDeque<T>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
    reset: Box<dyn Fn(&mut T) + Send + Sync>,
    max_size: usize,
}

impl<T> ObjectPool<T> {
    /// Create a new object pool.
    pub fn new<F, R>(max_size: usize, factory: F, reset: R) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
        R: Fn(&mut T) + Send + Sync + 'static,
    {
        Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size)),
            factory: Box::new(factory),
            reset: Box::new(reset),
            max_size,
        }
    }

    /// Get an object from the pool.
    pub fn get<'a>(&'a self) -> PooledObject<'a, T> {
        let obj = self
            .pool
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| (self.factory)());

        PooledObject::new(obj, self)
    }

    /// Return an object to the pool.
    fn return_object(&self, mut obj: T) {
        (self.reset)(&mut obj);
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push_back(obj);
        }
    }

    /// Get current pool size.
    pub fn pool_size(&self) -> usize {
        self.pool.lock().unwrap().len()
    }
}

/// RAII wrapper for pooled objects.
pub struct PooledObject<'a, T> {
    obj: Option<T>,
    pool: &'a ObjectPool<T>,
}

impl<'a, T> PooledObject<'a, T> {
    fn new(obj: T, pool: &'a ObjectPool<T>) -> Self {
        Self {
            obj: Some(obj),
            pool,
        }
    }
}

impl<'a, T> std::ops::Deref for PooledObject<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.obj.as_ref().unwrap()
    }
}

impl<'a, T> std::ops::DerefMut for PooledObject<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.obj.as_mut().unwrap()
    }
}

impl<'a, T> Drop for PooledObject<'a, T> {
    fn drop(&mut self) {
        if let Some(obj) = self.obj.take() {
            self.pool.return_object(obj);
        }
    }
}

/// Optimized string operations for frequent use.
pub mod string_ops {
    use super::*;
    use std::collections::HashMap;

    thread_local! {
        static STRING_POOL: StringPool = StringPool::default();
    }

    /// Get a string from the thread-local pool.
    pub fn get_pooled_string() -> String {
        STRING_POOL.with(|pool| pool.get_string())
    }

    /// Return a string to the thread-local pool.
    pub fn return_pooled_string(s: String) {
        STRING_POOL.with(|pool| pool.return_string(s));
    }

    /// Create an optimized permission key with minimal allocations.
    pub fn create_permission_key(action: &str, resource_id: &str, context_hash: &str) -> String {
        if context_hash.is_empty() {
            format!("{}:{}", action, resource_id)
        } else {
            format!("{}:{}:{}", action, resource_id, context_hash)
        }
    }

    /// Create a simple hash of context for caching.
    pub fn hash_context(context: &HashMap<String, String>) -> String {
        if context.is_empty() {
            String::new()
        } else {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();

            // Sort keys for consistent hashing
            let mut sorted_keys: Vec<_> = context.keys().collect();
            sorted_keys.sort();

            for key in sorted_keys {
                key.hash(&mut hasher);
                context[key].hash(&mut hasher);
            }

            format!("{:x}", hasher.finish())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_string_pool() {
        let pool = StringPool::new(5);

        // Get and return strings
        let s1 = pool.get_string();
        let s2 = pool.get_string();

        pool.return_string(s1);
        pool.return_string(s2);

        assert_eq!(pool.pool_size(), 2);

        // Pool should not exceed max size
        for _ in 0..10 {
            pool.return_string(String::new());
        }
        assert_eq!(pool.pool_size(), 5);
    }

    #[test]
    fn test_cache_key() {
        let key1 = CacheKey::borrowed("user1", "read:docs");
        let key2 = CacheKey::owned("user1".to_string(), "read:docs".to_string());

        assert_eq!(key1, key2);

        let owned_key = key1.into_owned();
        assert_eq!(owned_key.subject_id, "user1");
    }

    #[test]
    fn test_object_pool() {
        let pool = ObjectPool::new(3, Vec::<i32>::new, |v| v.clear());

        {
            let mut obj1 = pool.get();
            obj1.push(42);
            assert_eq!(obj1[0], 42);
        } // obj1 is returned to pool here

        {
            let obj2 = pool.get();
            assert!(obj2.is_empty()); // Should be reset
        }

        assert_eq!(pool.pool_size(), 1);
    }

    #[test]
    fn test_string_ops() {
        use super::string_ops::*;

        let key = create_permission_key("read", "doc1", "");
        assert_eq!(key, "read:doc1");

        let key_with_context = create_permission_key("read", "doc1", "abc123");
        assert_eq!(key_with_context, "read:doc1:abc123");

        let mut context = HashMap::new();
        context.insert("user".to_string(), "admin".to_string());
        context.insert("time".to_string(), "day".to_string());

        let hash1 = hash_context(&context);
        let hash2 = hash_context(&context);
        assert_eq!(hash1, hash2); // Should be consistent

        let empty_hash = hash_context(&HashMap::new());
        assert!(empty_hash.is_empty());
    }
}
