# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-08-18

### Fixed

- **Critical Fix**: Resolved compilation error with `serde_json::Error` not implementing `Clone`
  - Changed `Serialization` error variant from `serde_json::Error` to `String`
  - Added custom `From<serde_json::Error>` implementation to preserve error messages
  - This fixes the build failure when using the crate with newer versions of `serde_json`
- **Code Quality**: Removed unused imports in temporal module

### Technical Details

The issue occurred because `serde_json` v1.0.96+ removed the `Clone` implementation from their `Error` type for security and API design reasons. Our error enum derived `Clone` but contained a `serde_json::Error` field, causing compilation failures.

**Solution**: Store the error message as a `String` instead of the raw `serde_json::Error`, with automatic conversion preserving all error information.

## [1.0.0] - 2025-08-18

### Added

- **Production-ready RBAC system** with comprehensive security features
- **Async support** with Tokio runtime for high-performance applications
- **File-based storage backend** with persistence and data integrity
- **In-memory caching** for improved performance (up to 95% cache hit rates)
- **Audit logging capabilities** with comprehensive event tracking
- **Conditional permission support** with context-aware authorization
- **Hierarchical role management** with inheritance and privilege elevation
- **Multiple subject type support** (users, services, applications, etc.)
- **Thread-safe concurrent access** using lock-free data structures
- **Rate limiting** with per-subject and global limits
- **Comprehensive security validation** preventing injection attacks
- **Health monitoring** with storage validation and performance metrics
- **Temporal permissions** with timezone-aware scheduling
- **Web framework middleware** for Axum, Actix, Rocket, and Warp
- **Property-based testing** with fuzzing for security validation
- **Extensive telemetry** and observability features

### Security Features

- **Input validation** preventing SQL injection, script injection, path traversal
- **Memory safety** with comprehensive fuzzing and load testing
- **Privilege escalation prevention** with strict hierarchy validation
- **Cache integrity** protection against timing attacks
- **Error information sanitization** preventing data leakage
- **Concurrent access safety** with atomic operations

### Performance Features

- **Ultra-low latency** operations optimized for minimal delay
- **Memory efficiency** with zero-copy operations where possible
- **String pooling** for reduced allocations
- **Object pooling** for frequently used resources
- **Caching** with intelligent invalidation strategies

### Testing & Quality

- **154 comprehensive tests** covering all functionality
- **Property-based testing** for edge case discovery
- **Security-focused test suite** validating all attack vectors
- **Integration tests** for real-world scenario validation
- **Fuzzing capabilities** for robustness testing
- **Benchmark suite** for performance regression detection

### Dependencies

- **Updated dependencies** resolving security vulnerabilities
- **chrono-tz** for proper timezone handling
- **Minimal dependency footprint** focusing on essential crates only

- Improved error handling with custom error types
- Enhanced documentation and examples
- Optimized permission checking algorithms

### Fixed

- Security improvements in permission parsing
- Memory leak in role hierarchy management
- Race conditions in concurrent role updates

## [0.1.0] - 2025-07-10

### Initial Release Features

- Initial release
- Basic RBAC functionality
- Role management
- Permission system
- Subject handling
- Resource definitions
- Storage abstraction
- Memory storage implementation
- Basic documentation
- Unit and integration tests

[0.1.0]: https://github.com/ciresnave/role-system/releases/tag/v0.1.0
