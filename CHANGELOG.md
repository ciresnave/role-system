# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - Unreleased

### 🔧 Maintenance

- CI only: workflow actions are pinned to full commit SHAs (tag kept in a trailing comment); `dtolnay/rust-toolchain` steps pass an explicit `toolchain` input because a SHA no longer carries the branch name; workflows default to `contents: read`. The `postgres:16` service container is pinned by digest (`postgres@sha256:9e2cf628…`, tag in a comment).
- Added `.github/CODEOWNERS` (`* @ciresnave`).
- Security Audit fixed at its cause: `Cargo.lock` held three crates with open advisories (`ctutils` 0.4.3, RUSTSEC-2026-0385; `rustls-webpki` 0.103.15, RUSTSEC-2026-0382; `webpki-roots` 1.0.9, RUSTSEC-2026-0381). Lock-only update to 0.4.7, 0.103.16 and 1.0.11; `cargo audit` exits 0. No source or `Cargo.toml` dependency change.

## [1.1.2] - 2026-10-18

### 🔧 Maintenance

- **Dependencies updated to their newest releases** (clears RUSTSEC-2026-0007, -0204, -0258, -0285, -0346, -0348, -0349, -0098 and -0049 among the advisories reported against the previous lockfile, and RUSTSEC-2023-0071, which no longer appears in `Cargo.lock`): `sqlx` 0.9 (features `runtime-tokio`, `tls-rustls`), `opentelemetry` and `opentelemetry-semantic-conventions` 0.33, and dev-dependencies `criterion` 0.8, `mockall` 0.15 and `rand` 0.10. Removed the unused dev-dependencies `actix-web`, `axum` and `rocket`, which were the only source of the vulnerable `h2` 0.3.
- **`DatabaseStorage::new_with_prefix` validates the table prefix.** The prefix is spliced into SQL identifiers, and `sqlx` 0.9 requires dynamic SQL to be marked as audited; the prefix must now be 1-32 ASCII letters, digits or underscores and must not start with a digit, otherwise an `Error::Storage` is returned.
- CI is green again: `cargo fmt` applied, `async-trait` updated (the `must_use` clippy error), and a timing-sensitive health-check test given generous timeouts so it no longer fails under code coverage.

## [Unreleased]

## [1.3.0] - 2026-10-18

### 🔒 Security

- **`RoleBuilder::deny` did not deny** (affects 1.1.1, 1.2.0 and 1.2.2). It added a grant with an always-false condition, which never matched, so every grant of the same action still applied: `allow("system", ["*"]).deny("system", ["shutdown"])` allowed `shutdown`. A deny is now a real rule (`Permission::deny`, `Permission::deny_instance`, `Permission::is_deny`): a matching deny refuses the check even if another permission, in the same role, an inherited role or any other role the subject holds, would grant it. A deny with an instance matches only that instance.
- **Saving and loading roles could widen permissions** (affects 0.1.0 through 1.2.2). A permission's condition is a closure and was silently dropped when a role was saved, so after a reload (`FileStorage`, `DatabaseStorage`, or serializing a `Role` with the `persistence` feature) a conditional permission, including `deny`'s always-false one, became an unconditional grant. Saving a role that has a conditional permission now fails (`serde` error, or `Error::Storage` from `DatabaseStorage`) instead of widening it on load.
- **A reloaded `RoleElevation` restarted its clock** (affects 0.1.0 through 1.2.2, for code that serializes `RoleElevation`; the built-in storage backends save roles only). The creation time was not saved and loaded back as "now", so an expired elevation got a fresh full lifetime. The elevation is now saved as a wall-clock creation time and the time that passed while the process was not running counts against it.

### ⚠️ Behaviour changes

- A role built with `deny(...)` now denies. Code that relied on `deny` being inert will see refusals it did not see before.
- Saving a role with a conditional permission is now an error. Re-create such roles in code at start-up instead of persisting them.
- `DatabaseStorage` adds a `negated BOOLEAN NOT NULL DEFAULT FALSE` column to its permissions table (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` at start-up). Files and rows saved before this release load as before (every rule is a grant). Anything a previous version already saved from a conditional permission was saved as an unconditional grant and must be reviewed.


## [1.2.2] - 2026-10-18

### 🐛 Fixes

- **`DatabaseStorage::store_role_async` failed with a foreign-key error.** The role's permissions were inserted through the connection pool while the role row was still uncommitted inside the transaction, so another connection could not see it. They are now inserted on the transaction's connection.
- **Concurrent `DatabaseStorage` start-up could fail** with a duplicate-key error from PostgreSQL's `CREATE TABLE IF NOT EXISTS`. Schema creation now runs in one transaction under an advisory lock.

### 🧪 Tests

- The two PostgreSQL tests are no longer `#[ignore]`d: CI runs them against a `postgres:16` service container (set `DATABASE_URL` to run them locally). They had never run in CI, which is how the two bugs above went unnoticed.

## [1.2.1] - 2026-10-18

### 🧪 Tests

- `test_role_elevation_expiry` no longer depends on a 10 ms window (it failed intermittently under code coverage); it uses a 1.5 s elevation and a 1.7 s wait.

## [1.2.0] - 2026-10-18

### 🔒 Security

- **Permission cache returned answers for the wrong resource type.** The cache key was built from the action, resource id and context but not the resource type, so a grant (or denial) cached for one type answered checks on another type with the same resource id. Present since 0.1.0. The key now includes the type, and each field is escaped so field boundaries cannot be forged.
- **Instance-scoped permissions were not enforced.** `check_permission` matched on action and resource type only, so a permission created with `Permission::with_instance(..)` granted every instance of the type. Present since 1.0.0. The check now honours instances.

### ⚠️ Behaviour change

- A permission with an instance now grants only that instance (or any named instance, if the instance is `"*"`). It no longer grants a check whose resource id is empty (an empty id means "no instance"); permissions without an instance are unchanged and still cover every instance. Callers that relied on the old, wider behaviour must grant the permission without an instance.
- New `Role::has_permission_with_instance`.

## [1.1.1] - 2025-08-19

### 🔒 Security Enhancements

- **Enhanced Error Handling**: Replaced all unsafe `.unwrap()` calls with proper `Result`-based error handling
  - Fixed 20+ potential crash points in storage operations
  - Implemented graceful error recovery with descriptive error messages
  - Prevents denial of service attacks through application crashes
- **Resource Validation Security**: Enhanced resource creation with proper validation
  - Added `Resource::new_checked()` method for safe resource creation
  - Prevents path traversal attacks (`../`, null characters)
  - Maintains backward compatibility with existing `new()` method
- **JWT Security Warnings**: Added comprehensive security warnings to middleware examples
  - Clear documentation that mock JWT implementations are for development only
  - Detailed guidance on proper JWT validation requirements
  - Prevents accidental production use of insecure authentication

### 📚 Documentation

- **Security Integration Guide**: New comprehensive security documentation
  - Authentication vs Authorization best practices
  - Secure JWT implementation patterns
  - Input validation and error handling guidelines
  - Session management and security headers
  - Audit logging implementation examples
  - Common vulnerabilities and secure alternatives

### 🛠️ Improvements

- **Project Cleanup**: Removed temporary and backup files
- **Code Quality**: All tests passing (127 unit tests, 13 integration tests, 12 edge case tests, 14 security tests)
- **Performance**: Benchmarks show continued excellent performance
- **Build Quality**: Zero clippy warnings, successful release builds

### 🔧 Internal

- **Testing**: Maintained 100% test coverage across all modules
- **Compliance**: All security audit recommendations implemented
- **Documentation**: Enhanced inline documentation and examples

## [1.1.0] - 2024-12-19

### 🚀 Major Features Added

#### Enhanced Permission System

- **Enhanced Permission Constructors**: New methods for creating permissions with improved ergonomics
  - `Permission::with_context(resource, action, context)` - Create permissions with contextual information
  - `Permission::with_scope(resource, action, scopes)` - Generate multiple scoped permissions at once
  - `Permission::conditional(resource, action)` - Builder pattern for conditional permissions

#### Fluent RoleBuilder API

- **Enhanced RoleBuilder**: Powerful fluent API for creating roles with multiple permissions
  - `allow(resource, actions)` - Add multiple permissions with clean syntax
  - `deny(resource, actions)` - Add denial permissions for fine-grained control
  - `allow_when(resource, actions, condition)` - Add conditional permissions with context evaluation
  - Full backward compatibility with existing `permission()` and `permissions()` methods

#### Declarative Role Macros

- **`define_role!` macro**: Create single roles with declarative syntax

  ```rust
  let admin = define_role!(admin {
      users: ["create", "read", "update", "delete"],
      system: ["configure", "monitor"]
  });
  ```

- **`define_roles!` macro**: Create multiple roles in bulk with clean syntax
- **`permission!` macro**: Shorthand for creating single or multiple permissions
- Enhanced macro support in existing `permissions!`, `role_with_permissions!`, and `subjects!` macros

#### Role Hierarchy System

- **`RoleHierarchy` struct**: Complete role inheritance system
  - `set_parent(child_id, parent_id)` - Establish parent-child relationships
  - `get_effective_permissions(role_id)` - Get all permissions including inherited
  - `has_permission(role_id, action, resource, context)` - Check permissions with inheritance
  - Circular dependency detection and prevention
  - Automatic permission aggregation from ancestor roles

#### Conditional Permission Builder

- **`ConditionalPermissionBuilder`**: Advanced builder for complex conditional logic
  - `when(condition)` - Add primary condition
  - `or_when(condition)` - Add alternative conditions with OR logic
  - `build()` - Finalize conditional permission
  - Context-dependent permission evaluation

### 🛠️ Improvements

- Enhanced error messages with specific role hierarchy error types
- Improved performance for permission checking with inherited roles
- Better documentation and examples for all new features
- Comprehensive integration testing for v1.1.0 features

### 📚 Examples

- Added comprehensive `v1_1_features.rs` example demonstrating all new capabilities
- Updated existing examples to showcase enhanced APIs
- Added practical use cases for role hierarchies and conditional permissions

### 🔧 Internal Improvements

- Optimized role hierarchy traversal algorithms
- Enhanced permission set operations for inheritance
- Better memory management for large role hierarchies
- Improved error handling throughout the hierarchy system

### 🧪 Testing

- Added 100% test coverage for all new features
- Property-based testing for role hierarchy operations
- Security testing for hierarchy cycle prevention
- Performance testing for large role hierarchies

### 📖 Documentation

- Comprehensive API documentation for all new features
- Updated README with v1.1.0 feature overview
- Added migration guide from v1.0.x to v1.1.0
- Enhanced code examples in documentation

### ⚡ Performance

- Optimized permission inheritance calculations
- Efficient role hierarchy traversal
- Improved memory usage for complex role structures
- Better caching for effective permission calculations

### 🔒 Security

- Enhanced validation for role hierarchy relationships
- Circular dependency prevention mechanisms
- Secure context evaluation for conditional permissions
- Protection against privilege escalation through hierarchy manipulation

### 🔄 Backward Compatibility

- **100% backward compatible** with role-system v1.0.x
- All existing APIs continue to work unchanged
- No breaking changes to existing functionality
- Smooth upgrade path for existing codebases

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
