# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Async support with Tokio runtime
- File-based storage backend with persistence
- In-memory caching for improved performance
- Audit logging capabilities
- Conditional permission support
- Hierarchical role management
- Multiple subject type support
- Thread-safe concurrent access

### Changed

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

[Unreleased]: https://github.com/ciresnave/role-system/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ciresnave/role-system/releases/tag/v0.1.0
