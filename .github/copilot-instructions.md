# Role System Crate - Copilot Instructions

<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

This is a Rust library crate for role-based access control (RBAC). When working on this project:

## Code Style and Architecture
- Follow Rust best practices and idiomatic code patterns
- Use strong typing and leverage the type system for safety
- Implement proper error handling with custom error types
- Use builder patterns for complex object construction
- Prefer composition over inheritance where applicable

## Key Design Principles
- **Security First**: All permission checks should be explicit and fail-safe
- **Performance**: Use efficient data structures like DashMap for concurrent access
- **Flexibility**: Support hierarchical roles and conditional permissions
- **Auditability**: Log all permission checks and role changes when audit feature is enabled
- **Thread Safety**: All operations should be thread-safe by default

## Project Structure
- `src/lib.rs` - Main library entry point and public API
- `src/core/` - Core RBAC types and traits
- `src/permission/` - Permission checking and validation logic
- `src/role/` - Role management and hierarchy
- `src/subject/` - Subject (user/entity) management
- `src/resource/` - Resource definitions and management
- `src/error/` - Custom error types
- `src/storage/` - Data storage abstractions
- `tests/` - Integration tests

## Testing Guidelines
- Write comprehensive unit tests for all public APIs
- Include integration tests for complex workflows
- Test edge cases and error conditions
- Use property-based testing for permission logic where appropriate

## Feature Flags
- `async` - Enables async/await support with Tokio
- `persistence` - Enables serialization with Serde
- `audit` - Enables tracing and audit logging

## Documentation
- Include comprehensive doc comments for all public APIs
- Provide examples in doc comments
- Keep the README.md up to date with latest features
