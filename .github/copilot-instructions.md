# Role System Crate - Copilot Instructions

This is a Rust library crate for role-based access control (RBAC). When working on this project:

## Core Principles

### SOLID Principles
- **Single Responsibility Principle (SRP)**: Each module, struct, and function serves one clear purpose
- **Open/Closed Principle (OCP)**: Design for extension without modification of existing code
- **Liskov Substitution Principle (LSP)**: Ensure proper inheritance and trait implementations
- **Interface Segregation Principle (ISP)**: Create focused, minimal trait interfaces
- **Dependency Inversion Principle (DIP)**: Depend on abstractions, not concretions

### Design Principles
- **DRY (Don't Repeat Yourself)**: Eliminate code duplication through proper abstraction
- **KISS (Keep It Simple, Stupid)**: Prefer simple, clear solutions over complex ones
- **Law of Demeter**: Minimize coupling between modules
- **Boy Scout Rule**: Always leave code cleaner than you found it
- **Polymorphism over Conditionals**: Use traits and generics instead of match/if chains

### Architecture Guidelines
- **Centralized Configuration**: All settings managed through unified config system
- **Minimal Dependencies**: Only essential external crates, prefer std library
- **Purposeful Layers**: Clear separation between protocol, core logic, and I/O layers
- **Avoid Over-engineering**: Build what's needed, not what might be needed

## Quality Standards

### Performance Requirements
- **Ultra-low Latency**: Every operation optimized for minimal delay
- **Memory Efficiency**: Zero-copy operations where possible
- **Concurrent by Design**: Async/await throughout, proper resource sharing

### Security Requirements
- **Security by Default**: All communications encrypted, secure defaults only
- **No Security Fallbacks**: Reject insecure connections rather than downgrade
- **Configurable Security**: Admin/user control over security requirements

### Testing Standards
- **Test-Driven Development**: Write tests before implementation
- **No Mocking**: Real implementations only, except for external system boundaries
- **Comprehensive Coverage**: Unit, integration, and property-based tests

### Documentation Requirements
- **Live Documentation**: Update docs with every code change
- **Multiple Audiences**: Admin guides, developer docs, contributor guides
- **Decision Log**: Document all architectural decisions with rationale

## Rust-Specific Guidelines

### Code Style
- Use `cargo fmt` and `cargo clippy` standards
- Prefer explicit types in public APIs
- Use `Result<T, E>` for all fallible operations
- Leverage zero-cost abstractions

### Error Handling
- Custom error types with `thiserror`
- Propagate errors with `?` operator
- Provide meaningful error context

### Async Programming
- Use `tokio` for async runtime
- Prefer `async fn` over manual `Future` implementations
- Handle cancellation properly with `select!`

## Project Structure
- Core library in `src/lib.rs`
- Binary targets in `src/bin/`
- FFI bindings in `ffi/` subdirectories
- Tests co-located with code
- Integration tests in `tests/`
- Documentation in `docs/`

## Cross-Platform Considerations
- Use conditional compilation for OS-specific code
- Abstract OS interfaces behind traits
- Test on all target platforms
- Minimize platform-specific dependencies

## Multi-Language SDK Guidelines
- C-compatible FFI layer as foundation
- Language-specific wrappers for ergonomics
- Consistent API design across languages
- Comprehensive examples for each language


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

Remember: This project aims to become THE role system solution everyone uses. Make every decision based on what creates the best, most complete solution, not what's quickest or easiest.

