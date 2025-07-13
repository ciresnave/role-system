# Role System

A flexible and powerful role-based access control (RBAC) library for Rust applications.

[![Crates.io](https://img.shields.io/crates/v/role-system.svg)](https://crates.io/crates/role-system)
[![Documentation](https://docs.rs/role-system/badge.svg)](https://docs.rs/role-system)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/ciresnave/role-system)
[![Security Audit](https://github.com/ciresnave/role-system/actions/workflows/audit.yml/badge.svg)](https://github.com/ciresnave/role-system/actions/workflows/audit.yml)
[![CI](https://github.com/ciresnave/role-system/actions/workflows/ci.yml/badge.svg)](https://github.com/ciresnave/role-system/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/ciresnave/role-system/branch/main/graph/badge.svg)](https://codecov.io/gh/ciresnave/role-system)

🚀 Production-ready RBAC system with hierarchical roles, conditional permissions, and async support.

## Features

✨ **Core Features**

- Hierarchical Roles with inheritance
- Fine-grained Permissions with wildcards
- Dynamic Role Management and elevation
- Context-based Conditional Permissions
- Thread-safe Concurrent Access

🔒 **Security**

- Fail-safe Default Deny
- Comprehensive Audit Logging
- Input Validation and Sanitization
- Security-first Design

⚡ **Performance**

- Built-in Permission Caching
- Efficient Lock-free Data Structures
- Optimized Pattern Matching
- [Detailed Performance Analysis](PERFORMANCE.md)

🔧 **Integration**

- [Comprehensive Middleware Examples](examples/middleware/) - **NEW!**
- [Web Framework Examples](examples/web-frameworks/)
- Multiple Storage Backends
- Async/Await Support
- Custom Storage Adapters

📚 **Documentation**

- Comprehensive API Docs
- [Versioning Policy](VERSIONING.md)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

- **Hierarchical Roles**: Support for role inheritance and hierarchy
- **Fine-grained Permissions**: Detailed permission control with action and resource type specifications
- **Dynamic Role Management**: Runtime role assignment, removal, and temporary elevation
- **Conditional Permissions**: Context-based permission validation
- **Multiple Subject Types**: Support for users, groups, services, and devices
- **Thread-safe**: Built with concurrent access in mind using `DashMap`
- **Async Support**: Optional async/await support with Tokio
- **Persistence**: Optional serialization support with Serde
- **Audit Logging**: Optional audit trail with tracing
- **Caching**: Built-in permission caching for performance
- **Flexible Storage**: Pluggable storage backends (memory, file, custom)

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
role-system = "0.1"
```

### ⚡ 5-Minute Integration

For web applications, check out our [comprehensive middleware examples](examples/middleware/) that show how to integrate with popular frameworks in just 5-10 lines of code:

- **[Actix Web](examples/middleware/actix_middleware.rs)** - Custom middleware with Transform trait
- **[Axum](examples/middleware/axum_middleware.rs)** - Type-safe extractors and layers  
- **[Rocket](examples/middleware/rocket_middleware.rs)** - Request guards and fairings
- **[Warp](examples/middleware/warp_middleware.rs)** - Filter-based authorization

Each example includes JWT authentication, role-based authorization, and production-ready error handling.

### Basic Example

```rust
use role_system::{RoleSystem, Role, Permission, Subject, Resource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the role system
    let mut role_system = RoleSystem::new();
    
    // Define permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    
    // Define roles with permissions
    let reader = Role::new("reader").add_permission(read_docs.clone());
    let writer = Role::new("writer")
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());
    
    // Register roles
    role_system.register_role(reader)?;
    role_system.register_role(writer)?;
    
    // Create hierarchical roles (writer inherits from reader)
    role_system.add_role_inheritance("writer", "reader")?;
    
    // Assign roles to subjects
    let user = Subject::new("user1");
    role_system.assign_role(&user, "reader")?;
    
    // Check permissions
    let document = Resource::new("doc1", "documents");
    let can_read = role_system.check_permission(&user, "read", &document)?;
    let can_write = role_system.check_permission(&user, "write", &document)?;
    
    println!("User can read: {}", can_read);   // true
    println!("User can write: {}", can_write); // false
    
    Ok(())
}
```

### Advanced Example with Conditional Permissions

```rust
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut role_system = RoleSystem::new();
    
    // Create a conditional permission that only works during business hours
    let conditional_print = Permission::with_condition("print", "documents", |context| {
        context.get("time") == Some(&"business_hours".to_string()) && 
        context.get("location") == Some(&"office".to_string())
    });
    
    let office_worker = Role::new("office_worker")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(conditional_print);
    
    role_system.register_role(office_worker)?;
    
    let user = Subject::new("employee1");
    role_system.assign_role(&user, "office_worker")?;
    
    let document = Resource::new("report.pdf", "documents");
    
    // Create context
    let mut context = HashMap::new();
    context.insert("time".to_string(), "business_hours".to_string());
    context.insert("location".to_string(), "office".to_string());
    
    // Check permission with context
    let can_print = role_system.check_permission_with_context(
        &user, "print", &document, &context
    )?;
    
    println!("Can print during business hours at office: {}", can_print); // true
    
    // Change context - now at home
    context.insert("location".to_string(), "home".to_string());
    let can_print_home = role_system.check_permission_with_context(
        &user, "print", &document, &context
    )?;
    
    println!("Can print from home: {}", can_print_home); // false
    
    Ok(())
}
```

### Async Example

```rust
use role_system::{
    async_support::{AsyncRoleSystem, AsyncRoleSystemBuilder},
    Role, Permission, Subject, Resource,
    storage::MemoryStorage,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create async role system
    let async_system = AsyncRoleSystemBuilder::<MemoryStorage>::new()
        .enable_caching(true)
        .build();
    
    // Define role and permissions
    let admin_role = Role::new("admin")
        .add_permission(Permission::super_admin()); // Grants access to everything
    
    async_system.register_role(admin_role).await?;
    
    // Assign role to user
    let admin_user = Subject::user("admin1");
    async_system.assign_role(&admin_user, "admin").await?;
    
    // Check permission
    let sensitive_data = Resource::new("secrets.txt", "files");
    let can_access = async_system
        .check_permission(&admin_user, "read", &sensitive_data)
        .await?;
    
    println!("Admin can access sensitive data: {}", can_access); // true
    
    Ok(())
}
```

## Features and Configuration

### Feature Flags

- `async` (default): Enables async/await support with Tokio
- `persistence`: Enables serialization support with Serde
- `audit`: Enables audit logging with tracing

```toml
[dependencies]
role-system = { version = "0.1", features = ["persistence", "audit"] }
```

### Storage Backends

The role system supports multiple storage backends:

#### Memory Storage (Default)

```rust
use role_system::{RoleSystem, storage::MemoryStorage};

let role_system = RoleSystem::<MemoryStorage>::new();
```

#### File Storage (with `persistence` feature)

```rust
use role_system::{RoleSystem, storage::FileStorage, core::RoleSystemConfig};

let storage = FileStorage::new("./roles.json")?;
let config = RoleSystemConfig::default();
let role_system = RoleSystem::with_storage(storage, config);
```

#### Custom Storage

Implement the `Storage` trait to create your own storage backend:

```rust
use role_system::storage::Storage;

struct DatabaseStorage {
    // Your database connection
}

impl Storage for DatabaseStorage {
    fn store_role(&mut self, role: Role) -> Result<()> {
        // Store role in database
    }
    
    fn get_role(&self, name: &str) -> Result<Option<Role>> {
        // Retrieve role from database
    }
    
    // ... implement other methods
}
```

## Architecture

### Core Components

- **RoleSystem**: Main entry point for role-based access control
- **Role**: Represents a collection of permissions that can be assigned to subjects
- **Permission**: Represents an action that can be performed on a resource type
- **Subject**: Represents an entity that can have roles (user, group, service, device)
- **Resource**: Represents something that can be accessed or acted upon
- **Storage**: Pluggable storage backend for persisting role data

### Permission Model

Permissions follow the format `action:resource_type`:

- `read:documents` - Read access to documents
- `write:users` - Write access to user records
- `admin:*` - Admin access to all resource types
- `*:documents` - All actions on documents

### Role Hierarchy

Roles can inherit from other roles, creating a hierarchy:

```rust
// admin inherits all permissions from writer
role_system.add_role_inheritance("admin", "writer")?;

// writer inherits all permissions from reader
role_system.add_role_inheritance("writer", "reader")?;
```

### Subject Types

The system supports different types of subjects:

- **User**: Human users
- **Group**: Collections of users
- **Service**: Applications or services
- **Device**: IoT devices or systems
- **Custom**: User-defined subject types

### Temporary Role Elevation

Users can be temporarily granted additional roles:

```rust
// Elevate user to admin role for 1 hour
role_system.elevate_role(&user, "admin", Some(Duration::from_secs(3600)))?;
```

## Performance

- **Caching**: Built-in permission caching to avoid repeated calculations
- **Thread-safe**: Uses `DashMap` for concurrent access without locks
- **Efficient hierarchy**: Smart hierarchy traversal with cycle detection
- **Lazy evaluation**: Permissions are only calculated when needed

## Security Considerations

- **Fail-safe defaults**: Permissions are denied by default
- **Explicit grants**: All permissions must be explicitly granted
- **Hierarchy validation**: Prevents circular dependencies in role hierarchy
- **Audit logging**: Optional comprehensive audit trail
- **Context validation**: Conditional permissions based on runtime context

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

This library was extracted and evolved from the role management system originally developed for the COAD (Code Organization and Analysis Dashboard) project, providing a standalone, reusable RBAC solution for the Rust ecosystem.
