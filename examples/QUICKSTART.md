# Quick Start Guide

Get role-based access control running in your Rust web application in under 5 minutes.

## 🚀 1-Minute Setup

```toml
# Cargo.toml
[dependencies]
role-system = "0.1"
```

```rust
// main.rs
use role_system::{RoleSystem, Role, Permission, Subject, Resource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create role system
    let mut system = RoleSystem::new();
    
    // 2. Define role with permissions
    let admin = Role::new("admin")
        .add_permission(Permission::super_admin());
    system.register_role(admin)?;
    
    // 3. Assign role to user
    let user = Subject::user("user123");
    system.assign_role(&user, "admin")?;
    
    // 4. Check permissions
    let resource = Resource::new("doc1", "documents");
    let can_delete = system.check_permission(&user, "delete", &resource)?;
    
    println!("Can delete: {}", can_delete); // true
    Ok(())
}
```

## 🌐 Web Framework Integration (5 minutes)

### Actix Web

```rust
use actix_web::{web, App, HttpServer, middleware::from_fn};
use role_system::RoleSystem;

// 1. Add middleware
.wrap(require_permission("read", "documents"))

// 2. Use in handlers
async fn handler(user: AuthenticatedUser) -> HttpResponse {
    HttpResponse::Ok().json("Access granted")
}
```

### Axum

```rust
use axum::{Router, extract::State};
use role_system::RoleSystem;

// 1. Type-safe extractors
async fn handler(admin: RequireAdmin) -> Json<Value> {
    Json(json!({"message": "Admin access granted"}))
}

// 2. Add to router
Router::new()
    .route("/admin", get(handler))
    .with_state(role_system)
```

### Rocket

```rust
use rocket::{get, routes, launch};
use role_system::RoleSystem;

// 1. Request guards
#[get("/admin")]
fn admin_endpoint(admin: AdminUser) -> Json<Value> {
    Json(json!({"message": "Admin access"}))
}

// 2. Mount routes
#[launch]
fn rocket() -> _ {
    rocket::build()
        .manage(role_system)
        .mount("/", routes![admin_endpoint])
}
```

### Warp

```rust
use warp::Filter;
use role_system::RoleSystem;

// 1. Create filters
let admin_route = warp::get()
    .and(warp::path("admin"))
    .and(admin_only())
    .and_then(admin_handler);

// 2. Serve
warp::serve(admin_route).run(([127, 0, 0, 1], 3030));
```

## 📋 Complete Example Templates

### Basic Web API

```rust
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup role system
    let mut system = RoleSystem::new();
    
    // Create roles
    let admin = Role::new("admin").add_permission(Permission::super_admin());
    let editor = Role::new("editor")
        .add_permission(Permission::new("read", "documents"))
        .add_permission(Permission::new("write", "documents"));
    let viewer = Role::new("viewer")
        .add_permission(Permission::new("read", "documents"));
    
    // Register roles
    system.register_role(admin)?;
    system.register_role(editor)?;
    system.register_role(viewer)?;
    
    // Setup hierarchy (editor inherits viewer permissions)
    system.add_role_inheritance("editor", "viewer")?;
    system.add_role_inheritance("admin", "editor")?;
    
    // Your web framework setup here...
    let shared_system = Arc::new(system);
    
    Ok(())
}
```

### Production Setup with Persistence

```rust
use role_system::{
    RoleSystem, 
    storage::FileStorage,
    core::RoleSystemConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Production configuration
    let config = RoleSystemConfig {
        max_hierarchy_depth: 5,
        enable_caching: true,
        cache_ttl_seconds: 300,
        enable_audit: true,
    };
    
    // Persistent storage
    let storage = FileStorage::new("./roles.json")?;
    let system = RoleSystem::with_storage(storage, config);
    
    // Load roles from config file or database
    setup_roles_from_config(&system).await?;
    
    // Start your web server...
    Ok(())
}
```

## 🎯 Common Patterns

### API Key Authorization

```rust
// Middleware that checks API key permissions
async fn api_key_auth(req: Request, next: Next) -> Result<Response> {
    let api_key = extract_api_key(&req)?;
    let service = Subject::service(&api_key);
    
    if !role_system.check_permission(&service, "api_access", &resource)? {
        return Err(Forbidden);
    }
    
    next.run(req).await
}
```

### Multi-Tenant Authorization

```rust
// Check permissions within tenant context
let tenant_resource = Resource::new(&doc_id, "documents")
    .with_tenant(&user.tenant_id);

let can_access = system.check_permission(&user, "read", &tenant_resource)?;
```

### Time-Based Permissions

```rust
// Business hours only access
let conditional_perm = Permission::with_condition("print", "documents", |ctx| {
    let hour = chrono::Utc::now().hour();
    (9..17).contains(&hour) // 9 AM to 5 PM
});

let role = Role::new("office_worker").add_permission(conditional_perm);
```

### Rate Limiting by Role

```rust
// Different rate limits based on user role
let rate_limit = if user.has_role("premium") {
    RateLimit::per_hour(1000)
} else {
    RateLimit::per_hour(100)
};
```

## 🔧 Framework-Specific Features

### Actix Web

- ✅ Custom Transform middleware
- ✅ Request guards
- ✅ State management
- ✅ Error handling

### Axum  

- ✅ Type-safe extractors
- ✅ Layer middleware
- ✅ FromRequest trait
- ✅ Tower integration

### Rocket

- ✅ Request guards
- ✅ Fairings
- ✅ State management
- ✅ Custom responders

### Warp

- ✅ Filter composition
- ✅ Rejection handling
- ✅ Query integration
- ✅ CORS support

## 📚 Next Steps

1. **[View Complete Examples](../middleware/)** - Full middleware implementations
2. **[Read Security Guide](../SECURITY.md)** - Security best practices  
3. **[Performance Tuning](../PERFORMANCE.md)** - Optimization tips
4. **[API Documentation](https://docs.rs/role-system)** - Complete API reference

## 🤝 Need Help?

- 📖 **[Documentation](https://docs.rs/role-system)**
- 🐛 **[Issues](https://github.com/ciresnave/role-system/issues)**
- 💬 **[Discussions](https://github.com/ciresnave/role-system/discussions)**
- 📧 **[Email Support](mailto:support@ciresnave.dev)**

Ready to get started? Pick your web framework and check out the [complete middleware examples](../middleware/)!
