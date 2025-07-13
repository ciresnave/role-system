# Web Framework Middleware Examples

This directory contains comprehensive middleware implementations for popular Rust web frameworks, demonstrating how to integrate the Role System library with minimal code and maximum flexibility.

## 🚀 Quick Start

Each example is a complete, runnable application that demonstrates:
- JWT token authentication
- Role-based authorization
- Permission checking middleware
- Error handling
- Type-safe request guards
- Real-world usage patterns

## 📁 Available Examples

### 1. Actix Web (`actix_middleware.rs`)

**Features:**
- Custom middleware using `Transform` trait
- Request guards for authentication
- Flexible permission configuration
- JWT token extraction
- Context-aware permissions

**Usage:**
```rust
// Simple permission middleware
.wrap(require_permission("read", "documents"))

// Admin-only middleware
.wrap(admin_only())

// Custom role requirements
.wrap(require_roles("write", "documents", &["editor", "admin"]))
```

**Run the example:**
```bash
cd examples/middleware
cargo run --bin actix_middleware
# Server starts on http://127.0.0.1:8080
```

### 2. Axum (`axum_middleware.rs`)

**Features:**
- Custom extractors for type-safe authentication
- Layer-based middleware
- Compile-time permission checking
- Generic permission extractors
- Tower middleware integration

**Usage:**
```rust
// Type-safe extractors
async fn handler(admin: RequireAdmin) -> Json<Value> { ... }
async fn read_handler(reader: RequireRead<"documents">) -> Json<Value> { ... }

// Middleware layers
.layer(middleware::from_fn_with_state(state, auth_middleware))
```

**Run the example:**
```bash
cd examples/middleware
cargo run --bin axum_middleware
# Server starts on http://127.0.0.1:3000
```

### 3. Rocket (`rocket_middleware.rs`)

**Features:**
- Request guards for role-based access
- Fairings for request/response processing
- Type-safe permission guards
- Custom error responses
- Automatic CORS handling

**Usage:**
```rust
// Request guards
#[get("/admin")]
fn admin_endpoint(admin: AdminUser) -> Json<Value> { ... }

#[get("/docs/<id>")]
fn read_doc(reader: DocumentReader, id: String) -> Json<Value> { ... }
```

**Run the example:**
```bash
cd examples/middleware
cargo run --bin rocket_middleware
# Server starts on http://127.0.0.1:8000
```

### 4. Warp (`warp_middleware.rs`)

**Features:**
- Filter-based authorization
- Composable permission filters
- Custom rejection handling
- Query parameter integration
- CORS support

**Usage:**
```rust
// Composable filters
let admin_route = warp::get()
    .and(warp::path("admin"))
    .and(admin_only())
    .and_then(admin_handler);

let read_docs = warp::get()
    .and(warp::path("documents"))
    .and(can_read("documents"))
    .and_then(read_handler);
```

**Run the example:**
```bash
cd examples/middleware
cargo run --bin warp_middleware
# Server starts on http://127.0.0.1:3030
```

## 🔧 Testing the Examples

Each example includes test endpoints and mock JWT tokens for easy testing:

### Test Tokens

| Framework | Admin Token | Editor Token | User Token |
|-----------|-------------|--------------|------------|
| Actix Web | `Bearer user1` | `Bearer user2` | `Bearer guest` |
| Axum | `Bearer admin-token` | `Bearer editor-token` | `Bearer user-token` |
| Rocket | `Bearer rocket-admin` | `Bearer rocket-editor` | `Bearer rocket-user` |
| Warp | `Bearer warp-admin` | `Bearer warp-editor` | `Bearer warp-user` |

### Test Commands

```bash
# Public endpoint (no auth required)
curl http://localhost:8080/public

# Protected endpoint (any valid token)
curl -H "Authorization: Bearer admin-token" http://localhost:3000/api/protected

# Admin-only endpoint
curl -H "Authorization: Bearer admin-token" http://localhost:3000/api/admin

# Document read (requires read permission)
curl -H "Authorization: Bearer editor-token" http://localhost:3000/api/documents/123

# Document create (requires write permission)
curl -X POST -H "Authorization: Bearer editor-token" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test Doc","content":"Content here"}' \
     http://localhost:3000/api/documents

# Custom permission check
curl -H "Authorization: Bearer admin-token" \
     "http://localhost:3000/api/custom-check?action=read&resource=files"
```

## 🏗️ Integration Patterns

### 1. Simple Integration (5-10 lines)

```rust
// Add to your existing web app
use role_system::{RoleSystem, Role, Permission, Subject, Resource};

// Initialize (1 line)
let role_system = RoleSystem::new();

// Setup roles (3 lines)
let admin = Role::new("admin").add_permission(Permission::super_admin());
role_system.register_role(admin)?;
role_system.assign_role(&Subject::user("user123"), "admin")?;

// Use in handlers (1 line per check)
if role_system.check_permission(&user, "read", &resource)? {
    // Allow access
}
```

### 2. Middleware Integration (10-20 lines)

```rust
// Create reusable middleware
pub fn require_admin() -> impl Middleware {
    move |req, next| {
        // Extract user from JWT
        let user = extract_user_from_jwt(&req)?;
        
        // Check admin permission
        if !role_system.check_permission(&user, "admin", &resource)? {
            return Err(Forbidden);
        }
        
        next(req)
    }
}

// Apply to routes
app.route("/admin/*", require_admin())
```

### 3. Production Setup (20-50 lines)

```rust
// Full production setup with persistence, audit logging, and caching
let role_system = RoleSystemBuilder::new()
    .with_storage(DatabaseStorage::new(db_url)?)
    .with_audit_logging(true)
    .with_caching(true)
    .with_cache_ttl(Duration::from_secs(300))
    .build()?;

// Setup roles from configuration
for role_config in config.roles {
    let role = Role::from_config(role_config)?;
    role_system.register_role(role)?;
}

// Apply to web framework
let middleware = RoleAuthMiddleware::new(role_system);
app.wrap(middleware);
```

## 🎯 Common Use Cases

### 1. API Rate Limiting by Role

```rust
// Different rate limits based on user role
let rate_limit = match user.roles.contains("premium") {
    true => RateLimit::new(1000, Duration::from_hour(1)),
    false => RateLimit::new(100, Duration::from_hour(1)),
};
```

### 2. Resource-Specific Permissions

```rust
// Check permission for specific resource
let document = Resource::new(&doc_id, "documents")
    .with_owner(&user.id)
    .with_department(&user.department);

let can_edit = role_system.check_permission_with_context(
    &user, "edit", &document, &context
)?;
```

### 3. Time-Based Permissions

```rust
// Business hours only
let permission = Permission::with_condition("print", "documents", |ctx| {
    let now = chrono::Utc::now().hour();
    (9..17).contains(&now) // 9 AM to 5 PM
});
```

### 4. Multi-Tenant Authorization

```rust
// Tenant-specific permissions
let tenant_resource = Resource::new(&resource_id, "documents")
    .with_tenant(&user.tenant_id);

let can_access = role_system.check_permission(
    &user, &action, &tenant_resource
)?;
```

## 🛠️ Customization

### Custom Storage Backend

```rust
use role_system::storage::Storage;

struct RedisStorage { /* ... */ }

impl Storage for RedisStorage {
    async fn store_role(&mut self, role: Role) -> Result<()> {
        // Store in Redis
    }
    
    async fn get_role(&self, name: &str) -> Result<Option<Role>> {
        // Retrieve from Redis
    }
}
```

### Custom Permission Conditions

```rust
// Geographic restrictions
let geo_permission = Permission::with_condition("access", "api", |ctx| {
    let ip = ctx.get("client_ip").unwrap();
    is_allowed_country(ip)
});

// Device-based permissions
let device_permission = Permission::with_condition("admin", "system", |ctx| {
    let device = ctx.get("device_id").unwrap();
    is_trusted_device(device)
});
```

### Integration with Authentication Systems

```rust
// Auth0 integration
async fn extract_user_from_auth0(token: &str) -> Result<AuthenticatedUser> {
    let claims = validate_auth0_token(token).await?;
    
    Ok(AuthenticatedUser {
        user_id: claims.sub,
        roles: claims.custom_claims.roles,
        permissions: get_user_permissions(&claims.sub).await?,
    })
}

// OAuth2 integration
async fn extract_user_from_oauth2(token: &str) -> Result<AuthenticatedUser> {
    let user_info = oauth2_client.get_user_info(token).await?;
    
    Ok(AuthenticatedUser {
        user_id: user_info.id,
        roles: user_info.roles,
        permissions: vec![], // Load from your system
    })
}
```

## 📚 Additional Resources

- **[Main Documentation](../../README.md)** - Complete API reference
- **[Security Guide](../../SECURITY.md)** - Security best practices
- **[Performance Guide](../../PERFORMANCE.md)** - Optimization tips
- **[Examples](../basic_usage.rs)** - Basic usage examples

## 🤝 Contributing

Found a bug or want to add support for another framework? 

1. Check existing [issues](https://github.com/ciresnave/role-system/issues)
2. Open a new issue or PR
3. Follow our [contributing guidelines](../../CONTRIBUTING.md)

## 📄 License

These examples are part of the Role System project and are licensed under either MIT or Apache 2.0 licenses.
