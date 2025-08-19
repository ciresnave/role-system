# Security Integration Guide

This guide covers secure integration practices for the Role System library.

## Table of Contents

- [Authentication vs Authorization](#authentication-vs-authorization)
- [JWT Integration](#jwt-integration)
- [Input Validation](#input-validation)
- [Error Handling](#error-handling)
- [Session Management](#session-management)
- [Security Headers](#security-headers)
- [Audit Logging](#audit-logging)
- [Best Practices](#best-practices)

## Authentication vs Authorization

**Understanding the Distinction:**

- **Authentication**: Verifying the identity of a user/subject ("Who are you?")
- **Authorization**: Determining what actions a user can perform ("What can you do?")

The Role System library focuses on **authorization**. You must implement secure authentication separately.

### Integration Pattern

```rust
// 1. Authenticate the user (your responsibility)
let user_id = authenticate_user(jwt_token)?;

// 2. Use Role System for authorization (our responsibility)
let subject = Subject::user(user_id);
let resource = Resource::new_checked("document", "file")?;
let permission = Permission::new("read", "document");

let authorized = role_system.check_permission(&subject, &permission, &resource);
```

## JWT Integration

### ⚠️ Security Warning

**NEVER use the JWT examples from the middleware directory in production!** They are mock implementations that accept hardcoded tokens.

### Secure JWT Implementation

```rust
use jsonwebtoken::{decode, encode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
}

fn decode_jwt_secure(token: &str, secret: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation {
        algorithms: vec![Algorithm::HS256],
        validate_exp: true,
        validate_iat: true,
        iss: Some("your-issuer".to_string()),
        aud: Some(vec!["your-audience".to_string()]),
        ..Default::default()
    };

    let decoding_key = DecodingKey::from_secret(secret);
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}
```

### Required JWT Validations

1. **Signature Verification**: Use proper cryptographic algorithms (HS256, RS256, etc.)
2. **Expiration Check**: Validate `exp` claim
3. **Not Before Check**: Validate `nbf` claim if present
4. **Issued At Check**: Validate `iat` claim
5. **Issuer Verification**: Validate `iss` claim
6. **Audience Verification**: Validate `aud` claim

## Input Validation

### Resource Creation

```rust
use role_system::{Resource, Error};

// Use the secure constructor
let resource = Resource::new_checked(user_input_id, user_input_type)?;

// The library validates against:
// - Path traversal attempts ("../", "..")
// - Null characters (\0)
// - Invalid UTF-8 sequences
```

### Permission Validation

```rust
use role_system::Permission;

// Built-in validation prevents:
// - Empty actions or resources
// - Path traversal in resource names
// - Null bytes in permission strings
let permission = Permission::parse("read:documents")?;
```

## Error Handling

### Secure Error Responses

```rust
use role_system::Error;

fn handle_permission_error(error: Error) -> HttpResponse {
    match error {
        Error::PermissionDenied(_) => {
            // Log security event (without sensitive details)
            log::warn!("Permission denied for operation");

            // Return generic error to client
            HttpResponse::Forbidden().json(json!({
                "error": "Access denied",
                "code": "PERMISSION_DENIED"
            }))
        },
        Error::ValidationError { field, reason, .. } => {
            // Log validation failure
            log::warn!("Validation failed for field '{}': {}", field, reason);

            // Return validation error (safe to expose)
            HttpResponse::BadRequest().json(json!({
                "error": "Invalid input",
                "field": field,
                "code": "VALIDATION_ERROR"
            }))
        },
        _ => {
            // Log internal error
            log::error!("Internal error: {}", error);

            // Return generic error
            HttpResponse::InternalServerError().json(json!({
                "error": "Internal server error",
                "code": "INTERNAL_ERROR"
            }))
        }
    }
}
```

### Error Logging Security

**Do not log sensitive information:**

- User passwords or tokens
- Permission details in public logs
- Full stack traces to external services

**Do log security events:**

- Failed authentication attempts
- Permission denials
- Unusual access patterns
- System errors (in secure logs)

## Session Management

### Token Lifecycle

```rust
use std::time::{SystemTime, UNIX_EPOCH};

struct SecureSession {
    user_id: String,
    roles: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    session_id: String,
}

impl SecureSession {
    fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now < self.expires_at
    }

    fn should_refresh(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Refresh if more than half the session time has passed
        let session_duration = self.expires_at - self.issued_at;
        now > self.issued_at + (session_duration / 2)
    }
}
```

### Session Security

1. **Short Expiration Times**: Max 1-4 hours for sensitive applications
2. **Automatic Refresh**: Refresh tokens before expiration
3. **Secure Storage**: Store session tokens in HTTP-only cookies
4. **Session Invalidation**: Implement logout and session revocation
5. **Concurrent Session Limits**: Prevent session hijacking

## Security Headers

### Required Headers

```rust
use actix_web::HttpResponse;

fn add_security_headers(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap()
    );
    response.headers_mut().insert(
        "X-Frame-Options",
        "DENY".parse().unwrap()
    );
    response.headers_mut().insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap()
    );
    response.headers_mut().insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap()
    );
    response.headers_mut().insert(
        "Content-Security-Policy",
        "default-src 'self'".parse().unwrap()
    );

    response
}
```

## Audit Logging

### Security Event Logging

```rust
use serde_json::json;
use tracing::{info, warn, error};

fn log_permission_check(
    subject: &Subject,
    permission: &Permission,
    resource: &Resource,
    granted: bool,
    request_id: &str,
) {
    let event = json!({
        "event_type": "permission_check",
        "subject_id": subject.id(),
        "subject_type": subject.subject_type(),
        "permission": permission.to_string(),
        "resource_id": resource.id(),
        "resource_type": resource.resource_type(),
        "granted": granted,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "request_id": request_id,
    });

    if granted {
        info!("Permission granted: {}", event);
    } else {
        warn!("Permission denied: {}", event);
    }
}

fn log_role_assignment(
    subject: &Subject,
    role: &Role,
    granted_by: &str,
    request_id: &str,
) {
    let event = json!({
        "event_type": "role_assignment",
        "subject_id": subject.id(),
        "role_name": role.name(),
        "granted_by": granted_by,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "request_id": request_id,
    });

    info!("Role assigned: {}", event);
}
```

### Audit Requirements

For compliance (SOX, GDPR, HIPAA), ensure you log:

1. **Authentication Events**: Login, logout, failed attempts
2. **Authorization Events**: Permission grants/denials
3. **Administrative Actions**: Role assignments, system changes
4. **Data Access**: Sensitive resource access
5. **System Events**: Errors, security violations

## Best Practices

### 1. Principle of Least Privilege

```rust
// Good: Specific permissions
let read_permission = Permission::new("read", "user_profile");
let edit_permission = Permission::new("edit", "own_profile");

// Bad: Overly broad permissions
let admin_permission = Permission::new("*", "*");
```

### 2. Defense in Depth

```rust
// Layer 1: Authentication
let user = authenticate_jwt(&token)?;

// Layer 2: Rate limiting
rate_limiter.check_rate_limit(&user.id)?;

// Layer 3: Authorization
let authorized = role_system.check_permission(&user.subject, &permission, &resource);

// Layer 4: Resource-level validation
validate_resource_access(&resource, &user)?;
```

### 3. Secure Configuration

```rust
use role_system::RoleSystemBuilder;

let role_system = RoleSystemBuilder::new()
    .with_storage(secure_storage)
    .with_cache_ttl(300) // 5 minutes
    .with_max_role_depth(5) // Prevent deep hierarchies
    .with_audit_logging(true)
    .build()?;
```

### 4. Input Sanitization

```rust
fn sanitize_input(input: &str) -> Result<String, Error> {
    // Remove null bytes
    let clean = input.replace('\0', "");

    // Check length
    if clean.len() > 1000 {
        return Err(Error::ValidationError {
            field: "input".to_string(),
            reason: "Input too long".to_string(),
            invalid_value: Some(clean),
        });
    }

    // Validate UTF-8
    if !clean.is_ascii() {
        return Err(Error::ValidationError {
            field: "input".to_string(),
            reason: "Invalid characters".to_string(),
            invalid_value: Some(clean),
        });
    }

    Ok(clean)
}
```

### 5. Secure Defaults

- Use HTTPS in production
- Enable audit logging
- Set conservative cache TTLs
- Limit role hierarchy depth
- Use strong authentication
- Implement rate limiting
- Validate all inputs
- Log security events

### 6. Regular Security Reviews

- Review role assignments quarterly
- Audit permission grants monthly
- Monitor for unusual access patterns
- Update dependencies regularly
- Conduct penetration testing
- Review security logs daily

## Common Vulnerabilities

### Avoid These Patterns

```rust
// ❌ Never do this - exposes system to path traversal
let resource = Resource::new("../../../etc/passwd", "file");

// ❌ Never do this - accepts any token
fn decode_jwt_insecure(token: &str) -> Claims {
    // This is what the examples do - DO NOT USE
    Claims { sub: "user".to_string(), ..Default::default() }
}

// ❌ Never do this - logs sensitive data
log::info!("User {} failed to access {}", password, secret_resource);

// ❌ Never do this - generic admin permission
let admin_role = Role::new("admin").add_permission(Permission::new("*", "*"));
```

### Secure Alternatives

```rust
// ✅ Use validated resource creation
let resource = Resource::new_checked(sanitized_id, sanitized_type)?;

// ✅ Use proper JWT validation
let claims = decode_jwt_secure(&token, &secret_key)?;

// ✅ Log security events safely
log::warn!("Permission denied for user {} on resource type {}",
    user_id, resource.resource_type());

// ✅ Use specific permissions
let admin_role = Role::new("admin")
    .add_permission(Permission::new("manage", "users"))
    .add_permission(Permission::new("read", "system_logs"));
```

## Support

For security questions or to report vulnerabilities:

- Email: <security@role-system.dev>
- Security Policy: See [SECURITY.md](../SECURITY.md)
- Documentation: [docs/](./README.md)

---

**Remember**: Security is a shared responsibility. This library provides authorization tools, but you must implement authentication, secure communication, and proper deployment practices.
