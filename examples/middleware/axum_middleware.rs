//! # Axum Middleware for Role System
//!
//! This example demonstrates how to create reusable middleware and extractors
//! for Axum that automatically handle role-based authorization.
//!
//! ## Features
//! - Custom extractors for authenticated users
//! - Layer-based middleware
//! - Type-safe permission checking
//! - JWT token extraction
//! - Route-specific authorization

use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use role_system::{Permission, Resource, Role, RoleSystem, Subject};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

// =============================================================================
// App State and Configuration
// =============================================================================

#[derive(Clone)]
pub struct AppState {
    pub role_system: Arc<RoleSystem>,
}

// =============================================================================
// User Authentication Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
}

// =============================================================================
// Custom Extractors
// =============================================================================

/// Extractor that provides an authenticated user
/// This will automatically check if the user is authenticated
/// and return a 401 if not
#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Decode JWT (simplified)
        let claims = decode_jwt(auth_header).map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthenticatedUser {
            user_id: claims.sub,
            roles: claims.roles,
            permissions: vec![], // Could be populated from roles
        })
    }
}

/// Extractor that requires specific permissions
pub struct RequirePermission<const ACTION: &'static str, const RESOURCE: &'static str> {
    pub user: AuthenticatedUser,
}

#[axum::async_trait]
impl<S, const ACTION: &'static str, const RESOURCE: &'static str> FromRequestParts<S>
    for RequirePermission<ACTION, RESOURCE>
where
    S: Send + Sync,
    AppState: FromRequestParts<S, Rejection = std::convert::Infallible>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // First get the authenticated user
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        // Get the app state to access role system
        let Ok(app_state) = AppState::from_request_parts(parts, state).await else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        // Check permission
        let subject = Subject::user(&user.user_id);
        let resource = Resource::new("api", RESOURCE);

        let has_permission = app_state
            .role_system
            .check_permission(&subject, ACTION, &resource)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if !has_permission {
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(RequirePermission { user })
    }
}

/// Type alias for common permission extractors
pub type RequireRead<const RESOURCE: &'static str> = RequirePermission<"read", RESOURCE>;
pub type RequireWrite<const RESOURCE: &'static str> = RequirePermission<"write", RESOURCE>;
pub type RequireAdmin = RequirePermission<"admin", "*">;

// =============================================================================
// Middleware Functions
// =============================================================================

/// Middleware that adds CORS headers and request logging
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Log the request
    let method = request.method().clone();
    let uri = request.uri().clone();

    println!("🔍 {} {}", method, uri);

    // Check if this is a protected route
    let path = request.uri().path();
    if path.starts_with("/api/protected") || path.starts_with("/api/admin") {
        // Extract and validate token
        let auth_header = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let _claims = decode_jwt(auth_header).map_err(|_| StatusCode::UNAUTHORIZED)?;
    }

    // Continue to next middleware/handler
    let response = next.run(request).await;
    Ok(response)
}

/// Role-based authorization middleware
pub async fn require_role_middleware(
    required_role: &str,
) -> impl Fn(
    State<AppState>,
    AuthenticatedUser,
    axum::extract::Request,
    Next,
)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>
+ Clone {
    let required_role = required_role.to_string();

    move |State(state): State<AppState>,
          user: AuthenticatedUser,
          request: axum::extract::Request,
          next: Next| {
        let required_role = required_role.clone();
        Box::pin(async move {
            // Check if user has required role
            let subject = Subject::user(&user.user_id);
            let user_roles = state
                .role_system
                .get_subject_roles(&subject)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            if !user_roles.contains(&required_role) {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok(next.run(request).await)
        })
    }
}

// =============================================================================
// Handler Functions
// =============================================================================

/// Public endpoint - no authentication required
async fn public_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "This is a public endpoint",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Protected endpoint - requires authentication
async fn protected_handler(user: AuthenticatedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Access granted to protected endpoint",
        "user": {
            "id": user.user_id,
            "roles": user.roles
        }
    }))
}

/// Admin-only endpoint using extractor
async fn admin_handler(admin: RequireAdmin) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Admin access granted",
        "user": admin.user.user_id,
        "admin_data": {
            "server_stats": "sensitive information",
            "user_count": 1337
        }
    }))
}

/// Document handler with read permission
async fn read_document_handler(
    reader: RequireRead<"documents">,
    Path(doc_id): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Document access granted",
        "user": reader.user.user_id,
        "document": {
            "id": doc_id,
            "title": "Sample Document",
            "content": "This is a sample document..."
        }
    }))
}

/// Document creation handler with write permission
async fn create_document_handler(
    writer: RequireWrite<"documents">,
    Json(payload): Json<CreateDocumentRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Json(serde_json::json!({
        "message": "Document created successfully",
        "created_by": writer.user.user_id,
        "document": {
            "id": uuid::Uuid::new_v4(),
            "title": payload.title,
            "content": payload.content
        }
    }))
    .into()
}

/// Custom permission check in handler
async fn custom_permission_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let resource_type = params.get("resource").ok_or(StatusCode::BAD_REQUEST)?;

    let action = params.get("action").ok_or(StatusCode::BAD_REQUEST)?;

    // Custom permission check with context
    let subject = Subject::user(&user.user_id);
    let resource = Resource::new("dynamic", resource_type);

    let mut context = HashMap::new();
    context.insert("request_origin".to_string(), "api".to_string());
    context.insert("user_agent".to_string(), "axum-client".to_string());

    let has_permission = state
        .role_system
        .check_permission_with_context(&subject, action, &resource, &context)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !has_permission {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(serde_json::json!({
        "message": "Custom permission check passed",
        "user": user.user_id,
        "action": action,
        "resource": resource_type
    })))
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
}

// =============================================================================
// Error Handling
// =============================================================================

/// Custom error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    status: u16,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Json(self).into_response().with_status(status)
    }
}

// =============================================================================
// JWT Helper (Mock Implementation)
// =============================================================================

// ⚠️ SECURITY WARNING: Mock JWT decoder - DO NOT USE IN PRODUCTION! ⚠️
// This is a demonstration-only implementation that accepts hardcoded tokens.
// In production applications, you MUST use proper JWT validation with:
// - The `jsonwebtoken` crate or similar secure library
// - Proper cryptographic signature verification
// - Token expiration checking
// - Issuer and audience validation
// - Secure secret key management
// Using this mock implementation in production exposes your application to
// serious security vulnerabilities including authentication bypass.
fn decode_jwt(token: &str) -> Result<Claims, Box<dyn std::error::Error>> {
    // Mock JWT decoder - in production use `jsonwebtoken` crate
    match token {
        "Bearer admin-token" => Ok(Claims {
            sub: "admin-user".to_string(),
            roles: vec!["admin".to_string(), "super_admin".to_string()],
            exp: 9999999999,
        }),
        "Bearer editor-token" => Ok(Claims {
            sub: "editor-user".to_string(),
            roles: vec!["editor".to_string()],
            exp: 9999999999,
        }),
        "Bearer user-token" => Ok(Claims {
            sub: "regular-user".to_string(),
            roles: vec!["user".to_string()],
            exp: 9999999999,
        }),
        _ => Err("Invalid token".into()),
    }
}

// =============================================================================
// Application Setup
// =============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::init();

    // Setup role system
    let role_system = setup_role_system()
        .await
        .expect("Failed to setup role system");

    // Create app state
    let state = AppState {
        role_system: Arc::new(role_system),
    };

    // Build the application
    let app = Router::new()
        // Public routes
        .route("/", get(public_handler))
        .route("/public", get(public_handler))
        // API routes with different protection levels
        .route("/api/protected", get(protected_handler))
        .route("/api/admin", get(admin_handler))
        .route("/api/documents/:id", get(read_document_handler))
        .route("/api/documents", post(create_document_handler))
        .route("/api/custom-check", get(custom_permission_handler))
        // Add middleware stack
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth_middleware,
                )),
        )
        .with_state(state);

    println!("🚀 Axum server starting on http://127.0.0.1:3000");
    println!("📋 Available endpoints:");
    println!("   GET  /               - Public endpoint");
    println!("   GET  /public         - Public endpoint");
    println!("   GET  /api/protected  - Protected endpoint (any valid token)");
    println!("   GET  /api/admin      - Admin-only endpoint");
    println!("   GET  /api/documents/123 - Read document (requires read permission)");
    println!("   POST /api/documents  - Create document (requires write permission)");
    println!("   GET  /api/custom-check?action=read&resource=files - Custom permission check");
    println!();
    println!("🔑 Test tokens:");
    println!("   Authorization: Bearer admin-token   - Admin user");
    println!("   Authorization: Bearer editor-token  - Editor user");
    println!("   Authorization: Bearer user-token    - Regular user");

    // Start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn setup_role_system() -> Result<RoleSystem, Box<dyn std::error::Error>> {
    let mut role_system = RoleSystem::new();

    // Create permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    let admin_perm = Permission::new("admin", "*");

    // Create roles
    let user = Role::new("user").add_permission(Permission::new("access", "api"));

    let editor = Role::new("editor")
        .add_permission(Permission::new("access", "api"))
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());

    let admin = Role::new("admin")
        .add_permission(Permission::new("access", "api"))
        .add_permission(admin_perm.clone());

    let super_admin = Role::new("super_admin").add_permission(Permission::super_admin());

    // Register roles
    role_system.register_role(user)?;
    role_system.register_role(editor)?;
    role_system.register_role(admin)?;
    role_system.register_role(super_admin)?;

    // Setup hierarchy
    role_system.add_role_inheritance("editor", "user")?;
    role_system.add_role_inheritance("admin", "editor")?;
    role_system.add_role_inheritance("super_admin", "admin")?;

    // Assign roles to mock users
    let admin_user = Subject::user("admin-user");
    let editor_user = Subject::user("editor-user");
    let regular_user = Subject::user("regular-user");

    role_system.assign_role(&admin_user, "admin")?;
    role_system.assign_role(&editor_user, "editor")?;
    role_system.assign_role(&regular_user, "user")?;

    Ok(role_system)
}
