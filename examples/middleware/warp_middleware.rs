//! # Warp Middleware for Role System
//! 
//! This example demonstrates how to create reusable filters and middleware
//! for Warp that automatically handle role-based authorization.
//! 
//! ## Features
//! - Filter-based authorization
//! - JWT token extraction
//! - Composable permission filters
//! - Type-safe request handling
//! - Automatic error responses

use warp::{Filter, Rejection, Reply, hyper::StatusCode};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::Arc,
};

// =============================================================================
// App State and Types
// =============================================================================

#[derive(Clone)]
pub struct AppState {
    pub role_system: Arc<RoleSystem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
}

// =============================================================================
// Custom Rejections
// =============================================================================

#[derive(Debug)]
struct AuthError {
    kind: AuthErrorKind,
}

#[derive(Debug)]
enum AuthErrorKind {
    MissingToken,
    InvalidToken,
    InsufficientPermissions,
    SystemError,
}

impl warp::reject::Reject for AuthError {}

// =============================================================================
// Authentication Filters
// =============================================================================

/// Extract JWT token from Authorization header
fn with_auth() -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .and_then(|auth_header: Option<String>| async move {
            match auth_header {
                Some(header) => {
                    match decode_jwt(&header) {
                        Ok(claims) => Ok(AuthenticatedUser {
                            user_id: claims.sub,
                            roles: claims.roles,
                        }),
                        Err(_) => Err(warp::reject::custom(AuthError {
                            kind: AuthErrorKind::InvalidToken,
                        })),
                    }
                }
                None => Err(warp::reject::custom(AuthError {
                    kind: AuthErrorKind::MissingToken,
                })),
            }
        })
}

/// Filter that requires specific permission
fn with_permission(
    action: &'static str,
    resource_type: &'static str,
) -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    with_auth()
        .and(with_role_system())
        .and_then(move |user: AuthenticatedUser, role_system: Arc<RoleSystem>| async move {
            let subject = Subject::user(&user.user_id);
            let resource = Resource::new("api", resource_type);

            match role_system.check_permission(&subject, action, &resource) {
                Ok(true) => Ok(user),
                Ok(false) => Err(warp::reject::custom(AuthError {
                    kind: AuthErrorKind::InsufficientPermissions,
                })),
                Err(_) => Err(warp::reject::custom(AuthError {
                    kind: AuthErrorKind::SystemError,
                })),
            }
        })
}

/// Filter that provides role system from app state
fn with_role_system() -> impl Filter<Extract = (Arc<RoleSystem>,), Error = Infallible> + Clone {
    warp::any().map(|| {
        // In a real app, you'd inject this from somewhere
        // For demo purposes, we'll create it here
        setup_role_system().expect("Failed to setup role system")
    })
}

/// Admin-only filter
fn admin_only() -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    with_permission("admin", "*")
}

/// Read permission filter
fn can_read(resource_type: &'static str) -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    with_permission("read", resource_type)
}

/// Write permission filter
fn can_write(resource_type: &'static str) -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    with_permission("write", resource_type)
}

/// Custom permission filter with context
fn with_custom_permission() -> impl Filter<Extract = (AuthenticatedUser,), Error = Rejection> + Clone {
    with_auth()
        .and(with_role_system())
        .and(warp::query::<HashMap<String, String>>())
        .and_then(|user: AuthenticatedUser, role_system: Arc<RoleSystem>, params: HashMap<String, String>| async move {
            let action = params.get("action").ok_or_else(|| warp::reject::custom(AuthError {
                kind: AuthErrorKind::SystemError,
            }))?;
            
            let resource_type = params.get("resource").ok_or_else(|| warp::reject::custom(AuthError {
                kind: AuthErrorKind::SystemError,
            }))?;

            let subject = Subject::user(&user.user_id);
            let resource = Resource::new("dynamic", resource_type);
            
            let mut context = HashMap::new();
            context.insert("request_origin".to_string(), "warp-api".to_string());
            context.insert("timestamp".to_string(), chrono::Utc::now().timestamp().to_string());

            match role_system.check_permission_with_context(&subject, action, &resource, &context) {
                Ok(true) => Ok(user),
                Ok(false) => Err(warp::reject::custom(AuthError {
                    kind: AuthErrorKind::InsufficientPermissions,
                })),
                Err(_) => Err(warp::reject::custom(AuthError {
                    kind: AuthErrorKind::SystemError,
                })),
            }
        })
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// =============================================================================
// Handler Functions
// =============================================================================

async fn public_handler() -> Result<impl Reply, Infallible> {
    let response = ApiResponse::success(serde_json::json!({
        "message": "This is a public endpoint",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));
    
    Ok(warp::reply::json(&response))
}

async fn protected_handler(user: AuthenticatedUser) -> Result<impl Reply, Infallible> {
    let response = ApiResponse::success(serde_json::json!({
        "message": "Access granted to protected endpoint",
        "user": {
            "id": user.user_id,
            "roles": user.roles
        }
    }));
    
    Ok(warp::reply::json(&response))
}

async fn admin_handler(admin: AuthenticatedUser) -> Result<impl Reply, Infallible> {
    let response = ApiResponse::success(serde_json::json!({
        "message": "Admin access granted",
        "user": admin.user_id,
        "admin_data": {
            "server_stats": "sensitive information",
            "user_count": 1337
        }
    }));
    
    Ok(warp::reply::json(&response))
}

async fn read_document_handler(
    doc_id: String,
    reader: AuthenticatedUser,
) -> Result<impl Reply, Infallible> {
    let response = ApiResponse::success(serde_json::json!({
        "message": "Document access granted",
        "user": reader.user_id,
        "document": {
            "id": doc_id,
            "title": "Sample Document",
            "content": "This is a sample document..."
        }
    }));
    
    Ok(warp::reply::json(&response))
}

async fn create_document_handler(
    doc_request: CreateDocumentRequest,
    writer: AuthenticatedUser,
) -> Result<impl Reply, Infallible> {
    let response = ApiResponse::success(serde_json::json!({
        "message": "Document created successfully",
        "created_by": writer.user_id,
        "document": {
            "id": uuid::Uuid::new_v4(),
            "title": doc_request.title,
            "content": doc_request.content
        }
    }));
    
    Ok(warp::reply::json(&response))
}

async fn custom_permission_handler(
    user: AuthenticatedUser,
    params: HashMap<String, String>,
) -> Result<impl Reply, Infallible> {
    let action = params.get("action").unwrap_or(&"unknown".to_string());
    let resource = params.get("resource").unwrap_or(&"unknown".to_string());

    let response = ApiResponse::success(serde_json::json!({
        "message": "Custom permission check passed",
        "user": user.user_id,
        "action": action,
        "resource": resource
    }));
    
    Ok(warp::reply::json(&response))
}

// =============================================================================
// Error Handling
// =============================================================================

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(auth_error) = err.find::<AuthError>() {
        match auth_error.kind {
            AuthErrorKind::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Missing authorization token".to_string(),
            ),
            AuthErrorKind::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization token".to_string(),
            ),
            AuthErrorKind::InsufficientPermissions => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
            ),
            AuthErrorKind::SystemError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed".to_string())
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string())
    };

    let response = ApiResponse::<()>::error(message);
    Ok(warp::reply::with_status(warp::reply::json(&response), code))
}

// =============================================================================
// JWT Helper (Mock Implementation)
// =============================================================================

fn decode_jwt(token: &str) -> Result<Claims, Box<dyn std::error::Error>> {
    // Mock JWT decoder - in production use `jsonwebtoken` crate
    match token {
        "Bearer warp-admin" => Ok(Claims {
            sub: "warp-admin-user".to_string(),
            roles: vec!["admin".to_string(), "super_admin".to_string()],
            exp: 9999999999,
        }),
        "Bearer warp-editor" => Ok(Claims {
            sub: "warp-editor-user".to_string(),
            roles: vec!["editor".to_string()],
            exp: 9999999999,
        }),
        "Bearer warp-user" => Ok(Claims {
            sub: "warp-regular-user".to_string(),
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
    // Enable logging
    pretty_env_logger::init();

    println!("🚀 Warp server starting on http://127.0.0.1:3030");
    println!("📋 Available endpoints:");
    println!("   GET  /               - Welcome page");
    println!("   GET  /public         - Public endpoint");
    println!("   GET  /api/protected  - Protected endpoint (any valid token)");
    println!("   GET  /api/admin      - Admin-only endpoint");
    println!("   GET  /api/documents/123 - Read document (requires read permission)");
    println!("   POST /api/documents  - Create document (requires write permission)");
    println!("   GET  /api/custom-check?action=read&resource=files - Custom permission check");
    println!();
    println!("🔑 Test tokens:");
    println!("   Authorization: Bearer warp-admin   - Admin user");
    println!("   Authorization: Bearer warp-editor  - Editor user");
    println!("   Authorization: Bearer warp-user    - Regular user");

    // Build routes
    let welcome = warp::get()
        .and(warp::path::end())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "message": "Welcome to Warp Role System Example",
                "endpoints": {
                    "public": "/public",
                    "protected": "/api/protected",
                    "admin": "/api/admin",
                    "documents": "/api/documents"
                }
            }))
        });

    let public = warp::get()
        .and(warp::path("public"))
        .and_then(public_handler);

    let protected = warp::get()
        .and(warp::path("api"))
        .and(warp::path("protected"))
        .and(with_auth())
        .and_then(protected_handler);

    let admin = warp::get()
        .and(warp::path("api"))
        .and(warp::path("admin"))
        .and(admin_only())
        .and_then(admin_handler);

    let read_document = warp::get()
        .and(warp::path("api"))
        .and(warp::path("documents"))
        .and(warp::path::param::<String>())
        .and(can_read("documents"))
        .and_then(read_document_handler);

    let create_document = warp::post()
        .and(warp::path("api"))
        .and(warp::path("documents"))
        .and(warp::body::json())
        .and(can_write("documents"))
        .and_then(create_document_handler);

    let custom_check = warp::get()
        .and(warp::path("api"))
        .and(warp::path("custom-check"))
        .and(with_custom_permission())
        .and(warp::query::<HashMap<String, String>>())
        .and_then(custom_permission_handler);

    let routes = welcome
        .or(public)
        .or(protected)
        .or(admin)
        .or(read_document)
        .or(create_document)
        .or(custom_check)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["authorization", "content-type"]))
        .recover(handle_rejection);

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

fn setup_role_system() -> Result<Arc<RoleSystem>, Box<dyn std::error::Error>> {
    let mut role_system = RoleSystem::new();

    // Create permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    let admin_perm = Permission::new("admin", "*");

    // Create roles
    let user = Role::new("user")
        .add_permission(Permission::new("access", "api"));

    let editor = Role::new("editor")
        .add_permission(Permission::new("access", "api"))
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());

    let admin = Role::new("admin")
        .add_permission(Permission::new("access", "api"))
        .add_permission(admin_perm.clone());

    let super_admin = Role::new("super_admin")
        .add_permission(Permission::super_admin());

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
    let admin_user = Subject::user("warp-admin-user");
    let editor_user = Subject::user("warp-editor-user");
    let regular_user = Subject::user("warp-regular-user");

    role_system.assign_role(&admin_user, "admin")?;
    role_system.assign_role(&editor_user, "editor")?;
    role_system.assign_role(&regular_user, "user")?;

    Ok(Arc::new(role_system))
}
