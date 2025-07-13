//! # Rocket Middleware for Role System
//! 
//! This example demonstrates how to create reusable guards and fairings
//! for Rocket that automatically handle role-based authorization.
//! 
//! ## Features
//! - Custom request guards for authentication
//! - Role-based route protection
//! - JWT token extraction
//! - Type-safe permission checking
//! - Automatic error responses

use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{Header, Status},
    request::{FromRequest, Outcome, Request},
    response::{self, Responder, Response},
    routes, get, post, launch,
    serde::{Deserialize, Serialize, json::Json},
    State, Build, Rocket,
};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::{
    collections::HashMap,
    sync::Arc,
    io::Cursor,
};

// =============================================================================
// App State
// =============================================================================

pub type AppRoleSystem = Arc<RoleSystem>;

// =============================================================================
// Authentication Types
// =============================================================================

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
// Request Guards
// =============================================================================

/// Basic authentication guard that extracts user from JWT
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Extract authorization header
        let auth_header = match request.headers().get_one("authorization") {
            Some(header) => header,
            None => return Outcome::Failure((Status::Unauthorized, AuthError::MissingToken)),
        };

        // Decode JWT
        let claims = match decode_jwt(auth_header) {
            Ok(claims) => claims,
            Err(_) => return Outcome::Failure((Status::Unauthorized, AuthError::InvalidToken)),
        };

        Outcome::Success(AuthenticatedUser {
            user_id: claims.sub,
            roles: claims.roles,
        })
    }
}

/// Guard that requires specific permission
pub struct RequirePermission {
    pub user: AuthenticatedUser,
    pub action: String,
    pub resource_type: String,
}

impl RequirePermission {
    pub fn new(action: &str, resource_type: &str) -> RequirePermissionBuilder {
        RequirePermissionBuilder {
            action: action.to_string(),
            resource_type: resource_type.to_string(),
        }
    }
}

pub struct RequirePermissionBuilder {
    action: String,
    resource_type: String,
}

impl RequirePermissionBuilder {
    pub async fn from_request<'r>(
        self,
        request: &'r Request<'_>,
    ) -> Outcome<RequirePermission, AuthError> {
        // First get authenticated user
        let user = match AuthenticatedUser::from_request(request).await {
            Outcome::Success(user) => user,
            Outcome::Failure(f) => return Outcome::Failure(f),
            Outcome::Forward(f) => return Outcome::Forward(f),
        };

        // Get role system from state
        let role_system = match request.guard::<&State<AppRoleSystem>>().await {
            Outcome::Success(rs) => rs,
            Outcome::Failure(_) => {
                return Outcome::Failure((Status::InternalServerError, AuthError::SystemError))
            }
            Outcome::Forward(f) => return Outcome::Forward(f),
        };

        // Check permission
        let subject = Subject::user(&user.user_id);
        let resource = Resource::new("api", &self.resource_type);

        let has_permission = match role_system.check_permission(&subject, &self.action, &resource) {
            Ok(result) => result,
            Err(_) => {
                return Outcome::Failure((Status::InternalServerError, AuthError::SystemError))
            }
        };

        if !has_permission {
            return Outcome::Failure((Status::Forbidden, AuthError::InsufficientPermissions));
        }

        Outcome::Success(RequirePermission {
            user,
            action: self.action,
            resource_type: self.resource_type,
        })
    }
}

/// Convenience guards for common permissions
pub struct AdminUser(pub AuthenticatedUser);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminUser {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match RequirePermission::new("admin", "*").from_request(request).await {
            Outcome::Success(req_perm) => Outcome::Success(AdminUser(req_perm.user)),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Forward(f) => Outcome::Forward(f),
        }
    }
}

pub struct DocumentReader(pub AuthenticatedUser);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DocumentReader {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match RequirePermission::new("read", "documents").from_request(request).await {
            Outcome::Success(req_perm) => Outcome::Success(DocumentReader(req_perm.user)),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Forward(f) => Outcome::Forward(f),
        }
    }
}

pub struct DocumentWriter(pub AuthenticatedUser);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DocumentWriter {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match RequirePermission::new("write", "documents").from_request(request).await {
            Outcome::Success(req_perm) => Outcome::Success(DocumentWriter(req_perm.user)),
            Outcome::Failure(f) => Outcome::Failure(f),
            Outcome::Forward(f) => Outcome::Forward(f),
        }
    }
}

// =============================================================================
// Error Handling
// =============================================================================

#[derive(Debug, Serialize)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    InsufficientPermissions,
    SystemError,
}

impl<'r> Responder<'r, 'static> for AuthError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let (status, message) = match self {
            AuthError::MissingToken => (Status::Unauthorized, "Missing authorization token"),
            AuthError::InvalidToken => (Status::Unauthorized, "Invalid authorization token"),
            AuthError::InsufficientPermissions => (Status::Forbidden, "Insufficient permissions"),
            AuthError::SystemError => (Status::InternalServerError, "System error"),
        };

        let error_json = serde_json::json!({
            "error": format!("{:?}", self),
            "message": message
        });

        Response::build()
            .status(status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(error_json.to_string().len(), Cursor::new(error_json.to_string()))
            .ok()
    }
}

// =============================================================================
// Fairings (Middleware)
// =============================================================================

pub struct AuthFairing;

#[rocket::async_trait]
impl Fairing for AuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "Authentication and Authorization",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut rocket::Data<'_>) {
        // Add request ID for tracing
        let request_id = uuid::Uuid::new_v4().to_string();
        request.local_cache(|| request_id);

        // Log the request
        println!("🔍 {} {} - ID: {}", 
                request.method(), 
                request.uri(),
                request.local_cache(|| String::new()));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // Add CORS headers
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type, Authorization"));

        // Log the response
        let request_id = request.local_cache(|| "unknown".to_string());
        println!("📤 Response {} - ID: {}", response.status(), request_id);
    }
}

// =============================================================================
// Route Handlers
// =============================================================================

#[get("/")]
fn index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Welcome to Rocket Role System Example",
        "endpoints": {
            "public": "/public",
            "protected": "/api/protected",
            "admin": "/api/admin",
            "documents": "/api/documents"
        }
    }))
}

#[get("/public")]
fn public() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "This is a public endpoint",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[get("/protected")]
fn protected(user: AuthenticatedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Access granted to protected endpoint",
        "user": {
            "id": user.user_id,
            "roles": user.roles
        }
    }))
}

#[get("/admin")]
fn admin(admin: AdminUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Admin access granted",
        "user": admin.0.user_id,
        "admin_data": {
            "server_stats": "sensitive information",
            "user_count": 1337
        }
    }))
}

#[get("/documents/<id>")]
fn read_document(reader: DocumentReader, id: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Document access granted",
        "user": reader.0.user_id,
        "document": {
            "id": id,
            "title": "Sample Document",
            "content": "This is a sample document..."
        }
    }))
}

#[post("/documents", data = "<doc_request>")]
fn create_document(
    writer: DocumentWriter,
    doc_request: Json<CreateDocumentRequest>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Document created successfully",
        "created_by": writer.0.user_id,
        "document": {
            "id": uuid::Uuid::new_v4(),
            "title": doc_request.title,
            "content": doc_request.content
        }
    }))
}

#[get("/custom-check?<action>&<resource>")]
fn custom_permission_check(
    user: AuthenticatedUser,
    role_system: &State<AppRoleSystem>,
    action: String,
    resource: String,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Custom permission check with context
    let subject = Subject::user(&user.user_id);
    let resource_obj = Resource::new("dynamic", &resource);
    
    let mut context = HashMap::new();
    context.insert("request_origin".to_string(), "rocket-api".to_string());

    let has_permission = role_system
        .check_permission_with_context(&subject, &action, &resource_obj, &context)
        .map_err(|_| AuthError::SystemError)?;

    if !has_permission {
        return Err(AuthError::InsufficientPermissions);
    }

    Ok(Json(serde_json::json!({
        "message": "Custom permission check passed",
        "user": user.user_id,
        "action": action,
        "resource": resource
    })))
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Deserialize)]
struct CreateDocumentRequest {
    title: String,
    content: String,
}

// =============================================================================
// JWT Helper (Mock Implementation)
// =============================================================================

fn decode_jwt(token: &str) -> Result<Claims, Box<dyn std::error::Error>> {
    // Mock JWT decoder - in production use `jsonwebtoken` crate
    match token {
        "Bearer rocket-admin" => Ok(Claims {
            sub: "rocket-admin-user".to_string(),
            roles: vec!["admin".to_string(), "super_admin".to_string()],
            exp: 9999999999,
        }),
        "Bearer rocket-editor" => Ok(Claims {
            sub: "rocket-editor-user".to_string(),
            roles: vec!["editor".to_string()],
            exp: 9999999999,
        }),
        "Bearer rocket-user" => Ok(Claims {
            sub: "rocket-regular-user".to_string(),
            roles: vec!["user".to_string()],
            exp: 9999999999,
        }),
        _ => Err("Invalid token".into()),
    }
}

// =============================================================================
// Application Setup
// =============================================================================

#[launch]
fn rocket() -> Rocket<Build> {
    // Setup role system
    let role_system = setup_role_system().expect("Failed to setup role system");

    println!("🚀 Rocket server starting...");
    println!("📋 Available endpoints:");
    println!("   GET  /               - Welcome page");
    println!("   GET  /public         - Public endpoint");
    println!("   GET  /protected      - Protected endpoint (any valid token)");
    println!("   GET  /admin          - Admin-only endpoint");
    println!("   GET  /documents/123  - Read document (requires read permission)");
    println!("   POST /documents      - Create document (requires write permission)");
    println!("   GET  /custom-check?action=read&resource=files - Custom permission check");
    println!();
    println!("🔑 Test tokens:");
    println!("   Authorization: Bearer rocket-admin   - Admin user");
    println!("   Authorization: Bearer rocket-editor  - Editor user");
    println!("   Authorization: Bearer rocket-user    - Regular user");

    rocket::build()
        .manage(Arc::new(role_system))
        .attach(AuthFairing)
        .mount("/", routes![index, public])
        .mount("/api", routes![
            protected,
            admin,
            read_document,
            create_document,
            custom_permission_check
        ])
}

fn setup_role_system() -> Result<RoleSystem, Box<dyn std::error::Error>> {
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
    let admin_user = Subject::user("rocket-admin-user");
    let editor_user = Subject::user("rocket-editor-user");
    let regular_user = Subject::user("rocket-regular-user");

    role_system.assign_role(&admin_user, "admin")?;
    role_system.assign_role(&editor_user, "editor")?;
    role_system.assign_role(&regular_user, "user")?;

    Ok(role_system)
}
