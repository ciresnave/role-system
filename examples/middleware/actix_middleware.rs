//! # Actix Web Middleware for Role System
//! 
//! This example demonstrates how to create reusable middleware for Actix Web
//! that automatically handles role-based authorization.
//! 
//! ## Features
//! - Automatic permission checking
//! - Custom error responses
//! - JWT token extraction
//! - Role-based route protection
//! - Context-aware permissions

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, App, HttpMessage, HttpResponse, HttpServer, Result, 
    middleware::Logger,
    http::header::AUTHORIZATION,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    rc::Rc,
    sync::Arc,
};

// =============================================================================
// App State and Configuration
// =============================================================================

#[derive(Clone)]
pub struct AppState {
    pub role_system: Arc<RoleSystem>,
}

#[derive(Debug, Clone)]
pub struct RoleConfig {
    pub action: String,
    pub resource_type: String,
    pub required_roles: Vec<String>,
    pub allow_elevated: bool,
}

impl RoleConfig {
    pub fn new(action: &str, resource_type: &str) -> Self {
        Self {
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            required_roles: vec![],
            allow_elevated: true,
        }
    }

    pub fn require_role(mut self, role: &str) -> Self {
        self.required_roles.push(role.to_string());
        self
    }

    pub fn require_roles(mut self, roles: &[&str]) -> Self {
        self.required_roles.extend(roles.iter().map(|r| r.to_string()));
        self
    }

    pub fn no_elevation(mut self) -> Self {
        self.allow_elevated = false;
        self
    }
}

// =============================================================================
// JWT Claims (simplified for demo)
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user ID
    roles: Vec<String>,
    exp: usize,
}

// Mock JWT decoder (in real app, use jsonwebtoken crate)
fn decode_jwt(token: &str) -> Result<Claims> {
    // This is a mock implementation
    // In production, use the `jsonwebtoken` crate
    if token.starts_with("Bearer user1") {
        Ok(Claims {
            sub: "user1".to_string(),
            roles: vec!["admin".to_string()],
            exp: 9999999999,
        })
    } else if token.starts_with("Bearer user2") {
        Ok(Claims {
            sub: "user2".to_string(),
            roles: vec!["editor".to_string()],
            exp: 9999999999,
        })
    } else {
        Ok(Claims {
            sub: "guest".to_string(),
            roles: vec!["guest".to_string()],
            exp: 9999999999,
        })
    }
}

// =============================================================================
// Role-Based Authorization Middleware
// =============================================================================

pub struct RoleAuth {
    config: RoleConfig,
}

impl RoleAuth {
    pub fn new(config: RoleConfig) -> Self {
        Self { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RoleAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = RoleAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RoleAuthMiddleware {
            service: Rc::new(service),
            config: self.config.clone(),
        }))
    }
}

pub struct RoleAuthMiddleware<S> {
    service: Rc<S>,
    config: RoleConfig,
}

impl<S, B> Service<ServiceRequest> for RoleAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = Rc::clone(&self.service);
        let config = self.config.clone();

        Box::pin(async move {
            // Extract authorization header
            let auth_header = req.headers().get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");

            // Decode JWT to get user info
            let claims = match decode_jwt(auth_header) {
                Ok(claims) => claims,
                Err(_) => {
                    return Ok(req.into_response(
                        HttpResponse::Unauthorized()
                            .json(serde_json::json!({
                                "error": "Invalid or missing token"
                            }))
                    ));
                }
            };

            // Get role system from app data
            let role_system = match req.app_data::<web::Data<AppState>>() {
                Some(state) => state.role_system.clone(),
                None => {
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError()
                            .json(serde_json::json!({
                                "error": "Role system not configured"
                            }))
                    ));
                }
            };

            // Create subject and resource
            let subject = Subject::user(&claims.sub);
            let resource = Resource::new("api", &config.resource_type);

            // Build context from request
            let mut context = HashMap::new();
            context.insert("method".to_string(), req.method().to_string());
            context.insert("path".to_string(), req.path().to_string());
            
            // Add query parameters to context
            for (key, value) in req.query_string().split('&').filter_map(|s| {
                let parts: Vec<&str> = s.split('=').collect();
                if parts.len() == 2 {
                    Some((parts[0].to_string(), parts[1].to_string()))
                } else {
                    None
                }
            }) {
                context.insert(format!("query_{}", key), value);
            }

            // Check permission with context
            let has_permission = match role_system.check_permission_with_context(
                &subject, 
                &config.action, 
                &resource, 
                &context
            ) {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Permission check failed: {}", e);
                    return Ok(req.into_response(
                        HttpResponse::InternalServerError()
                            .json(serde_json::json!({
                                "error": "Permission check failed"
                            }))
                    ));
                }
            };

            if !has_permission {
                return Ok(req.into_response(
                    HttpResponse::Forbidden()
                        .json(serde_json::json!({
                            "error": "Insufficient permissions",
                            "required_action": config.action,
                            "required_resource": config.resource_type,
                            "user_roles": claims.roles
                        }))
                ));
            }

            // Store user info in request extensions for handlers to use
            req.extensions_mut().insert(claims);

            // Continue to the actual handler
            srv.call(req).await
        })
    }
}

// =============================================================================
// Convenience Macros and Functions
// =============================================================================

/// Create a role-based auth middleware with simple configuration
pub fn require_permission(action: &str, resource_type: &str) -> RoleAuth {
    RoleAuth::new(RoleConfig::new(action, resource_type))
}

/// Create auth middleware that requires specific roles
pub fn require_roles(action: &str, resource_type: &str, roles: &[&str]) -> RoleAuth {
    RoleAuth::new(
        RoleConfig::new(action, resource_type)
            .require_roles(roles)
    )
}

/// Admin-only middleware
pub fn admin_only() -> RoleAuth {
    require_roles("admin", "*", &["admin", "super_admin"])
}

/// Read-only access middleware
pub fn read_only(resource_type: &str) -> RoleAuth {
    require_permission("read", resource_type)
}

/// Write access middleware
pub fn write_access(resource_type: &str) -> RoleAuth {
    require_permission("write", resource_type)
}

// =============================================================================
// Handler Examples
// =============================================================================

async fn public_endpoint() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a public endpoint"
    }))
}

async fn protected_endpoint(req: actix_web::HttpRequest) -> HttpResponse {
    // Get user info from middleware
    let claims = req.extensions().get::<Claims>().unwrap();
    
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Access granted",
        "user": claims.sub,
        "roles": claims.roles
    }))
}

async fn admin_endpoint(req: actix_web::HttpRequest) -> HttpResponse {
    let claims = req.extensions().get::<Claims>().unwrap();
    
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Admin access granted",
        "user": claims.sub,
        "admin_data": "sensitive information"
    }))
}

async fn document_endpoint(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = req.extensions().get::<Claims>().unwrap();
    let doc_id = path.into_inner();
    
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Document access granted",
        "user": claims.sub,
        "document_id": doc_id
    }))
}

// =============================================================================
// Application Setup
// =============================================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Initialize role system
    let mut role_system = RoleSystem::new();

    // Setup roles and permissions
    setup_roles(&mut role_system).unwrap();

    // Create app state
    let app_state = web::Data::new(AppState {
        role_system: Arc::new(role_system),
    });

    println!("🚀 Server starting on http://127.0.0.1:8080");
    println!("📋 Try these endpoints:");
    println!("   GET /public - Public endpoint (no auth required)");
    println!("   GET /protected - Protected endpoint (any valid token)");
    println!("   GET /admin - Admin-only endpoint (Bearer user1)");
    println!("   GET /documents/123 - Document access (Bearer user1 or user2)");
    println!();
    println!("🔑 Test tokens:");
    println!("   Bearer user1 - Admin user");
    println!("   Bearer user2 - Editor user");
    println!("   Bearer guest - Guest user");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(Logger::default())
            // Public routes (no middleware)
            .route("/public", web::get().to(public_endpoint))
            
            // Protected routes with different permission requirements
            .service(
                web::scope("/protected")
                    .wrap(require_permission("access", "api"))
                    .route("", web::get().to(protected_endpoint))
            )
            .service(
                web::scope("/admin")
                    .wrap(admin_only())
                    .route("", web::get().to(admin_endpoint))
            )
            .service(
                web::scope("/documents")
                    .wrap(require_permission("read", "documents"))
                    .route("/{id}", web::get().to(document_endpoint))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

fn setup_roles(role_system: &mut RoleSystem) -> Result<(), Box<dyn std::error::Error>> {
    // Create permissions
    let read_docs = Permission::new("read", "documents");
    let write_docs = Permission::new("write", "documents");
    let admin_perm = Permission::new("admin", "*");
    let api_access = Permission::new("access", "api");

    // Create roles
    let guest = Role::new("guest")
        .add_permission(api_access.clone());

    let editor = Role::new("editor")
        .add_permission(api_access.clone())
        .add_permission(read_docs.clone())
        .add_permission(write_docs.clone());

    let admin = Role::new("admin")
        .add_permission(api_access.clone())
        .add_permission(admin_perm.clone());

    let super_admin = Role::new("super_admin")
        .add_permission(Permission::super_admin());

    // Register roles
    role_system.register_role(guest)?;
    role_system.register_role(editor)?;
    role_system.register_role(admin)?;
    role_system.register_role(super_admin)?;

    // Setup role hierarchy
    role_system.add_role_inheritance("editor", "guest")?;
    role_system.add_role_inheritance("admin", "editor")?;
    role_system.add_role_inheritance("super_admin", "admin")?;

    // Assign roles to users (in real app, this would be done via admin interface)
    let user1 = Subject::user("user1");
    let user2 = Subject::user("user2");
    let guest_user = Subject::user("guest");

    role_system.assign_role(&user1, "admin")?;
    role_system.assign_role(&user2, "editor")?;
    role_system.assign_role(&guest_user, "guest")?;

    Ok(())
}
