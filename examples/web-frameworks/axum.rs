use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::sync::Arc;

// State wrapper containing role system
#[derive(Clone)]
struct AppState {
    role_system: Arc<RoleSystem>,
}

async fn check_access(
    State(state): State<AppState>,
    Path((user_id, resource_id)): Path<(String, String)>,
) -> Result<&'static str, StatusCode> {
    let subject = Subject::new(&user_id);
    let resource = Resource::new(&resource_id, "documents");
    
    match state.role_system.check_permission(&subject, "read", &resource) {
        Ok(true) => Ok("Access granted"),
        Ok(false) => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[tokio::main]
async fn main() {
    // Initialize role system
    let mut role_system = RoleSystem::new();
    
    // Set up roles and permissions
    let reader = Role::new("reader")
        .add_permission(Permission::new("read", "documents"));
        
    role_system.register_role(reader).unwrap();
    
    // Create app state
    let state = AppState {
        role_system: Arc::new(role_system),
    };
    
    // Create router
    let app = Router::new()
        .route("/access/:user_id/:resource_id", get(check_access))
        .with_state(state);
    
    // Start server
    axum::Server::bind(&"127.0.0.1:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
