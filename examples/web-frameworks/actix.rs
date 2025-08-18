use actix_web::{web, App, HttpResponse, HttpServer};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};

// State wrapper containing role system
struct AppState {
    role_system: RoleSystem,
}

async fn check_access(
    state: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (user_id, resource_id) = path.into_inner();
    
    let subject = Subject::new(&user_id);
    let resource = Resource::new(&resource_id, "documents");
    
    match state.role_system.check_permission(&subject, "read", &resource) {
        Ok(true) => HttpResponse::Ok().body("Access granted"),
        Ok(false) => HttpResponse::Forbidden().body("Access denied"),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize role system
    let mut role_system = RoleSystem::new();
    
    // Set up roles and permissions
    let reader = Role::new("reader")
        .add_permission(Permission::new("read", "documents"));
        
    role_system.register_role(reader).unwrap();
    
    // Create app state
    let state = web::Data::new(AppState { role_system });
    
    // Start server
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/access/{user_id}/{resource_id}", web::get().to(check_access))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
