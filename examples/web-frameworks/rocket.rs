use rocket::{State, get, routes};
use role_system::{RoleSystem, Role, Permission, Subject, Resource};
use std::sync::RwLock;

// State wrapper containing role system
struct AppState {
    role_system: RwLock<RoleSystem>,
}

#[get("/access/<user_id>/<resource_id>")]
fn check_access(
    state: &State<AppState>,
    user_id: String,
    resource_id: String,
) -> rocket::http::Status {
    let subject = Subject::new(&user_id);
    let resource = Resource::new(&resource_id, "documents");
    
    match state.role_system.read().unwrap().check_permission(&subject, "read", &resource) {
        Ok(true) => rocket::http::Status::Ok,
        Ok(false) => rocket::http::Status::Forbidden,
        Err(_) => rocket::http::Status::InternalServerError,
    }
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    // Initialize role system
    let mut role_system = RoleSystem::new();
    
    // Set up roles and permissions
    let reader = Role::new("reader")
        .add_permission(Permission::new("read", "documents"));
        
    role_system.register_role(reader).unwrap();
    
    // Create app state
    let state = AppState {
        role_system: RwLock::new(role_system),
    };
    
    // Launch server
    rocket::build()
        .mount("/", routes![check_access])
        .manage(state)
        .launch()
        .await
}
