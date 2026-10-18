//! A save/load round trip must not widen or extend privileges.
#![cfg(feature = "persistence")]

use role_system::{
    permission::Permission,
    role::{Role, RoleBuilder, RoleElevation},
};
use std::{collections::HashMap, time::Duration};

fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) -> T {
    serde_json::from_str(&serde_json::to_string(v).unwrap()).unwrap()
}

#[test]
fn conditional_permission_cannot_be_saved() {
    // A condition is a closure and cannot be saved; saving it must fail rather than load back
    // as an unconditional grant.
    let role = Role::new("r").add_permission(Permission::with_condition("read", "docs", |ctx| {
        ctx.get("dept").map(String::as_str) == Some("hr")
    }));
    assert!(serde_json::to_string(&role).is_err());
}

#[test]
fn deny_survives_a_round_trip() {
    let role = RoleBuilder::new()
        .name("r")
        .allow("system", ["*"])
        .deny("system", ["shutdown"])
        .build()
        .unwrap();
    let ctx = HashMap::new();
    let loaded: Role = roundtrip(&role);
    assert!(!loaded.has_permission("shutdown", "system", &ctx));
    assert!(loaded.has_permission("read", "system", &ctx));
}

#[test]
fn reloaded_elevation_does_not_restart_its_clock() {
    let e = RoleElevation::new("admin".into(), Some(Duration::from_millis(300)));
    std::thread::sleep(Duration::from_millis(400));
    let now = std::time::Instant::now();
    assert!(e.is_expired(now), "precondition: expired");
    let loaded: RoleElevation = roundtrip(&e);
    assert!(
        loaded.is_expired(std::time::Instant::now()),
        "a reload must not give an expired elevation a fresh lifetime"
    );
}

#[test]
fn old_files_without_the_deny_field_still_load() {
    let json = r#"{"action":"read","resource_type":"docs","instance":null}"#;
    let p: Permission = serde_json::from_str(json).unwrap();
    assert!(!p.is_deny());
}

#[test]
fn unexpired_elevation_keeps_its_remaining_time() {
    let e = RoleElevation::new("admin".into(), Some(Duration::from_secs(3600)));
    let loaded: RoleElevation = roundtrip(&e);
    let now = std::time::Instant::now();
    assert!(!loaded.is_expired(now));
    let left = loaded.time_remaining(now).unwrap();
    assert!(
        left > Duration::from_secs(3590) && left <= Duration::from_secs(3600),
        "{left:?}"
    );
}
