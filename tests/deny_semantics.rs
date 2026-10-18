//! `RoleBuilder::deny` must actually deny.

use role_system::{core::RoleSystem, resource::Resource, role::RoleBuilder, subject::Subject};

fn check(role: role_system::role::Role, action: &str, res: &str) -> bool {
    let mut rs = RoleSystem::new();
    rs.register_role(role).unwrap();
    let s = Subject::new("s");
    rs.assign_role(&s, "r").unwrap();
    rs.check_permission(&s, action, &Resource::new("x", res))
        .unwrap()
}

#[test]
fn deny_after_allow_same_action_denies() {
    let role = RoleBuilder::new()
        .name("r")
        .allow("system", ["shutdown", "read"])
        .deny("system", ["shutdown"])
        .build()
        .unwrap();
    assert!(
        !check(role.clone(), "shutdown", "system"),
        "deny(shutdown) must override allow"
    );
    assert!(check(role, "read", "system"));
}

#[test]
fn deny_before_allow_same_action_denies() {
    let role = RoleBuilder::new()
        .name("r")
        .deny("system", ["shutdown"])
        .allow("system", ["shutdown"])
        .build()
        .unwrap();
    assert!(!check(role, "shutdown", "system"));
}

#[test]
fn deny_overrides_wildcard_allow() {
    let role = RoleBuilder::new()
        .name("r")
        .allow("system", ["*"])
        .deny("system", ["shutdown"])
        .build()
        .unwrap();
    assert!(!check(role.clone(), "shutdown", "system"));
    assert!(check(role, "read", "system"));
}

#[test]
fn deny_in_one_role_overrides_allow_in_another() {
    let mut rs = RoleSystem::new();
    rs.register_role(
        RoleBuilder::new()
            .name("a")
            .allow("system", ["shutdown"])
            .build()
            .unwrap(),
    )
    .unwrap();
    rs.register_role(
        RoleBuilder::new()
            .name("b")
            .deny("system", ["shutdown"])
            .build()
            .unwrap(),
    )
    .unwrap();
    let s = Subject::new("s");
    rs.assign_role(&s, "a").unwrap();
    rs.assign_role(&s, "b").unwrap();
    assert!(
        !rs.check_permission(&s, "shutdown", &Resource::new("x", "system"))
            .unwrap()
    );
}

#[test]
fn deny_does_not_affect_other_actions_or_resources() {
    let role = RoleBuilder::new()
        .name("r")
        .allow("system", ["shutdown", "read"])
        .allow("other", ["shutdown"])
        .deny("system", ["shutdown"])
        .build()
        .unwrap();
    assert!(check(role.clone(), "read", "system"));
    assert!(check(role, "shutdown", "other"));
}

#[test]
fn instance_deny_blocks_only_that_instance() {
    let mut rs = RoleSystem::new();
    let role = role_system::role::Role::new("r")
        .add_permission(role_system::permission::Permission::new("read", "docs"))
        .add_permission(role_system::permission::Permission::deny_instance(
            "read", "docs", "secret",
        ));
    rs.register_role(role).unwrap();
    let s = Subject::new("s");
    rs.assign_role(&s, "r").unwrap();
    assert!(
        !rs.check_permission(&s, "read", &Resource::new("secret", "docs"))
            .unwrap()
    );
    assert!(
        rs.check_permission(&s, "read", &Resource::new("public", "docs"))
            .unwrap()
    );
}

#[test]
fn deny_without_any_allow_denies() {
    let role = RoleBuilder::new()
        .name("r")
        .deny("system", ["shutdown"])
        .build()
        .unwrap();
    assert!(!check(role, "shutdown", "system"));
}
