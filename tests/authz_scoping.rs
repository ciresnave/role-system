//! Regression tests for resource-type and instance scoping of permission checks.
//!
//! Before the fix: (1) the permission cache key omitted the resource type, so a
//! cached grant on one type answered checks on another type that shared a
//! resource id; (2) a permission's instance was stored but never consulted by
//! `check_permission`, so an instance-scoped grant covered every instance.

use role_system::{
    core::{RoleSystem, RoleSystemConfig},
    permission::Permission,
    resource::Resource,
    role::Role,
    subject::Subject,
};

fn system(caching: bool) -> RoleSystem {
    let config = RoleSystemConfig {
        enable_caching: caching,
        ..RoleSystemConfig::default()
    };
    RoleSystem::with_config(config)
}

fn with_role(caching: bool, permission: Permission) -> (RoleSystem, Subject) {
    let mut rs = system(caching);
    rs.register_role(Role::new("r").add_permission(permission))
        .unwrap();
    let subject = Subject::new("s1");
    rs.assign_role(&subject, "r").unwrap();
    (rs, subject)
}

#[test]
fn cache_does_not_leak_grant_across_resource_types() {
    let (rs, s) = with_role(true, Permission::new("read", "service_a"));
    let a = Resource::new("x", "service_a");
    let b = Resource::new("x", "service_b");
    assert!(rs.check_permission(&s, "read", &a).unwrap());
    assert!(
        !rs.check_permission(&s, "read", &b).unwrap(),
        "grant on service_a must not answer a check on service_b"
    );
}

#[test]
fn cache_does_not_leak_denial_across_resource_types() {
    let (rs, s) = with_role(true, Permission::new("read", "service_a"));
    let a = Resource::new("x", "service_a");
    let b = Resource::new("x", "service_b");
    assert!(!rs.check_permission(&s, "read", &b).unwrap());
    assert!(
        rs.check_permission(&s, "read", &a).unwrap(),
        "denial on service_b must not answer a check on service_a"
    );
}

#[test]
fn cache_does_not_leak_grant_across_instances() {
    let (rs, s) = with_role(true, Permission::with_instance("read", "svc", "only1"));
    assert!(
        rs.check_permission(&s, "read", &Resource::new("only1", "svc"))
            .unwrap()
    );
    assert!(
        !rs.check_permission(&s, "read", &Resource::new("other", "svc"))
            .unwrap()
    );
}

#[test]
fn instance_scoped_permission_grants_only_that_instance() {
    for caching in [false, true] {
        let (rs, s) = with_role(caching, Permission::with_instance("read", "svc", "only1"));
        assert!(
            rs.check_permission(&s, "read", &Resource::new("only1", "svc"))
                .unwrap(),
            "caching={caching}: matching instance must be granted"
        );
        assert!(
            !rs.check_permission(&s, "read", &Resource::new("other", "svc"))
                .unwrap(),
            "caching={caching}: other instance must be denied"
        );
    }
}

#[test]
fn instance_scoped_permission_does_not_grant_a_check_without_an_instance() {
    for caching in [false, true] {
        let (rs, s) = with_role(caching, Permission::with_instance("read", "svc", "only1"));
        assert!(
            !rs.check_permission(&s, "read", &Resource::new("", "svc"))
                .unwrap(),
            "caching={caching}: an empty resource id carries no instance"
        );
    }
}

#[test]
fn wildcard_instance_grants_every_named_instance() {
    for caching in [false, true] {
        let (rs, s) = with_role(caching, Permission::with_instance("read", "svc", "*"));
        for id in ["a", "b"] {
            assert!(
                rs.check_permission(&s, "read", &Resource::new(id, "svc"))
                    .unwrap(),
                "caching={caching}: id {id:?}"
            );
        }
        // Fail closed: a check that names no instance is not covered by an instance grant.
        assert!(
            !rs.check_permission(&s, "read", &Resource::new("", "svc"))
                .unwrap()
        );
    }
}

#[test]
fn type_wide_permission_still_grants_every_instance() {
    for caching in [false, true] {
        let (rs, s) = with_role(caching, Permission::new("read", "svc"));
        for id in ["a", "b", ""] {
            assert!(
                rs.check_permission(&s, "read", &Resource::new(id, "svc"))
                    .unwrap(),
                "caching={caching}: id {id:?}"
            );
        }
        assert!(
            !rs.check_permission(&s, "read", &Resource::new("a", "other"))
                .unwrap()
        );
    }
}

#[test]
fn removing_a_role_revokes_instance_grants() {
    let (mut rs, s) = with_role(true, Permission::with_instance("read", "svc", "only1"));
    let r = Resource::new("only1", "svc");
    assert!(rs.check_permission(&s, "read", &r).unwrap());
    rs.remove_role(&s, "r").unwrap();
    assert!(!rs.check_permission(&s, "read", &r).unwrap());
}

#[test]
fn batch_check_respects_instances() {
    let (rs, s) = with_role(true, Permission::with_instance("read", "svc", "only1"));
    let ok = Resource::new("only1", "svc");
    let no = Resource::new("other", "svc");
    let out = rs
        .check_permissions_batch(&s, &[("read", &ok), ("read", &no)])
        .unwrap();
    assert!(out[0].2);
    assert!(!out[1].2);
}
