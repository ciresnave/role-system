//! Convenience macros for the role system.

/// Macro for creating multiple permissions with a clean syntax.
///
/// # Examples
///
/// ```rust
/// use role_system::permissions;
///
/// let perms = permissions![
///     "read" => "documents",
///     "write" => "documents",
///     "delete" => "documents"
/// ];
/// ```
#[macro_export]
macro_rules! permissions {
    ($($action:expr => $resource:expr),* $(,)?) => {
        vec![$(
            $crate::permission::Permission::new($action, $resource)
        ),*]
    };
}

/// Macro for creating a role with permissions in a single expression.
///
/// # Examples
///
/// ```rust
/// use role_system::role_with_permissions;
///
/// let role = role_with_permissions! {
///     name: "editor",
///     description: "Content editor role",
///     permissions: [
///         "read" => "documents",
///         "write" => "documents",
///         "create" => "documents"
///     ]
/// };
/// ```
#[macro_export]
macro_rules! role_with_permissions {
    (
        name: $name:expr,
        description: $desc:expr,
        permissions: [
            $($action:expr => $resource:expr),* $(,)?
        ]
    ) => {
        {
            let mut role = $crate::role::Role::new($name).with_description($desc);
            $(
                role = role.add_permission($crate::permission::Permission::new($action, $resource));
            )*
            role
        }
    };
    (
        name: $name:expr,
        permissions: [
            $($action:expr => $resource:expr),* $(,)?
        ]
    ) => {
        {
            let mut role = $crate::role::Role::new($name);
            $(
                role = role.add_permission($crate::permission::Permission::new($action, $resource));
            )*
            role
        }
    };
}

/// Macro for creating subjects with different types.
///
/// # Examples
///
/// ```rust
/// use role_system::subjects;
///
/// let (admin, service, device) = subjects! {
///     user "admin" => display_name: "Administrator",
///     service "api_service" => display_name: "API Service",
///     device "printer_01" => display_name: "Office Printer"
/// };
/// ```
#[macro_export]
macro_rules! subjects {
    (
        $(
            $type:ident $id:expr => display_name: $name:expr
        ),* $(,)?
    ) => {
        ($(
            $crate::subject::Subject::$type($id).with_display_name($name)
        ),*)
    };
    (
        $(
            $type:ident $id:expr
        ),* $(,)?
    ) => {
        ($(
            $crate::subject::Subject::$type($id)
        ),*)
    };
}

/// Macro for defining conditional permissions with context requirements.
///
/// # Examples
///
/// ```rust
/// use role_system::conditional_permission;
///
/// let perm = conditional_permission! {
///     action: "access",
///     resource: "secure_area",
///     condition: |context| {
///         context.get("clearance_level") == Some(&"top_secret".to_string()) &&
///         context.get("time_of_day") == Some(&"business_hours".to_string())
///     }
/// };
/// ```
#[macro_export]
macro_rules! conditional_permission {
    (
        action: $action:expr,
        resource: $resource:expr,
        condition: $condition:expr
    ) => {
        $crate::permission::Permission::with_condition($action, $resource, $condition)
    };
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn test_permissions_macro() {
        let perms = permissions![
            "read" => "documents",
            "write" => "documents",
            "delete" => "documents"
        ];

        assert_eq!(perms.len(), 3);
        assert_eq!(perms[0].action(), "read");
        assert_eq!(perms[0].resource_type(), "documents");
    }

    #[test]
    fn test_role_with_permissions_macro() {
        let role = role_with_permissions! {
            name: "editor",
            description: "Content editor role",
            permissions: [
                "read" => "documents",
                "write" => "documents"
            ]
        };

        assert_eq!(role.name(), "editor");
        assert_eq!(role.description(), Some("Content editor role"));
        assert_eq!(role.permissions().permissions().len(), 2);
    }

    #[test]
    fn test_subjects_macro() {
        let (admin, service) = subjects! {
            user "admin_user" => display_name: "Administrator",
            service "api_service" => display_name: "API Service"
        };

        assert_eq!(admin.id(), "admin_user");
        assert_eq!(admin.display_name(), Some("Administrator"));
        assert_eq!(service.id(), "api_service");
        assert_eq!(service.display_name(), Some("API Service"));
    }

    #[test]
    fn test_conditional_permission_macro() {
        let perm = conditional_permission! {
            action: "access",
            resource: "secure_area",
            condition: |context: &HashMap<String, String>| {
                context.get("clearance") == Some(&"top_secret".to_string())
            }
        };

        assert_eq!(perm.action(), "access");
        assert_eq!(perm.resource_type(), "secure_area");

        let mut valid_context = HashMap::new();
        valid_context.insert("clearance".to_string(), "top_secret".to_string());
        assert!(perm.is_granted("access", "secure_area", &valid_context));

        let invalid_context = HashMap::new();
        assert!(!perm.is_granted("access", "secure_area", &invalid_context));
    }
}
