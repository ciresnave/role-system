//! Contextual permission checking with external authentication contexts.

use crate::{
    auth_context::AuthenticationContext,
    core::RoleSystem,
    error::Result,
    resource::Resource,
    subject::Subject,
    storage::Storage,
};
use std::collections::HashMap;

// Extension methods for RoleSystem when working with AuthenticationContext
pub trait ContextualPermissions<T: AuthenticationContext> {
    /// Check permission using an authentication context
    fn check_contextual_permission(
        &self,
        context: &T,
        action: &str,
        resource: &Resource,
        additional_context: Option<HashMap<String, String>>,
    ) -> Result<bool>;
    
    /// Check permission against a list of required scopes
    fn check_scope_permission(
        &self,
        context: &T,
        required_scopes: &[String],
    ) -> Result<bool>;
}

impl<S, T> ContextualPermissions<T> for RoleSystem<S>
where
    S: Storage,
    T: AuthenticationContext,
{
    /// Check permission using an authentication context.
    /// 
    /// This method combines role-based permissions with any scopes/permissions
    /// granted directly by the authentication context (e.g., JWT token scopes).
    /// 
    /// # Arguments
    /// 
    /// * `context` - The authentication context to use
    /// * `action` - The action to check permission for
    /// * `resource` - The resource to check permission for
    /// * `additional_context` - Additional context values for conditional permissions
    /// 
    /// # Returns
    /// 
    /// `true` if permission is granted, `false` otherwise
    fn check_contextual_permission(
        &self,
        context: &T,
        action: &str,
        resource: &Resource,
        _additional_context: Option<HashMap<String, String>>, // Prefixed with _ to mark as intentionally unused
    ) -> Result<bool> {
        // 1. Check if context is valid
        if !context.is_valid() {
            #[cfg(feature = "audit")]
            log::warn!(
                "Permission check denied: invalid authentication context for action '{}' on resource '{}'",
                action,
                resource.id()
            );
            
            return Ok(false);
        }
        
        // 2. Check if the context grants the permission directly through scopes
        let permission_string = format!("{}:{}", action, resource.resource_type());
        let instance_permission_string = format!("{}:{}:{}", action, resource.resource_type(), resource.id());
        
        let granted_scopes = context.get_granted_scopes();
        let has_scope = granted_scopes.iter().any(|scope| {
            scope == &permission_string || 
            scope == &instance_permission_string || 
            scope == "*:*" ||
            scope == &format!("*:{}", resource.resource_type()) ||
            scope == &format!("{}:*", action)
        });
        
        if has_scope {
            #[cfg(feature = "audit")]
            log::info!(
                "Permission granted via authentication context scope for action '{}' on resource '{}'",
                action,
                resource.id()
            );
            
            return Ok(true);
        }
        
        // 3. Check role-based permissions for the user from the context
        let subject = Subject::user(context.get_user_id().as_ref() as &str);
        
        // Note: We're not using the additional_context or context data
        // from the authentication context for now
        
        // Delegate to the standard permission check
        self.check_permission(&subject, action, resource)
    }
    
    /// Check permission against a list of required scopes.
    /// 
    /// This is useful for API endpoints that require specific scopes.
    /// 
    /// # Arguments
    /// 
    /// * `context` - The authentication context to use
    /// * `required_scopes` - List of required scopes (any match grants permission)
    /// 
    /// # Returns
    /// 
    /// `true` if any required scope is granted, `false` otherwise
    fn check_scope_permission(
        &self,
        context: &T,
        required_scopes: &[String],
    ) -> Result<bool> {
        // Check if context is valid
        if !context.is_valid() {
            return Ok(false);
        }
        
        let granted_scopes = context.get_granted_scopes();
        
        // Check if any required scope is present in granted scopes
        for required in required_scopes {
            if granted_scopes.contains(required) {
                return Ok(true);
            }
            
            // Check for wildcard scopes
            if required.contains(':') {
                // Split into parts (e.g., "read:documents")
                let parts: Vec<&str> = required.split(':').collect();
                
                // Check if wildcards cover this scope
                if granted_scopes.contains(&"*:*".to_string()) {
                    return Ok(true);
                }
                
                if parts.len() >= 2 {
                    let action = parts[0];
                    let resource = parts[1];
                    
                    // Check action wildcards (e.g., "*:documents")
                    if granted_scopes.contains(&format!("*:{}", resource)) {
                        return Ok(true);
                    }
                    
                    // Check resource wildcards (e.g., "read:*")
                    if granted_scopes.contains(&format!("{}:*", action)) {
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_context::JwtContext;
    use crate::core::RoleSystem;
    use crate::permission::Permission;
    use crate::role::Role;
    use std::collections::HashMap;
    
    #[test]
    fn test_jwt_context_permissions() {
        let mut role_system = RoleSystem::new();
        
        // Create and register roles
        let editor = Role::new("editor")
            .add_permission(Permission::new("edit", "documents"))
            .add_permission(Permission::new("read", "documents"));
        
        role_system.register_role(editor).unwrap();
        
        // Create a simple HashMap for the payload instead of using serde_json
        let mut payload = HashMap::new();
        payload.insert("exp".to_string(), "1625097600".to_string());
        payload.insert("iat".to_string(), "1625011200".to_string());
        
        // Create JWT context with direct scope grants
        let context = JwtContext::new(
            "user123".to_string(),
            vec!["read:documents".to_string()],
            true,
            payload
        );
        
        // Test document resource
        let document = Resource::new("doc1", "documents");
        
        // Direct scope permission should be granted
        assert!(role_system.check_contextual_permission(&context, "read", &document, None).unwrap());
        
        // Permission not in token scopes should be denied (since user has no roles)
        assert!(!role_system.check_contextual_permission(&context, "edit", &document, None).unwrap());
        
        // Now assign the editor role to the user
        let subject = Subject::user(context.get_user_id().as_ref() as &str);
        role_system.assign_role(&subject, "editor").unwrap();
        
        // Now edit permission should be granted via role
        assert!(role_system.check_contextual_permission(&context, "edit", &document, None).unwrap());
    }
    
    #[test]
    fn test_scope_permission() {
        let role_system = RoleSystem::new();
        
        // Create a simple HashMap for the payload
        let payload = HashMap::new();
        
        // Create JWT context with scopes
        let context = JwtContext::new(
            "user123".to_string(),
            vec!["read:documents".to_string(), "write:posts".to_string()],
            true,
            payload
        );
        
        // Check individual scope permissions
        assert!(role_system.check_scope_permission(&context, &["read:documents".to_string()]).unwrap());
        assert!(role_system.check_scope_permission(&context, &["write:posts".to_string()]).unwrap());
        assert!(!role_system.check_scope_permission(&context, &["admin:users".to_string()]).unwrap());
        
        // Check multiple required scopes (any match should succeed)
        assert!(role_system.check_scope_permission(
            &context, 
            &["read:documents".to_string(), "admin:users".to_string()]
        ).unwrap());
        
        // Check with wildcard
        let admin_context = JwtContext::new(
            "admin".to_string(),
            vec!["*:*".to_string()],
            true,
            HashMap::new()
        );
        
        assert!(role_system.check_scope_permission(&admin_context, &["read:any".to_string()]).unwrap());
        assert!(role_system.check_scope_permission(&admin_context, &["admin:users".to_string()]).unwrap());
    }
}
