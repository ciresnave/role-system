//! Generic authentication context integration.
//! 
//! This module provides a trait for integrating with various authentication
//! systems, making it easy to adapt the role system to work with any auth
//! framework like OAuth, JWT, or custom token solutions.

use std::fmt::Debug;

/// A generic trait that any authentication system can implement.
/// 
/// This allows the role system to be integrated with any authentication
/// mechanism, such as JWT tokens, OAuth tokens, session data, etc.
pub trait AuthenticationContext: Send + Sync + Debug {
    /// The type used to identify users
    type UserId: AsRef<str> + Debug;
    
    /// Additional context data type
    type ContextData: Debug;
    
    /// Get the user ID from the authentication context
    fn get_user_id(&self) -> &Self::UserId;
    
    /// Get any granted scopes from the authentication context
    /// These are typically permissions granted directly via tokens
    fn get_granted_scopes(&self) -> Vec<String>;
    
    /// Get additional context data
    fn get_context(&self) -> &Self::ContextData;
    
    /// Check if this authentication context is valid
    /// (e.g., token not expired, signature valid, etc.)
    fn is_valid(&self) -> bool;
}

/// Simple JWT-based authentication context example
#[derive(Debug)]
pub struct JwtContext {
    /// The user ID extracted from the token
    user_id: String,
    /// Scopes/permissions granted by the token
    scopes: Vec<String>,
    /// Whether the token is valid
    valid: bool,
    /// Additional data from the token
    payload: std::collections::HashMap<String, String>,
}

impl JwtContext {
    /// Create a new JWT context
    pub fn new(
        user_id: String, 
        scopes: Vec<String>, 
        valid: bool, 
        payload: std::collections::HashMap<String, String>
    ) -> Self {
        Self {
            user_id,
            scopes,
            valid,
            payload,
        }
    }
}

impl AuthenticationContext for JwtContext {
    type UserId = String;
    type ContextData = std::collections::HashMap<String, String>;
    
    fn get_user_id(&self) -> &Self::UserId {
        &self.user_id
    }
    
    fn get_granted_scopes(&self) -> Vec<String> {
        self.scopes.clone()
    }
    
    fn get_context(&self) -> &Self::ContextData {
        &self.payload
    }
    
    fn is_valid(&self) -> bool {
        self.valid
    }
}

/// Example session-based authentication context
#[derive(Debug)]
pub struct SessionContext {
    /// The user ID from the session
    user_id: String,
    /// Roles assigned in the session
    roles: Vec<String>,
    /// Whether the session is active
    active: bool,
    /// Additional session data
    data: std::collections::HashMap<String, String>,
}

impl SessionContext {
    /// Create a new session context
    pub fn new(
        user_id: String,
        roles: Vec<String>,
        active: bool,
        data: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            user_id,
            roles,
            active,
            data,
        }
    }
    
    /// Get roles assigned in the session
    pub fn get_roles(&self) -> &[String] {
        &self.roles
    }
}

impl AuthenticationContext for SessionContext {
    type UserId = String;
    type ContextData = std::collections::HashMap<String, String>;
    
    fn get_user_id(&self) -> &Self::UserId {
        &self.user_id
    }
    
    fn get_granted_scopes(&self) -> Vec<String> {
        // Convert roles to scopes format (just an example approach)
        self.roles.iter()
            .map(|role| format!("role:{}", role))
            .collect()
    }
    
    fn get_context(&self) -> &Self::ContextData {
        &self.data
    }
    
    fn is_valid(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_jwt_context() {
        let mut payload = std::collections::HashMap::new();
        payload.insert("exp".to_string(), "1625097600".to_string());
        payload.insert("iat".to_string(), "1625011200".to_string());
        payload.insert("iss".to_string(), "auth-system".to_string());
        
        let context = JwtContext::new(
            "user123".to_string(),
            vec!["read:users".to_string(), "write:posts".to_string()],
            true,
            payload
        );
        
        assert_eq!(context.get_user_id(), "user123");
        assert!(context.get_granted_scopes().contains(&"read:users".to_string()));
        assert!(context.is_valid());
    }
    
    #[test]
    fn test_session_context() {
        let mut data = std::collections::HashMap::new();
        data.insert("last_login".to_string(), "2023-01-01T00:00:00Z".to_string());
        
        let context = SessionContext::new(
            "user456".to_string(),
            vec!["admin".to_string(), "editor".to_string()],
            true,
            data
        );
        
        assert_eq!(context.get_user_id(), "user456");
        assert!(context.get_granted_scopes().contains(&"role:admin".to_string()));
        assert!(context.is_valid());
        assert_eq!(context.get_roles().len(), 2);
    }
}
