//! Application types for role templates.

/// Application type for creating appropriate roles
#[derive(Debug, Clone)]
pub enum ApplicationType {
    /// Web application with user-facing interface
    WebApp,
    /// API service for machine-to-machine communication
    ApiService,
    /// Content management system
    Cms,
    /// E-commerce platform
    Ecommerce,
    /// Internal admin dashboard
    AdminDashboard,
}
