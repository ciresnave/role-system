//! Subject definitions (users, groups, or entities that can have roles).

use std::collections::HashMap;
use uuid::Uuid;

/// A subject represents an entity that can be assigned roles (user, group, service, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub struct Subject {
    /// Unique identifier for the subject.
    id: String,
    /// Type of subject (e.g., "user", "group", "service").
    subject_type: SubjectType,
    /// Display name for the subject.
    display_name: Option<String>,
    /// Additional attributes for the subject.
    attributes: HashMap<String, String>,
}

/// Types of subjects that can be assigned roles.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "persistence", derive(serde::Serialize, serde::Deserialize))]
pub enum SubjectType {
    /// A human user.
    User,
    /// A group of users.
    Group,
    /// A service or application.
    Service,
    /// A device or system.
    Device,
    /// Custom subject type.
    Custom(String),
}

impl Subject {
    /// Create a new subject with a generated UUID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::User,
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Create a new user subject.
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::User,
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Create a new group subject.
    pub fn group(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Group,
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Create a new service subject.
    pub fn service(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Service,
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Create a new device subject.
    pub fn device(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Device,
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Create a new custom subject type.
    pub fn custom(id: impl Into<String>, custom_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            subject_type: SubjectType::Custom(custom_type.into()),
            display_name: None,
            attributes: HashMap::new(),
        }
    }

    /// Get the subject's unique identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the subject's type.
    pub fn subject_type(&self) -> &SubjectType {
        &self.subject_type
    }

    /// Set the display name for the subject.
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Get the subject's display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Set the display name.
    pub fn set_display_name(&mut self, display_name: impl Into<String>) {
        self.display_name = Some(display_name.into());
    }

    /// Add an attribute to the subject.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Set an attribute on the subject.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Get an attribute value.
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// Get all attributes.
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// Remove an attribute.
    pub fn remove_attribute(&mut self, key: &str) -> Option<String> {
        self.attributes.remove(key)
    }

    /// Check if the subject has a specific attribute.
    pub fn has_attribute(&self, key: &str) -> bool {
        self.attributes.contains_key(key)
    }

    /// Get the effective name for display purposes.
    pub fn effective_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }
}

impl SubjectType {
    /// Get the string representation of the subject type.
    pub fn as_str(&self) -> &str {
        match self {
            SubjectType::User => "user",
            SubjectType::Group => "group",
            SubjectType::Service => "service",
            SubjectType::Device => "device",
            SubjectType::Custom(custom) => custom,
        }
    }

    /// Check if this is a user subject type.
    pub fn is_user(&self) -> bool {
        matches!(self, SubjectType::User)
    }

    /// Check if this is a group subject type.
    pub fn is_group(&self) -> bool {
        matches!(self, SubjectType::Group)
    }

    /// Check if this is a service subject type.
    pub fn is_service(&self) -> bool {
        matches!(self, SubjectType::Service)
    }

    /// Check if this is a device subject type.
    pub fn is_device(&self) -> bool {
        matches!(self, SubjectType::Device)
    }

    /// Check if this is a custom subject type.
    pub fn is_custom(&self) -> bool {
        matches!(self, SubjectType::Custom(_))
    }
}

impl std::fmt::Display for SubjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SubjectType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(SubjectType::User),
            "group" => Ok(SubjectType::Group),
            "service" => Ok(SubjectType::Service),
            "device" => Ok(SubjectType::Device),
            custom => Ok(SubjectType::Custom(custom.to_string())),
        }
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display_name {
            Some(name) => write!(f, "{} ({}:{})", name, self.subject_type, self.id),
            None => write!(f, "{}:{}", self.subject_type, self.id),
        }
    }
}

/// Builder for creating subjects with a fluent API.
#[derive(Debug, Default)]
pub struct SubjectBuilder {
    id: Option<String>,
    subject_type: Option<SubjectType>,
    display_name: Option<String>,
    attributes: HashMap<String, String>,
}

impl SubjectBuilder {
    /// Create a new subject builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject ID.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Generate a random UUID for the subject ID.
    pub fn generate_id(mut self) -> Self {
        self.id = Some(Uuid::new_v4().to_string());
        self
    }

    /// Set the subject type.
    pub fn subject_type(mut self, subject_type: SubjectType) -> Self {
        self.subject_type = Some(subject_type);
        self
    }

    /// Set as a user subject.
    pub fn user(mut self) -> Self {
        self.subject_type = Some(SubjectType::User);
        self
    }

    /// Set as a group subject.
    pub fn group(mut self) -> Self {
        self.subject_type = Some(SubjectType::Group);
        self
    }

    /// Set as a service subject.
    pub fn service(mut self) -> Self {
        self.subject_type = Some(SubjectType::Service);
        self
    }

    /// Set as a device subject.
    pub fn device(mut self) -> Self {
        self.subject_type = Some(SubjectType::Device);
        self
    }

    /// Set as a custom subject type.
    pub fn custom(mut self, custom_type: impl Into<String>) -> Self {
        self.subject_type = Some(SubjectType::Custom(custom_type.into()));
        self
    }

    /// Set the display name.
    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Add an attribute.
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Build the subject.
    pub fn build(self) -> Result<Subject, String> {
        let id = self.id.ok_or("Subject ID is required")?;
        let subject_type = self.subject_type.unwrap_or(SubjectType::User);

        let subject = Subject {
            id,
            subject_type,
            display_name: self.display_name,
            attributes: self.attributes,
        };

        Ok(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_creation() {
        let subject = Subject::user("user123")
            .with_display_name("John Doe")
            .with_attribute("email", "john@example.com")
            .with_attribute("department", "Engineering");

        assert_eq!(subject.id(), "user123");
        assert!(subject.subject_type().is_user());
        assert_eq!(subject.display_name(), Some("John Doe"));
        assert_eq!(subject.attribute("email"), Some("john@example.com"));
        assert_eq!(subject.attribute("department"), Some("Engineering"));
        assert_eq!(subject.effective_name(), "John Doe");
    }

    #[test]
    fn test_subject_types() {
        let user = Subject::user("u1");
        let group = Subject::group("g1");
        let service = Subject::service("s1");
        let device = Subject::device("d1");
        let custom = Subject::custom("c1", "robot");

        assert!(user.subject_type().is_user());
        assert!(group.subject_type().is_group());
        assert!(service.subject_type().is_service());
        assert!(device.subject_type().is_device());
        assert!(custom.subject_type().is_custom());
    }

    #[test]
    fn test_subject_builder() {
        let subject = SubjectBuilder::new()
            .id("test-id")
            .user()
            .display_name("Test User")
            .attribute("role", "developer")
            .build()
            .unwrap();

        assert_eq!(subject.id(), "test-id");
        assert!(subject.subject_type().is_user());
        assert_eq!(subject.display_name(), Some("Test User"));
        assert_eq!(subject.attribute("role"), Some("developer"));
    }

    #[test]
    fn test_subject_type_parsing() {
        assert!(matches!("user".parse::<SubjectType>().unwrap(), SubjectType::User));
        assert!(matches!("group".parse::<SubjectType>().unwrap(), SubjectType::Group));
        assert!(matches!("service".parse::<SubjectType>().unwrap(), SubjectType::Service));
        assert!(matches!("device".parse::<SubjectType>().unwrap(), SubjectType::Device));
        
        match "custom_type".parse::<SubjectType>().unwrap() {
            SubjectType::Custom(s) => assert_eq!(s, "custom_type"),
            _ => panic!("Expected custom type"),
        }
    }

    #[test]
    fn test_effective_name() {
        let subject_with_name = Subject::user("u1").with_display_name("John");
        let subject_without_name = Subject::user("u2");

        assert_eq!(subject_with_name.effective_name(), "John");
        assert_eq!(subject_without_name.effective_name(), "u2");
    }
}
