use serde::{Deserialize, Serialize};
use std::fmt;

/// A type-safe wrapper for Phalanx network topics.
/// Enforces naming conventions and prevents case-mismatch errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshTopic(String);

impl MeshTopic {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn new(name: &str) -> Self {
        let cleaned = name.to_lowercase();
        // Strip leading slashes and existing "phalanx/" prefixes
        let base = cleaned
            .trim_start_matches('/')
            .trim_start_matches("phalanx/");

        Self(format!("/phalanx/{}", base))
    }

    pub fn video() -> Self {
        Self::new("video/1.0.0")
    }

    pub fn revocation() -> Self {
        Self::new("revocation/1.0.0")
    }
}

impl Default for MeshTopic {
    fn default() -> Self {
        Self::new("default")
    }
}

impl fmt::Display for MeshTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for MeshTopic {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for MeshTopic {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

impl PartialEq<&str> for MeshTopic {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<MeshTopic> for &str {
    fn eq(&self, other: &MeshTopic) -> bool {
        *self == other.0
    }
}

impl PartialEq<String> for MeshTopic {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl From<MeshTopic> for String {
    fn from(topic: MeshTopic) -> Self {
        topic.0
    }
}

impl From<&MeshTopic> for String {
    fn from(topic: &MeshTopic) -> Self {
        topic.0.clone()
    }
}

impl AsRef<str> for MeshTopic {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
