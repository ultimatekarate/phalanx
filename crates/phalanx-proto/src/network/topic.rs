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

    pub fn audio() -> Self {
        Self::new("audio/1.0.0")
    }

    /// Heartbeat/presence control topic.
    pub fn control() -> Self {
        Self::new("control/1.0.0")
    }

    pub fn revocation() -> Self {
        Self::new("revocation/1.0.0")
    }

    /// Generic mesh control topic. Used for canary alerts and other
    /// encrypted community messages indistinguishable from normal traffic.
    pub fn mesh() -> Self {
        Self::new("mesh/1.0.0")
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

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn new_normalizes_mixed_case() {
        let topic = MeshTopic::new("Video/1.0.0");
        assert_eq!(topic.as_str(), "/phalanx/video/1.0.0");
    }

    #[test]
    fn new_deduplicates_phalanx_prefix() {
        // Input that already carries the phalanx/ prefix must not double-prefix.
        let topic = MeshTopic::new("/phalanx/custom");
        assert_eq!(topic.as_str(), "/phalanx/custom");
    }

    #[test]
    fn new_strips_leading_slashes() {
        // Multiple leading slashes should all be trimmed before re-prefixing.
        let topic = MeshTopic::new("///revocation");
        assert_eq!(topic.as_str(), "/phalanx/revocation");
    }

    #[test]
    fn well_known_topic_values_are_stable() {
        // Regression guard: these strings are wire-visible. Changing them
        // breaks compatibility with every peer on the mesh.
        assert_eq!(MeshTopic::video().as_str(), "/phalanx/video/1.0.0");
        assert_eq!(MeshTopic::audio().as_str(), "/phalanx/audio/1.0.0");
        assert_eq!(MeshTopic::control().as_str(), "/phalanx/control/1.0.0");
        assert_eq!(
            MeshTopic::revocation().as_str(),
            "/phalanx/revocation/1.0.0"
        );
        assert_eq!(MeshTopic::mesh().as_str(), "/phalanx/mesh/1.0.0");
    }
}
