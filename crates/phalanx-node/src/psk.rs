use std::fs;
use std::path::Path;

/// Reads and validates a Pre-Shared Key (PSK) from the filesystem.
///
/// Returns raw 32-byte key. The transport factory wraps it in the
/// wire-level PreSharedKey type internally.
pub fn load_swarm_key(path: &Path) -> Option<[u8; 32]> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() == 32 {
                let mut psk_bytes = [0u8; 32];
                psk_bytes.copy_from_slice(&bytes);
                Some(psk_bytes)
            } else {
                tracing::error!(
                    target: "phalanx_node::security",
                    path = ?path,
                    "Swarm key is corrupt (invalid length: {} bytes). Expected 32 bytes. Ignoring.",
                    bytes.len()
                );
                None
            }
        }
        Err(error) => {
            tracing::warn!(
                target: "phalanx_node::security",
                path = ?path,
                error = %error,
                "Failed to read swarm key"
            );
            None
        }
    }
}

pub fn generate_swarm_key(path: &Path) -> std::io::Result<()> {
    use rand_core::{OsRng, RngCore};
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    fs::write(path, key)
}
