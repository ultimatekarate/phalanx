// crates/phalanx-node/src/paths.rs
//
// On-disk state layout for the sentinel node binary.
//
// The sentinel is a deployable node. All of its persistent state — identity,
// swarm key, vault (salt + DHT store + PRNU posterior), transient WAL, and
// logs — lives under a single OS-correct, machine-local base directory rather
// than scattered across the process working directory.
//
// Mobile (the FFI path) does NOT use this: there, Flutter passes the OS app
// sandbox directory and everything derives under it. This module is for the
// headless desktop/server node form.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Compiled dev-only default for the vault root (see `config::StorageConfig`).
/// When the loaded config still carries this value, the sentinel treats the
/// vault location as "unset" and places it under the resolved base dir.
pub const DEV_DEFAULT_VAULT_PATH: &str = "./sim_vault";

/// Environment variable that overrides the entire state base directory (e.g. a
/// systemd `EnvironmentFile`). Moves identity, key, vault, WAL, and logs.
pub const HOME_ENV: &str = "PHALANX_HOME";

/// Failure to resolve or create the node's state directory. The sentinel
/// refuses to silently fall back to the working directory.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("no platform data directory available; set {HOME_ENV} to choose one")]
    NoPlatformDir,
    #[error("failed to create data directory {path}: {source}")]
    CreateFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Resolved, single-root layout for sentinel state. Construct via
/// [`NodePaths::resolve`], which also creates the base / vault / log dirs.
pub struct NodePaths {
    base: PathBuf,
}

impl NodePaths {
    /// Resolve the base directory (`PHALANX_HOME` override, else the OS-correct
    /// local data dir) and create the directories the node writes into.
    ///
    /// # Errors
    /// [`PathError::NoPlatformDir`] if no override is set and no platform data
    /// dir exists; [`PathError::CreateFailed`] if a directory cannot be created.
    pub fn resolve() -> Result<Self, PathError> {
        let base = Self::resolve_base(std::env::var_os(HOME_ENV))?;
        let paths = Self { base };
        paths.ensure_dirs()?;
        Ok(paths)
    }

    /// Pure base resolver — the environment value is injected so the precedence
    /// logic is fully testable without mutating process-global state.
    fn resolve_base(home_env: Option<OsString>) -> Result<PathBuf, PathError> {
        if let Some(home) = home_env {
            return Ok(PathBuf::from(home));
        }
        // `data_local_dir` (not `data_dir`): on Windows the latter is Roaming
        // AppData, wrong for a redb DHT store / vault / WAL. Linux/macOS resolve
        // both to the same place.
        let dirs = ProjectDirs::from("app", "Phalanx", "phalanx-sentinel")
            .ok_or(PathError::NoPlatformDir)?;
        Ok(dirs.data_local_dir().to_path_buf())
    }

    fn ensure_dirs(&self) -> Result<(), PathError> {
        for dir in [self.base.clone(), self.vault(), self.log_dir()] {
            std::fs::create_dir_all(&dir).map_err(|source| PathError::CreateFailed {
                path: dir.display().to_string(),
                source,
            })?;
        }
        Ok(())
    }

    #[must_use]
    pub fn base(&self) -> &Path {
        &self.base
    }
    #[must_use]
    pub fn vault(&self) -> PathBuf {
        self.base.join("vault")
    }
    #[must_use]
    pub fn identity(&self) -> PathBuf {
        self.base.join("identity.bin")
    }
    #[must_use]
    pub fn swarm_key(&self) -> PathBuf {
        self.base.join("swarm.key")
    }
    #[must_use]
    pub fn wal(&self) -> PathBuf {
        self.base.join("sentinel_transient_wal.bin")
    }
    #[must_use]
    pub fn log_dir(&self) -> PathBuf {
        self.base.join("logs")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn home_env_override_is_used_verbatim() {
        let base = NodePaths::resolve_base(Some(OsString::from("/srv/phalanx"))).expect("resolves");
        assert_eq!(base, PathBuf::from("/srv/phalanx"));
    }

    #[test]
    fn platform_dir_used_when_no_override() {
        let base = NodePaths::resolve_base(None).expect("platform dir resolves");
        assert!(
            base.is_absolute(),
            "platform base must be absolute: {base:?}"
        );
        assert_ne!(base, PathBuf::from(DEV_DEFAULT_VAULT_PATH));
    }

    #[test]
    fn accessors_derive_under_base() {
        let paths = NodePaths {
            base: PathBuf::from("/data/phx"),
        };
        assert_eq!(paths.vault(), PathBuf::from("/data/phx/vault"));
        assert_eq!(paths.identity(), PathBuf::from("/data/phx/identity.bin"));
        assert_eq!(paths.swarm_key(), PathBuf::from("/data/phx/swarm.key"));
        assert_eq!(
            paths.wal(),
            PathBuf::from("/data/phx/sentinel_transient_wal.bin")
        );
        assert_eq!(paths.log_dir(), PathBuf::from("/data/phx/logs"));
    }
}
