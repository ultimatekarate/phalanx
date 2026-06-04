// crates/phalanx-stronghold/src/paths.rs
//
// Data-root resolution for the Stronghold daemon.
//
// The Stronghold is a wall-power, always-on node. Its on-disk state (identity,
// communities, recordings, proofs) all lives under a single root directory.
// For a shipped daemon that root must be an OS-correct, machine-local data
// directory — not a dev-relative `./stronghold-data` under the working dir.

use std::ffi::OsString;
use std::path::PathBuf;

use directories::ProjectDirs;

/// Compiled dev-only default for the data root. When the loaded config still
/// carries this value, it is treated as "unset" and the platform data
/// directory is used instead. Kept only for local development convenience.
pub const DEV_DEFAULT_VAULT_PATH: &str = "./stronghold-data";

/// Environment variable that overrides the data root for service deployments
/// (e.g. a systemd `EnvironmentFile`).
pub const HOME_ENV: &str = "PHALANX_STRONGHOLD_HOME";

/// Failure to resolve a data root. The Stronghold refuses to silently fall
/// back to the working directory — a misplaced vault on an always-on node is
/// a data-integrity hazard.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error(
        "no platform data directory available; set {HOME_ENV} or pass --data-dir to choose one"
    )]
    NoPlatformDir,
}

/// Resolve the Stronghold data root. Precedence, highest first:
///   1. `cli_override` — the `--data-dir` flag.
///   2. `PHALANX_STRONGHOLD_HOME` — the operator/service environment.
///   3. an explicit `config.vault_path` (any value other than the dev default).
///   4. the OS-correct local data directory (`directories::ProjectDirs`).
///
/// Fails loudly rather than defaulting to the working directory.
///
/// # Errors
/// Returns [`PathError::NoPlatformDir`] when no override is supplied and the
/// platform exposes no home directory to derive a data dir from.
pub fn resolve_data_dir(
    config_vault_path: &str,
    cli_override: Option<&str>,
) -> Result<PathBuf, PathError> {
    resolve_with(config_vault_path, cli_override, std::env::var_os(HOME_ENV))
}

/// Pure resolver — the environment value is injected so the precedence logic
/// is fully testable without mutating process-global state.
fn resolve_with(
    config_vault_path: &str,
    cli_override: Option<&str>,
    home_env: Option<OsString>,
) -> Result<PathBuf, PathError> {
    if let Some(dir) = cli_override {
        return Ok(PathBuf::from(dir));
    }
    if let Some(home) = home_env {
        return Ok(PathBuf::from(home));
    }
    if config_vault_path != DEV_DEFAULT_VAULT_PATH {
        return Ok(PathBuf::from(config_vault_path));
    }
    // `data_local_dir` (not `data_dir`) on purpose: on Windows the latter is
    // Roaming AppData, which must not carry a redb vault / large evidence
    // store. Linux/macOS resolve both to the same place.
    let dirs = ProjectDirs::from("app", "Phalanx", "phalanx-stronghold")
        .ok_or(PathError::NoPlatformDir)?;
    Ok(dirs.data_local_dir().to_path_buf())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn cli_override_beats_everything() {
        // The flag wins even when an env override and an explicit config exist.
        let p = resolve_with(
            "/etc/phalanx/custom",
            Some("/srv/phalanx"),
            Some(OsString::from("/home/op/.phalanx")),
        )
        .expect("resolves");
        assert_eq!(p, PathBuf::from("/srv/phalanx"));
    }

    #[test]
    fn home_env_beats_config_and_platform() {
        let p = resolve_with(
            DEV_DEFAULT_VAULT_PATH,
            None,
            Some(OsString::from("/var/data")),
        )
        .expect("resolves");
        assert_eq!(p, PathBuf::from("/var/data"));
    }

    #[test]
    fn explicit_config_is_honored_when_no_override() {
        let p = resolve_with("/var/lib/phalanx-stronghold", None, None).expect("resolves");
        assert_eq!(p, PathBuf::from("/var/lib/phalanx-stronghold"));
    }

    #[test]
    fn dev_default_falls_through_to_platform_dir() {
        // With no overrides and the dev-default config, we must land on a real
        // platform path — never the literal "./stronghold-data" in the CWD.
        // (ProjectDirs resolves on all CI/test platforms.)
        let p = resolve_with(DEV_DEFAULT_VAULT_PATH, None, None).expect("platform dir resolves");
        assert_ne!(p, PathBuf::from(DEV_DEFAULT_VAULT_PATH));
        assert!(p.is_absolute(), "platform data dir must be absolute: {p:?}");
    }
}
