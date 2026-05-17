use std::path::{Path, PathBuf};
use tokio::io;

/// Atomically replace `final_path` with `bytes`.
///
/// Writes to `final_path` with a `.tmp` suffix appended, then renames into
/// place. Rename on the same filesystem is atomic; readers either see the
/// previous file or the new file, never a partial write. Used by both
/// `evidence_store` and `proof_store` to keep the WAL-style write semantics
/// consistent across stronghold persistence sites.
pub(super) async fn atomic_write(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp_path = with_tmp_suffix(final_path);
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, final_path).await?;
    Ok(())
}

fn with_tmp_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}
