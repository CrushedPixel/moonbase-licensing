//! Coordination of cache files shared by several threads and processes.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Returns the path of a companion file belonging to the given cache file.
///
/// The suffix is appended to the whole file name, so that the companions
/// of caches only differing in their extension don't collide.
pub(crate) fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Opens the lock file belonging to a cache file, creating it if necessary.
///
/// The lock file is never removed,
/// as other instances may still have it open.
fn open_lock(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sidecar(path, ".lock"))
}

/// Locks a cache file for this thread and process,
/// waiting until everyone else has released it.
///
/// The lock is held until the returned file is dropped.
/// If the process exits, the operating system releases it.
pub(crate) fn lock(path: &Path) -> io::Result<File> {
    let file = open_lock(path)?;
    file.lock()?;
    Ok(file)
}

/// Locks a cache file like [lock],
/// but returns [None] instead of waiting if it is already locked.
pub(crate) fn try_lock(path: &Path) -> io::Result<Option<File>> {
    let file = open_lock(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

/// Writes a cache file by replacing it with a temporary file
/// that already holds the complete contents.
///
/// This way readers never observe a partially written file,
/// so they don't have to take the writer's lock.
pub(crate) fn write(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(contents.as_ref())?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cache.rs"]
mod tests;
