use super::*;
use std::fs;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

/// The lock belongs to the cache path, not to a file that writing replaces.
#[test]
fn independent_handles_share_a_lock_across_atomic_replacements() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");

    let cache_guard = lock(&path).unwrap();
    write(&path, "old").unwrap();
    write(&path, "new").unwrap();

    assert!(try_lock(&path).unwrap().is_none());
    drop(cache_guard);
    assert!(try_lock(&path).unwrap().is_some());
}

/// Readers don't have to take the lock, as a cache file is never partially written.
#[test]
fn readers_only_observe_complete_files_during_concurrent_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache");
    let old = vec![b'a'; 65536];
    let new = vec![b'b'; 1024];
    write(&path, &old).unwrap();

    let start = Arc::new(Barrier::new(3));
    thread::scope(|scope| {
        for contents in [&old, &new] {
            let start = start.clone();
            let path = &path;
            scope.spawn(move || {
                start.wait();
                for _ in 0..100 {
                    write(path, contents).unwrap();
                }
            });
        }

        start.wait();
        for _ in 0..500 {
            let contents = fs::read(&path).unwrap();
            assert!(contents == old || contents == new);
        }
    });
}

/// Holds a lock for the test below, which runs this test in another process.
/// Without the test-only environment variable, there is nothing to do.
#[test]
fn lock_holder_subprocess() {
    let Some(path) = std::env::var_os("MOONBASE_TEST_LOCK_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let _cache_guard = lock(&path).unwrap();
    fs::write(sidecar(&path, ".ready"), "").unwrap();

    // the parent kills this process to see the operating system release the lock
    thread::sleep(Duration::from_secs(30));
}

/// A lock blocks other processes, and dies with the process holding it.
#[test]
fn locks_coordinate_processes_and_are_released_after_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cache::tests::lock_holder_subprocess",
            "--nocapture",
        ])
        .env("MOONBASE_TEST_LOCK_PATH", &path)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    // wait for the child process to acquire the lock
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sidecar(&path, ".ready").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = sidecar(&path, ".ready").exists();
    let locked = try_lock(&path).unwrap().is_none();

    child.kill().unwrap();
    child.wait().unwrap();

    assert!(ready, "child did not acquire its lock");
    assert!(locked, "another process must not acquire a held lock");
    assert!(try_lock(&path).unwrap().is_some());
}
