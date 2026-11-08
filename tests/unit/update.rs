use super::*;
use std::cell::Cell;

/// Time at which the checks in these tests run.
const NOW: u64 = 1_000_000;
/// Interval between successful checks in these tests.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A config whose cache file lives in a directory removed on drop.
struct TestCheck {
    /// Config pointing at the temporary cache file.
    cfg: UpdateCheckConfig,
    /// Directory holding the cache file.
    dir: PathBuf,
}

impl TestCheck {
    /// Creates an empty cache directory that is unique to the calling test.
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "moonbase-update-test-{}-{name}",
            std::process::id()
        ));
        _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        Self {
            cfg: UpdateCheckConfig {
                vendor_id: "vendor".to_string(),
                product_id: "product".to_string(),
                current_version: "1.0.0".to_string(),
                cache_path: dir.join("update_check"),
                check_interval: CHECK_INTERVAL,
                failure_retry_interval: Duration::from_secs(20 * 60),
            },
            dir,
        }
    }

    /// Stores a cache file with the given contents.
    fn seed(&self, next_check_at: u64, latest_version: Option<&str>) {
        write_cache(
            &self.cfg.cache_path,
            &UpdateCache {
                next_check_at,
                latest_version: latest_version.map(str::to_string),
            },
        );
    }

    /// Returns the cache file's contents.
    fn cache(&self) -> UpdateCache {
        read_cache(&self.cfg.cache_path).unwrap()
    }
}

impl Drop for TestCheck {
    /// Removes the cache directory.
    fn drop(&mut self) {
        _ = fs::remove_dir_all(&self.dir);
    }
}

/// A fetch that fails the test if the policy contacts Moonbase.
fn no_fetch() -> Result<Option<String>, UpdateCheckError> {
    panic!("Moonbase must not be contacted");
}

/// A fetch failing with an error that is not related to rate limiting.
fn failing_fetch() -> Result<Option<String>, UpdateCheckError> {
    Err(UpdateCheckError::UnexpectedResponse(
        StatusCode::BAD_GATEWAY,
        String::new(),
    ))
}

/// Releases above the running version are updates, including over prereleases.
#[test]
fn newer_release_is_an_update() {
    assert!(is_newer_version("1.0.0", "1.0.1"));
    assert!(is_newer_version("1.1.0-rc1", "1.1.0"));
    assert!(is_newer_version("1.1.0-rc1-46-gc80deff", "1.1.0"));
}

/// The running version and anything below it are not updates.
#[test]
fn same_or_older_release_is_not_an_update() {
    assert!(!is_newer_version("1.1.0", "1.1.0"));
    assert!(!is_newer_version("1.1.0", "1.0.1"));
    assert!(!is_newer_version("1.1.0", "1.1.0-rc1"));
}

/// Versions that are not SemVer never report an update.
#[test]
fn unparsable_versions_are_not_an_update() {
    assert!(!is_newer_version("beta-0.3.1", "1.0.0"));
    assert!(!is_newer_version("1.0.0", "latest"));
    assert!(!is_newer_version("1.0.0", ""));
}

/// The latest version is read from the product response.
#[test]
fn parses_version_from_product_response() {
    assert_eq!(
        parse_latest_version(r#"{"id": "swell", "currentVersion": "0.4.0"}"#),
        Some(Some("0.4.0".to_string()))
    );
}

/// A product without a release has no version, whether null or absent.
#[test]
fn parses_product_without_release() {
    assert_eq!(
        parse_latest_version(r#"{"id": "swell", "currentVersion": null}"#),
        Some(None)
    );
    assert_eq!(parse_latest_version(r#"{"id": "swell"}"#), Some(None));
}

/// A body that is not a product response is rejected.
#[test]
fn rejects_malformed_product_response() {
    assert_eq!(parse_latest_version("<html>"), None);
}

/// Moonbase is not contacted before the next check is due.
#[test]
fn check_that_is_not_due_uses_cache() {
    let test = TestCheck::new("not_due");
    test.seed(NOW + 60, Some("1.2.0"));

    let check = check_with(&test.cfg, NOW, no_fetch);

    assert_eq!(check.latest_version.as_deref(), Some("1.2.0"));
    assert!(check.update_available);
    assert!(check.error.is_none());
}

/// The next check is pushed back before the request is made.
#[test]
fn due_check_claims_cache_before_fetching() {
    let test = TestCheck::new("lease");
    test.seed(NOW, Some("1.2.0"));
    let fetched = Cell::new(false);

    check_with(&test.cfg, NOW, || {
        let cache = test.cache();
        assert_eq!(
            cache.next_check_at,
            NOW + test.cfg.failure_retry_interval.as_secs()
        );
        assert_eq!(cache.latest_version.as_deref(), Some("1.2.0"));
        fetched.set(true);
        Ok(Some("1.3.0".to_string()))
    });

    assert!(fetched.get());
}

/// Intervals below the retry delay still block concurrent checks.
#[test]
fn claim_never_exceeds_check_interval() {
    let mut test = TestCheck::new("short_interval");
    test.cfg.check_interval = Duration::from_secs(600);

    check_with(&test.cfg, NOW, || {
        assert_eq!(test.cache().next_check_at, NOW + 600);
        failing_fetch()
    });

    // the claim must block other checks rather than look like a clock change
    check_with(&test.cfg, NOW + 1, no_fetch);
}

/// A successful request schedules the next check a full interval later.
#[test]
fn successful_fetch_updates_cache() {
    let test = TestCheck::new("success");

    let check = check_with(&test.cfg, NOW, || Ok(Some("1.3.0".to_string())));

    assert_eq!(check.latest_version.as_deref(), Some("1.3.0"));
    assert!(check.update_available);
    assert!(check.error.is_none());

    let cache = test.cache();
    assert_eq!(cache.next_check_at, NOW + CHECK_INTERVAL.as_secs());
    assert_eq!(cache.latest_version.as_deref(), Some("1.3.0"));
}

/// A product without a release is a successful check with no update.
#[test]
fn product_without_release_is_not_an_update() {
    let test = TestCheck::new("no_release");

    let check = check_with(&test.cfg, NOW, || Ok(None));

    assert_eq!(check.latest_version, None);
    assert!(!check.update_available);
    assert!(check.error.is_none());
    assert_eq!(test.cache().next_check_at, NOW + CHECK_INTERVAL.as_secs());
}

/// A failed request keeps the cached version and waits the configured retry interval.
#[test]
fn failed_fetch_keeps_cached_version() {
    let mut test = TestCheck::new("failure");
    test.cfg.failure_retry_interval = Duration::from_secs(2 * 60 * 60);
    test.seed(NOW, Some("1.2.0"));

    let check = check_with(&test.cfg, NOW, failing_fetch);

    assert_eq!(check.latest_version.as_deref(), Some("1.2.0"));
    assert!(check.update_available);
    assert!(check.error.is_some());

    let cache = test.cache();
    assert_eq!(
        cache.next_check_at,
        NOW + test.cfg.failure_retry_interval.as_secs()
    );
    assert_eq!(cache.latest_version.as_deref(), Some("1.2.0"));

    check_with(&test.cfg, cache.next_check_at - 1, no_fetch);
    let retried = check_with(&test.cfg, cache.next_check_at, || {
        Ok(Some("1.3.0".to_string()))
    });
    assert_eq!(retried.latest_version.as_deref(), Some("1.3.0"));
    assert!(retried.error.is_none());
}

/// The delay requested by Moonbase is honored.
#[test]
fn rate_limit_delays_next_check() {
    let test = TestCheck::new("rate_limit");
    test.seed(NOW, Some("1.2.0"));

    let check = check_with(&test.cfg, NOW, || {
        Err(UpdateCheckError::RateLimited(Some(Duration::from_secs(
            7200,
        ))))
    });

    assert!(check.error.is_some());
    let cache = test.cache();
    assert_eq!(cache.next_check_at, NOW + 7200);
    assert_eq!(cache.latest_version.as_deref(), Some("1.2.0"));
}

/// A long requested delay can not suspend checks beyond one interval.
#[test]
fn rate_limit_delay_is_capped_at_check_interval() {
    let test = TestCheck::new("rate_limit_cap");

    check_with(&test.cfg, NOW, || {
        Err(UpdateCheckError::RateLimited(Some(CHECK_INTERVAL * 10)))
    });

    assert_eq!(test.cache().next_check_at, NOW + CHECK_INTERVAL.as_secs());
}

/// A rate limit without a usable delay falls back to the configured retry interval.
#[test]
fn rate_limit_without_delay_uses_retry_interval() {
    let test = TestCheck::new("rate_limit_date");

    check_with(&test.cfg, NOW, || Err(UpdateCheckError::RateLimited(None)));

    assert_eq!(
        test.cache().next_check_at,
        NOW + test.cfg.failure_retry_interval.as_secs()
    );
}

/// A next check further away than one interval is not honored.
#[test]
fn clock_rollback_makes_check_due() {
    let test = TestCheck::new("rollback");
    test.seed(NOW + CHECK_INTERVAL.as_secs() + 1, Some("1.2.0"));

    let check = check_with(&test.cfg, NOW, || Ok(Some("1.3.0".to_string())));

    assert_eq!(check.latest_version.as_deref(), Some("1.3.0"));
}

/// An unreadable cache behaves like an empty one.
#[test]
fn corrupt_cache_makes_check_due() {
    let test = TestCheck::new("corrupt");
    fs::write(&test.cfg.cache_path, "not json").unwrap();

    let check = check_with(&test.cfg, NOW, || Ok(Some("1.3.0".to_string())));

    assert_eq!(check.latest_version.as_deref(), Some("1.3.0"));
}

/// Failing to write the cache does not affect the result.
#[test]
fn unwritable_cache_does_not_prevent_check() {
    let mut test = TestCheck::new("unwritable");
    test.cfg.cache_path = test.dir.join("missing").join("update_check");

    let check = check_with(&test.cfg, NOW, || Ok(Some("1.3.0".to_string())));

    assert!(check.update_available);
}
