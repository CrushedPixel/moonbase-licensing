//! Checks Moonbase for newer product releases without requiring a license.

use crate::api::{moonbase_agent, moonbase_api_base_url};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use ureq::http::header::RETRY_AFTER;
use ureq::http::StatusCode;

/// Configures an update check for one product.
#[derive(Clone, Debug)]
pub struct UpdateCheckConfig {
    /// The vendor's id on Moonbase.
    pub vendor_id: String,
    /// The product's id on Moonbase.
    pub product_id: String,
    /// The version of the running software, in SemVer format.
    pub current_version: String,
    /// The file used to remember the latest version and the next check time.
    /// Its parent directory must exist for the cache to take effect.
    pub cache_path: PathBuf,
    /// The minimum time between two successful requests.
    pub check_interval: Duration,
    /// The delay before retrying a failed request.
    pub failure_retry_interval: Duration,
}

/// The outcome of [check_for_update].
#[derive(Debug)]
pub struct UpdateCheck {
    /// The latest released version, or [None] if Moonbase has no release
    /// or no version has been retrieved yet.
    pub latest_version: Option<String>,
    /// Whether `latest_version` is newer than the running software.
    pub update_available: bool,
    /// The reason why Moonbase could not be asked for the latest version.
    /// The other fields then reflect the cached version.
    pub error: Option<UpdateCheckError>,
}

impl UpdateCheck {
    /// Compares the given latest version against the running software.
    fn new(
        cfg: &UpdateCheckConfig,
        latest_version: Option<String>,
        error: Option<UpdateCheckError>,
    ) -> Self {
        let update_available = latest_version
            .as_deref()
            .is_some_and(|latest| is_newer_version(&cfg.current_version, latest));
        Self {
            latest_version,
            update_available,
            error,
        }
    }
}

/// An error encountered when asking Moonbase for the latest version.
#[derive(Error, Debug)]
pub enum UpdateCheckError {
    /// An I/O error occurred when contacting the Moonbase API.
    #[error("issues contacting API: {0}")]
    Io(#[from] ureq::Error),

    /// The Moonbase API rejected the request because too many have been made.
    /// Contains the requested delay, if it was expressed in seconds.
    #[error("rate limited by API, retry after {0:?}")]
    RateLimited(Option<Duration>),

    /// We received an unexpected response from the Moonbase API.
    #[error("unexpected response with status code {0} and body {1}")]
    UnexpectedResponse(StatusCode, String),
}

/// The contents of the update check cache file.
#[derive(Serialize, Deserialize)]
struct UpdateCache {
    /// Unix timestamp in seconds before which Moonbase must not be contacted.
    next_check_at: u64,
    /// The latest version reported by Moonbase.
    latest_version: Option<String>,
}

impl UpdateCache {
    /// Returns whether the next check is still in the future.
    ///
    /// A wait longer than `check_interval` can only be the result of the system
    /// clock moving backwards, so it does not block a check.
    fn is_check_pending(&self, now: u64, check_interval: Duration) -> bool {
        now < self.next_check_at && self.next_check_at <= now + check_interval.as_secs()
    }
}

/// The part of the Moonbase product response relevant for update checks.
#[derive(Deserialize)]
struct ProductResponse {
    /// The latest release's version, which is null without a published release.
    #[serde(rename = "currentVersion")]
    current_version: Option<String>,
}

/// Returns whether `latest_version` has greater SemVer precedence than `current_version`.
///
/// Versions that are not valid SemVer never compare as newer.
pub fn is_newer_version(current_version: &str, latest_version: &str) -> bool {
    let (Ok(current_version), Ok(latest_version)) = (
        Version::parse(current_version),
        Version::parse(latest_version),
    ) else {
        return false;
    };

    latest_version.cmp_precedence(&current_version).is_gt()
}

/// Reports whether Moonbase has a newer release of the product. This requires no license.
///
/// Results are cached in `cache_path`, and Moonbase is only contacted once
/// `check_interval` has passed since the last successful request.
/// Failed requests are retried by the first call after `failure_retry_interval`,
/// honoring the delay requested by Moonbase if rate limited.
/// Retry delays are capped at `check_interval`.
///
/// This call blocks while contacting Moonbase,
/// so it should not be made on a UI thread.
pub fn check_for_update(cfg: &UpdateCheckConfig) -> UpdateCheck {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    check_with(cfg, now, || fetch_latest_version(cfg))
}

/// Applies the caching policy of [check_for_update] around `fetch`.
fn check_with(
    cfg: &UpdateCheckConfig,
    now: u64,
    fetch: impl FnOnce() -> Result<Option<String>, UpdateCheckError>,
) -> UpdateCheck {
    let cache = read_cache(&cfg.cache_path);
    if let Some(cache) = cache.as_ref()
        && cache.is_check_pending(now, cfg.check_interval)
    {
        return UpdateCheck::new(cfg, cache.latest_version.clone(), None);
    }

    let cached_version = cache.and_then(|cache| cache.latest_version);
    let failure_retry_interval = cfg.failure_retry_interval.min(cfg.check_interval);

    // Claim this check before making the request, so that other instances
    // starting at the same time don't contact Moonbase as well.
    // This also serves as the retry delay if the request fails.
    write_cache(
        &cfg.cache_path,
        &UpdateCache {
            next_check_at: now + failure_retry_interval.as_secs(),
            latest_version: cached_version.clone(),
        },
    );

    match fetch() {
        Ok(latest_version) => {
            write_cache(
                &cfg.cache_path,
                &UpdateCache {
                    next_check_at: now + cfg.check_interval.as_secs(),
                    latest_version: latest_version.clone(),
                },
            );
            UpdateCheck::new(cfg, latest_version, None)
        }
        Err(error) => {
            if let UpdateCheckError::RateLimited(retry_after) = &error {
                let delay = retry_after
                    .unwrap_or(failure_retry_interval)
                    .min(cfg.check_interval);
                write_cache(
                    &cfg.cache_path,
                    &UpdateCache {
                        next_check_at: now + delay.as_secs(),
                        latest_version: cached_version.clone(),
                    },
                );
            }
            UpdateCheck::new(cfg, cached_version, Some(error))
        }
    }
}

/// Reads the cache file. A missing or unreadable file is the same as an empty cache,
/// as it only causes another request to Moonbase.
fn read_cache(path: &Path) -> Option<UpdateCache> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// Writes the cache file. Failure to do so is not an error,
/// as it only causes another request to Moonbase.
fn write_cache(path: &Path, cache: &UpdateCache) {
    if let Ok(contents) = serde_json::to_string(cache) {
        _ = fs::write(path, contents);
    }
}

/// Asks the Moonbase API for the product's latest version.
///
/// This endpoint is public, so no license or API key is involved.
fn fetch_latest_version(cfg: &UpdateCheckConfig) -> Result<Option<String>, UpdateCheckError> {
    let response = moonbase_agent()
        .get(format!(
            "{}/api/customer/inventory/products/{}",
            moonbase_api_base_url(&cfg.vendor_id),
            cfg.product_id
        ))
        .config()
        .http_status_as_error(false)
        .build()
        .call()?;

    let status = response.status();

    if status == StatusCode::TOO_MANY_REQUESTS {
        // Retry-After may also be an HTTP date, which is treated as no delay given
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .map(Duration::from_secs);
        return Err(UpdateCheckError::RateLimited(retry_after));
    }

    if status == StatusCode::OK {
        let body = response.into_body().read_to_string()?;
        return parse_latest_version(&body)
            .ok_or_else(|| UpdateCheckError::UnexpectedResponse(status, body));
    }

    // don't propagate any errors when reading the response body here,
    // as reporting the actual status code error is more important
    let body = response.into_body().read_to_string().unwrap_or_default();
    Err(UpdateCheckError::UnexpectedResponse(status, body))
}

/// Extracts the latest version from a product response body, returning [None] if it is malformed.
fn parse_latest_version(body: &str) -> Option<Option<String>> {
    let product: ProductResponse = serde_json::from_str(body).ok()?;
    Some(product.current_version)
}

#[cfg(test)]
#[path = "../tests/unit/update.rs"]
mod tests;
