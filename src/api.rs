use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Shared timeout for Moonbase API requests, in seconds.
static REQUEST_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(10);

/// Returns the shared Moonbase API request timeout in seconds.
///
/// The default is 10 seconds. See [set_request_timeout_secs] to change it.
pub fn request_timeout_secs() -> u64 {
    REQUEST_TIMEOUT_SECS.load(Ordering::Relaxed)
}

/// Sets the timeout in seconds for subsequent Moonbase API requests.
///
/// This applies to update checks and all license activation requests, including
/// requests made by already running activators. The timeout covers the entire
/// request through reading its response body. Requests already started retain
/// their timeout. The default is 10 seconds; zero means an immediate timeout.
///
/// ```
/// moonbase_licensing::set_request_timeout_secs(20);
/// assert_eq!(moonbase_licensing::request_timeout_secs(), 20);
/// ```
pub fn set_request_timeout_secs(seconds: u64) {
    REQUEST_TIMEOUT_SECS.store(seconds, Ordering::Relaxed);
}

/// Creates an agent with a snapshot of the timeout for one Moonbase request.
pub(crate) fn moonbase_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(request_timeout_secs())))
        .build()
        .into()
}

/// Returns the base URL to make any Moonbase API requests to.
pub(crate) fn moonbase_api_base_url(vendor_id: &str) -> String {
    format!("https://{vendor_id}.moonbase.sh")
}

#[cfg(test)]
#[path = "../tests/unit/api.rs"]
mod tests;
