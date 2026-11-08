/// Returns the base URL to make any Moonbase API requests to.
pub(crate) fn moonbase_api_base_url(vendor_id: &str) -> String {
    format!("https://{vendor_id}.moonbase.sh")
}
