use chrono::serde::ts_seconds;
use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Eq, PartialEq, Deserialize)]
pub enum ActivationMethod {
    /// The license has been activated offline and is irrevocable,
    /// therefore we mustn't check license validity online.
    Offline,
    /// The license has been activated online
    /// and may have been revoked from this machine since.
    /// We should regularly ask Moonbase if the license is still valid.
    Online,
}

/// The claims included in a validated license token provided by Moonbase.
#[derive(Deserialize)]
pub struct LicenseTokenClaims {
    pub method: ActivationMethod,

    /// The latest release version of the product, if any.
    #[serde(rename = "p:rel")]
    pub product_latest_version: Option<String>,

    /// The name of the user that owns this license.
    #[serde(rename = "u:name")]
    pub user_name: String,

    /// The signature of the device being activated.
    /// Should be checked against the user's device signature.
    #[serde(rename = "sig")]
    pub device_signature: String,

    /// The date and time at which the license token was last validated online.
    #[serde(rename = "validated", with = "ts_seconds")]
    pub last_validated: DateTime<Utc>,

    /// The date and time at which the license expires.
    #[serde(rename = "exp", with = "ts_seconds_option", default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether this license token represents a time-limited trial (true),
    /// or an owned license (false).
    pub trial: bool,
}
