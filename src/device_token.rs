use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::Serialize;

/// The contents of a device token
/// required by Moonbase for offline activation.
#[derive(Serialize)]
pub struct DeviceToken {
    /// The device's signature.
    #[serde(rename = "id")]
    pub signature: String,

    /// User-friendly device name shown to the customer
    /// when managing license activations.
    pub name: String,

    /// The id of the product being activated.
    #[serde(rename = "productId")]
    pub product_id: String,

    /// The license format to request from the Moonbase API.
    /// Must always be "JWT".
    format: String,
}

impl DeviceToken {
    /// Creates a new device token with the given device signature and display name
    /// for activation of the product with the given id.
    pub fn new(signature: String, name: String, product_id: String) -> Self {
        Self {
            signature,
            name,
            product_id,
            format: "JWT".into(),
        }
    }

    /// Creates the Base64-encoded payload that Moonbase
    /// expects from a device token file.
    pub fn serialize(&self) -> String {
        BASE64_STANDARD.encode(serde_json::to_string(self).unwrap())
    }
}
