use crate::claims::{ActivationMethod, LicenseTokenClaims};
use crate::device_token::DeviceToken;
use backon::{BlockingRetryable, ExponentialBuilder};
use chrono::Utc;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{get_current_timestamp, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{sleep, JoinHandle};
use std::time::Duration;
use std::{fs, io, thread};
use thiserror::Error;
use ureq::http::StatusCode;

/// Represents the software's current activation state.
pub enum ActivationState {
    /// The plugin requires activation.
    ///
    /// The provided String contains the URL to open
    /// in the user's browser for online activation.
    /// If it is None, only offline activation is available at this point,
    /// but online activation may become available later with a new [ActivationState].
    NeedsActivation(Option<String>),

    /// The plugin has been successfully activated.
    Activated(LicenseTokenClaims),
}

/// Errors that can occur during the activation process.
#[derive(Error, Debug)]
pub enum ActivationError {
    /// An error occurred when validating a cached token.
    #[error("Could not validate cached token: {0}")]
    LoadCachedToken(#[from] CachedTokenError),

    /// Could not persist the token to disk for caching purposes.
    #[error("Could not save license token to disk: {0}")]
    SaveCachedToken(#[from] io::Error),

    /// Could not fetch the online activation URL from the Moonbase API.
    #[error("Could not fetch online activation url: {0}")]
    FetchActivationUrl(MoonbaseApiError),

    /// Could not fetch the activation state of an online token from the Moonbase API.
    #[error("Could not fetch activation state of online token: {0}")]
    FetchActivationState(MoonbaseApiError),

    /// Could not validate an offline token provided by the user.
    #[error("Could not validate offline token: {0}")]
    OfflineToken(#[from] OfflineTokenValidationError),
}

#[derive(Error, Debug)]
pub enum OfflineTokenValidationError {
    #[error("the license token is invalid: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
    #[error("inapplicable token: {0}")]
    Inapplicable(#[from] InapplicableTokenError),
    #[error("the license token is not an offline token")]
    NoOfflineToken,
}

#[derive(Error, Debug)]
pub enum CachedTokenError {
    /// An I/O error occurred when reading the token file from disk.
    #[error("error loading cached token file: {0}")]
    Io(#[from] io::Error),

    /// The token failed validation by the JWT parser.
    #[error("invalid JWT payload: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),

    /// The token is not valid for the product or hardware device.
    #[error("inapplicable token: {0}")]
    Inapplicable(#[from] InapplicableTokenError),

    /// The token has been marked as revoked by Moonbase.
    #[error("token has been revoked")]
    Revoked,

    /// The token is valid, but too old to trust,
    /// and it couldn't be refreshed.
    #[error("token could not be refreshed")]
    RefreshFailed(#[from] MoonbaseApiError),
}

#[derive(Error, Debug)]
pub enum InapplicableTokenError {
    #[error("the license token is not valid for this device")]
    InvalidDeviceSignature,
}

#[derive(Error, Debug)]
pub enum MoonbaseApiError {
    /// An I/O error occurred when contacting the Moonbase API.
    #[error("issues contacting API: {0}")]
    Io(#[from] ureq::Error),

    /// We received an unexpected response from the Moonbase API.
    #[error("unexpected response with status code {0} and body {1}")]
    UnexpectedResponse(StatusCode, String),

    /// The token returned by the Moonbase API was malformed.
    #[error("invalid token: {0}")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),
}

/// Configuration options for the [LicenseActivator].
#[derive(Clone)]
pub struct LicenseActivationConfig {
    /// The Moonbase vendor id for the store.
    /// Used to determine the API endpoint, i.e.
    /// https://{vendor_id}.moonbase.sh
    pub vendor_id: String,
    /// The Moonbase product id that a license needs to be valid for.
    pub product_id: String,
    /// The public key to verify the signed JWT payload.
    pub jwt_pubkey: String,

    /// The path where the cached license token payload is stored on disk.
    pub cached_token_path: PathBuf,

    /// User-friendly display name of the device the software is running on.
    /// Reported to Moonbase when activating a license.
    pub device_name: String,
    /// The unique signature of the device the software is running on.
    pub device_signature: String,

    /// The age threshold beyond which the activator attempts to refresh online tokens.
    /// Before this age, the token is accepted without attempting any further online validation.
    pub online_token_refresh_threshold: Duration,
    /// The age threshold beyond which an online token is deemed
    /// too old to trust and must be refreshed before being accepted.
    pub online_token_expiration_threshold: Duration,
}

/// Performs license activation.
pub struct LicenseActivator {
    cfg: LicenseActivationConfig,

    /// Receiver for the main thread to poll changes to the license activation state.
    ///
    /// Once [ActivationState::Activated] has been received,
    /// the consumer can stop reading from this channel,
    /// as the license activation won't be revoked again during this session.
    ///
    /// Until the first value is received,
    /// the license activation state is undetermined,
    /// and the user should just be shown a "loading" state.
    pub state_recv: Receiver<ActivationState>,
    state_send: Sender<ActivationState>,

    /// Receiver for the main thread to poll errors encountered during license activation.
    ///
    /// Which of these you want to display is up to your discretion.
    /// You may want to display only the most recent error,
    /// or perhaps display each error and make them dismissable.
    pub error_recv: Receiver<ActivationError>,
    error_send: Sender<ActivationError>,

    /// While this is true, the license activator polls the Moonbase API
    /// to check if the user has activated the license online.
    ///
    /// Set this to false whenever the user isn't on the online activation screen
    /// to avoid spamming the Moonbase API and getting rate limited.
    pub poll_online_activation: Arc<AtomicBool>,

    /// Whether the worker thread should keep running.
    running: Arc<AtomicBool>,
    /// Join handle for the worker thread.
    join: Option<JoinHandle<()>>,
}

impl Drop for LicenseActivator {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.join.take().unwrap().join().unwrap();
    }
}

impl LicenseActivator {
    /// Creates a new license activator,
    /// spawning the background threads that perform license checking.
    ///
    /// These background threads run until activation is successful
    /// or the [LicenseActivator] is dropped.
    pub fn spawn(cfg: LicenseActivationConfig) -> Self {
        // create communication channels to report activation state changes to calling thread
        let (state_send, state_recv) = std::sync::mpsc::channel();
        let (error_send, error_recv) = std::sync::mpsc::channel();

        // spawn worker thread
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let poll_online_activation = Arc::new(AtomicBool::new(false));
        let poll_online_activation_clone = poll_online_activation.clone();

        let state_send_clone = state_send.clone();
        let error_send_clone = error_send.clone();
        let cfg_clone = cfg.clone();

        let join = thread::spawn(|| {
            worker_thread(
                running_clone,
                state_send_clone,
                error_send_clone,
                poll_online_activation_clone,
                cfg_clone,
            );
        });

        Self {
            cfg,

            state_recv,
            state_send,

            error_recv,
            error_send,

            poll_online_activation,

            running,
            join: Some(join),
        }
    }

    /// Creates and returns the contents to write to the machine file used for offline activation.
    pub fn machine_file_contents(&self) -> String {
        DeviceToken::new(
            self.cfg.device_signature.clone(),
            self.cfg.device_name.clone(),
            self.cfg.product_id.clone(),
        )
        .serialize()
    }

    /// Submits the given offline activation token for validation,
    /// caching it on disk if it's valid.
    ///
    /// The result of the validation can be obtained
    /// from the state and error receivers as usual.
    pub fn submit_offline_activation_token(&mut self, token: &String) {
        match self.check_offline_activation_token(token) {
            Ok(claims) => {
                _ = self.state_send.send(ActivationState::Activated(claims));

                // stop the worker thread, as we don't need any more validation from here on
                self.running.store(false, Ordering::Relaxed);

                // persist the token on disk
                if let Err(e) = fs::write(&self.cfg.cached_token_path, token) {
                    _ = self.error_send.send(ActivationError::SaveCachedToken(e));
                }
            }
            Err(e) => _ = self.error_send.send(ActivationError::OfflineToken(e)),
        }
    }

    fn check_offline_activation_token(
        &mut self,
        token: &String,
    ) -> Result<LicenseTokenClaims, OfflineTokenValidationError> {
        let claims = parse_token(&self.cfg, token)?;

        if claims.method != ActivationMethod::Offline {
            return Err(OfflineTokenValidationError::NoOfflineToken);
        }

        validate_token_applicable(&self.cfg, &claims)?;

        Ok(claims)
    }
}

impl LicenseActivationConfig {
    /// Returns the base URL to make any Moonbase API requests to.
    fn moonbase_api_base_url(&self) -> String {
        format!("https://{}.moonbase.sh", self.vendor_id)
    }
}

fn worker_thread(
    running: Arc<AtomicBool>,
    state_send: Sender<ActivationState>,
    error_send: Sender<ActivationError>,
    poll_online_activation: Arc<AtomicBool>,
    cfg: LicenseActivationConfig,
) {
    // first, try to load a cached license token from disk
    match check_cached_token(&cfg, running.clone()) {
        Ok(Some(result)) => {
            _ = state_send.send(ActivationState::Activated(result.claims));

            if let Some(token) = result.new_token {
                // persist the new token on disk
                if let Err(e) = fs::write(&cfg.cached_token_path, token) {
                    _ = error_send.send(ActivationError::SaveCachedToken(e));
                }
            }

            return;
        }
        Ok(None) => {
            // no cached token was found
        }
        Err(e) => {
            // cached token couldn't be validated
            _ = error_send.send(ActivationError::LoadCachedToken(e));
        }
    }

    // we don't have a valid cached token -
    // the user has to activate the plugin either offline or online.

    // we don't yet have a URL to provide for online activation,
    // but we can supply that in a subsequent state update.
    _ = state_send.send(ActivationState::NeedsActivation(None));

    // ask Moonbase for the endpoints to perform online activation
    let activation_urls = match (|| moonbase_request_online_activation(&cfg))
        .retry(
            &ExponentialBuilder::default()
                .with_max_delay(Duration::from_secs(10))
                .with_max_times(10),
        )
        .when(|_| running.load(Ordering::Relaxed))
        .call()
    {
        Ok(activation_urls) => Some(activation_urls),
        Err(e) => {
            // we couldn't get an online activation URL from Moonbase after several tries
            _ = error_send.send(ActivationError::FetchActivationUrl(e));
            None
        }
    };

    if let Some(activation_urls) = activation_urls.as_ref() {
        // we got the URLs for online activation
        // send the user-facing activation URL to the main thread
        _ = state_send.send(ActivationState::NeedsActivation(Some(
            activation_urls.browser.clone(),
        )));
    }

    // now we're waiting for the user to activate the plugin,
    // or the thread to be stopped
    while running.load(Ordering::Relaxed) {
        sleep(Duration::from_secs(5));

        match activation_urls.as_ref() {
            Some(activation_urls) if poll_online_activation.load(Ordering::Relaxed) => {
                // the user is attempting online activation -
                // check if they have succeeded

                match moonbase_check_online_activation(&cfg, &activation_urls.request) {
                    Ok(TokenValidationResponse::Valid(token, claims)) => {
                        // the software has been activated!
                        _ = state_send.send(ActivationState::Activated(claims));

                        // persist the token on disk
                        if let Err(e) = fs::write(&cfg.cached_token_path, token) {
                            _ = error_send.send(ActivationError::SaveCachedToken(e));
                        }

                        return;
                    }
                    Ok(TokenValidationResponse::Invalid) => {
                        // the token hasn't yet been activated - simply try again
                    }
                    Err(e) => {
                        _ = error_send.send(ActivationError::FetchActivationState(e));
                    }
                }
            }
            _ => {
                // if the user isn't currently attempting to activate the plugin in this plugin instance,
                // check if another instance of the software has activated the plugin in the meantime
                if let Ok(Some(result)) = check_cached_token(&cfg, running.clone()) {
                    _ = state_send.send(ActivationState::Activated(result.claims));

                    if let Some(token) = result.new_token {
                        // persist the new token on disk
                        if let Err(e) = fs::write(&cfg.cached_token_path, token) {
                            _ = error_send.send(ActivationError::SaveCachedToken(e));
                        }
                    }

                    return;
                }
            }
        }
    }
}

struct CachedTokenCheckResult {
    /// The claims that were validated.
    claims: LicenseTokenClaims,
    /// A new, refreshed token that must be cached on disk.
    new_token: Option<String>,
}

/// Checks whether there is an existing license token on disk
/// that represents an activated license.
///
/// Online tokens are refreshed if required,
/// and the new token is returned in this case.
///
/// None is returned if no cached token exists.
fn check_cached_token(
    cfg: &LicenseActivationConfig,
    running: Arc<AtomicBool>,
) -> Result<Option<CachedTokenCheckResult>, CachedTokenError> {
    match load_cached_token(cfg) {
        Ok(Some((token, claims))) => {
            match claims.method {
                ActivationMethod::Offline => {
                    // it's an offline activated token,
                    // so it will stay valid forever.
                    // validation succeeded!
                    Ok(Some(CachedTokenCheckResult {
                        claims,
                        new_token: None,
                    }))
                }
                ActivationMethod::Online => {
                    // it's an online activated token,
                    // so we should check if it's still valid

                    let token_validation_age = Utc::now() - claims.last_validated;

                    // Convert validation age to Duration.
                    // If last_validated lies in the future from the perspective
                    // of the machine running this code (conversion returns Error),
                    // we can't trust the token and require re-validation.
                    let token_validation_age = token_validation_age.to_std().ok();

                    if let Some(token_validation_age) = token_validation_age {
                        if token_validation_age < cfg.online_token_refresh_threshold {
                            // if the token was last validated very recently,
                            // we just accept it and don't even attempt to refresh and validate it.
                            // this minimizes API requests and waiting time for the user.
                            return Ok(Some(CachedTokenCheckResult {
                                claims,
                                new_token: None,
                            }));
                        }
                    }

                    // try to validate and refresh the token
                    match (|| moonbase_refresh_token(cfg, &token))
                        .retry(
                            &ExponentialBuilder::default()
                                .with_max_delay(Duration::from_secs(5))
                                .with_max_times(5),
                        )
                        .when(|_| running.load(Ordering::Relaxed))
                        .call()
                    {
                        Ok(TokenValidationResponse::Valid(new_token, claims)) => {
                            // the token was validated, and we received a refreshed one.
                            Ok(Some(CachedTokenCheckResult {
                                claims,
                                new_token: Some(new_token),
                            }))
                        }
                        Ok(TokenValidationResponse::Invalid) => {
                            // Moonbase has revoked the token!
                            Err(CachedTokenError::Revoked)
                        }
                        Err(e) => {
                            // the cached token couldn't be validated.

                            if let Some(token_validation_age) = token_validation_age {
                                if token_validation_age < cfg.online_token_expiration_threshold {
                                    // if the token was validated somewhat recently,
                                    // we give the user the benefit of the doubt
                                    // and allow them to use the token without refreshing.
                                    return Ok(Some(CachedTokenCheckResult {
                                        claims,
                                        new_token: None,
                                    }));
                                }
                            }

                            Err(e.into())
                        }
                    }
                }
            }
        }
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Parses and validates a license token file on disk.
///
/// If a license token is returned, it is or has been valid at some point in time,
/// but in the case of an Online activated license,
/// the caller should still check the `last_validated` field
/// and validate online if necessary.
fn load_cached_token(
    cfg: &LicenseActivationConfig,
) -> Result<Option<(String, LicenseTokenClaims)>, CachedTokenError> {
    if !fs::exists(&cfg.cached_token_path)? {
        return Ok(None);
    }

    let token = fs::read_to_string(&cfg.cached_token_path)?;

    // parse and validate the token
    let claims = parse_token(cfg, &token)?;

    // ensure the token applies to this product and device
    validate_token_applicable(cfg, &claims)?;

    Ok(Some((token, claims)))
}

/// Parses a JWT token and checks its validity.
///
/// This does not validate whether the token
/// applies to the current hardware and product,
/// only whether it's a well-formed token.
fn parse_token(
    cfg: &LicenseActivationConfig,
    token: &String,
) -> Result<LicenseTokenClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&cfg.product_id]);

    // disable validation of expiry as it's not always given
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let claims = jsonwebtoken::decode::<LicenseTokenClaims>(
        token.as_str(),
        &DecodingKey::from_rsa_pem(cfg.jwt_pubkey.as_bytes()).unwrap(),
        &validation,
    )?
    .claims;

    // validate token expiration date
    // similar to how the library does it when validate_exp is true
    if let Some(expires_at) = claims.expires_at {
        if expires_at.timestamp() as u64 - validation.reject_tokens_expiring_in_less_than
            < get_current_timestamp() - validation.leeway
        {
            return Err(ErrorKind::ExpiredSignature.into());
        }
    }
    Ok(claims)
}

fn validate_token_applicable(
    cfg: &LicenseActivationConfig,
    claims: &LicenseTokenClaims,
) -> Result<(), InapplicableTokenError> {
    if claims.device_signature != cfg.device_signature {
        return Err(InapplicableTokenError::InvalidDeviceSignature);
    }

    Ok(())
}

enum TokenValidationResponse {
    /// The token is valid and a refreshed token is provided.
    Valid(String, LicenseTokenClaims),
    /// The token is invalid.
    Invalid,
}

/// Asks the Moonbase API whether the given license token is still valid.
/// If it is, a new token with updated `last_updated` property is returned.
fn moonbase_refresh_token(
    cfg: &LicenseActivationConfig,
    token: &String,
) -> Result<TokenValidationResponse, MoonbaseApiError> {
    let response = ureq::post(format!(
        "{}/api/client/licenses/{}/validate",
        cfg.moonbase_api_base_url(),
        cfg.product_id
    ))
    .config()
    .timeout_global(Some(Duration::from_secs(10)))
    .build()
    .content_type("text/plain")
    .send(token)?;

    let status = response.status();

    if status == StatusCode::OK {
        // the token was successfully validated.
        // the response body contains the refreshed token
        let token = response.into_body().read_to_string()?;

        // parse the refreshed token
        return match parse_token(cfg, &token) {
            Ok(claims) => Ok(TokenValidationResponse::Valid(token, claims)),
            Err(_) => Err(MoonbaseApiError::UnexpectedResponse(status, token)),
        };
    }

    // Moonbase responds with 400 Bad Request if the license is not valid anymore
    if status == StatusCode::BAD_REQUEST {
        return Ok(TokenValidationResponse::Invalid);
    }

    // Moonbase responded with a status code that we don't expect.
    Err(MoonbaseApiError::UnexpectedResponse(
        status,
        response
            .into_body()
            .read_to_string()
            // don't propagate any errors when reading the response body here,
            // as reporting the actual status code error is more important
            .unwrap_or("".to_string()),
    ))
}

#[derive(Serialize)]
struct ActivationUrlsRequestPayload {
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "deviceSignature")]
    device_signature: String,
}

#[derive(Deserialize)]
struct ActivationUrls {
    /// The API endpoint to check whether the user
    /// has activated the software.
    request: String,
    /// The URL at which the user can activate
    /// the software in their browser.
    browser: String,
}

/// Asks the Moonbase API for the URLs to perform online activation.
fn moonbase_request_online_activation(
    cfg: &LicenseActivationConfig,
) -> Result<ActivationUrls, MoonbaseApiError> {
    let response = ureq::post(format!(
        "{}/api/client/activations/{}/request",
        cfg.moonbase_api_base_url(),
        cfg.product_id
    ))
    .config()
    .timeout_global(Some(Duration::from_secs(10)))
    .build()
    .send_json(ActivationUrlsRequestPayload {
        device_name: cfg.device_name.clone(),
        device_signature: cfg.device_signature.clone(),
    })?;

    let status = response.status();
    if status == StatusCode::OK {
        // parse the response body
        let mut body = response.into_body();
        return match body.read_json::<ActivationUrls>() {
            Ok(response) => Ok(response),
            Err(_) => Err(MoonbaseApiError::UnexpectedResponse(
                status,
                body.read_to_string().unwrap_or("".into()),
            )),
        };
    }

    // Moonbase responded with a status code that we don't expect.
    Err(MoonbaseApiError::UnexpectedResponse(
        status,
        response
            .into_body()
            .read_to_string()
            // don't propagate any errors when reading the response body here,
            // as reporting the actual status code error is more important
            .unwrap_or("".into()),
    ))
}

/// Polls the given Moonbase activation URL to check if the user
/// has activated their software using online activation.
fn moonbase_check_online_activation(
    cfg: &LicenseActivationConfig,
    url: &String,
) -> Result<TokenValidationResponse, MoonbaseApiError> {
    let response = ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .call()?;

    let status = response.status();

    if status == StatusCode::NO_CONTENT {
        // the product has not yet been activated.
        return Ok(TokenValidationResponse::Invalid);
    }

    if status == StatusCode::OK {
        // the product was activated.
        // the response body contains the license token
        let token = response.into_body().read_to_string()?;

        // parse the token
        let claims = parse_token(cfg, &token)?;
        return Ok(TokenValidationResponse::Valid(token, claims));
    }

    // Moonbase responded with a status code that we don't expect.
    Err(MoonbaseApiError::UnexpectedResponse(
        status,
        response
            .into_body()
            .read_to_string()
            // don't propagate any errors when reading the response body here,
            // as reporting the actual status code error is more important
            .unwrap_or("".to_string()),
    ))
}
