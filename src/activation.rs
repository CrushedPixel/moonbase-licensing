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
use std::thread::{JoinHandle, Thread};
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
    Activated {
        /// The validated claims that grant access to the product.
        claims: LicenseTokenClaims,

        /// When the license is a trial,
        /// this contains another online activation URL
        /// to open in the user's browser to install a purchased license.
        ///
        /// May be None temporarily for trials as well
        /// while fetching from the Moonbase API.
        followup_online_activation_url: Option<String>,
    },
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

    /// Online validation by Moonbase failed.
    #[error("online validation failed: {1}")]
    ValidationFailed(ValidationFailedType, String),

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

/// The reason why online license validation failed.
#[derive(Debug)]
pub enum ValidationFailedType {
    LicenseRevoked,
    LicenseActivationRevoked,
    LicenseExpired,
    NoEligibleLicense,
    /// Unknown error type in Moonbase API response -
    /// if this is reached, this library needs updating!
    Unknown,
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

    /// Receiver for activation states and any accepted token that must be cached.
    state_recv: Receiver<(ActivationState, Option<String>)>,
    /// Sender used to publish directly submitted offline activations.
    state_send: Sender<(ActivationState, Option<String>)>,
    /// Whether a purchased activation has already been returned by [Self::poll].
    activation_finished: bool,

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
    ///
    /// This flag is set to false automatically when a trial license is installed,
    /// so you must enable it again if you open
    /// the follow-up online activation URL in the user's browser.
    pub poll_online_activation: Arc<AtomicBool>,

    /// Whether the worker thread should keep running.
    running: Arc<AtomicBool>,
    /// Handle used to interrupt the worker's timed wait.
    worker_thread: Thread,
    /// Join handle for the worker thread.
    worker_join: Option<JoinHandle<()>>,
}

impl Drop for LicenseActivator {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        // wake the worker so shutdown does not wait for the polling interval
        self.worker_thread.unpark();
        self.worker_join.take().unwrap().join().unwrap();
    }
}

impl LicenseActivator {
    /// Creates a new license activator,
    /// spawning the background threads that perform license checking.
    ///
    /// The background worker runs until a non-trial license is activated
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
        // retain the thread handle so its timed wait can be interrupted
        let worker_thread = join.thread().clone();

        Self {
            cfg,

            state_recv,
            state_send,
            activation_finished: false,

            error_recv,
            error_send,

            poll_online_activation,

            running,
            worker_thread,
            worker_join: Some(join),
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

    /// Polls and returns the most recent activation state update, if any is available.
    ///
    /// Until the first value is returned, the license activation state is undetermined,
    /// and the user should just be shown a "loading" state.
    ///
    /// After a trial activation, you may receive another [ActivationState::Activated]
    /// with an URL to perform a follow-up non-trial activation.
    ///
    /// After a non-trial activation, the activator stops and you can stop polling.
    pub fn poll(&mut self) -> Option<ActivationState> {
        if self.activation_finished {
            return None;
        }

        let mut latest_state = None;
        let mut token_to_save = None;

        // drain updates so the caller receives only most recent state
        while let Ok((state, new_token)) = self.state_recv.try_recv() {
            // whenever the worker emits an activation state
            // _with_ a follow-up online activation url,
            // it previously already sent one without,
            // so we don't need to save token to file in this case.
            if matches!(
                &state,
                ActivationState::Activated {
                    followup_online_activation_url: None,
                    ..
                }
            ) {
                token_to_save = new_token;
            }

            if matches!(
                &state,
                ActivationState::Activated { claims, .. } if !claims.trial
            ) {
                // a non-trial activation finishes the flow
                self.activation_finished = true;
                latest_state = Some(state);
                break;
            }

            latest_state = Some(state);
        }

        // save token to file
        if let Some(token) = token_to_save
            && let Err(e) = fs::write(&self.cfg.cached_token_path, token)
        {
            _ = self.error_send.send(ActivationError::SaveCachedToken(e));
        }

        latest_state
    }

    /// Submits the given offline activation token for validation,
    /// queuing it to be cached if it's valid.
    ///
    /// The result of the validation can be obtained
    /// by polling activation states and errors as usual.
    pub fn submit_offline_activation_token(&mut self, token: &str) {
        match self.check_offline_activation_token(token) {
            Ok(claims) => {
                if publish_activation(
                    &self.running,
                    &self.state_send,
                    claims,
                    Some(token.to_string()),
                ) {
                    // interrupt the worker's timed wait so it can stop immediately
                    self.worker_thread.unpark();
                }
            }
            Err(e) => _ = self.error_send.send(ActivationError::OfflineToken(e)),
        }
    }

    fn check_offline_activation_token(
        &mut self,
        token: &str,
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
    state_send: Sender<(ActivationState, Option<String>)>,
    error_send: Sender<ActivationError>,
    poll_online_activation: Arc<AtomicBool>,
    cfg: LicenseActivationConfig,
) {
    let mut active_trial = None;

    // first, try to load a cached license token from disk
    let cached_result = check_cached_token(&cfg, running.clone(), false);

    if !running.load(Ordering::Relaxed) {
        return;
    }

    match cached_result {
        Ok(Some(result)) => {
            let claims = result.claims;

            // grant access immediately, without waiting for another activation URL
            if !publish_activation(&running, &state_send, claims.clone(), result.new_token) {
                return;
            }

            if claims.trial {
                // result polling must be enabled explicitly for the replacement activation
                poll_online_activation.store(false, Ordering::Relaxed);
                active_trial = Some(claims);
            } else {
                // a purchased cached license finishes activation
                return;
            }
        }
        Ok(None) => {
            // no cached token was found
        }
        Err(e) => {
            // cached token couldn't be validated
            _ = error_send.send(ActivationError::LoadCachedToken(e));
        }
    }

    if active_trial.is_none() {
        // we don't have a valid cached token -
        // the user has to activate the plugin either offline or online.

        // we don't yet have a URL to provide for online activation,
        // but we can supply that in a subsequent state update.
        _ = state_send.send((ActivationState::NeedsActivation(None), None));
    }

    'request_url: while running.load(Ordering::Relaxed) {
        // ask Moonbase for the endpoints to perform online activation
        let requested_urls = (|| moonbase_request_online_activation(&cfg))
            .retry(
                &ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .when(|_| running.load(Ordering::Relaxed))
            .call();

        if !running.load(Ordering::Relaxed) {
            return;
        }

        let activation_urls = match requested_urls {
            Ok(urls) => {
                // we got the URLs for online activation
                if let Some(claims) = active_trial.as_ref() {
                    // send the follow-up URL while preserving the active trial claims
                    _ = state_send.send((
                        ActivationState::Activated {
                            claims: claims.clone(),
                            followup_online_activation_url: Some(urls.browser.clone()),
                        },
                        None,
                    ));
                } else {
                    // send the user-facing activation URL to the main thread
                    _ = state_send.send((
                        ActivationState::NeedsActivation(Some(urls.browser.clone())),
                        None,
                    ));
                }
                Some(urls)
            }
            Err(e) => {
                // we couldn't get an online activation URL from Moonbase after several tries
                _ = error_send.send(ActivationError::FetchActivationUrl(e));
                None
            }
        };

        // now we're waiting for the user to activate the plugin,
        // for another instance to install a license, or for the thread to be stopped
        while running.load(Ordering::Relaxed) {
            // park instead of sleeping so shutdown and offline activation can wake the worker
            thread::park_timeout(Duration::from_secs(5));

            if !running.load(Ordering::Relaxed) {
                return;
            }

            if let Some(urls) = activation_urls.as_ref()
                && poll_online_activation.load(Ordering::Relaxed)
            {
                // the user is attempting online activation -
                // check if they have succeeded
                let activation_result = moonbase_check_online_activation(&cfg, &urls.request);

                if !running.load(Ordering::Relaxed) {
                    return;
                }

                match activation_result {
                    Ok(Some((token, claims))) => {
                        // the software has been activated!
                        if claims.trial {
                            // the next online result must not be polled until explicitly enabled
                            poll_online_activation.store(false, Ordering::Relaxed);
                        }
                        if !publish_activation(&running, &state_send, claims.clone(), Some(token)) {
                            return;
                        }

                        if claims.trial {
                            // keep the trial active and prefetch its replacement activation URL
                            active_trial = Some(claims);
                            continue 'request_url;
                        }

                        // a purchased license finishes activation
                        return;
                    }
                    Ok(None) => {
                        // not yet activated - simply try again
                    }
                    Err(e) => {
                        _ = error_send.send(ActivationError::FetchActivationState(e));
                    }
                }
            } else {
                // if the user isn't currently attempting to activate the plugin in this plugin instance,
                // check if another instance of the software has activated the plugin in the meantime
                let cached_result =
                    check_cached_token(&cfg, running.clone(), active_trial.is_some());

                if !running.load(Ordering::Relaxed) {
                    return;
                }

                if let Ok(Some(result)) = cached_result {
                    let claims = result.claims;
                    if claims.trial {
                        // the next online result must not be polled until explicitly enabled
                        poll_online_activation.store(false, Ordering::Relaxed);
                    }

                    // the software has been activated!
                    if !publish_activation(&running, &state_send, claims.clone(), result.new_token)
                    {
                        return;
                    }

                    if claims.trial {
                        // keep the trial active and prefetch its replacement activation URL
                        active_trial = Some(claims);
                        continue 'request_url;
                    }

                    // a purchased license finishes activation
                    return;
                }

                if activation_urls.is_none() {
                    // retry fetching an activation URL after the polling interval
                    continue 'request_url;
                }
            }
        }
    }
}

/// Publishes an accepted activation if it wins the purchased activation race.
fn publish_activation(
    running: &AtomicBool,
    state_send: &Sender<(ActivationState, Option<String>)>,
    claims: LicenseTokenClaims,
    token_to_cache: Option<String>,
) -> bool {
    if claims.trial {
        if !running.load(Ordering::Relaxed) {
            return false;
        }
    } else if !running.swap(false, Ordering::Relaxed) {
        return false;
    }

    state_send
        .send((
            ActivationState::Activated {
                claims,
                followup_online_activation_url: None,
            },
            token_to_cache,
        ))
        .is_ok()
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
/// None is returned if
/// - no cached token exists
/// - the cached token is a trial token and trials are being ignored
fn check_cached_token(
    cfg: &LicenseActivationConfig,
    running: Arc<AtomicBool>,
    ignore_trials: bool,
) -> Result<Option<CachedTokenCheckResult>, CachedTokenError> {
    match load_cached_token(cfg) {
        Ok(Some((token, claims))) => {
            if ignore_trials && claims.trial {
                // the active trial has already been accepted, so it must not mask
                // a purchased token installed by another instance
                return Ok(None);
            }

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
                        Ok(TokenValidationResponse::ValidationFailed(failure_type, detail)) => {
                            Err(CachedTokenError::ValidationFailed(failure_type, detail))
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
    token: &str,
) -> Result<LicenseTokenClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&cfg.product_id]);

    // disable validation of expiry as it's not always given
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let claims = jsonwebtoken::decode::<LicenseTokenClaims>(
        token,
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
    /// Online validation failed with a specific reason.
    ValidationFailed(ValidationFailedType, String),
}

/// Asks the Moonbase API whether the given license token is still valid.
/// If it is, a new token with updated `last_updated` property is returned.
fn moonbase_refresh_token(
    cfg: &LicenseActivationConfig,
    token: &str,
) -> Result<TokenValidationResponse, MoonbaseApiError> {
    let response = ureq::post(format!(
        "{}/api/client/licenses/{}/validate",
        cfg.moonbase_api_base_url(),
        cfg.product_id
    ))
    .config()
    .http_status_as_error(false)
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
        // error responses use the standard problem details format:
        // https://www.rfc-editor.org/rfc/rfc9457.html
        let body = response.into_body().read_to_string()?;
        let problem: ProblemDetails = serde_json::from_str(&body)
            .map_err(|_| MoonbaseApiError::UnexpectedResponse(status, body.clone()))?;
        let failure_type = match problem.error_type.as_str() {
            "LicenseRevoked" => ValidationFailedType::LicenseRevoked,
            "LicenseActivationRevoked" => ValidationFailedType::LicenseActivationRevoked,
            "LicenseExpired" => ValidationFailedType::LicenseExpired,
            "NoEligibleLicense" => ValidationFailedType::NoEligibleLicense,
            _ => ValidationFailedType::Unknown,
        };
        return Ok(TokenValidationResponse::ValidationFailed(
            failure_type,
            problem.detail,
        ));
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

#[derive(Deserialize)]
struct ProblemDetails {
    #[serde(rename = "errorType")]
    error_type: String,
    detail: String,
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
///
/// Returns `None` if the product has not yet been activated.
fn moonbase_check_online_activation(
    cfg: &LicenseActivationConfig,
    url: &str,
) -> Result<Option<(String, LicenseTokenClaims)>, MoonbaseApiError> {
    let response = ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .call()?;

    let status = response.status();

    if status == StatusCode::NO_CONTENT {
        // the product has not yet been activated.
        return Ok(None);
    }

    if status == StatusCode::OK {
        // the product was activated.
        // the response body contains the license token
        let token = response.into_body().read_to_string()?;

        // parse the token
        let claims = parse_token(cfg, &token)?;
        return Ok(Some((token, claims)));
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
