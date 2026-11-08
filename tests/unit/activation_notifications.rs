use super::*;
use std::sync::Barrier;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{self, TryRecvError};

/// Builds accepted claims without accessing a license server or local token cache.
fn confirmed_claims() -> LicenseTokenClaims {
    LicenseTokenClaims {
        method: ActivationMethod::Offline,
        product_latest_version: None,
        user_name: "Test user".to_owned(),
        device_signature: "Test device".to_owned(),
        last_validated: Utc::now(),
        expires_at: None,
        trial: false,
    }
}

/// Builds a config whose token cache lives in the given directory.
fn test_config(dir: &Path) -> LicenseActivationConfig {
    LicenseActivationConfig {
        vendor_id: "vendor".into(),
        product_id: "product".into(),
        jwt_pubkey: include_str!("../fixtures/test_license_public.pem").into(),
        cached_token_path: dir.join("license.jwt"),
        device_name: "Test device".into(),
        device_signature: "Test device".into(),
        online_token_refresh_threshold: Duration::from_secs(1800),
        online_token_expiration_threshold: Duration::from_secs(86400),
    }
}

/// Creates a license token for the test device and product, signed with the
/// key pair in `tests/fixtures` that never signs a real Moonbase license.
fn signed_token(method: &str, validated: DateTime<Utc>) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(Algorithm::RS256),
        &serde_json::json!({
            "aud": "product",
            "method": method,
            "u:name": "Test user",
            "sig": "Test device",
            "validated": validated.timestamp(),
            "trial": false,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../fixtures/test_license_private.pem"
        ))
        .unwrap(),
    )
    .unwrap()
}

/// Purchased activation wakes an idle consumer even though publishing ends the worker.
#[test]
fn delayed_confirmed_activation_requests_work_after_publication() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let cache_path = cfg.cached_token_path.clone();
    let (wake_send, wake_recv) = mpsc::channel();
    let (state_send, state_recv) = notifying_channel(Arc::new(move || {
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), "accepted token");
        wake_send.send(()).unwrap();
    }));
    let (error_send, error_recv) = notifying_channel(Arc::new(|| {}));
    let (release_send, release_recv) = mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let worker_running = running.clone();
    let worker = thread::spawn(move || {
        release_recv.recv().unwrap();
        assert!(publish_activation(
            &cfg,
            &worker_running,
            &state_send,
            &error_send,
            ActivationState::Confirmed(confirmed_claims()),
            Some("accepted token".to_owned()),
        ));
    });

    assert_eq!(wake_recv.try_recv(), Err(TryRecvError::Empty));
    assert!(matches!(state_recv.try_recv(), Err(TryRecvError::Empty)));
    release_send.send(()).unwrap();

    // Waiting solely for the notification models an otherwise idle host event loop.
    wake_recv.recv_timeout(Duration::from_secs(5)).unwrap();
    let state = state_recv.try_recv().unwrap();
    assert!(matches!(state, ActivationState::Confirmed(_)));
    assert!(error_recv.try_recv().is_err());
    assert!(!running.load(Ordering::Relaxed));
    worker.join().unwrap();
}

/// A delayed cached-token failure wakes an idle consumer without a state update.
#[test]
fn delayed_activation_error_requests_work_after_publication() {
    let (wake_send, wake_recv) = mpsc::channel();
    let (error_send, error_recv) = notifying_channel(Arc::new(move || {
        wake_send.send(()).unwrap();
    }));
    let (release_send, release_recv) = mpsc::channel();
    let worker = thread::spawn(move || {
        release_recv.recv().unwrap();
        report_cached_token_failure(
            &error_send,
            CachedTokenError::Io(io::Error::other("test cache failure")),
        );
    });

    assert_eq!(wake_recv.try_recv(), Err(TryRecvError::Empty));
    assert!(matches!(error_recv.try_recv(), Err(TryRecvError::Empty)));
    release_send.send(()).unwrap();

    wake_recv.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        error_recv.try_recv().unwrap(),
        ActivationError::LoadCachedToken(CachedTokenError::Io(_))
    ));
    worker.join().unwrap();
}

/// Only one of several instances refreshes a token, and all of them accept its result.
#[test]
fn simultaneous_license_refreshes_share_the_saved_result() {
    /// Number of instances sharing the token cache in this test.
    const INSTANCES: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let old = signed_token("Online", Utc::now() - chrono::Duration::hours(1));
    let fresh = signed_token("Online", Utc::now());
    cache::write(&cfg.cached_token_path, &old).unwrap();
    let start = Barrier::new(INSTANCES);
    let requests = AtomicUsize::new(0);
    thread::scope(|scope| {
        let mut instances = Vec::new();
        for _ in 0..INSTANCES {
            instances.push(scope.spawn(|| {
                let running = AtomicBool::new(true);
                let (state_send, _state_recv) = notifying_channel(Arc::new(|| {}));
                let (error_send, error_recv) = notifying_channel(Arc::new(|| {}));
                start.wait();
                let outcome = check_cached_token_with(
                    &cfg,
                    &running,
                    &state_send,
                    &error_send,
                    false,
                    |token| {
                        assert_eq!(token, old);
                        requests.fetch_add(1, Ordering::Relaxed);
                        Ok(TokenValidationResponse::Valid(
                            fresh.clone(),
                            parse_token(&cfg, &fresh).unwrap(),
                        ))
                    },
                )
                .unwrap();
                let CachedTokenCheckOutcome::Accepted(claims) = outcome else {
                    panic!("all instances must accept the refreshed license");
                };
                assert!(cached_token_can_defer_refresh(
                    claims.last_validated,
                    cfg.online_token_refresh_threshold,
                    cfg.online_token_expiration_threshold,
                    Utc::now(),
                ));
                assert!(error_recv.try_recv().is_err());
            }));
        }
        for instance in instances {
            instance.join().unwrap();
        }
    });
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    assert_eq!(fs::read_to_string(&cfg.cached_token_path).unwrap(), fresh);
}

/// A delayed refresh or rejection doesn't touch a license cached by another instance.
#[test]
fn refresh_and_rejection_cannot_replace_or_remove_another_license() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    cache::write(&cfg.cached_token_path, "old").unwrap();
    let cache_guard = cache::lock(&cfg.cached_token_path).unwrap();
    let (done_send, done_recv) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            let running = AtomicBool::new(true);
            assert!(
                !replace_cached_token_if_matches(
                    &cfg.cached_token_path,
                    Some("old"),
                    "stale refresh",
                    &running
                )
                .unwrap()
            );
            assert!(!remove_cached_token_if_matches(&cfg.cached_token_path, "old").unwrap());
            done_send.send(()).unwrap();
        });

        // both calls must wait for the lock instead of acting on the old token
        let premature = done_recv.recv_timeout(Duration::from_millis(100));
        cache::write(&cfg.cached_token_path, "replacement license").unwrap();
        drop(cache_guard);
        done_recv.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(premature.is_err());
    });
    assert_eq!(
        fs::read_to_string(&cfg.cached_token_path).unwrap(),
        "replacement license"
    );
}

/// An accepted token is cached before its state is published,
/// so another instance discovers it without the accepting one being polled.
#[test]
fn a_new_activation_is_discovered_without_polling_the_accepting_instance() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let token = signed_token("Offline", Utc::now());
    let claims = parse_token(&cfg, &token).unwrap();
    let (state_send, _state_recv) = notifying_channel(Arc::new(|| {}));
    let (error_send, _error_recv) = notifying_channel(Arc::new(|| {}));
    assert!(publish_activation(
        &cfg,
        &AtomicBool::new(true),
        &state_send,
        &error_send,
        ActivationState::Confirmed(claims),
        Some(token.clone())
    ));

    let (state_send, _state_recv) = notifying_channel(Arc::new(|| {}));
    let outcome = check_cached_token_with(
        &cfg,
        &AtomicBool::new(true),
        &state_send,
        &error_send,
        false,
        |_| panic!("offline tokens must never contact Moonbase"),
    )
    .unwrap();
    assert!(matches!(outcome, CachedTokenCheckOutcome::Accepted(_)));
    assert_eq!(fs::read_to_string(&cfg.cached_token_path).unwrap(), token);
}

/// An activator stops while another instance refreshes the token,
/// without waiting for that refresh to finish.
#[test]
fn an_activator_can_stop_while_another_instance_owns_the_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    cache::write(
        &cfg.cached_token_path,
        signed_token("Online", Utc::now() - chrono::Duration::hours(1)),
    )
    .unwrap();
    let _refresh_guard = cache::lock(&cache::sidecar(&cfg.cached_token_path, ".refresh")).unwrap();
    let running = AtomicBool::new(true);
    let (state_send, state_recv) = notifying_channel(Arc::new(|| {}));
    let (error_send, _error_recv) = notifying_channel(Arc::new(|| {}));
    let (done_send, done_recv) = mpsc::channel();
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let outcome =
                check_cached_token_with(&cfg, &running, &state_send, &error_send, false, |_| {
                    panic!("a busy refresh must not contact Moonbase")
                });
            done_send.send(outcome.unwrap()).unwrap();
        });

        // the cached token grants provisional access while the refresh is unavailable
        assert!(matches!(
            state_recv.recv_timeout(Duration::from_secs(5)).unwrap(),
            ActivationState::Cached(_)
        ));
        running.store(false, Ordering::Relaxed);
        worker.thread().unpark();
        assert!(matches!(
            done_recv.recv_timeout(Duration::from_secs(5)).unwrap(),
            CachedTokenCheckOutcome::NoToken { .. }
        ));
    });
}

/// A license installed while a refresh is in flight survives both of its outcomes.
#[test]
fn installing_an_offline_license_during_refresh_survives_stale_responses() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let old = signed_token("Online", Utc::now() - chrono::Duration::hours(1));
    let fresh = signed_token("Online", Utc::now());
    let offline = signed_token("Offline", Utc::now());
    let (state_send, _state_recv) = notifying_channel(Arc::new(|| {}));
    let (error_send, error_recv) = notifying_channel(Arc::new(|| {}));
    for rejected in [false, true] {
        cache::write(&cfg.cached_token_path, &old).unwrap();
        let outcome = check_cached_token_with(
            &cfg,
            &AtomicBool::new(true),
            &state_send,
            &error_send,
            false,
            |_| {
                // while we're refreshing, the user installs an offline license
                // in another instance, which must not wait for our request
                assert!(publish_activation(
                    &cfg,
                    &AtomicBool::new(true),
                    &state_send,
                    &error_send,
                    ActivationState::Confirmed(parse_token(&cfg, &offline).unwrap()),
                    Some(offline.clone()),
                ));
                if rejected {
                    Ok(TokenValidationResponse::ValidationFailed(
                        ValidationFailedType::LicenseRevoked,
                        "revoked old token".into(),
                    ))
                } else {
                    Ok(TokenValidationResponse::Valid(
                        fresh.clone(),
                        parse_token(&cfg, &fresh).unwrap(),
                    ))
                }
            },
        )
        .unwrap();
        let CachedTokenCheckOutcome::Accepted(claims) = outcome else {
            panic!("the newly installed offline license must be accepted");
        };
        assert_eq!(claims.method, ActivationMethod::Offline);
        assert_eq!(fs::read_to_string(&cfg.cached_token_path).unwrap(), offline);
        assert!(error_recv.try_recv().is_err());
    }
}

/// A license installed while the worker polls for an online activation
/// is not overwritten by the activation the worker started with.
#[test]
fn polling_an_old_activation_does_not_overwrite_a_replacement_license() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    cache::write(
        &cfg.cached_token_path,
        signed_token("Offline", Utc::now() - chrono::Duration::hours(1)),
    )
    .unwrap();
    let (wake_send, wake_recv) = mpsc::channel();
    let mut activator = LicenseActivator::spawn_with_callback(cfg.clone(), move || {
        wake_send.send(()).unwrap();
    });
    wake_recv.recv_timeout(Duration::from_secs(5)).unwrap();

    let replacement = signed_token("Offline", Utc::now());
    let cache_guard = cache::lock(&cfg.cached_token_path).unwrap();
    cache::write(&cfg.cached_token_path, &replacement).unwrap();
    drop(cache_guard);
    assert!(matches!(
        activator.poll(),
        Some(ActivationState::Confirmed(_))
    ));
    assert_eq!(
        fs::read_to_string(&cfg.cached_token_path).unwrap(),
        replacement
    );
}
