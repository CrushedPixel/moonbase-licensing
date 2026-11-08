use super::*;
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

/// Purchased activation wakes an idle consumer even though publishing ends the worker.
#[test]
fn delayed_confirmed_activation_requests_work_after_publication() {
    let (wake_send, wake_recv) = mpsc::channel();
    let (state_send, state_recv) = notifying_channel(Arc::new(move || {
        wake_send.send(()).unwrap();
    }));
    let (release_send, release_recv) = mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let worker_running = running.clone();
    let worker = thread::spawn(move || {
        release_recv.recv().unwrap();
        assert!(publish_activation(
            &worker_running,
            &state_send,
            ActivationState::Confirmed(confirmed_claims()),
            Some("accepted token".to_owned()),
        ));
    });

    assert_eq!(wake_recv.try_recv(), Err(TryRecvError::Empty));
    assert!(matches!(state_recv.try_recv(), Err(TryRecvError::Empty)));
    release_send.send(()).unwrap();

    // Waiting solely for the notification models an otherwise idle host event loop.
    wake_recv.recv_timeout(Duration::from_secs(5)).unwrap();
    let (state, token) = state_recv.try_recv().ok().unwrap();
    assert!(matches!(state, ActivationState::Confirmed(_)));
    assert_eq!(token.as_deref(), Some("accepted token"));
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
            &Mutex::new(()),
            Path::new("unused-license-cache"),
            &error_send,
            CachedTokenCheckFailure {
                error: CachedTokenError::Io(io::Error::other("test cache failure")),
                rejected_token: None,
            },
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
