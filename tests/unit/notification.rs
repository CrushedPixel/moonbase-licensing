use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A callback can consume every published value immediately, including cloned sends.
#[test]
fn callback_runs_after_the_value_is_available() {
    let receiver = Arc::new(Mutex::new(None::<Receiver<u32>>));
    let received = Arc::new(Mutex::new(Vec::new()));
    let callback_receiver = receiver.clone();
    let callback_received = received.clone();
    let (sender, channel_receiver) = notifying_channel(Arc::new(move || {
        let value = callback_receiver
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_recv()
            .expect("notification must follow publication");
        callback_received.lock().unwrap().push(value);
    }));
    *receiver.lock().unwrap() = Some(channel_receiver);

    sender.send(1).unwrap();
    let cloned_sender = sender.clone();
    std::thread::spawn(move || cloned_sender.send(2).unwrap())
        .join()
        .unwrap();

    assert_eq!(*received.lock().unwrap(), [1, 2]);
}

/// A disconnected channel returns the original value without a spurious wakeup.
#[test]
fn failed_publication_does_not_invoke_callback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let (sender, receiver) = notifying_channel(Arc::new(move || {
        callback_calls.fetch_add(1, Ordering::SeqCst);
    }));
    drop(receiver);

    assert_eq!(sender.send(7).unwrap_err().0, 7);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
