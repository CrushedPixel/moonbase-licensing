//! Publication channels that wake the consumer after an update is available.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SendError, Sender};

/// Shared notification invoked on the thread publishing an activation update.
pub(crate) type PublicationCallback = Arc<dyn Fn() + Send + Sync>;

/// Sender that schedules consumer work after successfully queuing each value.
pub(crate) struct NotifyingSender<T> {
    /// Channel carrying the published values.
    sender: Sender<T>,
    /// Callback shared by state and error publishers.
    callback: PublicationCallback,
}

impl<T> NotifyingSender<T> {
    /// Enqueues the value before waking the consumer; disconnected sends do not wake it.
    pub(crate) fn send(&self, value: T) -> Result<(), SendError<T>> {
        self.sender.send(value)?;
        (self.callback)();
        Ok(())
    }
}

impl<T> Clone for NotifyingSender<T> {
    /// Clones the channel endpoint and its shared notification without cloning values.
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            callback: self.callback.clone(),
        }
    }
}

/// Creates a publication channel using the supplied shared callback.
pub(crate) fn notifying_channel<T>(
    callback: PublicationCallback,
) -> (NotifyingSender<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::channel();
    (NotifyingSender { sender, callback }, receiver)
}

#[cfg(test)]
#[path = "../tests/unit/notification.rs"]
mod tests;
