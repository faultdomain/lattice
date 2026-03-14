//! Resilient K8s watcher that auto-restarts on error or stream end.
//!
//! Eliminates duplicated error-handling and stream-restart logic across
//! agent subtree watchers, route reconciler, and other controllers.

use std::time::Duration;

use futures::{Stream, StreamExt, TryStreamExt};
use kube::api::Api;
use kube::runtime::watcher::{self, Event};
use tracing::warn;

/// Default backoff duration between watcher restarts.
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// Create a resilient watcher stream that auto-restarts on error or stream end.
///
/// Yields `Event<T>` items indefinitely. On watcher errors or stream-end, sleeps
/// for 5 seconds and creates a new watcher stream. Only exits when the returned
/// stream is dropped.
///
/// # Usage
///
/// ```ignore
/// use lattice_common::watcher::resilient_watcher;
/// let mut stream = resilient_watcher(api, watcher::Config::default());
/// while let Some(event) = stream.next().await {
///     match event {
///         Event::Apply(obj) => { /* handle */ }
///         Event::Delete(obj) => { /* handle */ }
///         _ => {}
///     }
/// }
/// ```
pub fn resilient_watcher<T>(
    api: Api<T>,
    config: watcher::Config,
) -> impl Stream<Item = Event<T>> + Send
where
    T: kube::Resource
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
    T::DynamicType: Default + Clone + Eq + std::hash::Hash,
{
    async_stream::stream! {
        let resource_kind = std::any::type_name::<T>()
            .rsplit("::")
            .next()
            .unwrap_or("Unknown");

        loop {
            let mut stream = watcher::watcher(api.clone(), config.clone()).boxed();

            loop {
                match stream.try_next().await {
                    Ok(Some(event)) => {
                        yield event;
                    }
                    Ok(None) => {
                        warn!(kind = resource_kind, "watcher stream ended, restarting");
                        break;
                    }
                    Err(e) => {
                        warn!(kind = resource_kind, error = %e, "watcher error, restarting");
                        break;
                    }
                }
            }

            tokio::time::sleep(RESTART_BACKOFF).await;
        }
    }
}
