use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

/// Default per-attempt TCP connect timeout for LAN dialers.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default debounce window for coalescing rapid local mutations into one sync pass.
pub const DEFAULT_DEBOUNCE_WINDOW: Duration = Duration::from_millis(300);

/// Default periodic safety-net sync interval when no local changes occurred.
pub const DEFAULT_PERIODIC_INTERVAL: Duration = Duration::from_secs(30);

/// Default maximum concurrent incoming unauthenticated TLS handshakes.
pub const DEFAULT_MAX_CONCURRENT_HANDSHAKES: usize = 32;

/// Default maximum concurrent active authenticated exchange conversations.
pub const DEFAULT_MAX_CONCURRENT_CONVERSATIONS: usize = 4;

/// Reason the coalesced sync loop woke up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerWake {
    LocalChange,
    Periodic,
    Cancelled,
}

/// Coalesces bursts of local change notifications within `debounce` while ensuring at least one
/// periodic wakeup every `periodic` interval.
#[derive(Debug, Clone)]
pub struct CoalescedTrigger {
    notify: Arc<Notify>,
    debounce: Duration,
    periodic: Duration,
}

impl CoalescedTrigger {
    #[must_use]
    pub fn new(debounce: Duration, periodic: Duration) -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            debounce,
            periodic,
        }
    }

    pub fn notify_change(&self) {
        self.notify.notify_one();
    }

    pub async fn next_wake(&self, cancel: &CancellationToken) -> TriggerWake {
        tokio::select! {
            _ = cancel.cancelled() => return TriggerWake::Cancelled,
            _ = tokio::time::sleep(self.periodic) => return TriggerWake::Periodic,
            _ = self.notify.notified() => {}
        }

        // Coalesce additional bursts arriving inside the debounce window.
        let deadline = Instant::now() + self.debounce;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return TriggerWake::LocalChange;
            }
            tokio::select! {
                _ = cancel.cancelled() => return TriggerWake::Cancelled,
                _ = tokio::time::sleep(remaining) => return TriggerWake::LocalChange,
                _ = self.notify.notified() => {}
            }
        }
    }
}

/// Tracks peers that currently have an active exchange conversation in flight (at most one per key).
#[derive(Debug, Clone, Default)]
pub struct ActivePeers {
    inner: Arc<Mutex<HashSet<[u8; 32]>>>,
}

impl ActivePeers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to claim the exclusive conversation slot for `peer_key`.
    /// Returns `None` if a conversation with that peer is already in progress.
    pub fn try_acquire(&self, peer_key: [u8; 32]) -> Option<PeerFlightGuard> {
        let mut set = self.inner.lock().ok()?;
        if !set.insert(peer_key) {
            return None;
        }
        Some(PeerFlightGuard {
            inner: Arc::clone(&self.inner),
            peer_key,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|s| s.len()).unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// RAII guard releasing the peer's active conversation slot on drop.
#[derive(Debug)]
pub struct PeerFlightGuard {
    inner: Arc<Mutex<HashSet<[u8; 32]>>>,
    peer_key: [u8; 32],
}

impl Drop for PeerFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.inner.lock() {
            set.remove(&self.peer_key);
        }
    }
}

/// Connects to `addr` via TCP with `timeout_dur`.
pub async fn connect_tcp_with_timeout(
    addr: SocketAddr,
    timeout_dur: Duration,
) -> io::Result<TcpStream> {
    match tokio::time::timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("TCP connect to {addr} timed out"),
        )),
    }
}

/// Accepts connections on `listener` until `cancel` is triggered, bounding concurrency with a
/// semaphore of `max_concurrent` permits and waiting for in-flight handlers on shutdown.
pub async fn serve_tcp_listener<F, Fut>(
    listener: TcpListener,
    cancel: CancellationToken,
    max_concurrent: usize,
    handler: F,
) where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let handler = Arc::new(handler);
    let mut in_flight = tokio::task::JoinSet::new();

    loop {
        let permit = tokio::select! {
            _ = cancel.cancelled() => break,
            res = permits.clone().acquire_owned() => match res {
                Ok(p) => p,
                Err(_) => break,
            }
        };

        let accepted = tokio::select! {
            _ = cancel.cancelled() => {
                drop(permit);
                break;
            }
            res = listener.accept() => res,
        };

        match accepted {
            Ok((stream, addr)) => {
                let handler = Arc::clone(&handler);
                in_flight.spawn(async move {
                    let _permit = permit;
                    handler(stream, addr).await;
                });
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                drop(permit);
            }
            Err(_) => {
                drop(permit);
                break;
            }
        }

        while in_flight.try_join_next().is_some() {}
    }

    while in_flight.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_peers_enforces_single_slot_per_key() {
        let active = ActivePeers::new();
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];

        let g1 = active.try_acquire(k1).expect("first k1 slot");
        assert!(active.try_acquire(k1).is_none(), "duplicate k1 rejected");
        let g2 = active.try_acquire(k2).expect("different peer allowed");
        assert_eq!(active.len(), 2);

        drop(g1);
        assert_eq!(active.len(), 1);
        assert!(active.try_acquire(k1).is_some());
        drop(g2);
    }

    #[tokio::test]
    async fn coalesced_trigger_batches_burst_and_stops_on_cancel() {
        let trigger = CoalescedTrigger::new(Duration::from_millis(25), Duration::from_secs(60));
        let cancel = CancellationToken::new();

        trigger.notify_change();
        trigger.notify_change();
        trigger.notify_change();

        assert_eq!(trigger.next_wake(&cancel).await, TriggerWake::LocalChange);

        cancel.cancel();
        assert_eq!(trigger.next_wake(&cancel).await, TriggerWake::Cancelled);
    }
}
