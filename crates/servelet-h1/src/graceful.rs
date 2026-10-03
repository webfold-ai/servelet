//! Graceful drain — moved byte-for-byte from `biota/http-server`'s `kernel/runtime.rs` at rev
//! `4ce2dcd` (the `graceful` module: `bind_reuseport`, `ConnectionCounter`/`ConnectionGuard`,
//! `serve_gracefully`). Decided HTTP: it is a TCP accept loop that hands every accepted stream to
//! `serve_connection`, i.e. it is the h1 serve loop, not HTTP/2 framing.

use super::*;
use crate::wire::serve_connection;

/// How many connections are currently in flight. The drain condition is exactly `Web.lean`'s
/// `encircle_iff` at the single-process scale: shutdown is complete iff this residual reads
/// zero — checked in one place, not inferred from a fixed sleep.
#[derive(Clone)]
pub struct ConnectionCounter(Arc<AtomicUsize>);

impl ConnectionCounter {
    pub fn new() -> Self {
        ConnectionCounter(Arc::new(AtomicUsize::new(0)))
    }

    pub fn active(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    fn guard(&self) -> ConnectionGuard {
        self.0.fetch_add(1, Ordering::SeqCst);
        ConnectionGuard(self.0.clone())
    }
}

impl Default for ConnectionCounter {
    fn default() -> Self {
        ConnectionCounter::new()
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve with graceful drain on SIGTERM/SIGINT: on signal, stop accepting NEW connections but
/// let every in-flight one finish naturally (bounded by `drain_timeout`), then return. Paired
/// with `bind_reuseport` — start a new process bound the same way before signaling this one —
/// this is a zero-downtime rolling restart with no FD passing and no `unsafe` code.
pub async fn serve_gracefully(listener: TcpListener, router: Router, drain_timeout: Duration) -> Result<()> {
    let counter = ConnectionCounter::new();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tracing::info!(target: "bedrock::runtime::graceful", "listening (graceful drain enabled)");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                stream.set_nodelay(true)?;
                let router = router.clone();
                let guard = counter.guard();
                tokio::spawn(
                    async move {
                        let _guard = guard;
                        serve_connection(stream, router, Some(peer)).await;
                    }
                    .instrument(tracing::info_span!(target: "bedrock::runtime::graceful", "connection", %peer)),
                );
            }
            _ = sigterm.recv() => {
                tracing::info!(target: "bedrock::runtime::graceful", "SIGTERM received, draining");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!(target: "bedrock::runtime::graceful", "SIGINT received, draining");
                break;
            }
        }
    }

    let drain_start = std::time::Instant::now();
    while counter.active() > 0 && drain_start.elapsed() < drain_timeout {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let remaining = counter.active();
    if remaining > 0 {
        tracing::warn!(target: "bedrock::runtime::graceful", remaining, "drain timeout reached with connections still in flight");
    } else {
        tracing::info!(target: "bedrock::runtime::graceful", "drained cleanly, all connections finished");
    }
    Ok(())
}
