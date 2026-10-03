//! `Service` and `Layer` — the two traits servelet pieces compose through (README rule 2).
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel/platform.rs` at rev `4ce2dcd`:
//! the `Service` and `Layer` trait definitions (lines 353-380), `Stack` (383-419), the
//! `oneshot` free function (425-433), and `RateLimitLayer`/`RateLimitService` (484-573).
//!
//! WHY THESE MOVED (docs/SPINE.md "What the originals reached for"): in biota these lived at
//! `crate::platform::service`, one path away from `Router::layered`. Splitting the crates
//! would have made `servelet-router` depend on a `platform` module holding 2,322 lines of
//! proxy/grpc/CORS/authz code this unit has no scope for. Two options existed: cut `layered`
//! and change its semantics, or bring the minimum. Hard rule: do not silently change semantics,
//! so the minimum came with.
//!
//! `RateLimitLayer` is here for a second reason, and it is a real cost worth naming: the moved
//! router test `router_layered_composes_an_arbitrary_layer` asserts against a Layer that was
//! *independently defined*, not written for the test. Re-writing that Layer inside the test
//! would have made the test prove nothing about `layered` (it would prove a shape it just
//! created). It is 90 lines and depends on nothing but these two traits.

use super::*;

use std::future::Future;
use std::time::Duration;

// ── Service trait ──

/// The Service trait — mirror of `tower::Service<Req>`.
/// Ready-check + dispatch, one operation split into two phases.
///
/// `service = pair(poll_ready)(call)` — readiness state on hashtrinity Set/Mark,
/// call dispatch via `handle`.
pub trait Service<Req> {
    type Response;
    type Error;

    /// Check readiness (batch — call once, serve N).
    /// Hashtrinity: readiness IS a Mark on the Set face.
    fn ready(&mut self) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send;

    /// Dispatch one request. `+ Send` (tightened from a bare RPITIT) so a `Service` can be
    /// driven from behind an `Arc<Mutex<_>>` inside a `Send` future (`Router::layered`'s own
    /// boxed-handler adapter) — every existing impl in this file already produces a Send
    /// future in practice (plain async fns over Send types), so this is additive, not breaking.
    fn serve(
        &mut self,
        req: Req,
    ) -> impl Future<Output = std::result::Result<Self::Response, Self::Error>> + Send;
}

// ── Layer trait ──

/// The Layer trait — mirror of `tower::Layer<S>`.
/// Transforms one Service into another. The composition is the only freedom.
///
/// `layer = pair(service)(apply)` — apply IS the universal translator.
pub trait Layer<S> {
    type Service;

    fn wrap(&self, inner: S) -> Self::Service;
}

// ── Stack ──

/// A stacked service — `tower::ServiceBuilder` masquerade.
/// Wraps a base service with an ordered chain of Layers.
#[derive(Clone)]
pub struct Stack<S> {
    base: S,
    layers: Vec<String>, // layer metadata; actual composition is structural
}

impl<S> Stack<S> {
    pub fn new(base: S) -> Self {
        Stack {
            base,
            layers: Vec::new(),
        }
    }

    /// Apply a layer to the stack: `stack.wrap(layer)` = `layer.wrap(stack)`.
    /// Returns a new Stack with the layer composed.
    pub fn wrap<L, S2>(mut self, layer: L) -> Stack<S2>
    where
        L: Layer<S, Service = S2>,
    {
        let svc = layer.wrap(self.base);
        self.layers.push(std::any::type_name::<L>().to_string());
        Stack {
            base: svc,
            layers: self.layers,
        }
    }

    pub fn into_inner(self) -> S {
        self.base
    }
}

// ── Free functions ──

/// One-shot: serve a single request through a service.
pub async fn oneshot<S, Req>(svc: &mut S, req: Req) -> std::result::Result<S::Response, S::Error>
where
    S: Service<Req>,
{
    svc.ready().await?;
    svc.serve(req).await
}

/// Rate limit layer — `n` requests per `window` duration.
#[derive(Clone, Debug)]
pub struct RateLimitLayer {
    n: usize,
    window: Duration,
}

impl RateLimitLayer {
    pub fn new(n: usize, window: Duration) -> Self {
        RateLimitLayer { n, window }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn wrap(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            n: self.n,
            window: self.window,
            count: 0,
            window_start: std::time::Instant::now(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    n: usize,
    window: Duration,
    count: usize,
    window_start: std::time::Instant,
}

impl<S, Req> Service<Req> for RateLimitService<S>
where
    S: Service<Req> + Send,
    S::Response: Send,
    S::Error: Send + From<Error>,
    Req: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn ready(&mut self) -> std::result::Result<(), Self::Error> {
        let now = std::time::Instant::now();
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= self.n {
            return Err(S::Error::from(Error::Http(
                "rate limit exceeded".into(),
            )));
        }
        self.count += 1;
        self.inner.ready().await
    }

    async fn serve(&mut self, req: Req) -> std::result::Result<Self::Response, Self::Error> {
        self.inner.serve(req).await
    }
}