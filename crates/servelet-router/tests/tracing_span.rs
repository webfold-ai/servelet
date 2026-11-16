//! The tracing-span test, moved out of `moved.rs` into its own test binary.
//!
//! It installs a scoped subscriber with `tracing::subscriber::with_default` and expects the
//! `http.request` span of `Router::handle` to reach it. `tracing` caches per-callsite interest
//! process-wide, so when other tests in the same binary drive `Router::handle` on other threads
//! at the same time (as `moved.rs` does), the callsite can be registered with no subscriber
//! interested and this test sees an empty buffer (observed at servelet fbaaaad and at the
//! wirefold re-pin alike, about one run in three). A test binary of its own has no concurrent
//! caller of the callsite, so the result is deterministic.

use std::future::Future;

use servelet_core::{Method, Request, Response, StatusCode};
use servelet_router::Router;

/// Proof the tracing integration actually fires real spans with real fields — not just that
/// the `#[instrument]` attribute compiles. A custom `MakeWriter` captures `tracing-subscriber`'s
/// formatted output into a shared buffer; the test asserts the captured text contains what a
/// real subscriber (Jaeger, OTLP, a log aggregator) would actually see.
#[derive(Clone)]
struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut *self.0.lock().unwrap(), buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn router_handle_emits_a_real_tracing_span_with_method_path_status() {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CapturingWriter(buf.clone()))
        .with_ansi(false)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .finish();

    let router = Router::new().get("/health", |_req| async { Response::ok("alive") });
    let req = Request::new(Method::GET, "/health".parse().unwrap());
    // `tracing::subscriber::with_default` activates `subscriber` for exactly this call's
    // scope — this crate's own `tracing` dependency is the real crates.io crate (not a
    // masquerade shim), so the real API is available; a prior edit built `subscriber` and
    // never installed it, so nothing was ever captured.
    let resp = tracing::subscriber::with_default(subscriber, || futures_block_on(router.handle(req)));
    assert_eq!(resp.status(), StatusCode::OK);

    let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(out.contains("http.request"), "span name missing from captured output: {out}");
    assert!(out.contains("method=GET"), "method field missing: {out}");
    assert!(out.contains("path=/health"), "path field missing: {out}");
    assert!(out.contains("status=200"), "status field missing: {out}");
}

/// Minimal, dependency-free block-on for a future with no real async waiting (the router
/// handler above resolves immediately) — avoids pulling in a second async-test harness just
/// for this one synchronous-subscriber-scoping test.
fn futures_block_on<F: Future>(fut: F) -> F::Output {
    let waker = std::task::Waker::noop().clone();
    let mut cx = std::task::Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
