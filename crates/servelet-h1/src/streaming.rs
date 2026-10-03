//! The streaming response body — moved byte-for-byte from `biota/http-server`'s `lib.rs` at rev
//! `4ce2dcd`, lines 220-238 (the `StreamingBody` struct, its `extensions_mut().insert(..)` in
//! `HttpResponseBuilder::streaming`, and `Response::streaming_body`).
//!
//! DEVIATION, mechanics only (docs/SPINE.md): biota put these on `HttpResponseBuilder`/`Response`
//! in the crate ROOT. The root here is the WIRE crate, so they became three free/associated
//! functions with identical bodies. Three edits, all mechanical, none semantic:
//!   * `HttpResponseBuilder::streaming` took `&mut self` and read `self.status` from the builder.
//!     The builder is `servelet-sse`-adjacent masquerade code that is not this unit's to move, so
//!     `streaming(rx)` takes the `Response` to attach to instead. The status line a caller passes
//!     is the same value `self.status` held.
//!   * `Response::streaming_body` became the free `streaming_body(&Response)` — the body is the
//!     same one-liner, `self.extensions().get::<StreamingBody>().cloned()`.
//!   * `pub(crate)` -> `pub`: they are this crate's public API now.
//!
//! WHY NOT ON `servelet_core::Response`: `StreamingBody`'s field is a `tokio::sync::Mutex` over a
//! `tokio::sync::mpsc::Receiver`. Putting it in core's `Response` would put tokio's `sync` in a
//! crate whose whole contract (and whose compile-time test `core_is_pure_data_and_names_no_async_
//! runtime`) is that it names no runtime at all. The stashing seam is unchanged — it is still a
//! cloneable value inside `Extensions`, keyed by type, exactly as biota had it.

use crate::{Response, Result};

/// The streaming source stashed in a `Response`'s extensions by [`streaming`] — `serve_connection`
/// looks for this (via [`streaming_body`]) the same way it looks for
/// `crate::httpsrv::httpx::sse::SseBody`, and dispatches to a raw chunked writer instead of the SSE-formatted one or the
/// normal buffered `write_response`. `Arc<Mutex<Option<...>>>` for the same reason `SseBody` uses
/// it: `Extensions::insert` requires `Clone`, a receiver is consumed exactly once.
#[derive(Clone)]
pub struct StreamingBody {
    pub(crate) rx: std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>>>>,
}

/// actix's `HttpResponseBuilder::streaming(stream)` — an arbitrary byte stream piped into a
/// chunked response body, written to the wire as each chunk arrives (not buffered into
/// memory first). Scoped to an `mpsc::Receiver` rather than a generic `futures::Stream` (the
/// same choice `crate::httpsrv::httpx::sse::Sse` made): bedrock has no dependency on the `futures` ecosystem crate,
/// and every real caller (an S3 object proxy download) already has — or can trivially build —
/// a channel, by draining whatever stream type its own HTTP client returns into one first.
/// Errors are pre-stringified into the channel's `Err(String)` rather than kept generic, so
/// the stashed type (`StreamingBody`) stays concrete regardless of the caller's own error type.
pub fn streaming(mut resp: Response, rx: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>) -> Response {
    resp.extensions_mut().insert(StreamingBody { rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(rx))) });
    resp
}

/// The response's streaming source, if it carries one — the exact query `serve_connection` makes
/// to decide between `write_streaming_response` and the buffered `write_response`.
pub fn streaming_body(resp: &Response) -> Option<StreamingBody> {
    resp.extensions().get::<StreamingBody>().cloned()
}

/// Take the receiver out of a [`StreamingBody`], once.
///
/// DEVIATION, mechanics only: in biota `write_streaming_response` reached three levels into the
/// wrapper (`streaming_body.rx.lock().await.take()`). Taking it through a named method on the type
/// is the same operation with the same `expect` message; it exists so the crate can hand out the
/// body without handing out the field.
pub async fn take_receiver(body: StreamingBody) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>> {
    Ok(body
        .rx
        .lock()
        .await
        .take()
        .expect("StreamingBody's receiver is stashed exactly once per response and consumed exactly once, here"))
}
// -- The formatter seam (added after the move) ------------------------------
//
// WHY: `serve_connection` decides between the buffered writer and the streaming writer by
// asking the response what it carries. SSE needs the streaming writer with DIFFERENT framing
// (an `id:`/`event:`/`data:` encoder, a keep-alive comment on idle, a `retry:` preamble), and its
// framing lives in `servelet-sse`, which must not be a dependency of this crate — the reverse
// edge would make h1 know sse exists (README rule 2).
//
// The seam is a value in the response's own extensions, exactly like the body itself: no global,
// no registry, no "installed once" (rule 3). `servelet-sse` inserts one; `serve_connection`
// takes it out if it is there and uses the default writer if it is not. This crate never names
// the SSE type.

/// Writes a streaming RESPONSE to the wire, body and all. `servelet-h1`'s own default is
/// `write_streaming_response` over a [`StreamingBody`]; `servelet-sse` supplies its own, over the
/// SSE body it stashed.
///
/// The whole response, not a body: a body type this crate does not know (SSE's) has to be
/// reachable from here, and a formatter that pulls its own body out of the response it was handed
/// is the only shape that works without this crate naming it.
///
/// Higher-ranked over the writer's lifetime on purpose: the future writes to the stream it was
/// given, so it borrows it. It is awaited in place, never spawned, which is why the lifetime is
/// sound and why nothing here needs `'static`.
pub type StreamFormatter = std::sync::Arc<
    dyn for<'w> Fn(
            &'w mut (dyn tokio::io::AsyncWrite + Unpin + Send),
            Response,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'w>>
        + Send
        + Sync,
>;

/// Stash a formatter on a response that carries a streaming body of some kind. Called by the
/// crate that owns the framing; `serve_connection` picks it up.
pub fn with_formatter(mut resp: Response, formatter: StreamFormatter) -> Response {
    resp.extensions_mut().insert(formatter);
    resp
}

/// Take the stashed formatter, if there is one. `Extensions::remove`, once — a formatter is
/// consumed exactly once per response, like the receiver.
pub(crate) fn take_formatter(resp: &mut Response) -> Option<StreamFormatter> {
    resp.extensions_mut().remove()
}
