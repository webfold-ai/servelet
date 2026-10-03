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
pub(crate) async fn take_receiver(body: StreamingBody) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>> {
    Ok(body
        .rx
        .lock()
        .await
        .take()
        .expect("StreamingBody's receiver is stashed exactly once per response and consumed exactly once, here"))
}