//! `servelet-sse` — Server-Sent Events: the framing, and the streaming response body that
//! carries it.
//!
//! One job. This crate turns `Event`s into `text/event-stream` bytes and writes them to a live
//! connection as they arrive. It does not route, does not parse a request, and does not open a
//! socket: `servelet-h1` accepts, reads, and dispatches; the writer this crate hands it (see
//! `wire.rs`) is stashed on the response through `servelet_h1::with_formatter`.
//!
//! `HttpResponseBuilder` lives HERE, not in `servelet-core`. `docs/EXTRACTION.md` §7 puts it in
//! `servelet-sse` and §3 of `docs/EXTENSIONS.md` says why: its two jobs are `streaming(..)` and
//! carrying `Set-Cookie` values, and the census measured its dependencies as exactly this
//! crate's. Putting a `tokio`-using builder in `servelet-core` would have forced a runtime into
//! the one crate that must work without one.
//!
//! Moved byte-for-byte from `biota/http-server` at rev `4ce2dcd`:
//!   * `lib.rs` 2138-2418 — the `pub mod sse` body (`Sse`, `Event`, `Data`, `SseBody`,
//!     `content_type`, `encode_event`, `SseEvent`, `SseParser`) — `src/sse.rs`
//!   * `lib.rs` 2419-2469 — its `wire_tests` — `tests/moved.rs`
//!   * `lib.rs` 92-94 and 128-222 — `builder()` and `HttpResponseBuilder` — `src/builder.rs`
//!   * `kernel.rs` 3059-3130 — `write_sse_response`/`write_sse_chunk` — `src/wire.rs`
//!
//! Every deviation is listed, with its reason, in `docs/EXTENSIONS.md`.

#![forbid(unsafe_code)]

mod builder;
mod sse;
mod wire;

// The writer is crate-private: a consumer does not call it, it is stashed on the response by
// `sse_response`/`formatter` below and picked up by `servelet-h1`'s `serve_connection`.

pub use builder::HttpResponseBuilder;
pub use sse::{content_type, encode_event, sse_body, Data, Event, Sse, SseEvent, SseParser};

use servelet_core::{Request, Response};

/// The formatter `servelet-h1`'s `serve_connection` picks up off a response that carries an SSE
/// body, and the one [`Sse::respond_to`] stashes.
///
/// DEVIATION, mechanics only (`docs/EXTENSIONS.md` §5): in biota `serve_connection` named
/// `write_sse_response` directly, because both were in one crate. They cannot both be in one
/// crate here without `servelet-h1` depending on this one (rule 2). The writer is therefore
/// carried on the response, next to the body it writes — which is where the dispatch always
/// started.
pub fn formatter() -> servelet_h1::StreamFormatter {
    std::sync::Arc::new(|mut writer, response| {
        Box::pin(async move {
            // DEVIATION, one line: biota's `serve_connection` had already read the body out of
            // the response before calling the writer (`Response::sse_body()`), so the writer took
            // it as an argument. Here the writer is handed the response and takes its own body,
            // because the dispatch point is in a crate that cannot know the SSE body type.
            let body = sse_body(&response)
                .expect("the formatter is only stashed on a response that carries an SSE body");
            // `&mut writer` re-wraps the erased reference as a sized `&mut &mut dyn ..`, which
            // is what the moved generic signature takes (`W: AsyncWriteExt + Unpin`).
            let w = &mut writer;
            wire::write_sse_response(w, response, body).await
        })
    })
}

/// `Sse::respond_to`, with this crate's writer already stashed: the whole of turning a channel of
/// `Event`s into a live `text/event-stream` response, in one call. This is what a handler
/// returns, and what the SSE socket test drives.
pub fn sse_response(sse: Sse, req: &Request) -> Response {
    let resp = sse.respond_to(req);
    if sse_body(&resp).is_some() {
        servelet_h1::with_formatter(resp, formatter())
    } else {
        resp
    }
}
