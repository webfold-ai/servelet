//! The gRPC-unary layer on top of `h2::serve_h2c_connection`.
//!
//! [`grpc_unary`] wraps a handler so that the request body has its 5-byte gRPC
//! message header stripped before the handler sees it, and the handler's response body
//! is wrapped in a fresh 5-byte header on the way out, with a `grpc-status: 0` trailer
//! header set on the response (preserved from the handler if the application set one
//! -- an earlier version overwrote it with 0 unconditionally, which silently dropped
//! `grpc-status: 13` (INTERNAL) the handler set on a real error path).
//!
//! The gRPC unary call is HTTP/2 with one extra framing layer. The h2 transport already
//! produces a valid HEADERS + DATA + END_STREAM HEADERS wire form; the layer plugs into
//! the body bytes (5-byte prefix in, prefix out) and the response headers (the
//! `grpc-status` trailer the h2 transport writes is sourced from the response's
//! `grpc-status` header). No new connection-level code is needed; a consumer wires it
//! up directly under each `Router::post`/`fallback` call:
//!
//! ```ignore
//! let router = Router::new()
//!     .post("/pkg.Svc/Echo", grpc_unary(|req: Request| async move {
//!         Response::ok(req.into_body())
//!     }));
//! ```
//!
//! The `tests/grpc_unary.rs` integration test drives this path end-to-end with a
//! hand-rolled h2c + gRPC client that asserts the 5-byte prefix on both the request
//! and the response DATA frames and the `grpc-status: 0` trailer.

use std::future::Future;
use std::sync::Arc;

use servelet_core::{HeaderName, HeaderValue, Request, Response, StatusCode};
use servelet_router::BoxHandler;

use crate::grpc::{grpc_status, unwrap_request_body, wrap_response_body};

/// Per-handler gRPC-unary layer. Strips the 5-byte message header off the request body,
/// calls the inner handler, then wraps the response body in a fresh 5-byte header and
/// sets `grpc-status: 0` on the response (unless the inner handler set one -- a 13
/// INTERNAL from a real error path is reflected to the client, not relabelled 0).
///
/// The signature is the shape `Router::post` / `Router::fallback` wants: a function from
/// `Request` to a future of `Response`. The test in `tests/grpc_unary.rs` uses this
/// directly under a `Router::fallback(grpc_unary(...))` call.
pub fn grpc_unary<H, F>(inner: H) -> impl Fn(Request) -> std::pin::Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static + Clone
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let inner = Arc::new(inner);
    move |req: Request| {
        let inner = inner.clone();
        Box::pin(async move {
            // 1. Strip the 5-byte gRPC header from the request body. A malformed prefix
            //    is a wire error: respond 500 with grpc-status: 13 (INTERNAL) -- what a
            //    real gRPC client expects from a server that cannot read the wire.
            let method = req.method().clone();
            let uri = req.uri().clone();
            let body = req.into_body();
            let (compressed, message_body) = match unwrap_request_body(&body) {
                Ok((c, b)) => (c, b.to_vec()),
                Err(_) => {
                    return Response::new(StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
                        .with_header(grpc_status(), HeaderValue::from(13u32))
                        .with_header(
                            HeaderName::from_static("content-type"),
                            HeaderValue::from_static("application/grpc+proto"),
                        );
                }
            };

            // 2. Hand the message body (no prefix) to the inner handler.
            let inner_req = Request::new(method, uri).with_body(message_body);
            let resp = inner(inner_req).await;

            // 3. Wrap the response body in a fresh 5-byte gRPC header.
            let wrapped = wrap_response_body(&resp.body, compressed);

            // 4. Propagate or set grpc-status and grpc-message. The h2 transport reads
            //    these from the response headers to build the trailer HEADERS frame.
            let parsed_status: u32 = resp
                .headers()
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut out = Response::new(resp.status(), wrapped);
            for (k, v) in resp.headers().iter() {
                // Skip the fields we re-add below; `grpc-status` is regenerated from the
                // parsed value (so a handler that set "13" stays "13", not "0" + "13").
                let name: &str = k.as_ref();
                if name == "grpc-status" || name == "grpc-message" {
                    continue;
                }
                out = out.with_header(k.clone(), v.clone());
            }
            out = out.with_header(grpc_status(), HeaderValue::from(parsed_status));
            if let Some(m) = resp.headers().get("grpc-message") {
                if let Ok(s) = m.to_str() {
                    out = out.with_header(
                        HeaderName::from_static("grpc-message"),
                        HeaderValue::from(s),
                    );
                }
            }
            out
        })
    }
}

/// `BoxHandler`-shaped variant of [`grpc_unary`], for callers that already hold a
/// `BoxHandler` (e.g. one produced by `Router::layer`). The closure form is preferred
/// at registration time; this one exists for symmetry with the existing `Router::layer`
/// API.
pub fn grpc_unary_layer(inner: BoxHandler) -> BoxHandler {
    Arc::new(move |req: Request| {
        let inner = inner.clone();
        Box::pin(async move {
            let method = req.method().clone();
            let uri = req.uri().clone();
            let body = req.into_body();
            let (compressed, message_body) = match unwrap_request_body(&body) {
                Ok((c, b)) => (c, b.to_vec()),
                Err(_) => {
                    return Response::new(StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
                        .with_header(grpc_status(), HeaderValue::from(13u32))
                        .with_header(
                            HeaderName::from_static("content-type"),
                            HeaderValue::from_static("application/grpc+proto"),
                        );
                }
            };
            let inner_req = Request::new(method, uri).with_body(message_body);
            let resp = inner(inner_req).await;
            let wrapped = wrap_response_body(&resp.body, compressed);
            let parsed_status: u32 = resp
                .headers()
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut out = Response::new(resp.status(), wrapped);
            for (k, v) in resp.headers().iter() {
                let name: &str = k.as_ref();
                if name == "grpc-status" || name == "grpc-message" {
                    continue;
                }
                out = out.with_header(k.clone(), v.clone());
            }
            out = out.with_header(grpc_status(), HeaderValue::from(parsed_status));
            if let Some(m) = resp.headers().get("grpc-message") {
                if let Ok(s) = m.to_str() {
                    out = out.with_header(
                        HeaderName::from_static("grpc-message"),
                        HeaderValue::from(s),
                    );
                }
            }
            out
        })
    })
}
