//! `servelet-h1` — the HTTP/1.1 wire: read requests, write responses, chunked, keep-alive, serve.
//!
//! One job: bytes in, bytes out. It knows a `Router` exists (that is how a request becomes a
//! response) and nothing else — not TLS (that is `servelet-tls`, which hands the loop a
//! decrypted stream), not SSE framing, not HTTP/2.
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`:
//!   * `read_request_buffered`, `serve`, `serve_connection` — lines 2816-3007
//!   * `connection_close`, `read_request`, `write_response` — lines 3008-3065
//!   * `write_chunk` — lines 3132-3141
//!   * `write_streaming_response` — lines 3143-3197
//!
//! CUT, with the reason, in `docs/SPINE.md` (both belong to crates this unit does not build):
//!   * `write_sse_response`/`write_sse_chunk` (3066-3130) — `servelet-sse` owns the SSE framing;
//!     it reaches this crate's writer through the `StreamFormatter` seam (`streaming.rs`), not
//!     through a dependency edge in this direction.
//!   * the h2c-preface sniff at the top of `serve_connection` — `servelet-h2` owns the preface.
//!
//! Public API: [`serve`], [`serve_gracefully`], [`serve_connection`], [`read_request`],
//! [`write_response`], [`streaming`]/[`streaming_body`]/[`StreamingBody`].

#![forbid(unsafe_code)]

use tokio::net::{TcpListener, TcpSocket, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use servelet_core::{header, Error, Extensions, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Result, Uri, Version, status_reason};
use servelet_router::Router;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::Instrument;

mod streaming;
mod wire;

pub use streaming::{streaming, streaming_body, with_formatter, StreamFormatter, StreamingBody, take_receiver};
pub use wire::{read_request, serve, serve_connection, write_chunk, write_response};
pub use graceful::serve_gracefully;

mod graceful;
