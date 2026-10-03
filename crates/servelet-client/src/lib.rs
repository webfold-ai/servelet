//! `servelet-client` — an outbound HTTP client with a connection pool and a retry policy.
//!
//! One job: this crate makes requests. It is the mirror image of `servelet-h1`, and it shares
//! nothing with it but the types they both speak — `Request`'s little siblings `Method`, `Uri`,
//! `HeaderMap`, `StatusCode`, `Version`, and `Error`, all from `servelet-core`.
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`:
//!   * 1065-1673 — the Reqwest face: `RetryPolicy`, the cookie jar, `Part`/`Form`,
//!     `RequestBuilder`, `Client`, `ClientBuilder` — `src/reqwest.rs`
//!   * 1674-1825 — `Stream`/`StreamReader` — `src/stream.rs`
//!   * 1826-1852 — `tls_config()`, the client half — `src/stream.rs`
//!   * 1970-2083 — the connection pool (`pool`, `pool_take`, `pool_put`, `connect`) — `src/pool.rs`
//!   * 2085-2444 — `write_request`, `read_response_head`, `send_request`, `BodyFraming`,
//!     `StreamingResponse`, `parse_status_line`, `read_chunked` — `src/send.rs`
//!
//! Twelve tests moved with them (`tests/moved.rs`), all of which bind real local sockets.
//! Every deviation is listed, with its reason, in `docs/EXTENSIONS.md`.

#![forbid(unsafe_code)]

mod pool;
mod reqwest;
mod send;
mod stream;

pub use reqwest::*;
pub use send::*;
pub use stream::*;


pub(crate) use pool::{connect, pool_put, pool_take};
