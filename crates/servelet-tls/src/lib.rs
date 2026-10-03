//! `servelet-tls` — server-side TLS termination over rustls. One job: turn a TCP accept loop into
//! an encrypted one, then hand the decrypted stream to the same HTTP/1.1 loop plain HTTP uses.
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`, "Server-side TLS
//! termination", lines 1854-1968: `base64_decode`, `pem_blocks`, `tls_server_config`, `serve_tls`.
//! It depends on `servelet-h1` for `serve_connection` and `servelet-router` for `Router` — it does
//! not reimplement a request/response loop, which is the point of the split.

#![forbid(unsafe_code)]

use servelet_core::{Error, Result};
use servelet_h1::serve_connection;
use servelet_router::Router;
use tokio::net::{TcpListener, ToSocketAddrs};

mod tls;

pub use tls::{tls_server_config, serve_tls};