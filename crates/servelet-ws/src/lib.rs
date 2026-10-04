//! `servelet-ws` — WebSocket: the RFC 6455 frame codec and the upgrade handshake.
//!
//! One job. This crate turns bytes into [`Message`]s and back, and performs the handshake on
//! both sides — [`connect`] for the client, [`accept`] for the server. It does not route, does
//! not decide *whether* a connection upgrades (that is the handler's business, expressed as a
//! response), and does not own the socket loop: `servelet-h1` reads the request, hands the
//! response to [`accept`]'s caller, and keeps the connection for the WebSocket's lifetime.
//!
//! The seam with the wire is one value in the response's extensions:
//! `servelet_h1::with_upgrade(resp, callback)` -> the callback receives the connection after the
//! `101` and drives it with this crate. See `docs/EXTENSIONS.md` §7.
//!
//! Moved byte-for-byte from `biota/http-server`'s `lib.rs` at rev `4ce2dcd`, the `pub mod
//! websocket` body:
//!   * 2490-2598 — `WS_GUID`, `sha1`, `base64_encode`, `compute_accept_key`, `generate_key` —
//!     `src/handshake.rs`
//!   * 2600-2734 — `Message`, the opcodes, `WebSocket`, `read_n`, `write_frame`, `send_text`,
//!     `send_binary`, `ping`, `close`, `recv` — `src/frame.rs`
//!   * 2736-2785 — `connect` — `src/client.rs`
//!   * 2787-2808 — `accept` — this file
//!   * 2814-2927 — five `#[cfg(test)]` tests, real sockets — `tests/moved.rs`
//!
//! Every deviation is listed, with its reason, in `docs/EXTENSIONS.md`.

#![forbid(unsafe_code)]

mod client;
mod frame;
mod handshake;
mod limits;

pub use client::{connect, connect_with_limits};
pub use frame::{Message, WebSocket};
pub use handshake::{base64_encode, compute_accept_key, generate_key, sha1};
pub use limits::{
    WsLimits, CLOSE_GOING_AWAY, CLOSE_INVALID_PAYLOAD, CLOSE_PROTOCOL_ERROR, CLOSE_TOO_BIG,
};

use servelet_core::{Error, Method, Request, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};/// Server side: given a raw `TcpStream`, the already-parsed upgrade `Request` (the caller's own
/// accept loop reads the request head, checks it's an upgrade, then hands both here), and any
/// bytes already read off the socket past the request's header terminator (empty if the caller
/// read the request byte-exactly), write the `101 Switching Protocols` response and return an
/// established `WebSocket`.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    req: &Request,
    pending: Vec<u8>,
) -> Result<WebSocket<S>> {
    accept_with_limits(stream, req, pending, WsLimits::default()).await
}

/// [`accept`] with the inbound size ceilings stated by the caller instead of defaulted.
///
/// A server is the side that faces the internet, so this is the call that matters: `accept`
/// (the moved signature, unchanged) hands the connection the documented 1 MiB frame / 16 MiB
/// message ceilings, and this one lets an application that legitimately needs different numbers
/// say so per route rather than by editing a constant.
pub async fn accept_with_limits<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    req: &Request,
    pending: Vec<u8>,
    limits: WsLimits,
) -> Result<WebSocket<S>> {
    if req.method() != &Method::GET {
        return Err(Error::Http("WebSocket upgrade must be a GET".to_string()));
    }
    let client_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Http("missing Sec-WebSocket-Key".to_string()))?
        .to_string();
    let accept_key = compute_accept_key(&client_key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept_key}\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await.map_err(Error::Io)?;
    Ok(WebSocket { stream, is_client: false, pending, limits, msg_buf: Vec::new(), msg_opcode: 0, msg_active: false, idle_timeout: None, ping_interval: None })
}

/// splitmix64 — the crate's non-cryptographic clock-seeded randomness, verbatim from
/// `Ptyktos/transport`'s `http_client.rs` (the crate `biota/http-server` re-exported it from),
/// the same 4 lines `servelet-client` carries for the same reason. Needed only by
/// `generate_key`, for the client-side `Sec-WebSocket-Key`: RFC 6455 asks that the key look
/// plausible to a non-WebSocket-aware intermediary, not that it resist an attacker, and the
/// handshake's own secrecy is the `Sec-WebSocket-Accept` round trip, not this value.
fn splitmix64(x: u64) -> u64 {
    let x = x.wrapping_add(0x9E3779B97F4A7C15);
    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}
