//! The upgrade seam (added after the move) ------------------------------------------------
//
// WHY: `serve_connection` reads a request, hands the parsed `Request` to the `Router`, writes a
// response and moves on. That is a correct HTTP/1.1 loop and it cannot serve a WebSocket: once a
// connection is upgraded the socket stops being HTTP, and the value the protocol needs next (the
// stream itself) is exactly the value `serve_connection` owns and the `Router` never sees. biota
// hit this and left `websocket::accept` unreachable from any route -- the caller had to own the
// `TcpStream` and read the request head by hand.
//
// The seam is a value in the response's own extensions, exactly like the streaming formatter
// beside it (`streaming.rs`): no global, no registry, no "installed once" (rule 3). A handler
// that wants to upgrade returns [`with_upgrade`](with_upgrade)(resp, callback); `serve_connection`
// takes it out, hands the connection to the callback, and never writes a normal response for
// that request. A handler that does not upgrade returns a normal response and nothing here runs.
//
// WHAT THE CALLBACK OWNS: everything after the callback is called. `serve_connection` writes
// nothing more to that connection (not even a shutdown -- see `wire.rs`), because the callback
// has it. The callback is responsible for the protocol's first byte: a WebSocket handshake
// writes its own `101 Switching Protocols` (`servelet_ws::accept` does exactly that, verbatim
// from biota). That ordering is deliberate -- it keeps the HTTP response writer, which knows
// nothing about switching protocols, out of the upgrade path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Response, Result};

/// The connection an upgrade callback receives, as one type: something that reads AND writes.
///
/// Named rather than spelled `Box<dyn AsyncRead + AsyncWrite>` because Rust has no way to write
/// that: a trait object can combine auto traits (`Send`, `Unpin`) but not two non-auto traits.
/// This is the standard spelling of the same thing, and it keeps `servelet-ws`'s `accept`
/// generic over `AsyncRead + AsyncWrite` rather than forcing it to name this type at all.
pub trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}

/// The connection handed to an upgrade callback, boxed so `serve_connection` can give up its
/// generic stream type (`TcpStream`, or a TLS stream, or a `BufReader` over either) at the
/// moment the connection stops being HTTP.
///
/// It IS its own `AsyncRead`/`AsyncWrite`, so a protocol crate that is generic over a stream --
/// `servelet_ws` is exactly that -- accepts it with no wrapper, no trait-object gymnastics, and
/// no change to its moved frame code.
pub struct Upgraded {
    conn: Box<dyn Connection>,
}

impl Upgraded {
    /// Take ownership of a connection. Called by `serve_connection`, once, at the upgrade.
    pub fn new(conn: Box<dyn Connection>) -> Self {
        Upgraded { conn }
    }

    /// The connection underneath, for a caller that wants the box itself (a split read/write
    /// half, a `tokio::io::split`, a test that wants to assert on the socket).
    pub fn connection(&mut self) -> &mut Box<dyn Connection> {
        &mut self.conn
    }
}

// Delegating `AsyncRead`/`AsyncWrite` by hand rather than with a derive: there is no derive, and
// `Box<dyn Connection>` is `Unpin` (auto traits apply to trait objects), so the projection is a
// `Pin::new` of a plain reference -- no unsafe anywhere in this file.
impl AsyncRead for Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.conn).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.conn).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.conn).poll_shutdown(cx)
    }
}

/// What an upgrade response carries: a callback that takes the connection and runs the protocol.
///
/// `'static` on purpose. The connection is gone from `serve_connection` once this is called, so
/// the callback CANNOT borrow the connection, and it is not awaited inside anything that would
/// let it borrow the response. Spawnable, drivable to completion, and forgettable in one line --
/// which is what an upgrade actually is: the HTTP conversation is over, and what follows is a
/// conversation of its own with its own lifetime.
pub type UpgradeFn =
    Arc<dyn Fn(Upgraded) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Mark a response as an upgrade: when `serve_connection` sees this on the response, it hands the
/// connection to `upgrade` instead of writing a response and closing.
///
/// The status, `Upgrade: websocket`, `Connection: Upgrade` and `Sec-WebSocket-Accept` headers are
/// the PROTOCOL's business, not this crate's: `servelet_ws::accept` writes them, verbatim from
/// biota, before its first frame. Put the wrong status here and it would be silently ignored,
/// which is why there is no way to set one here.
pub fn with_upgrade(resp: Response, upgrade: UpgradeFn) -> Response {
    let mut resp = resp;
    resp.extensions_mut().insert(upgrade);
    resp
}

/// Take the stashed upgrade, if there is one. `Extensions::remove`, once -- an upgrade callback
/// runs exactly once per response, and exactly once per connection.
pub(crate) fn take_upgrade(resp: &mut Response) -> Option<UpgradeFn> {
    resp.extensions_mut().remove()
}