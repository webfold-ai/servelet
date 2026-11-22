// -- Connection pool (Pingora-style keepalive reuse) ---------------------

// DEVIATION, the `use` lines only: biota's `kernel.rs` had them at the top of the file (lines
// 1-16). Nothing is re-declared or renamed.

use wirefold::{Coord, CoordMap};
use tokio::net::TcpStream;

use crate::stream::Stream;
#[cfg(feature = "tls")]
use crate::stream::tls_config;
use servelet_core::{host_port, Error, Result, Uri};


/// A pooled, idle connection plus any bytes already pulled off the wire past the previous
/// response's end (see `StreamReader::into_inner`'s doc for why this must travel with it).
pub(crate) struct PooledConn {
    pub(crate) stream: Stream,
    pub(crate) leftover: Vec<u8>,
}

/// Max idle connections kept per upstream identity — mirrors Pingora's own
/// `keepalive_pool_size` (a per-identity cap, not a global one). Small and fixed rather than
/// configurable yet: an honest scope limit, not a hidden one.
const POOL_CAP_PER_IDENTITY: usize = 32;

/// Process-global keepalive pool, keyed by upstream identity (`scheme://host:port`) — mirrors
/// Pingora's own `pingora-core::connectors` pool (an `Arc<ConnectionPool>` keyed by
/// `peer.reuse_hash()`). This is the single biggest gap the architecture survey found on the
/// client side ("No connection pooling/keep-alive reuse... new TCP+TLS handshake per request").
/// `CoordMap` (not a synchronized `Table`) is fine here because the `Mutex` around it is the
/// actual synchronization — matches this file's own established convention of using
/// `identity.coord()` for a bounded, small set of distinct upstream identities (the same shape
/// `Router`'s route keys and `Proxy`'s upstream keys already use), not the opaque-hash misuse
/// `Extensions` had to move off of.
pub(crate) fn pool() -> &'static std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(CoordMap::coordinate()))
}

pub(crate) fn identity_for(uri: &Uri) -> Result<String> {
    let (host, port) = host_port(uri)?;
    let scheme = uri.scheme_str().unwrap_or("http");
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Pop the most-recently-returned idle connection for `identity`, if any (LIFO — better cache
/// locality than FIFO for the common bursty-traffic case). Takes the WHOLE per-identity `Vec`
/// out via `remove` (ownership, no clone — `PooledConn` holds a live socket and can't be cloned
/// anyway) and puts back whatever's left, rather than trying to mutate through a shared `&Vec`.
pub(crate) fn pool_take(identity: &str) -> Option<PooledConn> {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key)?;
    let popped = conns.pop();
    if !conns.is_empty() {
        guard.put(key, conns);
    }
    popped
}

/// Return an idle connection to the pool for reuse, capped at `POOL_CAP_PER_IDENTITY` (excess
/// connections are simply dropped/closed rather than kept, matching Pingora's own per-identity
/// cap behavior).
pub(crate) fn pool_put(identity: &str, conn: PooledConn) {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key).unwrap_or_default();
    if conns.len() < POOL_CAP_PER_IDENTITY {
        conns.push(conn);
    }
    guard.put(key, conns);
}

/// Connect, preferring a pooled idle connection. Returns whether the connection came from the
/// pool — the caller needs this to know whether a first-write failure warrants a transparent
/// retry on a guaranteed-fresh connection (a reused connection can always turn out to be stale:
/// the peer's own idle timeout, a network blip, or — found via this crate's own test suite — a
/// connection pooled under one tokio runtime and reused from a different one, since a socket is
/// registered with the specific runtime's I/O driver that was active when it was created. All
/// three are the same class of problem a robust pool has to handle, not paper over: never trust
/// an idle connection's first write to succeed).
pub(crate) async fn connect(uri: &Uri, resolve: &std::collections::HashMap<String, std::net::SocketAddr>) -> Result<(Stream, bool)> {
    let identity = identity_for(uri)?;
    if let Some(pooled) = pool_take(&identity) {
        // A pooled connection is only ever stored with an empty `leftover` (see `send_request`'s
        // pool-return step, which only pools a connection when there wasn't any) — there's no
        // plumbing here to hand leftover bytes into a fresh `send_request` call, so this
        // invariant is asserted rather than silently trusted.
        debug_assert!(pooled.leftover.is_empty(), "pooled connections are only stored with no leftover bytes");
        return Ok((pooled.stream, true));
    }
    Ok((connect_fresh(uri, resolve).await?, false))
}

/// Always open a brand new connection, bypassing the pool entirely — used for the initial
/// connect when nothing's pooled, and for the guaranteed-fresh retry after a pooled connection's
/// first write fails. `resolve` overrides the socket address a host connects to (reqwest's
/// `.resolve()`) while keeping the ORIGINAL hostname for TLS SNI — only the IP changes.
pub(crate) async fn connect_fresh(
    uri: &Uri,
    resolve: &std::collections::HashMap<String, std::net::SocketAddr>,
) -> Result<Stream> {
    // Refuse before any network I/O: without the `tls` feature an https URL must not resolve or dial
    // the host at all (the DNS query alone would disclose it), it must fail by name immediately.
    #[cfg(not(feature = "tls"))]
    if uri.scheme_str() == Some("https") {
        return Err(Error::Tls(
            "an https:// URL needs this crate's `tls` feature (rustls, tokio-rustls and the \
             system trust store); it is off by default so a plaintext consumer links no TLS \
             stack -- turn it on with `features = [\"tls\"]`"
                .to_string(),
        ));
    }
    let (host, port) = host_port(uri)?;
    let dial_target = resolve.get(&host).copied();
    let tcp = match dial_target {
        Some(addr) => TcpStream::connect(addr).await?,
        None => TcpStream::connect(format!("{}:{}", host, port)).await?,
    };
    tcp.set_nodelay(true)?;
    match uri.scheme_str() {
        #[cfg(feature = "tls")]
        Some("https") => {
            let server_name = rustls_pki_types::ServerName::try_from(host.clone())
                .map_err(|e| Error::Tls(format!("invalid hostname {host:?}: {e}")))?
                .to_owned();
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Tls(format!("handshake with {host} failed: {e}")))?;
            Ok(Stream::Tls(Box::new(tls)))
        }
        _ => Ok(Stream::Plain(tcp)),
    }
}
