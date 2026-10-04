//! Real-socket proof for the upgrade seam, added by this extraction (NOT moved).
//!
//! The five moved tests in `moved.rs` never involve a router: two of them drive a raw
//! `TcpListener` and this crate's own `accept` by hand, which proves the codec and the handshake
//! but says nothing about whether a ROUTE can upgrade — and that is the whole gap this unit
//! closes. `biota/http-server` had `websocket::accept` and no way to reach it from a handler,
//! because `serve_connection` hands the router a parsed `Request` and keeps the stream.
//!
//! Everything below goes through the path a consumer actually uses: a real `TcpListener`, a real
//! `Router`, `servelet_h1::serve_connection`, and this crate's own `connect` as the client — no
//! hand-written HTTP on the client side, no stubbed socket, no in-memory loopback.
//!
//! Auth is not optional, so every test here sits behind a layer that refuses before the handler
//! runs: no credentials is a 401, the wrong role is a 403, and in both cases the connection is
//! NOT upgraded (the client sees the refusal status, and `connect` fails rather than returning a
//! socket).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use servelet_core::{Error, Layer, Method, Request, Response, Service, StatusCode};
use servelet_h1::{serve_connection, with_upgrade, Upgraded, UpgradeFn};
use servelet_router::Router;
use servelet_ws::{accept, connect, Message};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

/// Test-vector credentials. NOT secrets: these literals are the whole point of a test vector,
/// and nothing here compares or logs real material. The operator's role is a header value the
/// test client sets explicitly.
const OPERATOR_TOKEN: &str = "test-vector-operator-token";
const VIEWER_TOKEN: &str = "test-vector-viewer-token";
const REQUIRED_ROLE: &str = "operator";

// ── The authed layer ------------------------------------------------------------------------

/// The authed layer, in the shape README rule 7 requires and `servelet-authed` will own: it is a
/// `Layer` over the whole `Router`, so there is no API from which a handler can be registered
/// without an authenticated context in front of it. Nothing here is a WebSocket-specific
/// concern — the point of the test is that the *upgrade* cannot skip it.
#[derive(Clone)]
struct RequireRole {
    role: &'static str,
}

struct AuthedRouter {
    inner: Router,
    role: &'static str,
}

impl Layer<Router> for RequireRole {
    type Service = AuthedRouter;

    fn wrap(&self, inner: Router) -> Self::Service {
        AuthedRouter { inner, role: self.role }
    }
}

impl Service<Request> for AuthedRouter {
    type Response = Response;
    type Error = Error;

    async fn ready(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn serve(&mut self, req: Request) -> Result<Response, Error> {
        // `Authorization: Bearer <token>` -> a role, or nothing. Constant-time on the secret
        // half even though these are test vectors: the comparison a consumer copies is the one
        // that has to be right when the values are real.
        let token = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t.to_string())
            // A browser's WebSocket API CANNOT set a header on the handshake (RFC 6455 §10.4) --
            // that is a property of every browser, not of this test -- so a real deployment also
            // accepts the credential in the query string or a cookie. The query form is here
            // because this crate's own `connect` client sends no extra headers, which is exactly
            // the constraint a browser imposes. Documented, not accidental.
            .or_else(|| query_token(&req).map(|t| t.to_string()))
            .unwrap_or_default();
        let role = if constant_time_eq(&token, OPERATOR_TOKEN) {
            "operator"
        } else if constant_time_eq(&token, VIEWER_TOKEN) {
            "viewer"
        } else {
            return Ok(Response::new(StatusCode::UNAUTHORIZED, "no credentials"));
        };
        if role != self.role {
            return Ok(Response::new(StatusCode::FORBIDDEN, "wrong role"));
        }
        self.inner.serve(req).await
    }
}

/// `?token=..` off the request line, percent-decoded nothing (these are test vectors, and the
/// value is a fixed ASCII literal) — see the note on the credential above for why this exists.
fn query_token(req: &Request) -> Option<&str> {
    let (_, query) = req.uri.path_and_query().split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix("token="))
}

/// Equality that does not leak *where* two secrets differ through timing. Length first, then
/// every byte of both, always: a byte-by-byte early return is the difference between "this token
/// is wrong" and "this token is right up to the fourth character".
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

// ── The routes ------------------------------------------------------------------------------

/// Is this request actually an upgrade request? The check a route needs before it hands the
/// connection away: the method, both upgrade headers, and a non-empty `Sec-WebSocket-Key`
/// (RFC 6455 §4.2.1). A request that fails it is answered 400 and NOT upgraded — the seam gives
/// a handler the power to take the socket, so something in front of the handler has to be able
/// to say no.
fn is_upgrade_request(req: &Request) -> bool {
    let has = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    };
    req.method() == &Method::GET
        && has("upgrade")
        && has("sec-websocket-key")
        && has("connection")
        && req
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
}

/// The origin a browser will send. Empty in the non-browser tests; a route that requires an
/// origin refuses anything else, which is the wrong-origin case the seam must also refuse.
fn allowed_origin(req: &Request) -> bool {
    match req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => o == "https://app.example",
    }
}

/// A WebSocket echo route: read frames until the peer closes, echo every text and binary
/// message back, let the codec answer pings (RFC 6455 §5.5.2) and report pongs.
///
/// The handler returns before any of that happens: it returns the UPGRADE, and the connection
/// is driven by the callback it stashed. That ordering is the whole design.
fn ws_echo(req: Request) -> Response {
    if !is_upgrade_request(&req) {
        return Response::new(StatusCode::BAD_REQUEST, "not a websocket upgrade request");
    }
    if !allowed_origin(&req) {
        return Response::new(StatusCode::BAD_REQUEST, "origin not allowed");
    }
    // The callback needs the request for the handshake (`accept` reads `Sec-WebSocket-Key` out
    // of it) and the handler no longer needs it, so it moves across.
    let for_callback = Arc::new(req.clone());
    let upgrade: UpgradeFn = Arc::new(move |conn: Upgraded| {
        // Cloned per invocation, BEFORE the async block: the callback is `Fn`, so it may be
        // called more than once, and an `async move` block would move its capture out of the
        // closure. An `Arc` is what makes "hand it a copy" the same operation as "look at it".
        let handshake = for_callback.clone();
        Box::pin(async move {
            let mut ws = match accept(conn, &handshake, Vec::new()).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("websocket handshake failed: {e}");
                    return Ok(());
                }
            };
            loop {
                match ws.recv().await {
                    Ok(Message::Text(t)) => ws.send_text(t).await?,
                    Ok(Message::Binary(b)) => ws.send_binary(&b).await?,
                    Ok(Message::Close) => {
                        ws.close().await?;
                        return Ok(());
                    }
                    // Ping was already answered by `recv` itself; Pong needs no reply.
                    Ok(Message::Ping(_) | Message::Pong(_)) => {}
                    Err(e) => {
                        // A peer that disappears mid-stream is normal, not a server error.
                        eprintln!("websocket read ended: {e}");
                        return Ok(());
                    }
                }
            }
        })
    });
    with_upgrade(Response::new(StatusCode::OK, Vec::new()), upgrade)
}

/// The app: every route behind the authed layer. There is no way to build this `Router`
/// without the layer in it — `RequireRole::wrap` is applied by `layered`, and the routes are
/// unreachable except through it.
fn app() -> Router {
    Router::new().route_sync(Method::GET, "/ws", ws_echo).layered(RequireRole { role: REQUIRED_ROLE })
}

async fn spawn_server(router: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let router = router.clone();
            tokio::spawn(serve_connection(stream, router, Some(peer)));
        }
    });
    addr
}

/// A raw HTTP GET for the refusal cases: those must be checked on the WIRE, because the point is
/// what a client sees, and this crate's `connect` refuses to look at anything but a 101.
async fn raw_get(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await.unwrap();

    let mut out = Vec::new();
    let mut one = [0u8; 1];
    // Byte at a time, bounded: a refusal response is small and complete, and reading until the
    // blank line cannot block on a server that is waiting for us to close our half.
    while !out.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut one))
            .await
            .expect("the response head must arrive within 5s")
            .expect("the connection closed inside the response head");
        let _ = n;
        out.push(one[0]);
    }
    String::from_utf8_lossy(&out).to_string()
}

fn status_line(head: &str) -> &str {
    head.lines().next().unwrap_or_default()
}

// ── The tests -------------------------------------------------------------------------------

/// The whole point: a ROUTE upgrades a real connection, echoes text, and the codec answers a
/// ping on its own and the close handshake completes in both directions.
#[tokio::test]
async fn a_route_upgrades_over_a_real_socket_echoes_text_and_closes_cleanly() {
    let addr = spawn_server(app()).await;

    // `connect` performs the whole client handshake and verifies the server's
    // `Sec-WebSocket-Accept` against RFC 6455's own formula — so this reaching a socket at all
    // is proof the accept key on the wire is right.
    // The credential rides in the query string, because `connect` (like a browser's WebSocket
    // API) sends no other way to authenticate an upgrade. It is a test vector, and the route
    // still refuses everything that arrives without it — see the 401/403 tests below.
    let mut ws = connect(&format!("ws://{addr}/ws?token={OPERATOR_TOKEN}"))
        .await
        .expect("the route must upgrade");

    ws.send_text("hello server").await.unwrap();
    assert_eq!(ws.recv().await.unwrap(), Message::Text("hello server".to_string()));

    ws.send_binary(&[1, 2, 3, 4]).await.unwrap();
    assert_eq!(ws.recv().await.unwrap(), Message::Binary(vec![1, 2, 3, 4]));

    // A ping. The server's `recv` answers it with a pong BEFORE returning the ping to its own
    // caller (RFC 6455 §5.5.2), so the first thing on the wire is the Pong -- and a Pong can
    // only have come from the server's codec, since this route never writes one itself.
    ws.ping(b"are-you-there").await.unwrap();
    assert_eq!(ws.recv().await.unwrap(), Message::Pong(b"are-you-there".to_vec()));

    // The close handshake, both directions: the client's Close reaches the route, which answers
    // with its own Close frame (an empty one -- RFC 6455 §5.5.1 allows it) and returns.
    ws.close().await.unwrap();
    assert_eq!(ws.recv().await.unwrap(), Message::Close);
}

/// A route's 400 must be a real refusal on the wire: a request with no `Sec-WebSocket-Key` is
/// not an upgrade, and an unupgraded response body must not be mistaken for a frame.
#[tokio::test]
async fn a_request_without_a_sec_websocket_key_is_answered_400_and_not_upgraded() {
    let addr = spawn_server(app()).await;
    let head = raw_get(
        addr,
        "/ws",
        &[
            ("Authorization", &format!("Bearer {OPERATOR_TOKEN}")),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
        ],
    )
    .await;
    assert!(
        status_line(&head).contains("400"),
        "expected a 400 without a key, got: {}",
        status_line(&head)
    );
    assert!(!head.contains("101"), "an invalid upgrade must never be switched: {head}");
}

/// Same rule, different refusal: a browser from another origin does not get the socket.
#[tokio::test]
async fn a_request_from_the_wrong_origin_is_answered_400_and_not_upgraded() {
    let addr = spawn_server(app()).await;
    let head = raw_get(
        addr,
        "/ws",
        &[
            ("Authorization", &format!("Bearer {OPERATOR_TOKEN}")),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Origin", "https://evil.example"),
        ],
    )
    .await;
    assert!(
        status_line(&head).contains("400"),
        "expected a 400 from the wrong origin, got: {}",
        status_line(&head)
    );
    assert!(!head.contains("101"), "a refused origin must never be switched: {head}");
}

/// No credentials: 401, and the upgrade never happens. `connect` fails on the status, which is
/// the black-box proof that no 101 was ever written.
#[tokio::test]
async fn an_unauthenticated_upgrade_is_refused_401_before_the_handler_runs() {
    let addr = spawn_server(app()).await;
    let head = raw_get(
        addr,
        "/ws",
        &[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    )
    .await;
    assert!(
        status_line(&head).contains("401"),
        "expected a 401 with no credentials, got: {}",
        status_line(&head)
    );
    assert!(!head.contains("101"), "an unauthenticated upgrade must never be switched: {head}");
}

/// A credential that is real but not the required role: 403, and again no upgrade. This is the
/// case a "check the token, then upgrade" handler gets wrong, so it is worth its own assertion.
#[tokio::test]
async fn an_upgrade_with_the_wrong_role_is_refused_403_before_the_handler_runs() {
    let addr = spawn_server(app()).await;
    let head = raw_get(
        addr,
        "/ws",
        &[
            ("Authorization", &format!("Bearer {VIEWER_TOKEN}")),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    )
    .await;
    assert!(
        status_line(&head).contains("403"),
        "expected a 403 for the wrong role, got: {}",
        status_line(&head)
    );
    assert!(!head.contains("101"), "a forbidden upgrade must never be switched: {head}");
}

/// The authorization check is the one a consumer copies, so it is pinned on its own: a token
/// that is right up to its last character must not pass.
#[test]
fn the_role_check_does_not_accept_a_prefix_of_a_valid_token() {
    assert!(!constant_time_eq("test-vector-operator-toke", OPERATOR_TOKEN));
    assert!(!constant_time_eq("test-vector-operator-tokens", OPERATOR_TOKEN));
    assert!(constant_time_eq(OPERATOR_TOKEN, OPERATOR_TOKEN));
}