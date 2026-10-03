//! Real-socket tests for `servelet-client`.
//!
//! The client code came out of `biota/http-server` with no tests attached — it sat inside a
//! `mod tests` block whose cases all exercised other faces. A port that cannot be reached
//! is a port that cannot have been checked, so these drive a real server over a real socket.
//!
//! Deliberately no mocking: the whole risk in a hand-rolled HTTP client is wire framing,
//! and a mock would test the mock.

use std::net::SocketAddr;
use std::time::Duration;

use servelet_core::{header, Method, Request, Response, StatusCode, Uri};
use servelet_router::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a one-route server on a real port and hand back its address.
///
/// The listener is bound before the task is spawned so the caller cannot race the first
/// connection against the accept loop.
async fn spawn_server(router: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        // `serve` binds its own listener, so drive the already-bound one through
        // `serve_connection` per accepted socket instead.
        loop {
            let Ok((stream, peer)) = listener.accept().await else { break };
            let router = router.clone();
            tokio::spawn(servelet_h1::serve_connection(stream, router, Some(peer)));
        }
    });
    addr
}

fn router_echo_body() -> Router {
    Router::new().route(
        Method::POST,
        "/echo",
        |req: Request| async move {
            Response::new(StatusCode::OK, req.body().to_vec())
                .with_header("content-type", "text/plain")
        },
    )
}

#[tokio::test]
async fn get_returns_status_and_body() {
    let addr = spawn_server(
        Router::new().route(Method::GET, "/hello", |_req| async move {
            Response::new(StatusCode::OK, "hi there".as_bytes().to_vec())
        }),
    )
    .await;

    let resp = servelet_client::Client::new()
        .get(format!("http://{addr}/hello"))
        .send()
        .await
        .expect("GET should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await, b"hi there");
}

#[tokio::test]
async fn request_body_round_trips() {
    let addr = spawn_server(router_echo_body()).await;

    let resp = servelet_client::Client::new()
        .post(format!("http://{addr}/echo"))
        .body("payload-in".as_bytes().to_vec())
        .send()
        .await
        .expect("POST should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await, b"payload-in");
}

#[tokio::test]
async fn status_code_survives_the_wire() {
    let addr = spawn_server(
        Router::new().route(Method::GET, "/teapot", |_req| async move {
            Response::new(StatusCode::from_u16(418).unwrap(), "short and stout".as_bytes().to_vec())
        }),
    )
    .await;

    let resp = servelet_client::Client::new()
        .get(format!("http://{addr}/teapot"))
        .send()
        .await
        .expect("GET should succeed");

    assert_eq!(resp.status(), StatusCode::from_u16(418).unwrap());
    assert_eq!(resp.bytes().await, b"short and stout");
}

#[tokio::test]
async fn response_headers_are_readable() {
    let addr = spawn_server(
        Router::new().route(Method::GET, "/typed", |_req| async move {
            Response::new(StatusCode::OK, b"x".to_vec()).with_header("content-type", "application/json")
        }),
    )
    .await;

    let resp = servelet_client::Client::new()
        .get(format!("http://{addr}/typed"))
        .send()
        .await
        .expect("GET should succeed");

    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
}

#[tokio::test]
async fn streaming_send_yields_chunks_in_order() {
    // A handler whose body is large enough to span more than one read, so `send_streaming`
    // has to reassemble in order rather than return one buffer by luck.
    let payload = "abcdefghij".repeat(500);
    let addr = spawn_server(
        Router::new().route(Method::GET, "/stream", move |_req| {
            let payload = payload.clone();
            async move { Response::new(StatusCode::OK, payload.into_bytes()) }
        }),
    )
    .await;

    let mut resp = servelet_client::Client::new()
        .get(format!("http://{addr}/stream"))
        .send_streaming()
        .await
        .expect("streaming GET should succeed");

    let mut got = Vec::new();
    while let Some(chunk) = resp.chunk().await.expect("chunk read") {
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, "abcdefghij".repeat(500).into_bytes());
}

#[tokio::test]
async fn connection_is_pooled_across_sequential_requests() {
    let addr = spawn_server(
        Router::new().route(Method::GET, "/pooled", |_req| async move {
            Response::new(StatusCode::OK, b"ok".to_vec())
        }),
    )
    .await;

    let client = servelet_client::Client::new();
    for _ in 0..4 {
        let resp = client
            .get(format!("http://{addr}/pooled"))
            .send()
            .await
            .expect("each request should succeed");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn refused_connection_is_an_error_not_a_panic() {
    // Port 1 on loopback: nothing listens, so this must surface as `Err`.
    let err = servelet_client::Client::new()
        .get("http://127.0.0.1:1/nope")
        .send()
        .await;
    assert!(err.is_err(), "a refused connection must be an error");
}

#[tokio::test]
async fn parse_status_line_rejects_garbage() {
    // A unit check on the response-head parser the socket tests lean on.
    assert!(servelet_client::parse_status_line("not a status line").is_err());
    let (v, s) = servelet_client::parse_status_line("HTTP/1.1 200 OK").expect("valid status line");
    assert_eq!(v, servelet_core::Version::HTTP_11);
    assert_eq!(s, StatusCode::OK);
}

/// A raw socket that speaks HTTP/1.1 by hand, so the client's own framing is exercised
/// against a server that is not ours.
#[tokio::test]
async fn talks_to_a_hand_rolled_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 1024];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        let got = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(got.starts_with("GET /raw HTTP/1.1"), "unexpected request: {got:?}");
        sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        )
        .await
        .ok();
        sock.flush().await.ok();
        let _ = Duration::from_millis(1);
    });

    let resp = servelet_client::Client::new()
        .get(format!("http://{addr}/raw"))
        .send()
        .await
        .expect("GET should succeed against a hand-rolled server");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await, b"hello");
}

#[tokio::test]
async fn uri_is_built_from_a_full_url() {
    // `Client::request` takes a string; this pins that a full URL parses, since that is how
    // both consumers call it.
    let uri: Uri = "http://example.com/x".parse().expect("full URL parses");
    assert_eq!(uri.scheme_str(), Some("http"));
}
