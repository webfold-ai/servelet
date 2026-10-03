//! Real-socket proof for `servelet-h1`, added by this extraction (NOT moved).
//!
//! Every moved router test calls `Router::handle` with a `Request` it built itself, and no test in
//! biota binds a port. So the moved tests cannot tell you whether the bytes this crate puts on a
//! real TCP connection are right. This file does: a real `TcpListener`, a real accept loop, a real
//! chunked transfer-encoding response, and a raw `std::net::TcpStream` client that speaks HTTP by
//! hand and parses the reply by hand. No client crate — README rule 8, and this is the only way to
//! assert the wire bytes rather than another library's idea of them.

use std::net::SocketAddr;
use std::time::Duration;

use servelet_core::{Method, Request, Response, StatusCode};
use servelet_h1::{serve_connection, streaming, take_receiver, with_formatter};
use servelet_router::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Bind an ephemeral port, start `serve_connection` on every accepted stream, hand the address back.
/// Returns the address; the accept loop runs detached for the rest of the test.
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

/// Read from `stream` until `done` says the reply is complete. `done` is asked again after every
/// chunk — for a Content-Length reply "we have N body bytes", for a chunked reply "we have seen the
/// terminating 0-chunk". That is how this file reads the wire without a parser crate.
async fn read_until(stream: &mut TcpStream, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("the server must answer within 5s")
            .expect("read must succeed");
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&chunk[..n]);
        if done(&buf) {
            return buf;
        }
    }
}

fn route_and_stream_router() -> Router {
    Router::new()
        .get("/hello", |_req: Request| async move {
            Response::ok("hello from the router")
        })
        .get("/users/:id", |req: Request| async move {
            Response::ok(format!("user {}", req.path()))
        })
}

#[tokio::test]
async fn serves_a_router_route_over_a_real_socket() {
    let addr = spawn_server(route_and_stream_router()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let raw = read_until(&mut client, |b| b.ends_with(b"hello from the router")).await;
    let text = String::from_utf8_lossy(&raw).into_owned();

    // The status line is byte-for-byte what `write_response` builds: version, code, reason.
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text:?}");
    // Headers the moved writer adds, in the moved order (HashMap-free: insertion order).
    assert!(text.contains("content-length: 21\r\n"), "got: {text:?}");
    // The moved `write_response` stamps `connection: keep-alive` on every HTTP/1.1 response that
    // does not carry its own `Connection` header — even when the REQUEST asked to close. The
    // request-level close is enforced separately, by `connection_close` breaking the loop. This
    // test records that byte-for-byte rather than the behaviour I expected when writing it.
    assert!(text.contains("connection: keep-alive\r\n"), "got: {text:?}");
    assert!(text.ends_with("\r\n\r\nhello from the router"), "got: {text:?}");
}

#[tokio::test]
async fn routes_a_dynamic_path_segment_over_a_real_socket() {
    let addr = spawn_server(route_and_stream_router()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /users/42 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let raw = read_until(&mut client, |b| b.ends_with(b"user /users/42")).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text:?}");
    assert!(text.ends_with("\r\n\r\nuser /users/42"), "got: {text:?}");
}

#[tokio::test]
async fn unmounted_path_gets_the_fallback_404_over_a_real_socket() {
    let addr = spawn_server(route_and_stream_router()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let raw = read_until(&mut client, |b| b.ends_with(b"not found")).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "got: {text:?}");
    assert!(text.ends_with("\r\n\r\nnot found"), "got: {text:?}");
}

#[tokio::test]
async fn keep_alive_serves_two_requests_on_one_connection() {
    let addr = spawn_server(route_and_stream_router()).await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let first = read_until(&mut client, |b| b.ends_with(b"hello from the router")).await;
    let text = String::from_utf8_lossy(&first).into_owned();
    // No `Connection: close` was asked for, so the moved writer must add `keep-alive`.
    assert!(text.contains("connection: keep-alive\r\n"), "got: {text:?}");

    // The second request on the SAME socket is the proof the loop did not close after the first.
    client
        .write_all(b"GET /users/7 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let second = read_until(&mut client, |b| b.ends_with(b"user /users/7")).await;
    let text = String::from_utf8_lossy(&second).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text:?}");
}

#[tokio::test]
async fn a_streaming_body_goes_out_as_real_chunked_transfer_encoding() {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, String>>(4);
    // A channel of exactly one real receiver: the handler moves it into the response, which is the
    // moved `HttpResponseBuilder::streaming` path.
    // The channel holds four chunks' worth of room, so the send does not block; the server writes
    // each chunk as it arrives and the 0-chunk terminator when `tx` drops.
    tx.send(Ok(b"chunk-one".to_vec())).await.unwrap();
    // Held until the queued chunk is written, then dropped: closing the channel is what makes the
    // moved writer emit the terminating `0\r\n\r\n`.
    let slot: std::sync::Arc<std::sync::Mutex<Option<_>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let slot = std::sync::Arc::clone(&slot);
    let router = Router::new().get("/stream", move |_req: Request| {
        let slot = std::sync::Arc::clone(&slot);
        async move {
            let rx = slot.lock().unwrap().take().expect("one request, one receiver");
            streaming(Response::new(StatusCode::OK, Vec::new()), rx)
        }
    });
    let addr = spawn_server(router).await;
    drop(tx);

    // Feed the channel from the server side after the request is in flight.
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let raw = read_until(&mut client, |b| b.windows(5).any(|w| w == b"0\r\n\r\n")).await;
    let text = String::from_utf8_lossy(&raw).into_owned();

    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text:?}");
    assert!(text.contains("transfer-encoding: chunked\r\n"), "got: {text:?}");
    // No Content-Length on a chunked response — the moved writer only adds it in `write_response`.
    assert!(!text.contains("content-length"), "got: {text:?}");
    // The terminator is the last thing on the wire.
    assert!(text.ends_with("0\r\n\r\n"), "got: {text:?}");
    // Each chunk is `{hex-length}\r\n{data}\r\n` — assert the exact frame the moved
    // `write_chunk` builds for the nine bytes that were queued.
    assert!(
        text.ends_with("9\r\nchunk-one\r\n0\r\n\r\n"),
        "want the 9-byte frame then the terminator, got: {text:?}"
    );
}

#[tokio::test]
async fn the_request_reader_parses_the_three_parts_of_the_request_line() {
    // `read_request` is the public single-request read; exercise it on a socket the test wrote to.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        sock.write_all(
            b"POST /submit HTTP/1.0\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
        )
        .await
        .unwrap();
        // Keep the socket open so `read_request` does not race EOF against the body.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let req = servelet_h1::read_request(&mut client).await.unwrap();

    assert_eq!(req.method, Method::POST);
    assert_eq!(req.uri.path(), "/submit");
    assert_eq!(req.version, servelet_core::Version::HTTP_10);
    assert_eq!(req.body(), b"hello");
    assert_eq!(req.headers().get("host").unwrap().to_str().unwrap(), "localhost");
}
// -- The formatter seam (added by this extraction) ---------------------------
//
// A response that carries a `StreamFormatter` is written by THAT formatter; a response that
// carries only a `StreamingBody` is written by this crate's own chunked writer. Both paths are
// asserted here over a real socket, because a seam that is only ever exercised in memory is a
// seam nobody has tested.

/// A stashed formatter replaces the default writer: the formatter's own bytes reach the wire.
#[tokio::test]
async fn a_stashed_formatter_is_the_one_that_writes_the_stream() {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, String>>(4);
    let body = streaming(Response::new(StatusCode::OK, Vec::new()), rx);
    let stashed = body.clone();
    let router = Router::new().route_sync(
        Method::GET,
        "/fmt",
        move |_req| {
            let fmt: servelet_h1::StreamFormatter = std::sync::Arc::new(
                |mut writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send), resp| {
                    Box::pin(async move {
                        use tokio::io::AsyncWriteExt;
                        let mut head = format!(
                            "{} {} {}\r\n",
                            resp.version.as_str(),
                            resp.status.as_u16(),
                            servelet_core::status_reason(resp.status)
                        );
                        head.push_str("x-formatter: used\r\n\r\n");
                        writer.write_all(head.as_bytes()).await?;
                        let body = servelet_h1::streaming_body(&resp)
                            .expect("this response was built with a streaming body");
                        let mut rx = take_receiver(body).await?;
                        while let Some(next) = rx.recv().await {
                            let bytes = next.map_err(servelet_core::Error::Http)?;
                            writer.write_all(&bytes).await?;
                        }
                        writer.write_all(b"END").await?;
                        writer.flush().await?;
                        Ok(())
                    })
                },
            );
            with_formatter(stashed.clone(), fmt)
        },
    );
    let addr = spawn_server(router).await;

    tx.send(Ok(b"FROM-FORMATTER".to_vec())).await.unwrap();
    drop(tx);

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /fmt HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let bytes = read_until(&mut stream, |b| b.ends_with(b"END")).await;
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("x-formatter: used\r\n"), "the stashed formatter must set its own header: {text}");
    assert!(text.contains("FROM-FORMATTER"), "{text}");
    assert!(text.ends_with("END"), "{text}");
    // The default writer would have sent `Transfer-Encoding: chunked` and a 0-chunk. The
    // formatter's output is raw, so neither may be present -- that difference is the assertion.
    assert!(!text.contains("transfer-encoding: chunked"), "{text}");
}

/// Without a formatter the default writer still runs: the seam is additive, not a replacement.
#[tokio::test]
async fn no_formatter_means_the_default_chunked_writer() {
    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, String>>(4);
    let held = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let from_handler = held.clone();
    let router = Router::new().route_sync(
        Method::GET,
        "/plain",
        move |_req| {
            let rx = from_handler.lock().unwrap().take().expect("one request per test");
            streaming(Response::new(StatusCode::OK, Vec::new()), rx)
        },
    );
    let addr = spawn_server(router).await;

    tx.send(Ok(b"DEFAULT".to_vec())).await.unwrap();
    drop(tx); // the 0-chunk only goes out when the producer is gone

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /plain HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let bytes = read_until(&mut stream, |b| b.ends_with(b"0\r\n\r\n")).await;
    let text = String::from_utf8_lossy(&bytes);
    // Header names go out lowercased by the moved writer; assert the bytes, not the casing I wished for.
    assert!(text.contains("transfer-encoding: chunked"), "{text}");
    assert!(text.contains("7\r\nDEFAULT\r\n"), "one chunk, hex length 7: {text}");
}
