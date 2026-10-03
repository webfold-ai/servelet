//! Real-socket proof for `servelet-sse`, added by this extraction (NOT moved).
//!
//! Every moved SSE test stops at the response: `Data::render` renders a string, `encode_event`
//! encodes a string, `SseParser` parses a string, and `respond_to_..stashes_the_receiver` checks
//! that a value went into a response's extensions. None of them opens a connection, so none of
//! them can tell you whether an event actually reaches a browser as it happens, in order, framed
//! as one chunk per event. This file does.
//!
//! It goes through the real path a consumer uses: `servelet-h1`'s `serve_connection`, a real
//! `TcpListener`, a real `Router`, `servelet_sse::sse_response`, and a raw `std::net::TcpStream`
//! client that speaks HTTP by hand. No client crate (README rule 8).

use std::net::SocketAddr;
use std::time::Duration;

use servelet_core::Method;
use servelet_h1::serve_connection;
use servelet_router::Router;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use servelet_sse::{sse_response, Data, Event, Sse};

/// Bind an ephemeral port, run `serve_connection` on every accepted stream, hand the address back.
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

async fn get(addr: SocketAddr, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    stream
}

/// Read the response head: one byte at a time until the blank line. Byte-at-a-time is correct
/// here, not fussy -- a read that waits for more than the head would deadlock against a stream
/// that is waiting for the client.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut b))
            .await
            .expect("the head must arrive within 5s")
            .expect("the connection closed inside the response head");
        out.push(b[0]);
        if out.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&out).to_string();
        }
    }
}

/// Read exactly `n` bytes. Streaming is the point: this returns as soon as the bytes have
/// arrived, so a caller that sends two events can observe the first before sending the second.
async fn read_exact(stream: &mut TcpStream, n: usize) -> String {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("the server must produce this within 5s; nothing else is running on this box")
        .expect("the connection closed before the bytes arrived");
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
async fn an_event_reaches_the_wire_as_one_chunk_before_the_next_one_is_sent() {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(4);
    let held = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let from_handler = held.clone();
    let router = Router::new().route_sync(Method::GET, "/events", move |req| {
        let rx = from_handler.lock().unwrap().take().expect("one request per test");
        let sse = Sse::from_infallible_receiver(rx);
        sse_response(sse, &req)
    });
    let addr = spawn_server(router).await;
    let mut stream = get(addr, "/events").await;

    // The head goes out before any event exists at all: chunked, closed after, event-stream.
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head:?}");
    assert!(head.contains("content-type: text/event-stream"), "{head:?}");
    assert!(head.contains("transfer-encoding: chunked"), "{head:?}");

    // Event one: `data: one\n\n` is 11 bytes, so its chunk frame is `b\r\ndata: one\n\n\r\n`.
    tx.send(Event::Data(Data::new("one"))).await.unwrap();
    let first = read_exact(&mut stream, 16).await;
    assert_eq!(first, "b\r\ndata: one\n\n\r\n", "one chunk per event, hex length 11");

    // The second event is only produced now, and arrives as its own frame. A buffered
    // implementation would have sent both at once, which is exactly what this ordering rules out.
    tx.send(Event::Data(Data::new("two"))).await.unwrap();
    let second = read_exact(&mut stream, 16).await;
    assert_eq!(second, "b\r\ndata: two\n\n\r\n");

    // Closing the producer terminates the body with the 0-chunk.
    drop(tx);
    let tail = read_exact(&mut stream, 5).await;
    assert_eq!(tail, "0\r\n\r\n");
}

#[tokio::test]
async fn a_multi_line_payload_becomes_several_data_lines_inside_one_chunk() {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(4);
    let held = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let from_handler = held.clone();
    let router = Router::new().route_sync(Method::GET, "/events", move |req| {
        let rx = from_handler.lock().unwrap().take().expect("one request per test");
        sse_response(Sse::from_infallible_receiver(rx), &req)
    });
    let addr = spawn_server(router).await;
    let mut stream = get(addr, "/events").await;
    let _ = read_head(&mut stream).await; // the head

    tx.send(Event::Data(Data::new("a\nb"))).await.unwrap();
    // `data: a\ndata: b\n\n` is 17 bytes -> hex `11`.
    let frame = read_exact(&mut stream, 4 + 17 + 2).await;
    assert_eq!(frame, "11\r\ndata: a\ndata: b\n\n\r\n");
}

#[tokio::test]
async fn keep_alive_puts_a_comment_chunk_on_the_wire_when_nothing_arrives() {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(4);
    let held = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let from_handler = held.clone();
    let router = Router::new().route_sync(Method::GET, "/events", move |req| {
        let rx = from_handler.lock().unwrap().take().expect("one request per test");
        let sse = Sse::from_infallible_receiver(rx).with_keep_alive(Duration::from_millis(80));
        sse_response(sse, &req)
    });
    let addr = spawn_server(router).await;
    let mut stream = get(addr, "/events").await;
    let _ = read_head(&mut stream).await; // the head

    // Nothing is sent on the channel at all: the writer's keep-alive timer is what produces
    // bytes, and it produces a COMMENT (`: keep-alive`), which a browser ignores as an event.
    let comment = read_exact(&mut stream, 19).await;
    assert_eq!(comment, "e\r\n: keep-alive\n\n\r\n", ": keep-alive\\n\\n is 14 bytes -> hex e");

    tx.send(Event::Data(Data::new("after"))).await.unwrap();
    let real = read_exact(&mut stream, 18).await;
    assert_eq!(real, "d\r\ndata: after\n\n\r\n", "a real event still goes out after a keep-alive");
}

#[tokio::test]
async fn a_retry_duration_is_sent_as_the_first_thing_on_the_stream() {
    let (tx, rx) = tokio::sync::mpsc::channel::<Event>(4);
    let held = std::sync::Arc::new(std::sync::Mutex::new(Some(rx)));
    let from_handler = held.clone();
    let router = Router::new().route_sync(Method::GET, "/events", move |req| {
        let rx = from_handler.lock().unwrap().take().expect("one request per test");
        let sse = Sse::from_infallible_receiver(rx).with_retry_duration(Duration::from_millis(2500));
        sse_response(sse, &req)
    });
    let addr = spawn_server(router).await;
    let mut stream = get(addr, "/events").await;
    let _ = read_head(&mut stream).await; // the head

    // RFC 9113 §9.1: the retry field is milliseconds, sent as a field line, before any event.
    // `retry: 2500\n\n` is 13 bytes -> hex `d`; a chunk frame is `{hex}\r\n{data}\r\n`.
    let preamble = read_exact(&mut stream, 3 + 13 + 2).await;
    assert_eq!(preamble, "d\r\nretry: 2500\n\n\r\n");

    drop(tx);
    let tail = read_exact(&mut stream, 5).await;
    assert_eq!(tail, "0\r\n\r\n");
}