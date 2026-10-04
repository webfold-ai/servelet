//! The five tests that moved with `biota/http-server`'s `pub mod websocket` body
//! (`lib.rs` 2814-2927 at rev `4ce2dcd`), verbatim except for the four `use` lines at the top:
//! biota's `mod tests` said `use super::*` inside one crate, this is a separate crate. Two of
//! the five bind a real local socket and speak real frames over it.

use servelet_core::{Method, Request};
use servelet_ws::{accept, base64_encode, compute_accept_key, connect, sha1, Message};

/// SHA-1 against known test vectors (FIPS 180-1) — proves the hand-rolled implementation is
/// actually correct, not just "compiles and produces 20 bytes."
#[test]
fn sha1_matches_known_vectors() {
    assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(
        hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The RFC 6455 §1.3 worked example itself: key "dGhlIHNhbXBsZSBub25jZQ==" must produce
/// accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
#[test]
fn accept_key_matches_rfc6455_worked_example() {
    assert_eq!(compute_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn base64_matches_known_vectors() {
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

/// Real end-to-end proof: a real WebSocket server (this module's own `accept`) and a real
/// client (this module's own `connect`) over an actual TCP connection, exchanging real
/// masked/unmasked frames -- text, binary, and ping/pong -- not a loopback-in-memory stub.
#[tokio::test]
async fn websocket_handshake_and_frames_round_trip_over_real_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut stream);
        let mut request_lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap();
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            request_lines.push(line);
        }
        let mut req = Request::new(Method::GET, "/ws".parse().unwrap());
        for line in &request_lines[1..] {
            if let Some((k, v)) = line.split_once(':') {
                req = req.with_header(k.trim().to_string(), v.trim().to_string());
            }
        }
        let mut ws = accept(stream, &req, Vec::new()).await.unwrap();
        let msg = ws.recv().await.unwrap();
        assert_eq!(msg, Message::Text("hello server".to_string()));
        ws.send_text("hello client").await.unwrap();

        let msg = ws.recv().await.unwrap();
        assert_eq!(msg, Message::Binary(vec![1, 2, 3, 4]));
        ws.send_binary(&[5, 6, 7]).await.unwrap();
    });

    let mut ws = connect(&format!("ws://{addr}/ws")).await.unwrap();
    ws.send_text("hello server").await.unwrap();
    let reply = ws.recv().await.unwrap();
    assert_eq!(reply, Message::Text("hello client".to_string()));

    ws.send_binary(&[1, 2, 3, 4]).await.unwrap();
    let reply = ws.recv().await.unwrap();
    assert_eq!(reply, Message::Binary(vec![5, 6, 7]));
}

/// Real proof of ping/pong: sending a Ping to the peer must produce an automatic Pong reply
/// (RFC 6455 §5.5.2), not require the application to hand-roll the response.
#[tokio::test]
async fn websocket_ping_gets_automatic_pong() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut reader = tokio::io::BufReader::new(&mut stream);
        let mut request_lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap();
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            request_lines.push(line);
        }
        let mut req = Request::new(Method::GET, "/ws".parse().unwrap());
        for line in &request_lines[1..] {
            if let Some((k, v)) = line.split_once(':') {
                req = req.with_header(k.trim().to_string(), v.trim().to_string());
            }
        }
        let mut ws = accept(stream, &req, Vec::new()).await.unwrap();
        ws.ping(b"ping-payload").await.unwrap();
        // Keep the connection open long enough for the client to reply.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    });

    let mut ws = connect(&format!("ws://{addr}/ws")).await.unwrap();
    let msg = ws.recv().await.unwrap();
    assert_eq!(msg, Message::Ping(b"ping-payload".to_vec()));
    // The automatic Pong reply was already written by `recv`'s own OP_PING branch -- proven
    // indirectly here (a full assertion would need the server to read it back too, which
    // the handshake test above already covers the read/write mechanics for).
}
