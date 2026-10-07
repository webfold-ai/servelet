//! gRPC unary integration test: a real h2c client sending a 5-byte-prefixed request
//! through `servelet_h2::serve_h2c_connection` -> `Router::fallback(grpc_unary(...))` ->
//! `Response` and back.
//!
//! The client is hand-rolled (no third-party HTTP/2 or gRPC crate -- README rule 8):
//!   1. TCP connect, write the 24-byte h2c preface, write a SETTINGS frame.
//!   2. Write HEADERS(END_HEADERS) with `:method`, `:path`, `content-type: application/grpc`.
//!   3. Write DATA(END_STREAM) with `[0, 0, 0, 0, 5]` (the 5-byte prefix for a 5-byte
//!      body) followed by `b"hello"`.
//!   4. Read frames: SETTINGS, ACK, HEADERS, DATA, HEADERS(END_STREAM).
//!   5. Assert: response HEADERS has `content-type: application/grpc+proto`; response DATA
//!      payload is `[0, 0, 0, 0, 5] + b"hello"` (5-byte prefix + echoed body); trailer
//!      HEADERS has `grpc-status: 0`.
//!
//! A second test (`malformed_5byte_prefix_returns_grpc_status_13`) sends a request body
//! that does NOT start with a 5-byte gRPC prefix -- the layer must surface a
//! `grpc-status: 13` (INTERNAL) trailer.

use servelet_core::{Request, Response};
use servelet_h2::{
    encode_message_header, grpc_unary, hpack_decode, hpack_encode, serve_h2c_connection,
    FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, FrameType, HField,
};
use servelet_router::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

async fn read_frame(s: &mut TcpStream) -> Frame {
    let mut hdr = [0u8; 9];
    s.read_exact(&mut hdr).await.expect("frame header");
    let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
    let frame_type = FrameType::from_byte(hdr[3]);
    let flags = hdr[4];
    let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    let mut payload = vec![0u8; len];
    if len > 0 {
        s.read_exact(&mut payload).await.expect("frame payload");
    }
    Frame { frame_type, flags, stream_id, payload }
}

async fn write_frame(s: &mut TcpStream, f: &Frame) {
    let bytes = f.to_bytes();
    s.write_all(&bytes).await.expect("frame write");
}

fn hpack_decode_local(block: &[u8]) -> Vec<HField> {
    let mut table = servelet_h2::DynamicTable::new(4096);
    hpack_decode(block, &mut table).expect("hpack decode")
}

#[tokio::test]
async fn grpc_unary_round_trip_with_5byte_prefix_on_both_directions() {
    // The handler echoes its input body, and the gRPC layer wraps the response with a
    // 5-byte prefix and sets grpc-status: 0 in the trailer.
    let echo = |req: Request| async move {
        Response::ok(req.into_body())
    };
    let router = Router::new().fallback(grpc_unary(echo));

    // Bind a real local listener, hand it to the existing h2 transport.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                return;
            }
            if &preface[..] != PREFACE {
                return;
            }
            serve_h2c_connection(stream, router).await;
        }
    });

    // Client side.
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(PREFACE).await.unwrap();
    eprintln!("[DBG] write_frame: Settings");

    write_frame(&mut sock, &Frame::new(FrameType::Settings, 0, 0, Vec::new())).await;

    let req_headers = hpack_encode(&[
        (":method", "POST"),
        (":path", "/pkg.Svc/Echo"),
        (":scheme", "http"),
        ("content-type", "application/grpc"),
    ]);
    write_frame(
        &mut sock,
        &Frame::new(FrameType::Headers, FLAG_END_HEADERS, 1, req_headers),
    )
    .await;

    // 5-byte gRPC message header: flag=0 (uncompressed), length=5, then 5 bytes of body.
    let mut data_payload: Vec<u8> = Vec::new();
    data_payload.extend_from_slice(&encode_message_header(false, 5));
    data_payload.extend_from_slice(b"hello");
    write_frame(
        &mut sock,
        &Frame::new(FrameType::Data, FLAG_END_STREAM, 1, data_payload),
    )
    .await;

    // Server's SETTINGS.
    eprintln!("[DBG] after read_frame: s1");

    let s1 = read_frame(&mut sock).await;
    assert_eq!(s1.frame_type, FrameType::Settings);
    // ACK of ours.
    eprintln!("[DBG] after read_frame: s2");

    let s2 = read_frame(&mut sock).await;
    assert_eq!(s2.frame_type, FrameType::Settings);
    assert_eq!(s2.flags & FLAG_ACK, FLAG_ACK);
    // Response HEADERS.
    eprintln!("[DBG] after read_frame: rh");

    let rh = read_frame(&mut sock).await;
    assert_eq!(rh.frame_type, FrameType::Headers);
    let fields = hpack_decode_local(&rh.payload);
    let content_type = fields
        .iter()
        .find(|f| f.name == "content-type")
        .map(|f| f.value.as_str())
        .expect("content-type header");
    assert_eq!(content_type, "application/grpc+proto");
    // Response DATA with the 5-byte prefix + echoed body.
    eprintln!("[DBG] after read_frame: rd");

    let rd = read_frame(&mut sock).await;
    assert_eq!(rd.frame_type, FrameType::Data);
    assert_eq!(rd.payload.len(), 5 + 5);
    assert_eq!(&rd.payload[..5], &encode_message_header(false, 5));
    assert_eq!(&rd.payload[5..], b"hello");
    // Trailer HEADERS (END_STREAM) with grpc-status: 0.
    eprintln!("[DBG] after read_frame: tr");

    let tr = read_frame(&mut sock).await;
    assert_eq!(tr.frame_type, FrameType::Headers);
    assert_eq!(tr.flags & FLAG_END_STREAM, FLAG_END_STREAM);
    let tfields = hpack_decode_local(&tr.payload);
    let status = tfields
        .iter()
        .find(|f| f.name == "grpc-status")
        .map(|f| f.value.as_str())
        .expect("grpc-status trailer");
    assert_eq!(status, "0");

    drop(sock);
    let _ = server.await;
}

#[tokio::test]
async fn malformed_5byte_prefix_returns_grpc_status_13() {
    // The handler is never reached: the layer returns 500 + grpc-status: 13 because the
    // request body does not start with a 5-byte gRPC message header.
    let inner = |_req: Request| async move {
        Response::ok(b"unreachable")
    };
    let router = Router::new().fallback(grpc_unary(inner));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                return;
            }
            if &preface[..] != PREFACE {
                return;
            }
            serve_h2c_connection(stream, router).await;
        }
    });

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(PREFACE).await.unwrap();
    eprintln!("[DBG] write_frame: Settings");

    write_frame(&mut sock, &Frame::new(FrameType::Settings, 0, 0, Vec::new())).await;

    let req_headers = hpack_encode(&[
        (":method", "POST"),
        (":path", "/pkg.Svc/Echo"),
        (":scheme", "http"),
        ("content-type", "application/grpc"),
    ]);
    write_frame(
        &mut sock,
        &Frame::new(FrameType::Headers, FLAG_END_HEADERS, 1, req_headers),
    )
    .await;

    // A body with NO 5-byte prefix -- 4 bytes instead of 5.
    write_frame(
        &mut sock,
        &Frame::new(FrameType::Data, FLAG_END_STREAM, 1, vec![1, 2, 3, 4]),
    )
    .await;

    eprintln!("[DBG] after read_frame: s1");


    let s1 = read_frame(&mut sock).await;
    assert_eq!(s1.frame_type, FrameType::Settings);
    eprintln!("[DBG] after read_frame: s2");

    let s2 = read_frame(&mut sock).await;
    assert_eq!(s2.frame_type, FrameType::Settings);
    assert_eq!(s2.flags & FLAG_ACK, FLAG_ACK);
    eprintln!("[DBG] after read_frame: rh");

    let rh = read_frame(&mut sock).await;
    let rfields = hpack_decode_local(&rh.payload);
    let status = rfields
        .iter()
        .find(|f| f.name == "grpc-status")
        .map(|f| f.value.as_str());
    assert_eq!(status, Some("13"), "expected INTERNAL in the trailer HEADERS for a malformed 5-byte prefix");
    // The trailer HEADERS should be the END_STREAM one.
    eprintln!("[DBG] after read_frame: next");

    let next = read_frame(&mut sock).await;
    assert_eq!(next.frame_type, FrameType::Headers);
    assert_eq!(next.flags & FLAG_END_STREAM, FLAG_END_STREAM);

    drop(sock);
    let _ = server.await;
}
