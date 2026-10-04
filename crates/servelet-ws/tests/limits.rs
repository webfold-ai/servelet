//! The inbound size ceilings — the hardening unit's first fix.
//!
//! These tests are written to FAIL against the code as moved from biota. That code read the
//! 64-bit payload length out of the frame header and handed it straight to `vec![0u8; n]`:
//!
//!     let mut payload = self.read_n(len as usize).await?;
//!
//! A peer that writes `0x7F` followed by `0x8000000000000000` therefore asks the server to
//! allocate an exabyte. On Linux that is an allocation failure that ABORTS the process — there is
//! no `Err` to return, no handler that can catch it, and one 14-byte frame from anyone who
//! completed a handshake is enough.
//!
//! What is asserted here, over a REAL socket with a REAL handshake:
//!   * the absurd header is refused with a Close carrying 1009 (RFC 6455 §7.4.1), on the wire;
//!   * the refusal happens BEFORE the payload is read — the client sends no payload at all and
//!     no mask key's worth of trailing bytes, so a server that read the payload first would
//!     block rather than answer;
//!   * a frame at exactly the limit is still served, so the limit is a ceiling and not a
//!     blanket refusal of anything large;
//!   * the ceiling is per-connection and configurable, and the DEFAULT is the documented one.

mod support;

use servelet_ws::{CLOSE_TOO_BIG, Message, WsLimits};
use support::{next_report, spawn_ws_server, RawWs};
use tokio::time::{timeout, Duration};

/// FIN | TEXT.
const FIN_TEXT: u8 = 0x81;

/// A frame header claiming 2^63 bytes must be refused with a 1009 Close, not allocated.
///
/// This is the test the whole unit exists for. Against the moved code it does not fail cleanly —
/// it takes the test process down, because `vec![0u8; 1 << 63]` is an abort, not a panic.
#[tokio::test]
async fn a_frame_header_claiming_two_pow_63_bytes_is_closed_1009_without_allocating() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    // 14 bytes total: 2 header + 8 extended length + 4 mask key. No payload follows, and none
    // ever will — the length claimed is unpayable by construction.
    ws.send_oversize_length_header(FIN_TEXT, 1u64 << 63).await;

    let (fin_opcode, payload) = timeout(Duration::from_secs(5), ws.read_frame())
        .await
        .expect("an oversize frame must be refused promptly, not left to time out");
    assert_eq!(fin_opcode & 0x0F, 0x8, "the refusal must be a Close frame, got opcode {fin_opcode:#x}");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLOSE_TOO_BIG,
        "the Close must carry 1009 (Message Too Big)"
    );

    // And the codec reports a size refusal, not an I/O error or a hang.
    let report = next_report(&mut rx).await.expect("the server must report what happened");
    assert!(report.starts_with("error "), "expected an error report, got {report:?}");
    assert!(
        report.contains("exceeds") && report.contains("frame"),
        "the error must name the limit it broke, got {report:?}"
    );
}

/// The refusal must come BEFORE the payload is read, not after. The client declares a gigabyte
/// and then sends sixteen bytes and stops: a server that checks the limit after `read_exact`
/// waits forever for a payload that is never coming, so the test's own timeout is the assertion.
#[tokio::test]
async fn an_oversize_frame_is_refused_before_the_payload_is_read() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_frame_bytes(1024)).await;
    let mut ws = RawWs::connect(addr).await;

    // Declares 1 GiB, delivers 16 bytes, then goes quiet.
    ws.send_frame_with_truncated_payload(FIN_TEXT, 1 << 30, &[0x41; 16]).await;

    let (fin_opcode, payload) = timeout(Duration::from_secs(5), ws.read_frame())
        .await
        .expect("the limit must be enforced on the declared length, before waiting for the bytes");
    assert_eq!(fin_opcode & 0x0F, 0x8, "the refusal must be a Close frame");
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), CLOSE_TOO_BIG);
    let _ = next_report(&mut rx).await;
}

/// The ceiling is a boundary, not a blanket ban: a frame of EXACTLY the limit is served, and one
/// byte more is refused. Without this, a limit set one byte too low would look identical to a
/// limit that works.
#[tokio::test]
async fn a_frame_at_exactly_the_limit_is_served_and_one_byte_more_is_refused() {
    let limit = 64u64;

    // Exactly at the limit.
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_frame_bytes(limit)).await;
    let mut ws = RawWs::connect(addr).await;
    let payload = vec![b'x'; limit as usize];
    ws.send_frame(FIN_TEXT, &payload).await;
    let report = next_report(&mut rx).await.expect("a frame at the limit must be decoded");
    assert_eq!(report, format!("message Text(\"{}\")", "x".repeat(limit as usize)));

    // One byte over, same server configuration.
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_frame_bytes(limit)).await;
    let mut ws = RawWs::connect(addr).await;
    ws.send_frame_with_truncated_payload(FIN_TEXT, limit + 1, &[b'x'; 8]).await;
    let (fin_opcode, body) = timeout(Duration::from_secs(5), ws.read_frame())
        .await
        .expect("the over-limit frame must be refused");
    assert_eq!(fin_opcode & 0x0F, 0x8);
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), CLOSE_TOO_BIG);
    let _ = next_report(&mut rx).await;
}

/// The limits are per connection: one connection configured for small frames refuses, its
/// neighbour on the same process does not. A limit that leaked between connections would make
/// the second of these two assertions fail.
#[tokio::test]
async fn the_frame_limit_is_per_connection_not_global() {
    // A strict server...
    let (strict, mut strict_rx) = spawn_ws_server(WsLimits::default().with_max_frame_bytes(16)).await;
    // ...and a permissive one, in the SAME process at the same time.
    let (permissive, mut permissive_rx) = spawn_ws_server(WsLimits::default()).await;

    let mut a = RawWs::connect(strict).await;
    a.send_frame_with_truncated_payload(FIN_TEXT, 4096, &[b'x'; 8]).await;
    let (op, body) = timeout(Duration::from_secs(5), a.read_frame()).await.unwrap();
    assert_eq!(op & 0x0F, 0x8);
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), CLOSE_TOO_BIG);
    let _ = next_report(&mut strict_rx).await;

    let mut b = RawWs::connect(permissive).await;
    let text = "a message the strict connection would have refused";
    b.send_frame(FIN_TEXT, text.as_bytes()).await;
    assert_eq!(
        next_report(&mut permissive_rx).await.unwrap(),
        format!("message Text({text:?})")
    );
}

/// The defaults are part of the contract, not an implementation detail: `docs/HARDENING.md`
/// publishes them, so a change here has to break a test rather than silently widen every
/// deployment's ceiling.
#[test]
fn the_documented_default_limits_are_one_mib_and_sixteen_mib() {
    let d = WsLimits::default();
    assert_eq!(d.max_frame_bytes, 1 << 20, "1 MiB frame ceiling");
    assert_eq!(d.max_message_bytes, 16 << 20, "16 MiB message ceiling");
    assert_eq!(WsLimits::new(), d);
    assert_eq!(d.with_max_frame_bytes(7).max_frame_bytes, 7);
    assert_eq!(d.with_max_message_bytes(9).max_message_bytes, 9);
    assert_eq!(d.with_max_frame_bytes(7).max_message_bytes, d.max_message_bytes);
}

/// The boundary value 1009 is what the peer sees, and it is a constant rather than a literal so
/// the value is stated once. Pinned here because the wire format is the security property: a
/// peer that gets 1000 instead of 1009 cannot distinguish "too big" from "I did not understand
/// you".
#[tokio::test]
async fn a_default_server_refuses_a_frame_just_over_one_mib() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    // One byte past the documented default frame ceiling.
    ws.send_frame_with_truncated_payload(FIN_TEXT, (1 << 20) + 1, &[b'x'; 8]).await;
    let (op, body) = timeout(Duration::from_secs(5), ws.read_frame()).await.unwrap();
    assert_eq!(op & 0x0F, 0x8);
    assert_eq!(u16::from_be_bytes([body[0], body[1]]), CLOSE_TOO_BIG);

    // And just UNDER it is served, so the two tests together pin the exact edge rather than
    // "some large number".
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;
    let at_limit = vec![b'z'; 1 << 20];
    ws.send_frame(FIN_TEXT, &at_limit).await;
    match next_report(&mut rx).await.expect("a 1 MiB frame is at the limit and must be served") {
        s if s.starts_with("message Text(") && s.len() > 1 << 20 => {}
        other => panic!("expected the 1 MiB frame to decode as text, got {other:.80}"),
    }
}

/// `Message::Text` is what a decoded frame becomes; asserting the round trip is what makes the
/// over-limit tests above meaningful — a server that refused EVERYTHING would also pass them.
#[tokio::test]
async fn a_normal_frame_still_round_trips_after_the_limits_were_added() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;
    ws.send_frame(FIN_TEXT, b"hello").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"hello\")");
    // The codec answers the ping itself (RFC 6455 §5.5.2), which is still true after the change.
    ws.send_frame(0x89, b"ping").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Ping(b\"ping\".to_vec())");
    assert_eq!(ws.read_frame().await, (0x8A, b"ping".to_vec()));
    // Unused import guard: `Message` is named above only in doc prose; keep it referenced so the
    // file does not depend on that being true.
    assert_eq!(Message::Close, Message::Close);
}