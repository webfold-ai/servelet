//! Fragmentation, control-frame rules and UTF-8 validation — the hardening unit's second fix.
//!
//! `docs/servelet-ws.md` recorded the moved `recv` as "one frame per message; a continuation
//! frame is binary" and called it "biota's stated reduction, kept as-is by rule 9". That is
//! exactly the kind of decision that is fine on a private socket and not fine on a public one,
//! and these tests are what it looks like when it is not fine:
//!
//!   * **Reassembly is unbounded.** A peer that opens a message and then sends a million
//!     one-byte continuations makes the server accumulate a million bytes in a buffer the moved
//!     code did not have. There is no total-message cap, so `WsLimits::max_message_bytes` is
//!     never consulted for a fragmented message at all.
//!   * **A continuation with nothing to continue is accepted** and handed to the application as
//!     `Message::Binary`, so a peer decides what the next "message" is.
//!   * **A control frame is not checked at all**: a fragmented ping (FIN clear) and a 4 KB ping
//!     are both served. §5.5 says a control frame must have FIN set and carry at most 125 bytes,
//!     and that ceiling is what lets a ping stay usable while a huge message is in flight.
//!   * **UTF-8 is validated per frame**, on a message that may not be per-frame at all: a
//!     multi-byte character split across a fragment boundary is legal and would be refused.
//!
//! Everything here goes over a real socket with a real handshake, because the codes being
//! asserted (1002 protocol error, 1007 invalid payload, 1009 too big) are codes on the wire.

mod support;

use servelet_ws::{CLOSE_INVALID_PAYLOAD, CLOSE_PROTOCOL_ERROR, CLOSE_TOO_BIG, WsLimits};
use support::{next_report, spawn_ws_server, RawWs};
use tokio::time::{timeout, Duration};

/// FIN=0|TEXT, then FIN=1|CONTINUATION: the two halves of one fragmented text message.
const TEXT_START: u8 = 0x01;
const CONT_FIN: u8 = 0x80;
/// FIN=0|BINARY.
const BINARY_START: u8 = 0x02;
/// FIN=0|PING — a control frame with FIN clear, which §5.5 forbids.
const PING_UNFIN: u8 = 0x09;
/// FIN=1|PING.
const PING_FIN: u8 = 0x89;
/// FIN=1|CLOSE.
const CLOSE_FIN: u8 = 0x88;

/// Read the server's next Close frame and return its status code.
async fn close_code(ws: &mut RawWs) -> u16 {
    let (fin_opcode, payload) = timeout(Duration::from_secs(5), ws.read_frame())
        .await
        .expect("the server must answer with a Close rather than hang")
        ;
    assert_eq!(fin_opcode & 0x0F, 0x8, "expected a Close frame, got opcode {fin_opcode:#x}");
    assert!(payload.len() >= 2, "a Close carrying a code has at least two payload bytes");
    u16::from_be_bytes([payload[0], payload[1]])
}

// ── Fragmentation that works ──────────────────────────────────────────────────────────────

/// The RFC 6455 §5.4 case the moved code got wrong in the SAFE direction: a message split across
/// frames must arrive as ONE message, not as a text frame and a mystery binary.
#[tokio::test]
async fn a_text_message_split_across_two_frames_arrives_as_one_message() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(TEXT_START, b"hello ").await;
    ws.send_frame(CONT_FIN, b"world").await;

    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"hello world\")");
}

/// The same for binary, including a continuation split across MORE than two frames.
#[tokio::test]
async fn a_binary_message_split_across_three_frames_arrives_as_one_message() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(BINARY_START, &[1, 2]).await;
    ws.send_frame(0x00, &[3, 4]).await;
    ws.send_frame(CONT_FIN, &[5, 6]).await;

    assert_eq!(next_report(&mut rx).await.unwrap(), "message Binary([1, 2, 3, 4, 5, 6])");
}

/// Two complete messages back to back must not be merged into one.
#[tokio::test]
async fn two_sequential_messages_stay_two_messages() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(0x81, b"first").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"first\")");
    ws.send_frame(0x82, &[9]).await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Binary([9])");
}

/// §5.4: a control frame MAY be injected in the middle of a fragmented message, and must be
/// answered without disturbing the message. This is what makes a ping usable while a large
/// message is still arriving, and it is why the 125-byte control-frame ceiling matters.
#[tokio::test]
async fn a_ping_in_the_middle_of_a_fragmented_message_is_answered_and_the_message_survives() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(TEXT_START, b"first half ").await;
    ws.send_frame(PING_FIN, b"still there?").await;
    // The automatic Pong goes out before the message is finished, exactly as §5.5.2 requires.
    assert_eq!(ws.read_frame().await, (0x8A, b"still there?".to_vec()));
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Ping([115, 116, 105, 108, 108, 32, 116, 104, 101, 114, 101, 63])");

    ws.send_frame(CONT_FIN, b"second half").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"first half second half\")");
}

// ── The total-message cap ──────────────────────────────────────────────────────────────────

/// The point of the fix: every frame is small and legal, and the MESSAGE is over the cap. The
/// moved code had no `max_message_bytes` check reachable from a fragmented message at all, so
/// this is the test that the new ceiling is wired into reassembly and not just into `read_n`.
#[tokio::test]
async fn a_fragmented_message_over_the_total_cap_is_closed_1009() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_message_bytes(1000)).await;
    let mut ws = RawWs::connect(addr).await;

    // 900 bytes so far, then a 200-byte continuation: 1100 total, over the 1000 cap. Every
    // individual frame is well under both the frame cap and the message cap.
    ws.send_frame(BINARY_START, &vec![1u8; 900]).await;
    ws.send_frame(CONT_FIN, &vec![2u8; 200]).await;

    assert_eq!(close_code(&mut ws).await, CLOSE_TOO_BIG);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("exceeds") && report.contains("message limit"), "got {report:?}");
}

/// The cap is a boundary, not a ban: exactly at the limit is served, one byte over is refused.
/// A limit that accidentally rejected everything would pass the test above.
#[tokio::test]
async fn a_fragmented_message_exactly_at_the_cap_is_served() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_message_bytes(1000)).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(BINARY_START, &vec![1u8; 600]).await;
    ws.send_frame(CONT_FIN, &vec![2u8; 400]).await;

    let report = next_report(&mut rx).await.unwrap();
    assert!(report.starts_with("message Binary("), "a message of exactly 1000 bytes is at the limit: {report:.40}");
}

/// The attack the cap exists for: a peer that never sends FIN, so the message never completes.
/// With a cap it is refused at the ceiling; without one it accumulates forever.
#[tokio::test]
async fn a_peer_that_sends_endless_continuations_is_stopped_at_the_cap() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default().with_max_message_bytes(2000)).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(BINARY_START, b"x").await;
    // 100 two-byte continuations, none of them final.
    for _ in 0..100 {
        ws.send_frame(0x00, b"yy").await;
    }

    assert_eq!(close_code(&mut ws).await, CLOSE_TOO_BIG);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("message limit"), "got {report:?}");
}

// ── Control frames ─────────────────────────────────────────────────────────────────────────

/// RFC 6455 §5.5: a control frame must have FIN set. The moved code read FIN and ignored it, so
/// a fragmented ping was served as if it were a well-formed one.
#[tokio::test]
async fn a_fragmented_control_frame_is_closed_1002() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(PING_UNFIN, b"unfinished ping").await;

    assert_eq!(close_code(&mut ws).await, CLOSE_PROTOCOL_ERROR);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("FIN"), "the error must say which rule was broken: {report:?}");
}

/// §5.5: a control frame carries at most 125 bytes — the one length that fits the 7-bit field.
/// 200 bytes must be a protocol error, not a "too big" error: a control frame is never allowed
/// to be big enough for the size guard to be the right answer.
#[tokio::test]
async fn an_oversized_control_frame_is_closed_1002() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(PING_FIN, &vec![0u8; 200]).await;

    assert_eq!(close_code(&mut ws).await, CLOSE_PROTOCOL_ERROR);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("125"), "the error must name the 125-byte rule: {report:?}");
}

/// Exactly 125 bytes is allowed — the boundary, in the serving direction.
#[tokio::test]
async fn a_control_frame_of_exactly_125_bytes_is_served() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(PING_FIN, &vec![b'p'; 125]).await;

    let report = next_report(&mut rx).await.unwrap();
    assert!(report.starts_with("message Ping("), "125 bytes is the limit, not over it: {report:.40}");
    let _ = ws.read_frame().await; // the automatic Pong
}

/// A continuation frame with no fragmented message open. The moved code returned this to the
/// application as `Message::Binary`, which let a peer choose what the next message is.
#[tokio::test]
async fn a_continuation_frame_with_no_message_in_progress_is_closed_1002() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(CONT_FIN, b"who started this?").await;

    assert_eq!(close_code(&mut ws).await, CLOSE_PROTOCOL_ERROR);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("continuation"), "got {report:?}");
}

/// A new data frame arriving inside an open fragmented message: the message boundaries are no
/// longer trustworthy, so the connection is refused rather than guessed at.
#[tokio::test]
async fn a_data_frame_inside_a_fragmented_message_is_closed_1002() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(TEXT_START, b"open").await;
    ws.send_frame(0x81, b"interrupting").await;

    assert_eq!(close_code(&mut ws).await, CLOSE_PROTOCOL_ERROR);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("inside a fragmented message"), "got {report:?}");
}

// ── UTF-8 ─────────────────────────────────────────────────────────────────────────────────

/// §5.6: a `TEXT` message must be valid UTF-8. 0xFF is not a legal byte in UTF-8 in any
/// position. The close code is 1007 (Invalid Payload Data), distinct from 1002 and 1009.
#[tokio::test]
async fn a_text_frame_that_is_not_utf8_is_closed_1007() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(0x81, &[0x68, 0x69, 0xFF, 0xFE]).await;

    assert_eq!(close_code(&mut ws).await, CLOSE_INVALID_PAYLOAD);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("not valid UTF-8"), "got {report:?}");
}

/// The reason validation happens on the ASSEMBLED message: "é" is 0xC3 0xA9, and split across
/// a fragment boundary neither half is valid UTF-8 on its own. A per-frame check — which is
/// what the moved code did — refuses this legitimate message.
#[tokio::test]
async fn a_multibyte_character_split_across_a_fragment_boundary_is_accepted() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(TEXT_START, &[b'c', b'a', b'f', 0xC3]).await;
    ws.send_frame(CONT_FIN, &[0xA9]).await;

    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"caf\u{e9}\")");
}

/// ...and the mirror image: bytes that are invalid only once ASSEMBLED must still be refused,
/// even though each frame alone would pass a per-frame check.
#[tokio::test]
async fn a_character_split_across_a_fragment_boundary_that_is_still_invalid_is_closed_1007() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    // 0xC3 opens a two-byte sequence; 0x28 is not a valid continuation byte.
    ws.send_frame(TEXT_START, &[0xC3]).await;
    ws.send_frame(CONT_FIN, &[0x28]).await;

    assert_eq!(close_code(&mut ws).await, CLOSE_INVALID_PAYLOAD);
    let _ = next_report(&mut rx).await;
}

/// Binary is NOT text and is not UTF-8-checked: the same bytes are perfectly legal in a binary
/// message, and refusing them would break every real client that sends arbitrary payloads.
#[tokio::test]
async fn binary_payloads_are_not_utf8_checked() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(0x82, &[0xFF, 0xFE, 0x00, 0x80]).await;

    assert_eq!(next_report(&mut rx).await.unwrap(), "message Binary([255, 254, 0, 128])");
}

/// The error for invalid text must not echo the payload back. A text frame is application
/// data; an error message that quotes it is a way to get untrusted bytes into a log line.
#[tokio::test]
async fn the_invalid_utf8_error_does_not_echo_the_payload() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    // A recognisable marker in the rejected bytes.
    ws.send_frame(0x81, b"CANARY-SECRET-MATERIAL\xFF").await;
    let _ = close_code(&mut ws).await;

    let report = next_report(&mut rx).await.unwrap();
    assert!(!report.contains("CANARY-SECRET-MATERIAL"), "the payload leaked into the error: {report:?}");
    assert!(report.contains("offset"), "the error should still be useful: {report:?}");
}

/// A Close from the peer still closes cleanly after all of the above — the new refusals must not
/// have broken the ordinary path.
#[tokio::test]
async fn an_ordinary_close_still_works_after_the_fragmentation_rules() {
    let (addr, mut rx) = spawn_ws_server(WsLimits::default()).await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(0x81, b"bye").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"bye\")");
    ws.send_frame(CLOSE_FIN, b"").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Close");
}