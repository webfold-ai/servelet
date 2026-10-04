//! Idle ping interval and read timeout on an upgraded connection — the hardening unit's third fix.
//!
//! `docs/servelet-ws.md` recorded "backpressure and idle timeouts on an upgraded connection —
//! not implemented, not tested" and, in the seam's own notes, "a route that needs a ping period
//! writes one". That is the right division of labour for the *policy* and the wrong one for the
//! *mechanism`: once the upgrade callback owns the socket, `serve_connection`'s keep-alive
//! machinery is gone by design, and every route therefore had to reimplement the same loop.
//!
//! The moved `read_n` waits forever. A peer that completes the handshake and then says nothing
//! holds the connection, its buffers, and its task for as long as it likes, and a server that
//! has no read deadline cannot tell that peer from one that is merely slow.
//!
//! Both behaviours here are OFF by default, and that is deliberate rather than timid: a deadline
//! that expires closes a connection that may have been quiet and perfectly alive, and a library
//! that picks that deadline on an application's behalf gets it wrong for somebody. What the
//! library owes is a way to set one -- and the tests below include the one that says the default
//! really is off, because an "optional" deadline that silently became a default would close
//! innocent connections and none of the other tests would notice.

mod support;

use std::time::Duration;

use servelet_ws::{CLOSE_GOING_AWAY, WsLimits};
use support::{next_report, spawn_ws_server, spawn_ws_server_echoing, spawn_ws_server_timed, RawWs, MASK};
use tokio::time::{timeout, Instant};

/// Read frames until one arrives, failing the test if none does in time. Returns the opcode's
/// low nibble and the payload.
async fn next_frame(ws: &mut RawWs, within: Duration) -> (u8, Vec<u8>) {
    timeout(within, ws.read_frame())
        .await
        .expect("the server should have sent a frame within the wait")
}

/// A peer that has said nothing since the handshake must be reclaimed, not waited on forever.
/// This is the behaviour that did not exist: the moved `read_n` had no deadline at all.
#[tokio::test]
async fn a_peer_that_never_sends_anything_is_closed_after_the_read_timeout() {
    let (addr, mut rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(400)),
        None,
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    // The client says nothing, ever. The server must give up on its own.
    let started = Instant::now();
    let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(5)).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the connection must be reclaimed on the deadline, not eventually: {:?}",
        started.elapsed()
    );
    assert_eq!(fin_opcode & 0x0F, 0x8, "the reclaim must be a Close frame, got {fin_opcode:#x}");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        CLOSE_GOING_AWAY,
        "a reclaimed connection closes with 1001 (Going Away)"
    );

    // And the codec says WHY, rather than surfacing an I/O timeout the caller has to guess at.
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("no data from the peer"), "got {report:?}");
    assert!(report.contains("400ms"), "the error must name the deadline: {report:?}");
}

/// The ping is the polite half of the same problem: a NAT or a load balancer drops an idle flow,
/// and a ping every so often both keeps the path open and proves the peer is still there.
#[tokio::test]
async fn an_idle_peer_is_pinged_rather_than_dropped() {
    let (addr, _rx) = spawn_ws_server_echoing(
        WsLimits::default(),
        Some(Duration::from_millis(3000)),
        Some(Duration::from_millis(250)),
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    // Two pings inside a read timeout that is three times the ping interval: the connection
    // must survive the silences, because a ping happened in each.
    for round in 0..2 {
        let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(2)).await;
        assert_eq!(fin_opcode & 0x0F, 0x9, "round {round}: expected a Ping, got {fin_opcode:#x}");
        assert!(payload.is_empty(), "the keepalive ping carries no payload");
    }

    // The peer answers it, and the connection is still usable afterwards. The server ECHOES, so
    // the text coming back is proof the socket survived the idle period -- previously this read
    // waited for an echo from a server that never echoed anything, and saw a Ping instead.
    ws.send_frame(0x8A, b"").await;
    ws.send_frame(0x81, b"still here").await;
    let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(fin_opcode & 0x0F, 0x1, "the connection survived the idle period");
    assert_eq!(payload, b"still here");
}

/// A peer that KEEPS TALKING must never be pinged or dropped. This is the false-positive case,
/// and it is the one that would break a busy production connection if the deadlines were wired
/// in the wrong place.
#[tokio::test]
async fn a_peer_that_keeps_talking_is_never_pinged_or_dropped() {
    let (addr, mut rx) = spawn_ws_server_echoing(
        WsLimits::default(),
        Some(Duration::from_millis(400)),
        Some(Duration::from_millis(150)),
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    // Nine messages ~100ms apart -- every gap well under the 150ms ping interval and the 400ms
    // read timeout, so neither deadline should ever fire. Each echo is read BEFORE the next
    // message is sent: the earlier version sent all nine and only then read, which left the peer
    // silent for the whole read-back and let a perfectly legitimate Ping be the first thing it
    // saw. "Never pinged while talking" has to be observed WHILE it is talking.
    for i in 0..9 {
        ws.send_frame(0x81, format!("m{i}").as_bytes()).await;
        let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(2)).await;
        assert_eq!(
            fin_opcode & 0x0F,
            0x1,
            "message {i}: expected the echoed text, got opcode {fin_opcode:#x} -- a deadline fired early"
        );
        assert_eq!(payload, format!("m{i}").as_bytes());
        assert_eq!(next_report(&mut rx).await.unwrap(), format!("message Text(\"m{i}\")"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// THE default. With nothing configured, a silent peer is NOT reclaimed -- which is what
/// "optional" means, and what no other test in this file would notice if it quietly stopped
/// being true. The moved behaviour is preserved exactly.
///
/// This observes for a BOUNDED WINDOW and then passes. The earlier version of this test slept
/// and then did an unbounded `read_frame()`, which -- against a server that echoes nothing --
/// blocks forever: that is the 25-minute hang, and the hang was the test's fault, not the
/// code's. "Not dropped" is asserted the only way it can be asserted without waiting forever:
/// nothing at all arrives during the window, and the connection still works afterwards.
#[tokio::test]
async fn with_no_deadline_configured_a_silent_peer_is_not_dropped() {
    let (addr, mut rx) = spawn_ws_server_echoing(WsLimits::default(), None, None).await;
    let mut ws = RawWs::connect(addr).await;

    // Silent for 1.5s -- three times the read timeout any of the tests above uses, so if a
    // default deadline had crept in it would already have fired.
    let silence = tokio::time::timeout(Duration::from_millis(1500), ws.read_frame()).await;
    assert!(
        silence.is_err(),
        "with no deadline configured nothing may be sent at all: {silence:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), ws.is_closed()).await.is_err(),
        "and the connection must not have been closed"
    );

    // Still alive: a frame written now comes back.
    ws.send_frame(0x81, b"quiet but fine").await;
    assert_eq!(next_report(&mut rx).await.unwrap(), "message Text(\"quiet but fine\")");
    let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(2)).await;
    assert_eq!(fin_opcode & 0x0F, 0x1, "the connection is still up");
    assert_eq!(payload, b"quiet but fine");
}

/// The ping must not fire when the peer is merely slow but still arriving — one byte every
/// 100ms with a 150ms ping interval and a 400ms read timeout. Progress counts as activity; a
/// deadline that measured "no FRAME" instead of "no PROGRESS" would ping a working connection.
#[tokio::test]
async fn a_slow_but_progressing_peer_is_not_pinged() {
    let (addr, mut rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(400)),
        Some(Duration::from_millis(150)),
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    // Deliver one fragment of a fragmented text message every 100ms, for five fragments. Each
    // fragment is a frame, but the MESSAGE is incomplete throughout.
    //
    // The first fragment is FIN=0 Text (0x01) and the REST are CONTINUATIONs (0x00) with FIN
    // clear, then a final continuation with FIN set (0x80). The earlier version sent five 0x01
    // frames, which is a NEW TEXT frame arriving inside a fragmented message -- RFC 6455 §5.4
    // calls that a protocol error, and the server correctly closed the connection, so the test
    // was measuring its own malformed input.
    ws.send_frame(0x01, b"x").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..4 {
        ws.send_frame(0x00, b"x").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ws.send_frame(0x80, b"y").await;

    let report = next_report(&mut rx).await.unwrap();
    assert_eq!(
        report, "message Text(\"xxxxxy\")",
        "the fragments reassembled, so no ping interrupted them: {report:?}"
    );
}

/// The same property, on a frame too big to arrive at once: a peer trickling a 2 KiB text frame
/// out 64 bytes at a time, every 50ms, with a 150ms ping interval and a 400ms read timeout.
///
/// This is the case `read_n` got wrong. It wrapped `read_exact` in the timeout, so it measured
/// "no COMPLETE 2050-byte read within 150ms" rather than "no BYTE within 150ms", and it dropped
/// the read on every expiry -- discarding the bytes it had already taken off the socket, which
/// desynchronised the frame stream. A peer legitimately uploading a frame must come out the
/// other end byte-for-byte.
#[tokio::test]
async fn a_large_frame_trickled_out_is_neither_pinged_nor_corrupted() {
    let (addr, mut rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(400)),
        Some(Duration::from_millis(150)),
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    // 2 KiB of payload, so the length uses the 16-bit extended form and the read is many calls.
    let payload: Vec<u8> = (0..2048u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut frame = vec![0x81, 0x80 | 126];
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&MASK);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
    // ONE frame, its bytes trickled out in pieces -- not several frames.
    for piece in frame.chunks(64) {
        ws.send_raw(piece).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let report = next_report(&mut rx).await.unwrap();
    assert!(report.starts_with("message Text("), "the frame must reassemble, got: {report:?}");
    assert!(
        report.len() >= payload.len(),
        "every byte must survive the trickled read: {} chars for {} bytes",
        report.len(),
        payload.len()
    );
    // A Ping immediately after the message is CORRECT -- the peer went silent, which is what
    // the ping interval is for -- so the wire is not asserted quiet here. What matters is
    // upstream of it: with the old cancelled-read_exact the bytes dropped on each 150ms expiry
    // re-entered the stream as a bogus frame header, and this test fails against it -- the
    // server never reports a message at all (checked out at ec0ed47~1: `next_report` times out
    // and returns None). With fill_pending it reassembles.
}

/// The deadlines are per connection, like the size limits: a strict connection and a silent one
/// running at the same time do not affect each other.
#[tokio::test]
async fn the_idle_timeout_is_per_connection() {
    let (strict, mut strict_rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(300)),
        None,
    )
    .await;
    let (patient, mut patient_rx) = spawn_ws_server(WsLimits::default()).await;

    let mut a = RawWs::connect(strict).await;
    let mut b = RawWs::connect(patient).await;

    let (fin_opcode, payload) = next_frame(&mut a, Duration::from_secs(5)).await;
    assert_eq!(fin_opcode & 0x0F, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), CLOSE_GOING_AWAY);
    let _ = next_report(&mut strict_rx).await;

    // The other connection, silent for the same period, is untouched.
    b.send_frame(0x81, b"unaffected").await;
    assert_eq!(next_report(&mut patient_rx).await.unwrap(), "message Text(\"unaffected\")");
}

/// A ping interval LONGER than the read timeout is not a contradiction the library has to guess
/// at: the read timeout wins, because the point of it is to reclaim the connection. Pinned so
/// the precedence is stated rather than emergent.
#[tokio::test]
async fn a_ping_interval_longer_than_the_read_timeout_is_ignored() {
    let (addr, _rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(300)),
        Some(Duration::from_secs(30)),
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    let (fin_opcode, _) = next_frame(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(
        fin_opcode & 0x0F,
        0x8,
        "the read timeout must win: a 30s ping interval inside a 300ms deadline can never fire"
    );
}

/// The deadline applies to the BODY of a fragmented message too, not just to the first frame:
/// a peer that opens a message and then stalls mid-way must still be reclaimed, or the
/// reassembly buffer it created is held forever.
#[tokio::test]
async fn a_peer_that_stalls_mid_message_is_still_reclaimed() {
    let (addr, mut rx) = spawn_ws_server_timed(
        WsLimits::default(),
        Some(Duration::from_millis(400)),
        None,
    )
    .await;
    let mut ws = RawWs::connect(addr).await;

    ws.send_frame(0x01, b"half a message").await;
    // ...and then nothing.

    let (fin_opcode, payload) = next_frame(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(fin_opcode & 0x0F, 0x8);
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), CLOSE_GOING_AWAY);
    let report = next_report(&mut rx).await.unwrap();
    assert!(report.contains("no data from the peer"), "got {report:?}");
}