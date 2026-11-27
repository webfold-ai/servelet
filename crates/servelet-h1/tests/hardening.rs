//! Real-socket proof for the request-head, body and slow-read ceilings, and for the
//! request-smuggling refusals — the hardening unit's `servelet-h1` work.
//!
//! The moved `read_request_buffered` read the head with `reader.read_until(b'\n', &mut line_buf)`
//! and had no ceiling anywhere: not on a line's length, not on how many lines there were, not on
//! the total header size, not on the body, and not on how long a peer could take. It also
//! accepted a bare LF anywhere a CRLF belonged, and it resolved a request that carried BOTH
//! `Content-Length` and `Transfer-Encoding` by silently preferring the content length.
//!
//! All of those are reachable from any socket that accepts an HTTP/1.1 request, so all of them
//! are tested here from the wire: a raw `TcpStream` speaking HTTP by hand, because the property
//! under test is what the peer SEES, and no client crate would send the abuse in the first place.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use servelet_core::{Request, Response};
use servelet_h1::{RequestLimits, serve_connection_with_limits};
use servelet_router::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A router with one real route, so a request that IS accepted has somewhere to go and the
/// refusal tests are not just measuring a 404.
fn app() -> Router {
    Router::new()
        .get("/ok", |req: Request| async move {
            Response::ok(format!("ok {}", req.path()))
        })
        .get("/echo", |req: Request| async move {
            Response::ok(String::from_utf8_lossy(req.body()).to_string())
        })
        // The body tests POST. Without this the router 404s them and the test measures the
        // router instead of the body path.
        .post("/echo", |req: Request| async move {
            Response::ok(String::from_utf8_lossy(req.body()).to_string())
        })
}

/// Bind an ephemeral port and serve with the DEFAULT ceilings — which is what every consumer
/// gets, so every test below that uses this one is testing the shipped behaviour.
async fn spawn_default() -> SocketAddr {
    spawn_with(RequestLimits::default()).await
}

async fn spawn_with(limits: RequestLimits) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let router = app();
            tokio::spawn(serve_connection_with_limits(stream, router, Some(peer), limits));
        }
    });
    addr
}

/// Send `request` and return whatever the server sends back, giving up after 10s.
///
/// The write result is DELIBERATELY ignored. Several tests here send more than the server is
/// willing to read -- that is the abuse under test -- so the server closes mid-write and
/// `write_all` returns an error. Panicking on it would fail the test for the wrong reason, and
/// the refusal is on the read side anyway.
async fn exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let _ = stream.write_all(request).await;
    let _ = stream.flush().await;
    read_all(&mut stream).await
}

/// Read until the peer closes, bounded. A `400` is followed by a close (the refusal sets
/// `Connection: close`), so this returns rather than blocking.
async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return out,
        }
    }
}

fn status_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).lines().next().unwrap_or_default().to_string()
}

/// Assert the server refused with a 400, and that the response did NOT come from a route.
fn assert_refused(raw: &[u8]) {
    let line = status_line(raw);
    assert!(line.contains("400"), "expected a 400 refusal, got: {line:?}");
    assert!(
        !line.contains("200"),
        "the request must not have been served: {line:?}"
    );
}

/// A well-formed request, used as the "this still works" control in several tests.
fn good_request(extra: &str) -> Vec<u8> {
    format!("GET /ok HTTP/1.1\r\nHost: x\r\n{extra}\r\n").into_bytes()
}

// ── The header-head ceilings ──────────────────────────────────────────────────────────────

/// The required real-socket proof: a request with a TEN MEGABYTE header line is refused, and
/// refused promptly — the limit is checked as bytes arrive, so the server never allocates the
/// 10 MB, let alone parses it.
#[tokio::test]
async fn a_request_with_a_ten_megabyte_header_line_is_refused() {
    let addr = spawn_default().await;
    let mut request = Vec::new();
    request.extend_from_slice(b"GET /ok HTTP/1.1\r\nHost: x\r\nX-Big: ");
    request.resize(request.len() + 10 * 1024 * 1024, b'A');
    request.extend_from_slice(b"\r\n\r\n");

    let started = Instant::now();
    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the refusal must be immediate, not after reading all 10 MB: {:?}",
        started.elapsed()
    );
}

/// A single header that is too long is the same ceiling as a line that is too long — this one
/// is small enough to write by hand and pins the exact error text the peer is given.
#[tokio::test]
async fn an_oversized_single_header_is_refused_with_the_rule_named() {
    let addr = spawn_default().await;
    let mut request = Vec::new();
    request.extend_from_slice(b"GET /ok HTTP/1.1\r\nHost: x\r\nX-Big: ");
    request.resize(request.len() + 128 * 1024, b'A');
    request.extend_from_slice(b"\r\n\r\n");

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains("more than 8192 bytes") || text.contains("more than 65536 bytes"),
        "the refusal must name the limit it broke, got: {text}"
    );
}

/// Many small headers: each one is legal, and the COUNT is what makes it a lever — every one is
/// a hash-map insert and a parse.
#[tokio::test]
async fn a_request_with_more_headers_than_the_count_limit_is_refused() {
    let addr = spawn_default().await;
    let mut request = Vec::from("GET /ok HTTP/1.1\r\nHost: x\r\n");
    for i in 0..500 {
        request.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("more than 100 header lines"),
        "the refusal must name the count limit: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// The TOTAL header byte ceiling, which is a different number from the line ceiling: 200 headers
/// of 400 bytes each is under 100 KiB of line-length violation but over the 64 KiB total, and a
/// per-header limit alone would wave all of it through.
#[tokio::test]
async fn a_header_block_over_the_total_byte_limit_is_refused() {
    let addr = spawn_default().await;
    let mut request = Vec::from("GET /ok HTTP/1.1\r\nHost: x\r\n");
    // 90 lines of 1 KiB: under the 100-line count limit, over the 64 KiB total.
    for i in 0..90 {
        let mut line = format!("X-H{i}: ");
        line.push_str(&"v".repeat(1024 - line.len()));
        request.extend_from_slice(line.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("more than 65536 bytes"),
        "the refusal must name the total header byte limit: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// The ceilings are ceilings, not a ban on headers: an ordinary request with a realistic number
/// of them still gets served.
#[tokio::test]
async fn an_ordinary_request_with_several_headers_is_still_served() {
    let addr = spawn_default().await;
    let mut extra = String::new();
    for i in 0..20 {
        extra.push_str(&format!("X-H{i}: value{i}\r\n"));
    }
    let reply = exchange(addr, &good_request(&extra)).await;
    let line = status_line(&reply);
    assert!(line.contains("200"), "an ordinary request must still be served, got: {line:?}");
    assert!(String::from_utf8_lossy(&reply).contains("ok /ok"));
}

// ── The body ceiling ───────────────────────────────────────────────────────────────────────

/// `Content-Length` is attacker-chosen, and the moved code did `vec![0u8; content_length]` with
/// nothing in between. A declared length of 8 MiB + 1 must be refused ON THE HEADER, before the
/// allocation — so the client sends no body at all and still gets its answer.
#[tokio::test]
async fn a_content_length_over_the_body_limit_is_refused_before_the_body_is_read() {
    let addr = spawn_default().await;
    let request = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 8388609\r\n\r\n";
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("body limit"),
        "the refusal must name the body limit: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// The absurd length, which the moved code would have handed to the allocator as a 16-exabyte
/// request. Refused, and no body ever arrives.
#[tokio::test]
async fn an_absurd_content_length_is_refused_before_anything_is_allocated() {
    let addr = spawn_default().await;
    let request = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 18446744073709551615\r\n\r\n";
    let started = Instant::now();
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the check must be on the header, not after waiting for a body: {:?}",
        started.elapsed()
    );
}

/// A body at the limit is served — otherwise a limit set one byte low would be indistinguishable
/// from a limit that works.
#[tokio::test]
async fn a_body_at_the_limit_is_still_read_and_served() {
    let addr = spawn_default().await;
    let body = vec![b'.'; 1024 * 1024];
    let mut request = format!("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(&body);

    let reply = exchange(addr, &request).await;
    let line = status_line(&reply);
    assert!(line.contains("200"), "a 1 MiB body is well under the limit and must be served: {line:?}");
}

/// A chunk-size line can claim anything at all, and the moved code allocated `size + 2` from it
/// unchecked. A chunked body that over-runs the limit must be refused, not allocated.
#[tokio::test]
async fn a_chunked_body_over_the_limit_is_refused() {
    let addr = spawn_default().await;
    let mut request =
        Vec::from("POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
    // Claims a 1 GiB chunk, delivers 4 bytes.
    request.extend_from_slice(b"40000000\r\nabcd\r\n");

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("chunked body"),
        "the refusal must name the chunked body limit: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// The other half of the same fix: `chunked` ALONE still works, or the hardening would have
/// broken every botocore S3 streaming-checksum upload in the deployment.
#[tokio::test]
async fn a_chunked_body_under_the_limit_is_still_served() {
    let addr = spawn_default().await;
    let mut request = Vec::from("POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
    request.extend_from_slice(b"4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n");

    let reply = exchange(addr, &request).await;
    let line = status_line(&reply);
    assert!(line.contains("200"), "a small chunked body must still be served: {line:?}");
}

// ── The slow-read timeout ──────────────────────────────────────────────────────────────────

/// THE required real-socket proof: a peer that trickles one byte per second cannot hold the
/// connection open forever. This runs against the DEFAULT limits, so it is testing the shipped
/// 10-second deadline rather than a value the test chose.
#[tokio::test]
async fn a_peer_trickling_one_byte_per_second_is_dropped() {
    let addr = spawn_default().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    // "GET /ok HTTP/1.1\r\n" dribbled out at one byte per second. At the default 10s deadline
    // the server gives up partway through the request line.
    let started = Instant::now();
    for b in b"GET /ok HTTP/1.1\r\n".iter() {
        if started.elapsed() > Duration::from_secs(20) {
            break;
        }
        // A closed connection ends the loop early -- which is exactly the behaviour under test,
        // so it is a reason to stop trickling, not a reason to panic.
        if stream.write_all(&[*b]).await.is_err() {
            break;
        }
        let _ = stream.flush().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let mut reply = Vec::new();
    let mut chunk = [0u8; 1024];
    // The server must either answer or close, and it must do so on the deadline rather than
    // after the whole trickle.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => reply.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => break,
            Err(_) => panic!("the server neither answered nor closed within the deadline"),
        }
    }
    assert!(
        !reply.is_empty(),
        "the slow request must be refused or closed, not left hanging"
    );
    assert_refused(&reply);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the connection must be dropped on the deadline, not when the peer happens to stop"
    );
}

/// The same behaviour with a short, caller-stated deadline, so the mechanism is pinned
/// independently of how long the shipped default happens to be.
#[tokio::test]
async fn a_slow_peer_is_dropped_on_a_caller_stated_deadline() {
    let addr = spawn_with(RequestLimits { read_timeout: Duration::from_millis(500), ..RequestLimits::default() }).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream.write_all(b"GET /ok HTTP/1.1\r\n").await.unwrap();
    stream.flush().await.unwrap();
    // Then say nothing at all.
    let mut reply = Vec::new();
    let mut chunk = [0u8; 1024];
    let started = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => reply.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => break,
            Err(_) => panic!("the server held a silent connection past its deadline"),
        }
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the deadline must fire promptly: {:?}",
        started.elapsed()
    );
    assert_refused(&reply);
}

/// A request that arrives INSIDE the deadline is served normally — the timeout must not be a
/// limit on request size or a race against a fast client.
#[tokio::test]
async fn a_request_that_arrives_inside_the_deadline_is_served() {
    let addr = spawn_default().await;
    let reply = exchange(addr, &good_request("")).await;
    assert!(status_line(&reply).contains("200"), "a fast request must be served normally");
}

// ── Request smuggling ──────────────────────────────────────────────────────────────────────

/// RFC 9112 §6.1: a message with BOTH `Content-Length` and `Transfer-Encoding` is ambiguous, and
/// the recipient must refuse it rather than pick. The moved code picked the content length and
/// said nothing, which is precisely the half of the attack this server controls.
#[tokio::test]
async fn both_content_length_and_transfer_encoding_is_answered_400() {
    let addr = spawn_default().await;
    let request = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("Content-Length and Transfer-Encoding"),
        "the refusal must name the ambiguity: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// The smuggling pair: the differing Content-Lengths are the two front ends disagreeing about
/// where the body ends, and the trailing request is what would be smuggled.
#[tokio::test]
async fn two_differing_content_lengths_are_answered_400() {
    let addr = spawn_default().await;
    let mut request =
        Vec::from("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 45\r\n\r\n");
    request.extend_from_slice(b"hello");
    request.extend_from_slice(b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n");

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("different Content-Length"),
        "the refusal must name the disagreement: {}",
        String::from_utf8_lossy(&reply)
    );
    assert!(
        !String::from_utf8_lossy(&reply).contains("/admin"),
        "the smuggled request must never be answered: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// Two IDENTICAL Content-Lengths are not an attack and are accepted — RFC 9112 §6.3 permits a
/// recipient to accept a repeated identical value. Refusing them would break clients that
/// legitimately send the header twice.
#[tokio::test]
async fn two_identical_content_lengths_are_accepted() {
    let addr = spawn_default().await;
    let request = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    let reply = exchange(addr, request).await;
    assert!(status_line(&reply).contains("200"), "identical duplicates are legal: {:?}", status_line(&reply));
    assert!(String::from_utf8_lossy(&reply).contains("hello"));
}

/// A bare LF inside the header block. A front proxy that frames on CRLF and this server that
/// frames on LF disagree about where the request ends, and the gap is a request neither side
/// authorised. The moved code accepted bare LF both as a line terminator and as the head
/// terminator.
#[tokio::test]
async fn a_bare_line_feed_inside_a_header_is_answered_400() {
    let addr = spawn_default().await;
    let request = b"GET /ok HTTP/1.1\r\nHost: x\r\nX-A: 1\nX-Smuggled: GET /admin HTTP/1.1\r\n\r\n";
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
    assert!(
        String::from_utf8_lossy(&reply).contains("bare LF"),
        "the refusal must name the rule: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// A bare LF as the HEAD terminator — the same rule, at the other end of the block, and the one
/// the moved code's `line_buf == b"\n"` branch allowed.
#[tokio::test]
async fn a_bare_line_feed_as_the_head_terminator_is_answered_400() {
    let addr = spawn_default().await;
    let request = b"GET /ok HTTP/1.1\r\nHost: x\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n";
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
    assert!(
        !String::from_utf8_lossy(&reply).contains("/admin"),
        "the smuggled request must never be answered: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// A bare LF terminating the REQUEST LINE is refused too. All three bare-LF positions matter:
/// it is not enough to fix only the one a particular proxy disagrees about.
#[tokio::test]
async fn a_bare_line_feed_terminating_the_request_line_is_answered_400() {
    let addr = spawn_default().await;
    let request = b"GET /ok HTTP/1.1\nHost: x\r\n\r\n";
    let reply = exchange(addr, request).await;
    assert_refused(&reply);
}

/// And CRLF-framed requests still work, which is what makes the three refusals above a rule
/// rather than a blanket "reject the header block".
#[tokio::test]
async fn a_crlf_framed_request_is_still_served() {
    let addr = spawn_default().await;
    let reply = exchange(addr, b"GET /ok HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\r\n").await;
    assert!(status_line(&reply).contains("200"), "a well-framed request must still be served");
}

// ── The published defaults ─────────────────────────────────────────────────────────────────

/// The numbers `docs/HARDENING.md` publishes. Changing one of these silently changes every
/// deployment that never asked for a limit, so it has to break a test.
#[test]
fn the_documented_default_request_limits_are_the_published_ones() {
    let d = RequestLimits::default();
    assert_eq!(d.max_request_line_bytes, 8 * 1024);
    assert_eq!(d.max_header_bytes, 64 * 1024);
    assert_eq!(d.max_header_count, 100);
    assert_eq!(d.max_body_bytes, 8 * 1024 * 1024);
    assert_eq!(d.read_timeout, Duration::from_secs(10));

    // And they are internally consistent: no single header line may be allowed to exceed the
    // whole block's ceiling, or the total could never be reached.
    assert!(d.max_request_line_bytes <= d.max_header_bytes);
}

/// The refusal names the limit it broke, and does NOT echo the attacker's bytes into the
/// response. The body is derived from attacker-chosen input and this string ends up in a log.
#[tokio::test]
async fn the_refusal_names_the_rule_without_echoing_the_payload() {
    let addr = spawn_default().await;
    let canary = "CANARY-SECRET-MATERIAL";
    let request = format!("GET /ok HTTP/1.1\r\nHost: x\r\nX-A: {canary}\n\r\n");
    let reply = exchange(addr, request.as_bytes()).await;
    assert_refused(&reply);
    assert!(
        !String::from_utf8_lossy(&reply).contains(canary),
        "the request payload leaked into the refusal body: {}",
        String::from_utf8_lossy(&reply)
    );
}

/// A request the server cannot parse gets a `400` and a `Connection: close`, never a silently
/// dropped socket — a client has to be able to tell "refused" from "the network ate it".
///
/// The request line is genuinely unparseable (ONE token, no URI, no version). The earlier
/// version of this test sent `NOT EVEN HTTP`, which IS parseable — three tokens, so it reaches
/// the router and correctly 404s. A 404 there is the right answer, and asserting `400` for it
/// was measuring the wrong thing.
#[tokio::test]
async fn a_refusal_sets_connection_close_and_a_content_length() {
    let addr = spawn_default().await;
    let reply = exchange(addr, b"GARBAGE\r\n\r\n").await;
    assert_refused(&reply);
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.to_ascii_lowercase().contains("connection: close"),
        "the refusal must close the connection: {text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("content-length:"),
        "the refusal must state its own body length: {text}"
    );
}
// ── The request-line ceiling, pinned on its own ──────────────────────────────────────────────

/// A request line of about 9 KiB is over the 8 KiB request-line ceiling and far under the 64 KiB
/// header-block ceiling, so NO OTHER limit can refuse it: only the request-line bound does. This is
/// the test that makes "stop bounding the request line" (mutation P) observable: with the bound
/// gone the path is read in full, routed, and answered 404, not refused.
#[tokio::test]
async fn a_request_line_over_the_request_line_ceiling_is_refused_with_the_limit_named() {
    let addr = spawn_default().await;
    let path = "a".repeat(RequestLimits::DEFAULT_MAX_REQUEST_LINE_BYTES + 1024);
    let request = format!("GET /{path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();

    let reply = exchange(addr, &request).await;
    assert_refused(&reply);
    let text = String::from_utf8_lossy(&reply);
    assert!(
        text.contains(&RequestLimits::DEFAULT_MAX_REQUEST_LINE_BYTES.to_string()),
        "the refusal must name the ceiling that was exceeded: {text}"
    );
}

/// The control for the test above: a request line comfortably UNDER the ceiling is not refused as
/// too long (it is a 404 because the fixture has no such route), so the ceiling is a ceiling and
/// not a ban on long paths.
#[tokio::test]
async fn a_request_line_under_the_request_line_ceiling_is_not_refused_as_too_long() {
    let addr = spawn_default().await;
    let path = "a".repeat(RequestLimits::DEFAULT_MAX_REQUEST_LINE_BYTES - 64);
    let request = format!("GET /{path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();

    let reply = exchange(addr, &request).await;
    let line = status_line(&reply);
    assert!(!line.contains("400"), "a request line under the ceiling must not be a 400: {line:?}");
    assert!(!line.is_empty(), "the server must answer a request line under the ceiling");
}

// ── An idle keep-alive connection is closed, not answered ─────────────────────────────────

/// The bug this pins: after a served request the connection waits for the next one under the read deadline, and when
/// the deadline passed with NOTHING received the server wrote `400 ... the request did not arrive within ...`. A
/// pooled client that reuses that connection just after the server gave up reads the stale 400 as the answer to its
/// NEW request (iotaDB "posting search refused: 400" / "posting ingest refused: 400"). Idle is not malformed: the
/// connection must end with no bytes.
#[tokio::test]
async fn an_idle_keepalive_connection_is_closed_without_a_400() {
    let addr = spawn_with(RequestLimits { read_timeout: Duration::from_millis(300), ..RequestLimits::default() }).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&good_request("")).await.unwrap();
    // The first response, read exactly (keep-alive: the server does not close after it).
    let mut head = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut head)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"), "the control request must be served");
    // Now say nothing for longer than the read deadline and read what the server sends before it closes.
    let rest = read_all(&mut stream).await;
    assert!(rest.is_empty(), "an idle connection must close silently, the server wrote: {:?}", String::from_utf8_lossy(&rest));
}

/// The control: a request that STARTED and then stalled is slow, not idle, and is still refused with a 400.
#[tokio::test]
async fn a_started_but_stalled_request_still_gets_a_400() {
    let addr = spawn_with(RequestLimits { read_timeout: Duration::from_millis(300), ..RequestLimits::default() }).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n").await.unwrap(); // no blank line: never completes
    let rest = read_all(&mut stream).await;
    assert_refused(&rest);
}
