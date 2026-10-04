//! The request-head and body ceilings — added by the hardening unit, NOT part of the biota move.
//!
//! WHY THIS FILE EXISTS: the moved `read_request_buffered` reads the head with
//! `reader.read_until(b'\n', &mut line_buf)`. `read_until` grows the buffer until it finds the
//! newline, with no ceiling of any kind — so a peer that sends a 10 MB header line, or ten
//! million 1-byte headers, or a body declared as `Content-Length: 18446744073709551615` (which
//! the moved code hands straight to `vec![0u8; content_length]`), controls how much memory the
//! server allocates before anything has decided whether the request is legitimate. There is also
//! no timeout: a peer that opens a connection and then sends one byte every ten seconds holds
//! the connection, its `BufReader`, and its task open indefinitely.
//!
//! Every number below is a DEFAULT that [`RequestLimits::default`] supplies and that
//! `serve_connection_with_limits` lets a caller change per listener. They are published in
//! `docs/HARDENING.md`, and each one has a test there that fails if the behaviour is removed.
//!
//! Where each bound belongs is a real design question, not a detail:
//!
//!   * The header bounds are HERE, at the parser, because they have to be: they bound the work
//!     of parsing itself, so a limit applied after parsing would arrive too late to help.
//!   * The body bound is here as a BACKSTOP only. An application that genuinely streams a large
//!     upload sets it higher, or replaces it with its own layer; the point is that the default
//!     is finite rather than whatever the peer typed in a header.
//!   * The read timeout is here because "how long may a peer take to send a request" is a
//!     property of the wire, not of any one route.

use std::time::Duration;

/// The ceilings one connection's request parsing works under.
///
/// [`Default`] is what `serve_connection` uses, which is what every deployment gets without
/// asking. [`crate::wire::serve_connection_with_limits`] takes one explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestLimits {
    /// Largest request line (`GET /path HTTP/1.1`) accepted, in bytes including CRLF.
    pub max_request_line_bytes: usize,
    /// Largest total size of ALL header lines in one request, in bytes including CRLFs.
    ///
    /// A total, not a per-header bound, because per-header is not what an attacker needs you to
    /// get wrong: a thousand headers of 1 KB each is a megabyte of parsing, and a per-header
    /// limit of 8 KB waves all of it through.
    pub max_header_bytes: usize,
    /// Largest number of header lines in one request.
    ///
    /// This is the one that costs the attacker the most per byte sent: 100 headers is a
    /// completely ordinary request, and a million is not. It exists because `HeaderMap::insert`
    /// and the per-line parse are not free, and because every one of them is a hash-map insert.
    pub max_header_count: usize,
    /// Largest request body buffered into memory, in bytes, when the application has not
    /// installed its own body limit.
    pub max_body_bytes: usize,
    /// How long the whole of one request — head plus body — may take to arrive before the
    /// connection is dropped.
    pub read_timeout: Duration,
}

impl RequestLimits {
    /// 8 KiB. A request line is a method, a URI and a version; the longest real ones (a deep
    /// path, a long query string on a tracking redirect) are hundreds of bytes. 8 KiB is far
    /// above any real request and far below the megabyte a peer would need to reach.
    pub const DEFAULT_MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
    /// 64 KiB total across all headers. Comfortably above nginx's 8 KiB per-header default and
    /// its 64-ish KiB whole-head practical ceiling, and above what any real client sends when
    /// it forwards a signed S3 request with its whole `X-Amz-*` metadata block.
    pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
    /// 100 header lines. More than any browser, curl, or SDK sends for a normal request.
    pub const DEFAULT_MAX_HEADER_COUNT: usize = 100;
    /// 8 MiB. Chosen against the body being fully BUFFERED into a `Vec` — the moved design,
    /// not a streaming one — so this is the largest single request a default deployment will
    /// hold in memory at once.
    pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
    /// 10 seconds for the whole request. Long enough that a slow mobile client on a bad
    /// connection finishes its headers; short enough that a peer holding connections open by
    /// dribbling a byte a second cannot.
    pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);
}

impl Default for RequestLimits {
    fn default() -> Self {
        RequestLimits {
            max_request_line_bytes: Self::DEFAULT_MAX_REQUEST_LINE_BYTES,
            max_header_bytes: Self::DEFAULT_MAX_HEADER_BYTES,
            max_header_count: Self::DEFAULT_MAX_HEADER_COUNT,
            max_body_bytes: Self::DEFAULT_MAX_BODY_BYTES,
            read_timeout: Self::DEFAULT_READ_TIMEOUT,
        }
    }
}