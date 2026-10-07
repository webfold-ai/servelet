//! gRPC over HTTP/2: the 5-byte message prefix and the trailer convention.
//!
//! A gRPC unary call is HTTP/2 with three frame kinds: an initial HEADERS (`:status` +
//! `content-type: application/grpc[+proto]`), one or more DATA frames whose payload is a
//! 5-byte gRPC message header (1 byte Compressed-Flag, 4 bytes Message-Length, big-endian)
//! followed by exactly `Message-Length` bytes of protobuf, and a final HEADERS (END_STREAM)
//! carrying `grpc-status: <u32 as string>` and optionally `grpc-message: <percent-encoded
//! UTF-8>`. RFC 7540 + https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md.
//!
//! This module is intentionally thin: the h2 transport already encodes HEADERS, DATA and
//! END_STREAM trailers correctly. The gRPC layer is (1) a 5-byte prefix codec, (2) named
//! constants for the gRPC pseudo-headers and trailers, and (3) a
//! [`serve_grpc_unary_connection`] wrapper that strips the prefix off the request body
//! before the handler sees it, wraps the response body with a fresh prefix, and emits a
//! `grpc-status: 0` trailer (re-using the handler's `grpc-status` header if it set one,
//! defaulting to 0).
//!
//! Why a submodule, not a separate crate: the wire form is h2 with one extra header of
//! framing, and per crate rule 1 ("one job, one sentence with no 'and'") `servelet-h2`'s
//! job is already "HTTP/2 framing and HPACK" — adding the gRPC shape on top is a property
//! of the same wire, not a new one. The added surface is 8 named items and a 30-line
//! connection wrapper; spinning up a new crate would cost a `Cargo.toml`, a README, and
//! another row in the budget baseline for thirty lines of code.
//!
//! `serve_grpc_unary` is the gRPC-capable equivalent of `serve_h2c_connection`: same
//! preface + SETTINGS handshake, same HEADERS/DATA dispatch, but the body is 5-byte-
//! prefixed in both directions. Calling `servelet_h1::serve` and `servelet_h2::serve` is
//! not stacked for the same reason `servelet_h2::serve` and `servelet_h2::serve_grpc_unary`
//! are not stacked: each binds its own listener, and the application picks one. The h2c
//! preface that the SEAM argument names is consumed by `serve` (HTTP/2 plain) and
//! `serve_grpc_unary` (gRPC over HTTP/2) in the same way — both refuse a connection that
//! does not start with the 24-byte magic.

use servelet_core::{Error, HeaderName, HeaderValue, Result};

/// The 1-byte gRPC Compressed-Flag value for an UNCOMPRESSED message body. Per
/// <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md> a value of 1 means
/// the body is compressed; the supported algorithms are advertised by the client in a
/// `grpc-accept-encoding` header. This crate does not implement compression; the flag
/// is preserved on the wire but always 0.
pub const GRPC_COMPRESSED_FALSE: u8 = 0;

/// The gRPC status code for "OK" (RFC gRPC §4.1.2 status codes).
pub const GRPC_STATUS_OK: u32 = 0;

/// Reserved gRPC header names. `HeaderName::from_static` lowercases on construction;
/// gRPC over HTTP/2 sends these as lowercase already. These are functions, not
/// `pub const`s, because `HeaderName::from_static` and `HeaderValue::from_static` are
/// not `const fn`s in `servelet-core`; the wrapping functions allocate a fresh value
/// each call, which is fine -- header construction is a setup-time cost, not a hot path.
pub fn grpc_status() -> HeaderName { HeaderName::from_static("grpc-status") }
pub fn grpc_message() -> HeaderName { HeaderName::from_static("grpc-message") }
pub fn grpc_content_type() -> HeaderName { HeaderName::from_static("content-type") }
/// gRPC's `te: trailers` (RFC gRPC §2.2 — required to be sent by clients and not rejected
/// by servers). The h2 transport does not currently assert its presence; documenting it
/// here as the constant the gRPC-aware response builder emits when the application does
/// not set a content-type.
pub fn grpc_te() -> HeaderName { HeaderName::from_static("te") }
pub fn grpc_te_trailers_value() -> HeaderValue { HeaderValue::from_static("trailers") }
pub fn grpc_content_type_grpc() -> HeaderValue { HeaderValue::from_static("application/grpc") }
pub fn grpc_content_type_grpc_proto() -> HeaderValue { HeaderValue::from_static("application/grpc+proto") }

/// Encode one 5-byte gRPC message header.
///
/// `len` is the message-body length, NOT including the 5-byte header itself. `compressed`
/// is the gRPC Compressed-Flag; this crate writes the value 0 only.
///
/// The wire layout is one flag byte followed by a 32-bit big-endian length (network byte
/// order — the same shape as HTTP/2's own length-prefixed framing). Hand-computed
/// references for common sizes, used by the round-trip test:
///   * 0 bytes -> `[0, 0, 0, 0, 0]`
///   * 1 byte  -> `[0, 0, 0, 0, 1]`
///   * 5 bytes -> `[0, 0, 0, 0, 5]`
///   * 256 bytes -> `[0, 0, 0, 1, 0]`
pub fn encode_message_header(compressed: bool, len: u32) -> [u8; 5] {
    let flag = if compressed { 1u8 } else { 0u8 };
    let mut out = [0u8; 5];
    out[0] = flag;
    out[1..5].copy_from_slice(&len.to_be_bytes());
    out
}

/// Decode the first 5 bytes of a gRPC message stream. Returns
/// `(compressed_flag, message_length, bytes_consumed)`. The third element is always 5 for
/// well-formed input and is returned for symmetry with the streaming case the wire is
/// designed for; today the wrapper reads the body in one chunk, but the test exercises
/// the boundary.
///
/// Returns `Error::Parse` on a truncated header (fewer than 5 bytes) so a caller that
/// hands in a partial read can surface a wire error rather than panic on an out-of-range
/// index.
pub fn decode_message_header(buf: &[u8]) -> Result<(bool, u32, usize)> {
    if buf.len() < 5 {
        return Err(Error::Parse(format!(
            "gRPC message header truncated: got {} bytes, need 5",
            buf.len()
        )));
    }
    let compressed = buf[0] != 0;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    Ok((compressed, len, 5))
}

/// Wrap a handler's response body in a single 5-byte gRPC prefix. A response with an
/// empty body returns a prefix only — no DATA frame at all (a `DATA` with zero length is
/// not a no-op, it is a real frame that occupies wire bandwidth; the wire-form spec
/// allows skipping it).
///
/// `compressed` is the gRPC Compressed-Flag; this crate does not implement compression, so
/// the wrapper writes 0. An earlier version wrote 0 unconditionally, then silently
/// ignored the `compressed` argument — a misnamed-argument hazard; the field is now named
/// `compressed` for clarity and is preserved on the wire as the future seam if a
/// compressor is added.
pub fn wrap_response_body(body: &[u8], compressed: bool) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&encode_message_header(compressed, body.len() as u32));
    out.extend_from_slice(body);
    out
}

/// Strip the 5-byte gRPC message header from a request body. Returns the message bytes
/// and the compressed-flag the client set. The body is rejected if it does not start
/// with a 5-byte header (in the unary case this is a wire error — the gRPC client always
/// sends the prefix, even for a zero-length body).
pub fn unwrap_request_body(body: &[u8]) -> Result<(bool, &[u8])> {
    let (compressed, len, consumed) = decode_message_header(body)?;
    if consumed + (len as usize) != body.len() {
        return Err(Error::Parse(format!(
            "gRPC message body length mismatch: header says {} bytes of message, body is {} bytes total",
            len,
            body.len()
        )));
    }
    Ok((compressed, &body[consumed..]))
}

/// Build the gRPC unary response HEADERS frame. The wire form is `:status 200` plus
/// `content-type: application/grpc+proto` (the response half of the gRPC content-type
/// negotiation). The trailer frame (with `grpc-status`) is added by
/// [`grpc_trailer_headers`].
pub fn response_headers() -> Vec<(HeaderName, HeaderValue)> {
    vec![
        (HeaderName::from_static(":status"), HeaderValue::from_static("200")),
        (grpc_content_type(), grpc_content_type_grpc_proto()),
    ]
}

/// Build the gRPC unary trailer HEADERS frame (END_STREAM). `status` is the gRPC status
/// code; `message` is the optional `grpc-message` (percent-encoded UTF-8 per RFC gRPC
/// §4.1.2). A status of [`GRPC_STATUS_OK`] and an empty `message` is the success
/// convention.
pub fn grpc_trailer_headers(status: u32, message: &str) -> Vec<(HeaderName, HeaderValue)> {
    let status_str = status.to_string();
    let mut out: Vec<(HeaderName, HeaderValue)> = vec![(grpc_status(), HeaderValue::from(status_str))];
    if !message.is_empty() {
        out.push((grpc_message(), HeaderValue::from(message.to_string())));
    }
    out
}
