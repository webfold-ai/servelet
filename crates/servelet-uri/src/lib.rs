//! `servelet-uri` — percent-encoding and percent-decoding of a URL component.
//!
//! One job: the `%%XX` transformation, both directions. It knows nothing about `Request`,
//! `Response`, a route, or a socket: `percent_encode("hello world")` is a string function.
//!
//! Moved byte-for-byte from `biota/http-server`'s `helpers.rs` at rev `4ce2dcd`, lines 77-131:
//! `percent_decode` (77-111) and `percent_encode` (113-131). Their two tests moved to
//! `tests/moved.rs`.
//!
//! SCOPE, measured. `docs/EXTRACTION.md` §1 counts **one** live name in all of `helpers.rs`:
//! `percent_encode`, at 58 call sites across `ptyktos-api-wallet-wiring` / `caretaker-release`
//! (`src/engines/{bing,duckduckgo,google,searxng}.rs`). The other 24 public functions there have 0
//! external callers and stayed behind. `percent_decode` comes WITH `percent_encode` for two
//! reasons, both stated rather than assumed: the moved test round-trips through it
//! (`percent_encode_round_trips_and_keeps_unreserved`), and an encoder with no decoder next to
//! it is how "encode once here, decode nowhere" bugs get written. It is 35 lines and std only.
//!
//! std only: zero dependencies.

#![forbid(unsafe_code)]

/// Decode a query-string value: `+` → space, `%XX` → byte.
///
/// Byte-based, not char-based: `%C3%A9` (é) must reassemble into one UTF-8 sequence. A
/// char-based decode would push 0xC3 and 0xA9 as two separate (invalid) chars, producing
/// `Ã©`. The result is lossy-decoded to UTF-8 like the two byte-based copies it replaces.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Encode a string as a URL component (RFC 3986 unreserved chars kept, everything else
/// `%XX`). The inverse of [`percent_decode`], for building URLs with query params — the
/// one-directional sibling the four search engines in ptyktos-api each used to carry their
/// own byte-identical copy of.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}
