//! The six `wire_tests` moved out of `biota/http-server`'s `lib.rs` `pub mod sse` at rev `4ce2dcd`
//! (lines 2419-2469), verbatim: `encode_event` and `SseParser`, the parse/emit half.
//!
//! The only edit at this seam: biota's `mod wire_tests` sat inside `pub mod sse` and read its own
//! names out of that module. As an integration test the file has to name the crate explicitly,
//! and `mod wire_tests` became `mod moved` so it is obviously a moved file. The other three tests
//! of this module (`sse.rs`'s own `mod tests`, lines 2256-2285) stay inside `sse.rs`, because
//! they call `Data::render`, which is deliberately not public.

use servelet_sse::*;

mod moved {
    use super::*;

    #[test]
    fn encode_simple() {
        let e = encode_event("hello", None, None);
        assert_eq!(e, "data: hello\n\n");
    }

    #[test]
    fn encode_with_event_and_id() {
        let e = encode_event("hello", Some("msg"), Some("1"));
        assert_eq!(e, "id: 1\nevent: msg\ndata: hello\n\n");
    }

    #[test]
    fn parser_across_chunk_boundaries() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: hel").is_empty());
        let evs = p.feed(b"lo\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "hello");
    }

    #[test]
    fn parser_multiple_data_lines_concatenate() {
        let mut p = SseParser::new();
        let evs = p.feed(b"event: msg\ndata: line1\ndata: line2\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event.as_deref(), Some("msg"));
        assert_eq!(evs[0].data, "line1\nline2");
    }

    #[test]
    fn parser_two_events_in_one_chunk() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: one\n\ndata: two\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "one");
        assert_eq!(evs[1].data, "two");
    }

    #[test]
    fn parser_flush_partial() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: partial").is_empty());
        let ev = p.flush();
        assert_eq!(ev.as_ref().map(|e| e.data.as_str()), Some("partial"));
    }
}

/// CRLF boundary coverage.
///
/// `feed()` checks `\n\n` before `\r\n\r\n`, which looks like it should mis-slice a CRLF
/// stream — and does not. `\r\n\r\n` is CR,LF,CR,LF, so it contains no adjacent LF pair and
/// `\n\n` never matches inside it; the CRLF arm is always the one taken. (A worker asserted
/// the opposite, added a "fix", and these tests then passed against the *unfixed* code, which
/// is what settled it.)
///
/// These exist so that reasoning is pinned rather than re-derived — and so a real change to
/// the boundary logic cannot land without these being re-checked.
#[test]
fn parser_handles_crlf_boundaries() {
    let mut p = servelet_sse::SseParser::new();
    let evs = p.feed(b"data: one\r\n\r\ndata: two\r\n\r\n");
    assert_eq!(evs.len(), 2, "both events should parse from a CRLF stream");
    assert_eq!(evs[0].data, "one");
    assert_eq!(evs[1].data, "two");
}

/// The same stream with named event and id fields — the case that would catch a stray `\r`
/// leaking into a field name rather than being swallowed by a data value.
#[test]
fn parser_keeps_crlf_field_names_clean() {
    let mut p = servelet_sse::SseParser::new();
    let evs = p.feed(b"event: msg\r\nid: 3\r\ndata: hi\r\n\r\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event.as_deref(), Some("msg"));
    assert_eq!(evs[0].id.as_deref(), Some("3"));
    assert_eq!(evs[0].data, "hi");
}

/// A CRLF boundary split across two chunks: the second feed lands mid-boundary, which is
/// where an off-by-two would be worst.
#[test]
fn parser_handles_crlf_boundary_split_across_chunks() {
    let mut p = servelet_sse::SseParser::new();
    assert!(p.feed(b"data: hello\r").is_empty());
    let evs = p.feed(b"\n\r\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "hello");
}
