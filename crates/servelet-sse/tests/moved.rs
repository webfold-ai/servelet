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
