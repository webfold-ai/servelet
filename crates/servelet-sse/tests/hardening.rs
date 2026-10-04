//! Hostile-input tests for `servelet-sse` — the hardening unit's census of what else in the
//! moved code parses attacker bytes.
//!
//! CENSUS, and why this crate is in it: `SseParser` is the only moved parser that runs on a
//! stream it does not control the length of. Every other one reads a header block that ends at a
//! blank line; this one is fed whatever arrives and decides where an event ended, which means
//! an attacker who controls the server side of the stream controls where the parser believes the
//! event boundaries are.
//!
//! The obviously hostile input required here is a NEWLINE INJECTED INTO AN SSE FIELD. The subtle
//! part is WHICH newline: `\n` and `\r\n` are line terminators everywhere, so injecting one
//! just splits the event the way the spec says it should. A LONE `\r` is different. The WHATWG
//! event-stream grammar treats CR, LF and CRLF as three spellings of the same terminator, but
//! Rust's `str::lines` knows only about `\n` and strips a single trailing `\r` — so a lone CR
//! in the middle of a field survives into the parsed value.
//!
//! That surviving CR is a forgery primitive rather than a cosmetic bug. Every consumer
//! downstream treats a lone CR as a line break: a log line, a CSV reader, a terminal, a `fold`.
//! A field value of `col1\rFAKE LOG LINE` renders in a log viewer as two lines, the second of
//! which the attacker wrote and nothing in the application ever sanctioned.

use servelet_sse::SseParser;

/// THE obviously hostile input. A lone carriage return injected into the middle of a `data`
/// field must be a line terminator, so it ENDS the data line — and cannot hide inside the value.
///
/// The result is `"col1"`, not `"col1\ncol2"`: once the CR terminates the line, what follows is
/// a new line whose field name is `col2` and whose value is empty. The parser is line-based, so
/// `col2` is a field NAME, not a second piece of data. The security property this test exists
/// for is that no `\r` survives into `event.data`; the earlier expectation of `"col1\ncol2"`
/// encoded a wrong belief about how a colon-less line is read and was wrong.
#[test]
fn a_lone_carriage_return_injected_into_an_sse_field_becomes_a_line_break() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: col1\rcol2\n\n");

    assert_eq!(events.len(), 1, "it is still ONE event: the CR is a line break, not an event break");
    assert_eq!(
        events[0].data, "col1",
        "the CR terminates the data line; `col2` is the next line's field NAME, not more data"
    );
    assert!(
        !events[0].data.contains('\r'),
        "a lone CR survived into the parsed value -- it will render as a line break downstream: {:?}",
        events[0].data
    );
}

/// The forgery case, spelled out. Two `data:` fields separated by a lone CR must concatenate
/// per the SSE rule (multiple `data` lines join with `\n`) — NOT come back as one value that
/// still contains the CR and still contains the text `data: `.
#[test]
fn a_carriage_return_cannot_smuggle_a_second_field_past_the_parser() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: x\rdata: y\n\n");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "x\ny", "two data lines join with a newline");
    assert!(
        !events[0].data.contains("data:"),
        "a field name leaked into the field VALUE: {:?}",
        events[0].data
    );
}

/// An `event:`/`id:` field after a lone CR is a genuinely separate field, and must be read as
/// one rather than staying glued inside the previous field's value.
#[test]
fn a_carriage_return_before_another_field_reads_as_that_field() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: payload\revent: forged\n\n");

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, "payload");
    assert_eq!(events[0].event.as_deref(), Some("forged"));
}

/// The three terminator spellings must all mean the same thing. If CR and CRLF and LF disagreed,
/// then which one an attacker sent would decide what the parser saw — and the attacker picks.
#[test]
fn all_three_line_terminator_spellings_mean_the_same_thing() {
    let lf = SseParser::new().feed(b"data: a\ndata: b\n\n");
    let crlf = SseParser::new().feed(b"data: a\r\ndata: b\r\n\r\n");
    let cr = SseParser::new().feed(b"data: a\rdata: b\r\r");

    assert_eq!(lf[0].data, "a\nb");
    assert_eq!(crlf[0].data, "a\nb", "CRLF must join data lines with a single newline");
    assert_eq!(cr[0].data, "a\nb", "CR must mean the same as LF and CRLF");
}

/// A `\r` immediately before the `\n` is CRLF, i.e. ONE terminator — not two, which would
/// inject a blank line and split the event in half.
#[test]
fn a_carriage_return_before_a_line_feed_is_one_terminator_not_two() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: a\r\ndata: b\r\n\r\n");
    assert_eq!(events.len(), 1, "CRLF must not manufacture an extra event boundary");
    assert_eq!(events[0].data, "a\nb");
}

/// The flush path takes whatever is left when no blank line ever arrives — which is the case a
/// hostile server produces by simply never terminating an event. The trailing `\r` must not
/// become part of the last field either.
#[test]
fn a_trailing_carriage_return_in_a_flushed_event_is_a_terminator() {
    let mut parser = SseParser::new();
    assert!(parser.feed(b"data: last\r").is_empty(), "no blank line, so no event yet");
    let flushed = parser.flush().expect("the partial event must be flushed");
    assert_eq!(flushed.data, "last");
    assert!(!flushed.data.contains('\r'), "the trailing CR leaked into the value: {:?}", flushed.data);
}

/// A `\n`-terminated field list still behaves exactly as before: this hardening must not have
/// changed the ordinary path, and the moved tests next door are the real proof of that.
#[test]
fn ordinary_line_feed_separated_events_are_unaffected() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"id: 1\nevent: msg\ndata: hello\ndata: world\n\n");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id.as_deref(), Some("1"));
    assert_eq!(events[0].event.as_deref(), Some("msg"));
    assert_eq!(events[0].data, "hello\nworld");
}

/// Hostile volume: a stream of nothing but line terminators, and one of nothing but field names.
/// Neither may loop forever, allocate per character, or panic.
#[test]
fn a_stream_of_pure_terminators_and_field_names_does_not_blow_up() {
    let mut parser = SseParser::new();
    assert!(parser.feed(&b"\r".repeat(200_000)).is_empty());

    let mut parser = SseParser::new();
    let mut names = b"data: x\r".repeat(100_000);
    // The blank line the stream NEEDS to terminate the event. The earlier version of this test
    // asserted one event from a stream that never sent one, which contradicts every other
    // event-stream rule here: without a blank line there is no event boundary, and the parser
    // correctly holds the partial event for the next chunk.
    names.extend_from_slice(b"\r\r");
    let events = parser.feed(&names);
    assert_eq!(events.len(), 1, "the blank line is the event boundary");
    // 100k lines of `x` joined by the 99_999 newlines BETWEEN them — the join count is
    // lines-1, which the earlier version got wrong by one.
    assert_eq!(events[0].data.len(), 199_999, "100k lines of `x` joined by 99_999 newlines");
    assert!(parser.feed(b"").is_empty(), "and nothing is left over");
}

/// A field value carrying a NUL, and one carrying bytes that are not valid UTF-8. The parser is
/// `from_utf8_lossy`, so it must be lossy and not panic — pinned because "lossy" is not a
/// specification and a caller reading `event.data` should know what it is getting.
#[test]
fn a_field_with_a_nul_or_invalid_utf8_is_handled_lossily_not_fatal() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: a\x00b\n\n");
    assert_eq!(events[0].data, "a\u{0}b", "a NUL is data, not a terminator");

    let mut parser = SseParser::new();
    let events = parser.feed(b"data: a\xffb\n\n");
    assert_eq!(events[0].data, "a\u{FFFD}b", "invalid UTF-8 becomes the replacement character");
}

/// A CR-only stream is TERMINATED, not left dangling. This used to be pinned as a "KNOWN GAP"
/// — a peer that spells every terminator with a lone CR produced no `\n\n`, so `feed` never
/// found a boundary and the buffer grew until the stream ended. That gap is closed: `absorb`
/// collapses all three spellings to `\n` on the way in, so all three find a boundary.
#[test]
fn a_lone_cr_only_stream_still_finds_an_event_boundary() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: a\rdata: b\r\r");
    assert_eq!(events.len(), 1, "a CR-CR blank line is a boundary like any other");
    assert_eq!(events[0].data, "a\nb");
}

/// A CRLF split across two `feed` calls is still ONE terminator. This is the case the held-back
/// trailing CR exists for: committing a `\r` at the end of a chunk would turn the `\n` at the
/// start of the next chunk into a second terminator, manufacturing a blank line — and therefore
/// an event boundary — that the peer never sent.
#[test]
fn a_carriage_return_split_across_two_feeds_is_still_one_terminator() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: a\r");
    assert!(events.is_empty(), "a half-written CRLF is not an event boundary");
    let events = parser.feed(b"\ndata: b\r\n\r\n");
    assert_eq!(events.len(), 1, "the split CRLF must not manufacture a second event");
    assert_eq!(events[0].data, "a\nb");
}