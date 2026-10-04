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
/// field must be a line terminator, so it splits the field — and therefore cannot hide inside
/// the value.
#[test]
fn a_lone_carriage_return_injected_into_an_sse_field_becomes_a_line_break() {
    let mut parser = SseParser::new();
    let events = parser.feed(b"data: col1\rcol2\n\n");

    assert_eq!(events.len(), 1, "it is still ONE event: the CR is a line break, not an event break");
    assert_eq!(
        events[0].data, "col1\ncol2",
        "the lone CR must become an LF, exactly as if the peer had sent one"
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
    let names = b"data: x\r".repeat(100_000);
    let events = parser.feed(&names);
    // 100k data lines with no blank line between them: ONE event, joined with newlines.
    assert_eq!(events.len(), 1, "no blank line means no event boundary");
    assert_eq!(events[0].data.len(), 200_000, "100k lines of `x` joined by 100k newlines");
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

/// KNOWN GAP, pinned rather than left implicit: a peer that uses ONLY lone CR as its line
/// terminator produces no `\n\n`, so `feed` never finds an event boundary and the internal
/// buffer keeps growing until the stream ends. This test records that behaviour honestly. The
/// bound is the caller's read size, not this parser — see `docs/HARDENING.md`.
#[test]
fn a_lone_cr_only_stream_finds_no_event_boundary_until_an_lf_pair_arrives() {
    let mut parser = SsEProbe::new();
    parser.parser.feed(b"data: a\rdata: b\r");
    assert!(
        parser.parser.feed(b"\n\n").len() == 1,
        "the LF pair finally terminates the event"
    );
    assert_eq!(parser.parser.flush().map(|e| e.data), None);
}

/// Small wrapper so the gap test above reads as a probe rather than a bare call.
struct SsEProbe {
    parser: SseParser,
}

impl SsEProbe {
    fn new() -> Self {
        SsEProbe { parser: SseParser::new() }
    }
}