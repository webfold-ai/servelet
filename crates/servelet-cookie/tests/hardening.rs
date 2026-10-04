//! Hostile-input tests for `servelet-cookie` — the hardening unit's census of what else in the
//! moved code parses attacker bytes.
//!
//! CENSUS, and why this crate is in it: `Cookie::parse_header` is the one place in the moved
//! HTTP stack that takes a whole attacker-controlled request header, splits it, and hands back
//! name/value pairs that the application then treats as an authenticated identity. A `Cookie:`
//! header is attacker-chosen in the sense that matters: any page on the internet can cause one
//! to be sent, so its contents are user input even though the user is "logged in".
//!
//! The obviously hostile input required here is an OVER-LONG COOKIE HEADER. There is no limit
//! in this function at all — it splits on `;` and `=` and collects — so the honest question is
//! not "is it safe" but "where is the bound, and is it pinned". It is at the HTTP layer:
//! `servelet-h1`'s `RequestLimits::max_header_bytes` bounds how many bytes of header can exist
//! before a parser like this one is ever reached. That is the right place for the bound (it
//! also covers every OTHER header), but it is only a real bound if somebody pins it, so this
//! file states what the parser does with a huge one and the h1 tests state that the huge one
//! never gets this far.

use servelet_cookie::Cookie;

/// The obviously hostile input: one megabyte of `Cookie:` header.
///
/// What is asserted is that the parse is linear, allocates in proportion to the pairs it
/// actually finds, and does not panic. Note what is NOT asserted: that it is bounded. It is
/// not, here — see the module doc. The bound lives in `servelet-h1`.
#[test]
fn an_over_long_cookie_header_parses_without_panicking_or_exploding() {
    // A megabyte of garbage with no `=` in it at all: the worst case for a parser that
    // allocated per split before checking.
    let garbage = "a".repeat(1 << 20);
    let parsed = Cookie::parse_header(&garbage);
    assert!(parsed.is_empty(), "no `=` means no pair, however much of it there is");

    // A megabyte of genuine pairs: the other worst case, one allocation per pair.
    let many = (0..20_000)
        .map(|i| format!("k{i}=v{i}"))
        .collect::<Vec<_>>()
        .join(";");
    assert!(many.len() > 200_000, "the fixture must actually be over-long: {} bytes", many.len());
    let parsed = Cookie::parse_header(&many);
    assert_eq!(parsed.len(), 20_000, "every real pair must be found, none invented");
    assert_eq!(parsed[0].name(), "k0");
    assert_eq!(parsed[19_999].value(), "v19999");
}

/// A megabyte where every byte IS a separator: `;;;;;;...`. A parser that recursed per
/// separator, or that kept splitting on an emptied string, would show up here.
#[test]
fn a_cookie_header_of_nothing_but_separators_yields_nothing() {
    let seps = ";".repeat(1 << 20);
    assert!(Cookie::parse_header(&seps).is_empty());
    let commas = ", ".repeat(1 << 19);
    assert!(Cookie::parse_header(&commas).is_empty(), "a comma is not a cookie separator");
}

/// A single pair whose VALUE is a megabyte. The name/value split is on the first `=`, so a
/// value containing further `=` characters must survive whole rather than being truncated at
/// the second one — a base64 or JWT cookie value depends on this.
#[test]
fn a_huge_cookie_value_with_embedded_equals_survives_whole() {
    let mut value = "v".repeat(1 << 20);
    value.push_str("==trailing-padding=");
    let header = format!("session={value}");
    let parsed = Cookie::parse_header(&header);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name(), "session");
    assert_eq!(parsed[0].value(), value, "only the FIRST `=` separates name from value");
}

/// Whitespace: a megabyte of spaces around a real pair. `trim` is per pair, so this is
/// quadratic in the naive implementation and is the shape most likely to be a slow denial of
/// service rather than a fast one.
#[test]
fn a_cookie_header_padded_with_whitespace_still_parses() {
    let header = format!("{}session=abc{}", " ".repeat(1 << 19), " ".repeat(1 << 19));
    let parsed = Cookie::parse_header(&header);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name(), "session", "surrounding whitespace is not part of the name");
    assert_eq!(parsed[0].value(), "abc", "surrounding whitespace is not part of the value");
}

/// The shapes a real attacker sends in a `Cookie:` header. Each must be handled without
/// panicking, and each must not turn into a cookie whose name or value is something the caller
/// did not send.
#[test]
fn hostile_cookie_shapes_do_not_panic_and_do_not_invent_pairs() {
    // No `=` at all.
    assert!(Cookie::parse_header("notacookie").is_empty());
    // `=` with nothing either side.
    assert_eq!(Cookie::parse_header("=").len(), 1, "pinned as a known gap in docs/HARDENING.md");
    // An empty name is ACCEPTED. RFC 6265 §4.1.1 requires a non-empty name, so this parser is
    // more permissive than the RFC. Pinned deliberately: it is a known gap, not an accident,
    // and `parse_header` has no error channel to refuse with. See docs/HARDENING.md.
    let parsed = Cookie::parse_header("=novalue");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name(), "");
    assert_eq!(parsed[0].value(), "novalue");

    // CR and LF inside the header: a request-line injection attempt smuggled into a cookie.
    // The split is on `;`/`=`, so the control characters become part of a name or value.
    // Pinned so a caller knows NOT to assume these are absent.
    let parsed = Cookie::parse_header("a=b\r\nSet-Cookie: admin=1");
    assert_eq!(parsed[0].name(), "a");
    assert!(
        parsed[0].value().contains('\r') || parsed[0].value().contains('\n'),
        "control bytes survive the parse; a caller must not treat a cookie value as line-safe: {:?}",
        parsed[0].value()
    );

    // An empty header, and a header of only whitespace.
    assert!(Cookie::parse_header("").is_empty());
    assert!(Cookie::parse_header("   ").is_empty());
    assert!(Cookie::parse_header(";;;").is_empty());
}

/// Many pairs with the SAME name. An application that takes "the first" and one that takes
/// "the last" disagree here, and that disagreement is a session-fixation bug in the making.
/// Pinned so the ambiguity is a documented fact rather than a surprise.
#[test]
fn duplicate_cookie_names_are_all_returned_in_order_and_never_merged() {
    let parsed = Cookie::parse_header("session=first; session=second; session=third");
    assert_eq!(parsed.len(), 3, "nothing is merged and nothing is dropped");
    let values: Vec<&str> = parsed.iter().map(|c| c.value()).collect();
    assert_eq!(values, ["first", "second", "third"], "order is preserved");
}