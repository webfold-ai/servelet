//! Hostile-input tests for `servelet-uri` — the hardening unit's census of what else in the
//! moved code parses attacker bytes.
//!
//! CENSUS, and why this crate is in it: `percent_decode` is the only part of the moved HTTP
//! stack that takes an arbitrary attacker-supplied string and turns it into a DIFFERENT string
//! that the application then acts on — a query parameter, a path segment, a cache key. Every
//! other moved parser either rejects or forwards. A decoder has two ways to hurt its caller:
//! it can panic on the input, and it can silently produce something the caller did not intend to
//! authorise (a `%2e%2e%2f` that turns into `../`, or a `%00` that becomes an embedded NUL).
//!
//! The obviously hostile input required here is the UNTERMINATED PERCENT ESCAPE: a trailing `%`,
//! or a `%` with only one hex digit after it. `from_str_radix` on a slice taken from arbitrary
//! bytes is exactly where an off-by-one turns into either a panic or a read past the end, and
//! the moved guard is `b'%' if i + 2 < bytes.len()` — one comparison, easy to get wrong, and
//! until now pinned by nothing.
//!
//! What is asserted: no panic, no out-of-bounds read, no silently dropped bytes, and the exact
//! output for each shape. A decoder's contract on malformed input is "pass the bytes through
//! literally", and that is what has to be pinned, because a decoder that instead guesses is a
//! decoder that lets two different requests authenticate as the same thing.

use servelet_uri::{percent_decode, percent_encode};

// ── The unterminated escape ────────────────────────────────────────────────────────────────

/// A bare `%` at the very end of the string: there is no escape at all, so the `%` is data.
/// This is the case the `i + 2 < bytes.len()` guard exists for.
#[test]
fn a_trailing_percent_sign_is_data_not_a_panic() {
    assert_eq!(percent_decode("%"), "%");
}

/// A `%` with exactly ONE hex digit after it — an escape that was cut off mid-way. The digit is
/// data. `i + 2 < len` is false here (`i + 2 == len`), so the guard must fall through to the
/// ordinary byte case; an off-by-one that used `<=` instead would slice past the end.
#[test]
fn a_percent_sign_with_one_hex_digit_is_passed_through_literally() {
    assert_eq!(percent_decode("%2"), "%2");
    assert_eq!(percent_decode("%A"), "%A");
}

/// The same shape with something in front of it, so the `%` is not at index 0 — the case that
/// catches a guard written against the wrong base index.
#[test]
fn an_unterminated_escape_mid_string_is_passed_through() {
    assert_eq!(percent_decode("a%"), "a%");
    assert_eq!(percent_decode("value=%"), "value=%");
    // A genuinely unterminated escape, not at index 0. The earlier version of this line read
    // `query%41` and expected it unchanged -- but `%41` is a COMPLETE escape (`41` is hex), so
    // it decodes to "queryA", and asserting otherwise was a wrong expectation, not a bug.
    assert_eq!(percent_decode("query%4"), "query%4");
    assert_eq!(percent_decode("query%"), "query%");
    assert_eq!(percent_decode("query%41"), "queryA", "a complete escape decodes, wherever it sits");
}

/// Two hex digits that are not hex at all. The escape is undecodable, so the WHOLE thing —
/// `%` included — is literal. A decoder that dropped just the `%` would turn `%zz` into `zz`,
/// which is a different string and a different authorization decision.
#[test]
fn a_non_hex_escape_is_passed_through_whole() {
    assert_eq!(percent_decode("%zz"), "%zz");
    assert_eq!(percent_decode("%GG"), "%GG");
    assert_eq!(percent_decode("a%zzb"), "a%zzb");
}

/// The full cross product of "where does the `%` sit relative to the end", as one table, so a
/// future change to the guard has to walk every branch rather than the one that was reported.
#[test]
fn every_truncation_of_the_same_escape_is_handled() {
    // "abc%41" truncated at each length. Only the full one decodes to "abcA".
    assert_eq!(percent_decode(""), "");
    assert_eq!(percent_decode("a"), "a");
    assert_eq!(percent_decode("ab"), "ab");
    assert_eq!(percent_decode("abc"), "abc");
    assert_eq!(percent_decode("abc%"), "abc%");
    assert_eq!(percent_decode("abc%4"), "abc%4");
    assert_eq!(percent_decode("abc%41"), "abcA");
}

// ── The hostile inputs that change what the caller authorised ──────────────────────────────

/// `%2e%2e%2f` decodes to `../`. If a decoded value is ever joined onto a filesystem or URL
/// path, this is directory traversal — and the ONLY reason it is not one here is that this
/// function does not do path joining. Pinned so that the moment a caller starts doing so, this
/// test is the thing that says so out loud.
#[test]
fn a_percent_encoded_path_traversal_decodes_to_the_traversal_it_names() {
    assert_eq!(percent_decode("%2e%2e%2f"), "../");
    assert_eq!(percent_decode("%2E%2E%2F"), "../");
    assert_eq!(percent_decode("/files%2f..%2f..%2fetc%2fpasswd"), "/files/../../etc/passwd");
    // And it is NOT the same string as the encoded form: a caller comparing a decoded value
    // against an allow-list of raw paths must not be handed something that looks safe.
    assert_ne!(percent_decode("%2e%2e%2f"), "%2e%2e%2f");
}

/// `%00` decodes to an embedded NUL byte. Many C-interop boundaries (a path handed to libc, a
/// value written into a C string) truncate at the first NUL, so `%00admin` can be "admin" to
/// one hop and something else to the next.
#[test]
fn a_percent_encoded_nul_decodes_to_an_embedded_nul() {
    let decoded = percent_decode("user%00admin");
    assert_eq!(decoded.as_bytes(), b"user\0admin");
    assert_eq!(decoded.len(), "user%00admin".len() - 2, "the escape must consume exactly three bytes");
}

/// A lone continuation byte is not a UTF-8 sequence on its own, and the decoder is documented
/// as lossy — it must produce the replacement character rather than panicking or silently
/// dropping the byte. Pinning the exact output, because "lossy" is not a specification.
#[test]
fn an_incomplete_utf8_sequence_becomes_the_replacement_character() {
    assert_eq!(percent_decode("%C3"), "\u{FFFD}");
    assert_eq!(percent_decode("a%E2%82"), "a\u{FFFD}");
    // Two complete sequences reassemble into one character: this is why the decoder is
    // byte-based rather than char-based, and the round trip below depends on it.
    assert_eq!(percent_decode("%C3%A9"), "é");
    assert_eq!(percent_decode("caf%C3%A9"), "café");
}

// ── Bounds ─────────────────────────────────────────────────────────────────────────────────

/// A very long string of nothing but truncated escapes: the pathological case for a decoder
/// that re-slices on every iteration. It must return, and return the right thing.
#[test]
fn a_long_run_of_truncated_escapes_does_not_blow_up() {
    let hostile = "%".repeat(200_000);
    let decoded = percent_decode(&hostile);
    assert_eq!(decoded.len(), hostile.len(), "every undecodable byte must survive");
    assert!(decoded.bytes().all(|b| b == b'%'));
}

/// Alternating decodable and truncated escapes, so the index arithmetic is exercised on every
/// step rather than only in one branch.
#[test]
fn alternating_decodable_and_truncated_escapes_stay_in_step() {
    assert_eq!(percent_decode("%41%42%43"), "ABC");
    // `%41%%42%`: the `%` at index 3 is followed by `%4`, which is not two hex digits, so that
    // `%` is LITERAL and parsing resumes at the next byte -- where a perfectly valid `%42`
    // begins. So it decodes to `B`. The earlier expectation of "A%42%" encoded a different rule
    // (swallow the whole three-byte window as literal whenever the window is not hex), which is
    // not what this decoder does and not what the WHATWG percent-decode does: it keeps the `%`
    // and re-syncs on the next byte. Left as the moved code has it, since that behaviour is
    // what 58 live call sites in ptyktos-api decode with.
    assert_eq!(percent_decode("%41%%42%"), "A%B%");
    // `+%41%2+%4`: space, `A`, then `%2+` is not hex so the `%` is literal, then `2`, then the
    // `+` at index 6 is a FORM-ENCODED SPACE like any other, then a truncated `%4`. The earlier
    // expectation " A%2%4" silently dropped that `+` -- and it never ran before, because the
    // assertion above it panicked first.
    assert_eq!(percent_decode("+%41%2+%4"), " A%2 %4");
}

/// `+` is the form-encoded space, and it is decoded wherever a `%` would be. The two must not
/// interfere: a `+` immediately before a truncated escape is a space followed by a literal `%`.
#[test]
fn a_plus_before_a_truncated_escape_is_still_a_space() {
    assert_eq!(percent_decode("+%"), " %");
    assert_eq!(percent_decode("+%41"), " A");
}

// ── The encoder, which a caller reaches for when it distrusts the above ───────────────────

/// The encoder is the safe direction: it can only produce a strictly smaller alphabet, so an
/// attacker cannot get a character into a URL that the encoder would have escaped. Round trip
/// through a hostile string, which is what a caller does before trusting a decoded value.
#[test]
fn the_encoder_escapes_exactly_what_the_decoder_cannot_be_trusted_with() {
    // `%` is escaped by the encoder, so a round trip through encode/decode cannot smuggle a
    // second layer of encoding past the decoder.
    assert_eq!(percent_encode("100%"), "100%25");
    assert_eq!(percent_decode(&percent_encode("100%")), "100%");
    assert_eq!(percent_encode("a%2e%2e"), "a%252e%252e");
    assert_eq!(percent_decode(&percent_encode("a%2e%2e")), "a%2e%2e");
    // Round trip of a string full of raw control bytes and separators.
    let hostile = "\u{0}\n\r\t \"'<>%?#[]{}|\\^`";
    assert_eq!(percent_decode(&percent_encode(hostile)), hostile);
}