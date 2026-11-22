# HARDENING.md — what `servelet` refuses, and the test that proves each refusal

The numbers here are the SHIPPED defaults, not aspirations. Every one is a `const` in the crate
named, and every one has a test that fails if the behaviour is removed. Where a limit is off by
default that is stated with the reason, because "optional" that quietly becomes a default closes
innocent connections and no other test would notice.

Counts in this document come from one run of

```
cargo test -j3 --workspace --no-fail-fast
```

on this worktree at the commit that adds this file: **172 passed, 0 failed, 0 hung**
(171 before the last WebSocket test was added).

---

## 1. `servelet-h1` — request head, body and slow-read ceilings

`RequestLimits` (`crates/servelet-h1/src/limits.rs`), all five defaults applied by
`serve_connection`, overridable per listener with `serve_connection_with_limits`.

| Limit | Default | Enforced against | Test that proves it |
|---|---|---|---|
| `max_request_line_bytes` | 8 KiB | bytes arriving, before any parse | `a_request_with_a_ten_megabyte_header_line_is_refused`, `an_oversized_single_header_is_refused_with_the_rule_named` |
| `max_header_bytes` | 64 KiB total across ALL header lines | cumulative, as lines arrive | `a_header_block_over_the_total_byte_limit_is_refused` |
| `max_header_count` | 100 header lines | per line | `a_request_with_more_headers_than_the_count_limit_is_refused` |
| `max_body_bytes` | 8 MiB | the DECLARED `Content-Length` and each chunk size, before the allocation | `a_content_length_over_the_body_limit_is_refused_before_the_body_is_read`, `an_absurd_content_length_is_refused_before_anything_is_allocated`, `a_chunked_body_over_the_limit_is_refused` |
| `read_timeout` | 10 s for head + body | the whole of one request | `a_peer_trickling_one_byte_per_second_is_dropped`, `a_slow_peer_is_dropped_on_a_caller_stated_deadline` |

The two directions matter as much as the limits, and each has its own test:

* A limit set one byte low is indistinguishable from a limit that works, so the boundaries are
  served: `a_body_at_the_limit_is_still_read_and_served`,
  `a_chunked_body_under_the_limit_is_still_served`, `an_ordinary_request_with_several_headers_is_still_served`,
  `a_request_that_arrives_inside_the_deadline_is_served`. `chunked` alone still works — that is
  every botocore S3 streaming-checksum upload in the deployment.
* The refusal is a real `400` with `Connection: close` and a `Content-Length`, not a silently
  dropped socket: `a_refusal_sets_connection_close_and_a_content_length`.
* The refusal names the rule it broke and never echoes attacker bytes into a string that ends up
  in a log: `the_refusal_names_the_rule_without_echoing_the_payload`.
* The published numbers are pinned: `the_documented_default_request_limits_are_the_published_ones`.

**Request smuggling** (the moved code silently preferred `Content-Length` when both framings were
present, and overwrote `content_length` on every duplicate):

| Shape | Answer | Test |
|---|---|---|
| `Content-Length` **and** `Transfer-Encoding: chunked` | `400` (RFC 9112 §6.1: refuse, do not pick) | `both_content_length_and_transfer_encoding_is_answered_400` |
| two differing `Content-Length` | `400`, and the trailing request is never answered | `two_differing_content_lengths_are_answered_400` |
| two IDENTICAL `Content-Length` | accepted (RFC 9112 §6.3) | `two_identical_content_lengths_are_accepted` |
| bare LF inside a header | `400` | `a_bare_line_feed_inside_a_header_is_answered_400` |
| bare LF as the head terminator | `400` | `a_bare_line_feed_as_the_head_terminator_is_answered_400` |
| bare LF ending the request line | `400` | `a_bare_line_feed_terminating_the_request_line_is_answered_400` |
| ordinary CRLF framing | served | `a_crlf_framed_request_is_still_served` |

23 tests, all real sockets (`tests/hardening.rs`) — a hand-written `TcpStream` speaking HTTP,
because the property is what the peer SEES.

## 2. `servelet-ws` — frame, message, fragmentation and idle ceilings

`WsLimits` (`crates/servelet-ws/src/limits.rs`):

| Limit | Default | Test |
|---|---|---|
| `max_frame_bytes` | 1 MiB | `a_frame_header_claiming_two_pow_63_bytes_is_closed_1009_without_allocating`, `an_oversize_frame_is_refused_before_the_payload_is_read`, `a_frame_at_exactly_the_limit_is_served_and_one_byte_more_is_refused`, `the_documented_default_limits_are_one_mib_and_sixteen_mib` |
| `max_message_bytes` | 16 MiB, across all frames of a message | `a_fragmented_message_over_the_total_cap_is_closed_1009`, `a_fragmented_message_exactly_at_the_cap_is_served`, `a_peer_that_sends_endless_continuations_is_stopped_at_the_cap` |

Both are checked on the DECLARED length, before any payload byte is read, so an over-limit header
costs one 14-byte read rather than the allocation it asked for.

**Fragmentation and control frames** (RFC 6455), 18 tests in `tests/fragmentation.rs`: a
`CONTINUATION` reassembles into the message it belongs to, a message is capped in total rather
than per frame, a fragmented or oversized control frame is `1002`, a control frame of exactly 125
bytes is served, a continuation with no message in progress is `1002`, a data frame inside a
fragmented message is `1002`, a text message that is not UTF-8 is `1007` — checked on the
ASSEMBLED message, so a multi-byte character split across a fragment boundary is still legal
(`a_multibyte_character_split_across_a_fragment_boundary_is_accepted`).

**Idle timeout and ping** (`WebSocket::with_idle_timeout` / `with_ping_interval`), 9 tests in
`tests/idle.rs`. Both are **OFF by default**: a deadline that expires closes a connection that may
have been quiet and perfectly alive, and a library that picks that deadline for an application
gets it wrong for somebody. What the library owes is a way to set one.

| Behaviour | Default | Test |
|---|---|---|
| read deadline on PROGRESS — the clock restarts every time a byte arrives | `None` | `a_peer_that_never_sends_anything_is_closed_after_the_read_timeout`, `a_peer_that_stalls_mid_message_is_still_reclaimed` |
| a ping interval shorter than the read deadline keeps the path open instead of closing | `None` | `an_idle_peer_is_pinged_rather_than_dropped` |
| a peer that is talking is never pinged or dropped | — | `a_peer_that_keeps_talking_is_never_pinged_or_dropped`, `a_slow_but_progressing_peer_is_not_pinged`, `a_large_frame_trickled_out_is_neither_pinged_nor_corrupted` |
| **nothing at all happens when nothing is configured** | — | `with_no_deadline_configured_a_silent_peer_is_not_dropped` |
| deadlines are per connection | — | `the_idle_timeout_is_per_connection` |
| a ping interval longer than the read deadline: the read deadline wins | — | `a_ping_interval_longer_than_the_read_timeout_is_ignored` |

The progress rule is the substantive one: the deadline covers the wait for the *next byte*, not
for the completion of a read, and a cancelled read discards nothing. Both matter on a public port
— a peer legitimately uploading a large frame must come out the other end byte-for-byte, and must
not be pinged for doing it.

## 3. `servelet-sse` — hostile input to the only unbounded parser here

`SseParser` is the only moved parser that runs on a stream whose length it does not control. 11
tests in `tests/hardening.rs`.

CR, LF and CRLF are three spellings of ONE line terminator in the event-stream grammar, and
Rust's `str::lines` knows only about `\n`. A lone CR surviving into a parsed field value is a
forgery primitive rather than a cosmetic bug: every consumer downstream — a log writer, a
terminal, a CSV reader — treats it as a line break.

* all three spellings mean the same thing: `all_three_line_terminator_spellings_mean_the_same_thing`
* a CR-CR blank line is an event boundary like any other, so a CR-only peer is not left dangling:
  `a_lone_cr_only_stream_still_finds_an_event_boundary`
* a CRLF split across two `feed` calls is still ONE terminator, and does not manufacture an event
  boundary the peer never sent: `a_carriage_return_split_across_two_feeds_is_still_one_terminator`
* no CR survives into a value: `a_lone_carriage_return_injected_into_an_sse_field_becomes_a_line_break`,
  `a_trailing_carriage_return_in_a_flushed_event_is_a_terminator`
* a CR cannot smuggle a field name past the parser: `a_carriage_return_cannot_smuggle_a_second_field_past_the_parser`,
  `a_carriage_return_before_another_field_reads_as_that_field`
* volume and rubbish do not blow up: `a_stream_of_pure_terminators_and_field_names_does_not_blow_up`
  (200 000 bare terminators, then 100 000 field lines), `a_field_with_a_nul_or_invalid_utf8_is_handled_lossily_not_fatal`
* the ordinary LF path is untouched: `ordinary_line_feed_separated_events_are_unaffected`,
  `a_carriage_return_before_a_line_feed_is_one_terminator_not_two`

## 4. `servelet-uri` — the decoder a caller may not trust

12 tests in `tests/hardening.rs`, over a std-only, dependency-free function with 58 live call
sites in `ptyktos-api`.

* a truncated escape is data, not a panic: `a_trailing_percent_sign_is_data_not_a_panic`,
  `a_percent_sign_with_one_hex_digit_is_passed_through_literally`, `an_unterminated_escape_mid_string_is_passed_through`,
  `every_truncation_of_the_same_escape_is_handled`
* a non-hex escape is passed through WHOLE (`%zz` stays `%zz`), because dropping just the `%`
  changes the string and can change an authorization decision: `a_non_hex_escape_is_passed_through_whole`
* index arithmetic stays in step over mixed input: `alternating_decodable_and_truncated_escapes_stay_in_step`
* 200 000 truncated escapes return rather than re-slicing per character: `a_long_run_of_truncated_escapes_does_not_blow_up`
* what the caller is being handed is pinned, not described: `a_percent_encoded_path_traversal_decodes_to_the_traversal_it_names`
  (this function does NOT do path joining — that is the only reason `%2e%2e%2f` is not traversal here),
  `a_percent_encoded_nul_decodes_to_an_embedded_nul`,
  `an_incomplete_utf8_sequence_becomes_the_replacement_character`
* and the encoder round-trips against all of it: `the_encoder_escapes_exactly_what_the_decoder_cannot_be_trusted_with`

## 5. `servelet-cookie` — hostile cookie shapes

6 tests in `tests/hardening.rs`: over-long headers, a header of nothing but separators, huge
values with embedded `=`, whitespace padding, and duplicate names kept in order and never merged
(`an_over_long_cookie_header_parses_without_panicking_or_exploding`,
`a_cookie_header_of_nothing_but_separators_yields_nothing`,
`a_huge_cookie_value_with_embedded_equals_survives_whole`,
`a_cookie_header_padded_with_whitespace_still_parses`,
`hostile_cookie_shapes_do_not_panic_and_do_not_invent_pairs`,
`duplicate_cookie_names_are_all_returned_in_order_and_never_merged`).

---

## What is NOT run and NOT claimed

Stated plainly, because a hardening document that only lists successes is a sales page.

* **`scripts/mutation.sh` was NOT run.** It runs the suite 23 times to check the tests actually
  fail when the behaviour is removed. It is the coordinator's to run. Everything below "verified"
  means "the test passes and, where stated, fails against the pre-fix code" — not "mutation
  tested".
* **No fuzzing, no property testing, no load or soak testing.** Every test here is a hand-written
  example of a shape someone thought of.
* **The two ceilings that were reviewed but are not socket-tested here** are the TLS
  configuration (`crates/servelet-tls`) and the client pool; their coverage is the moved socket
  tests, unchanged by this unit.
* **`servelet-client` (14 tests), `servelet-core` (8), `servelet-router` (13)** carry no hardening
  tests: this unit found no attacker-controlled unbounded allocation or framing decision in them.
  That is a statement about what was read, not a proof.
* The other packages carry no hardening tests either: `servelet-tls` (4), `servelet-cookie` (19,
  §5), and the moved-behaviour suites everywhere else. The workspace totals are 14 / 19 / 8 /
  31 / 13 / 24 / 4 / 14 / 45 for client / cookie / core / h1 / router / sse / tls / uri / ws.
* **The 10 s `read_timeout` is a default, not a recommendation.** A deployment with legitimately
  slow uploads raises it with `serve_connection_with_limits`; the point of the default is that it
  is finite rather than whatever the peer chose.
* **`a_large_frame_trickled_out_is_neither_pinged_nor_corrupted` was verified against both
  versions of `frame.rs`** (fails on the old cancelled-read, passes on `fill_pending`). Every
  other regression test in this document was verified to fail before its fix and pass after, but
  was not re-checked against a mutation.