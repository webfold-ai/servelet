# servelet-uri

Percent-encoding and percent-decoding of a URL component.

One job: the `%XX` transformation, both directions. It knows nothing about `Request`, `Response`,
a route, or a socket.

**Dependencies: none.** Measured over the moved span (`biota/http-server` `helpers.rs` 77-131 at
rev `4ce2dcd`): `format!` and `String` only.

`cargo tree -p servelet-uri --prefix none | sort -u | wc -l` → **1** (the crate itself).
Committed in `budget/deps.tsv`; `scripts/gates.sh` fails if it grows.

## What was moved, and what did not

Moved byte-for-byte from `helpers.rs` at rev `4ce2dcd`: `percent_decode` (77-111) and
`percent_encode` (113-131), and their two tests (`tests/moved.rs`, from lines 465-482). Tests
moved: 2 of 2.

**Not** moved: the other 24 public functions in that file. `docs/EXTRACTION.md` §1 measured the
whole set and found exactly one live name — `percent_encode`, at 58 call sites in
`ptyktos-api-wallet-wiring` / `caretaker-release`. Everything else there is JSON escaping,
`bind!`, and query-string plumbing that a consumer either does not use or has its own copy of
(census §6: opsfold re-implemented the same preamble in `platform::http`, 161 references).

## Why `percent_decode` came along

It has 0 external callers of its own. It came for two stated reasons: the moved test round-trips
through it, and an encoder with no decoder beside it is how "encoded here, never decoded"
mistakes get written. It is 35 lines and pulls in nothing. If the coordinator wants the crate to
be encode-only, deleting it is a separate commit and the round-trip test goes with it.
