# servelet-sse

Server-Sent Events: the framing, and the streaming response body that carries it.

One job: turn `Event`s into `text/event-stream` bytes and write them to a live connection as they
arrive. It does not route, does not parse a request, and does not open a socket.

`HttpResponseBuilder` lives here, not in `servelet-core`. `docs/EXTRACTION.md` §7 puts it here and
`docs/EXTENSIONS.md` §3 gives the reason: its two jobs are `streaming(..)` and carrying
`Set-Cookie` values, and the census measured its dependencies as exactly this crate's. A
`tokio`-using builder in `servelet-core` would have forced a runtime into the one crate that must
work without one.

**Dependencies.** `servelet-core`, `servelet-cookie`, `servelet-h1` (the chunk writer and the
streaming body), `tokio` (`sync`, and `time` for the keep-alive timer), `hashtrinity` (the
`json`/`json_ref` render). The census (§7) measured `tokio` (6 hits) and `hashtrinity` (4) over the
moved span; every one of them is named in `Cargo.toml`.

`cargo tree -p servelet-sse --prefix none | sort -u | wc -l` → **48**. The number is committed in
`budget/deps.tsv` and `scripts/gates.sh` fails if it grows.

## How it reaches the wire

`Sse` is turned into a response by `sse_response`, which is `Sse::respond_to` plus this crate's
writer stashed on the response. `servelet-h1`'s `serve_connection` picks the writer up and calls
it. Neither crate knows the other's SSE types; the writer travels on the response, next to the
body it writes — see `docs/EXTENSIONS.md` §5.

## What was moved

Byte-for-byte from `biota/http-server` at rev `4ce2dcd`:

| to | from |
|---|---|
| `src/sse.rs` | `lib.rs` 2138-2285 (streaming half) + 2286-2418 (parse/emit half) |
| `tests/moved.rs` | `lib.rs` 2419-2469 (`wire_tests`) |
| `src/builder.rs` | `lib.rs` 92-94 + 128-222 (`builder`, `HttpResponseBuilder`) |
| `src/wire.rs` | `kernel.rs` 3059-3130 (`write_sse_response`, `write_sse_chunk`) |

Tests moved: 9 of 9 — three in `src/sse.rs`'s own `mod tests` (they call the deliberately private
`Data::render`, so they stay inside the module), six in `tests/moved.rs`. Four more are new and
drive a real socket; see the header of `tests/socket.rs`.
