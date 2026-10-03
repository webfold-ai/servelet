# servelet

The Ptyktos HTTP server, as small crates that each do one thing and compose.

It replaces two copies of the same code: `bedrock`'s `native_lib.rs`/`httpsrv.rs` and `biota/http-server`
(`lib.rs` 7,380 lines + `kernel.rs` 5,059 + `kernel/runtime.rs` 4,822 + `kernel/platform.rs` 2,322, measured
2026-10-03). A consumer takes the pieces it uses and nothing else. When a consumer runs on servelet, the
old copy is deleted in the same change: one home per capability, never a wrapper.

## The rules (the Unix ethos, made checkable)

1. **One crate, one job.** A crate's purpose fits in one sentence with no "and". `servelet-sse` frames
   server-sent events. It does not route.
2. **Compose through plain types.** Pieces meet at `Request`, `Response`, a `Handler` function and a
   `Layer` function (`Fn(Handler) -> Handler`). No crate needs to know another exists unless it is named in
   its `Cargo.toml`. Anything that can be a layer is a layer, not a field on the router.
3. **Text and bytes at the seams.** Wire formats are documented byte-for-byte and tested with fixtures. No
   hidden global state, no process-wide singletons, no "installed once" registries.
4. **Do not build what you can pipe.** No inference, no billing, no GraphQL, no x402, no S3 gateway, no
   compatibility "masquerade" for other frameworks inside the server. Those are other programs that talk to it.
5. **Small enough to read.** A crate is at most 3,000 lines and no file exceeds 1,200. A ratchet gate
   (`scripts/budget.sh`) fails a change that raises either number; it may only fall.
6. **Weight is a feature.** Default features pull nothing heavy. A crate with an optional heavy dependency
   puts it behind a feature that is off by default. `cargo tree -p <crate> --prefix none | wc -l` is recorded
   in the crate's README and a gate fails it if it grows.
7. **Auth is not optional.** The router has no way to register a handler without an authenticated context
   (see `servelet-authed`). The only escape is a registered, reasoned, counted public route.
8. **No third-party HTTP stack.** hashtrinity does JSON and codecs, transport does TLS/ACME/network. This
   repo adds no new third-party crates without a written reason in the crate's README.
9. **Extraction is byte-for-byte.** Moved code is moved, not refactored in the same commit. Behaviour
   changes are separate commits with their own tests.

## Crate map (target; each is extracted from biota/http-server unless noted)

| crate | does exactly one thing | from |
|---|---|---|
| `servelet-core` | `Request`, `Response`, `Method`, `StatusCode`, headers, `Extensions`, `Uri` | `kernel.rs` "native http-crate surface" + "Request / Response" |
| `servelet-router` | path routing with params and wildcards, `nest`, `merge`, `layer` | `kernel.rs` "Axum face" |
| `servelet-h1` | HTTP/1.1 wire: parse requests, write responses, chunked, keep-alive, `serve` | `kernel.rs` "Wire" + `serve*` |
| `servelet-tls` | server-side TLS termination over rustls | `kernel.rs` "Server-side TLS" |
| `servelet-h2` | HTTP/2 (h2c) framing and HPACK | `lib.rs` `h2`, `h2_huffman_table` |
| `servelet-client` | outbound HTTP client with pool and retry | `kernel.rs` "Reqwest face" + "Connection pool" |
| `servelet-sse` | server-sent events encoder and stream body | `lib.rs` `sse` (+ nexus `http::sse`) |
| `servelet-ws` | WebSocket frame codec and upgrade | `lib.rs` `websocket` |
| `servelet-cookie` | cookie parse and `Set-Cookie` build (`Domain`, `Partitioned`) | `lib.rs` `cookie` (+ nexus `cookie.rs`) |
| `servelet-multipart` | multipart/form-data parse | `lib.rs` `multipart` |
| `servelet-static` | static files with SPA fallback, ETag, traversal guard | nexus `http::static_files` |
| `servelet-cors` | origin-checking CORS layer | nexus `http::cors` |
| `servelet-limits` | body-size limit layer | nexus `http::limits` |
| `servelet-acme` | ACME certificate issuing wired to the server | `kernel/acme.rs` |
| `servelet-authed` | router wrapper that cannot register an unauthenticated handler | nexus `authed.rs` |
| `servelet-openapi` | OpenAPI document generation from routes | `lib.rs` `openapi` |

What is extracted and what is left out is decided per module in `docs/EXTRACTION.md`, from a census of
BOTH copies (biota's `http-server` and bedrock's `native_lib.rs`), with file:line callers. Correction
2026-10-04: this README first said `x402`, `webhook`, `s3_gateway`, `h2`, `websocket` and `openapi` had no
callers. That was wrong: it had searched only `biota_http_server::`. The bedrock copy's consumers call them
(webhook 135 sites, websocket 93, x402 72, h2 29, openapi 22, s3_gateway 16), mostly from repos being retired
(opsfold, syndesi). Whether those callers are live, and so whether each module is extracted or dropped, is a
per-row decision in EXTRACTION.md, not an assumption.

The first consumer is nexus, which uses exactly 12 public names: servelet-core, -router, -h1, -sse and -cookie
cover all of it. The outbound `Client` (34 call sites across ptyktos-api, relayfold, ptyktos-webgui,
webfold-fleet) and a replacement for the actix-style boot path (`App`, `HttpServer`, `to_handler*_async`) are
what blocks the other consumers.

## Status

Nine crates extracted from `biota/http-server` rev `4ce2dcd`, all byte-for-byte, all gated:

| crate | lines | `cargo tree` | tests |
|---|---|---|---|
| `servelet-core` | 1218 | 25 | 8 moved |
| `servelet-router` | 414 | 42 | 13 moved |
| `servelet-h1` | 556 | 45 | 6 moved + 2 socket |
| `servelet-tls` | 133 | 56 | 4 socket |
| `servelet-cookie` | 298 | **1** | 6 moved + 7 attributes |
| `servelet-sse` | 538 | 48 | 9 moved + 4 socket |
| `servelet-uri` | 76 | **1** | 2 moved |
| `servelet-client` | 1385 | **36** (47 with `tls`) | 12 moved + 2 TLS-feature |
| `servelet-ws` | 386 | **38** | 5 moved |

`scripts/gates.sh` runs the suite, the rule-5 line ratchet and the rule-6 dependency weight;
`scripts/mutation.sh` flips seven behaviours and requires each to turn the suite red (7/7);
`scripts/verify_move.py` reports 3414/3414 code lines verbatim in biota. Behaviour added after a
move, and what a consumer does instead of the actix surface, are in `docs/EXTENSIONS.md`.

Next, per `docs/EXTRACTION.md` §9.1: `servelet-h2`, `-openapi`, `-acme`, and the four
nexus-resident layers (`-limits`, `-cors`, `-static`, `-authed`). Then nexus switches over.
