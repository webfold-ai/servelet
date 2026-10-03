# SPINE — the four core crates of servelet

Extraction of the Ptyktos HTTP server out of `biota/http-server` into four crates that each do one
thing and compose. Source read at **biota rev `4ce2dcd`** (pushed `origin/main`) with
`git -C ~/projects/biota show 4ce2dcd:<path>` only — that checkout is shared and dirty and was
never read from the working tree and never written to. `bedrock`'s `native_lib.rs` was **not**
copied from (deprecated, FSL-1.1).

Everything in `crates/` was moved, not refactored (README rule 9). `scripts/verify_move.py` proves
it line-for-line; the deviations are the short list below, each with a reason.

---

## 1. Provenance: exact source line ranges moved

The same table is committed as `budget/ranges.tsv` and is the input `scripts/verify_move.py`
reads. Line numbers are 1-indexed and inclusive, measured against `4ce2dcd`.

| crate | file | biota source | lines | what |
|---|---|---|---|---|
| `servelet-core` | `src/error.rs` | `kernel.rs` | 60–84 | `Error`, `Result` |
| `servelet-core` | `src/types.rs` | `kernel.rs` | 86–731 | "Native http-crate surface": `Method`, `Version`, `StatusCode`, `HeaderName`, `HeaderValue`, `header`, `HeaderMap`, `Uri` |
| `servelet-core` | `src/extensions.rs` | `kernel.rs` | 732–830 | `Extensions`, the `TypeId`-keyed type-map |
| `servelet-core` | `src/message.rs` | `kernel.rs` | 831–1064 | "Request / Response": `Request`, `Response`, `ConnectionInfo` |
| `servelet-core` | `src/service.rs` | `kernel/platform.rs` | 353–440, 484–573 | `Service`, `Layer`, `oneshot`, `Stack`, `RateLimitLayer`/`RateLimitService` — **brought**, see §3 |
| `servelet-router` | `src/router.rs` | `kernel.rs` | 2446–2815 | "Axum face": `BoxHandler`, `PathParams`, `Router`, pattern parse + match, `handle`, `contains_route` |
| `servelet-router` | `src/lib.rs` | `kernel/platform.rs` | 1126–1138 | `impl Service<Request> for Router` — **brought**, see §3 |
| `servelet-h1` | `src/wire.rs` | `kernel.rs` | 2816–3065, 3132–3197 | "Wire": `serve`, `serve_connection`, `connection_close`, `read_request`, `write_response`, `write_chunk`, `write_streaming_response` |
| `servelet-h1` | `src/streaming.rs` | `lib.rs` | 200–203, 229–238 | `Response::streaming`, `StreamingBody` |
| `servelet-h1` | `src/graceful.rs` | `kernel/runtime.rs` | 2073–2320 | `serve_gracefully` + `ConnectionCounter`/`ConnectionGuard` + `bind_reuseport` |
| `servelet-tls` | `src/tls.rs` | `kernel.rs` | 1854–1968 | "Server-side TLS termination": `base64_decode`, `pem_blocks`, `tls_server_config`, `serve_tls` |

`kernel/runtime.rs` 2073–2320 **is** the HTTP `serve_gracefully` (it sits among the runtime's
`mod tests` boundaries; verified by reading the range — it is the HTTP drain loop, not the
actor/relay runtime's). The 3 `#[tokio::test]`s inside it moved with it.

**Evidence — the byte-for-byte check** (`python3 scripts/verify_move.py`, reads biota through
`git show` at `4ce2dcd`):

```
OK   servelet-core/src/error.rs         code-lines=  18 verbatim=  18 deviations= 0 unaccounted=0 (100.0%)
OK   servelet-core/src/types.rs         code-lines= 532 verbatim= 531 deviations= 1 unaccounted=0 (100.0%)
OK   servelet-core/src/extensions.rs    code-lines=  55 verbatim=  55 deviations= 0 unaccounted=0 (100.0%)
OK   servelet-core/src/message.rs       code-lines= 165 verbatim= 156 deviations= 9 unaccounted=0 (100.0%)
OK   servelet-core/src/service.rs       code-lines= 104 verbatim=  98 deviations= 6 unaccounted=0 (100.0%)
OK   servelet-router/src/router.rs      code-lines= 267 verbatim= 263 deviations= 4 unaccounted=0 (100.0%)
OK   servelet-router/src/lib.rs         code-lines=  11 verbatim=   6 deviations= 5 unaccounted=0 (100.0%)
OK   servelet-h1/src/wire.rs            code-lines= 232 verbatim= 229 deviations= 3 unaccounted=0 (100.0%)
OK   servelet-h1/src/streaming.rs       code-lines=  19 verbatim=   9 deviations=10 unaccounted=0 (100.0%)
OK   servelet-h1/src/graceful.rs        code-lines=  67 verbatim=  67 deviations= 0 unaccounted=0 (100.0%)
OK   servelet-tls/src/tls.rs            code-lines=  81 verbatim=  81 deviations= 0 unaccounted=0 (100.0%)
TOTAL 1551/1551 code lines verbatim in biota at 4ce2dcd
```

`unaccounted=0` on every file: no line exists in a crate that is not either verbatim from the
recorded range or on the documented-deviation list below. It is a **line-level** check — it proves
"this line is the line biota has at that range"; it does not prove the ranges are used exactly
once. What it cannot prove is covered by the mutation checks (`scripts/mutation.sh`) and §5.

---

## 2. Deviations from byte-for-byte, each with its reason

Every one of these is a path or visibility change forced by living in a different crate. **None
changes behaviour.** The list is machine-readable in `scripts/verify_move.py` (`KNOWN_DEVIATIONS`)
and a stale entry there is reported, so it cannot rot.

| crate | deviation | why |
|---|---|---|
| all | `crate::` → `servelet_core::` / `crate::streaming::` etc. | `crate::` means different things in different crates; the path has to be written out at the seam |
| `servelet-core` | `fn status_reason` → `pub fn` | `servelet-h1`'s `write_response` is in another crate and calls it |
| `servelet-core` | `Request`/`Response` fields private → `pub` (9 fields) | they were read only by crate-internal accessors; cross-crate readers need them visible. Visibility only |
| `servelet-core` | `Service`/`Layer` trait bodies: `crate::Result` → `std::result::Result`, and `+ Send` on the two RPITIT returns | the trait's `Error` is its own associated type, so the crate-local alias was never right in those two signatures; the `+ Send` is what makes a `Service` drivable from `Router::layered`'s `Arc<Mutex<_>>` inside a `Send` future |
| `servelet-router` | `Router::layered`'s bounds name `servelet_core::Layer<Router>` / `Service::ready` / `Service::serve` | same `crate::` rewrite, on the moved `layered` and the moved `impl Service<Request> for Router` |
| `servelet-h1` | `HttpResponseBuilder::streaming(..)` → free `streaming(..)` | the builder type stays in `servelet-core`; a free function can live in `servelet-h1` next to the writer that consumes it without the core depending on the wire crate |
| `servelet-h1` | `streaming_body()` and `take_receiver()` are **new** | `write_streaming_response` (kernel.rs 3177–3183) had the lock/take/`expect` inline. Streaming responses are the one place `Response` is read as data rather than by accessors, so it was lifted into two crate-private helpers that `streaming.rs` and `wire.rs` share — one copy, not two. `expect` message preserved verbatim |

### Cut, with reasons

| cut from | lines | why |
|---|---|---|
| `write_sse_response` / `write_sse_chunk` | `kernel.rs` 3066–3130 | SSE framing. `servelet-sse` is a later unit and README rule 1 gives framing one home. Leaving it in `servelet-h1` would make the crate route-and-framing. |
| the h2c-preface sniff at the top of `serve_connection` | within 2816–3007 | the HTTP/2 connection preface belongs to `servelet-h2`. Keeping the sniff in the h1 loop would make h1 know h2 exists. |
| `Reqwest face` (client), `Client`, `ClientBuilder`, `RetryPolicy`, cookie jar, multipart, pool | `kernel.rs` 1065–1673, 1676–2282, 3199–3574; `lib.rs` sse/ws/h2/openapi blocks | **not this unit.** `servelet-client`, `servelet-sse`, `servelet-ws`, `servelet-h2`, `servelet-cookie`, `servelet-multipart`, `servelet-openapi` are named "NOT YOURS" in the dispatch, and rule 4's census (`docs/EXTRACTION.md`, the `evidence` unit) decides what survives. Nothing was thrown away — it is untouched in biota at `4ce2dcd`. |

**What the originals reached for that had to be brought or cut** — `crate::platform::service::{Layer, Service}`:
`Router::layered` is moved and needs those two traits. Cutting `layered` would have silently changed
the crate's public API, so the traits were **brought**, not cut: `kernel/platform.rs` 353–440 and
484–573 moved verbatim into `servelet-core/src/service.rs`, because rule 2 says pieces meet at
`Request`/`Response`/`Handler`/`Layer` — and `Layer` is where they meet. The compiler then paid for
the choice: `service.rs` uses `CoordMap`/`PHI`/`Table`, so **`servelet-core` needs hashtrinity**,
which it would not otherwise have needed for a pure data model. That is the honest cost of bringing
it, recorded here rather than hidden. `impl Service<Request> for Router` came with it
(`platform.rs` 1126–1138) because without it `layered` has nothing to wrap.

---

## 3. Public API per crate

**`servelet-core`** — `Error`, `Result`, `Method`, `Version`, `StatusCode` (+ `status_reason`),
`HeaderName`, `HeaderValue`, `HeaderMap`, `header`, `Uri`, `Extensions`, `Request`, `Response`,
`ConnectionInfo`, `Service`, `Layer`, `oneshot`, `Stack`, `RateLimitLayer`, `RateLimitService`.

**`servelet-router`** — `Router::{new, route, route_sync, get, post, nest, merge, fallback,
with_state, layer, layered, handle, contains_route}`, `PathParams::{get, ordered_values, iter}`,
`BoxHandler`, `Default for Router`, `Debug for Router`, `Service<Request> for Router`.

**`servelet-h1`** — `serve`, `serve_connection`, `read_request`, `write_response`,
`streaming`, `streaming_body`, `StreamingBody`, `serve_gracefully`.

**`servelet-tls`** — `tls_server_config`, `serve_tls`.

### `servelet-core` dependencies, justified

`servelet-core` has **no tokio at all** — no runtime, no reactor, no `async fn` anywhere in the
crate. It builds and runs inside a plain `fn main` or a `#[test]`. Its only dependency is
**hashtrinity**, for exactly three uses the moved code already had:
`CoordMap` + `PHI` for `HeaderMap`'s store and coordinate hash (`types.rs`), `Table` for
`Extensions`' exact-key type-map (`extensions.rs`), and `#[derive(hashtrinity::Error)]` for the
`Error` enum's `Display`/`source` (`error.rs`). Replacing any of those with a hand-rolled map
would be a rewrite, which rule 9 forbids in the same commit as the move.

The other three crates take the **minimum** they need — `servelet-h1` does not pull
`hashtrinity`, and neither `servelet-h1` nor `servelet-tls` pulls `serde`/`serde_json`/`bytes`/
`base64`. `hashtrinity` is the GitLab mirror exactly as `nexus/Cargo.toml` has it
(`https://gitlab.tas.twn.network/twn/ptyktos/hashtrinity.git`, branch `main`) — the GitHub copy
does not unify with sangdb, which nexus proved.

---

## 4. The gates

`scripts/gates.sh` runs, in order: `cargo test --workspace -j3`; `scripts/budget.sh` (rule 5
ratchet); the dependency-weight check (rule 6).

**`scripts/budget.sh` is a RATCHET, not a limit.** It reads the committed `budget/baseline.tsv`
and fails when any number *rises* — a file may only get shorter, never longer. A crate over 3,000
lines or a file over 1,200 that got there by a byte-for-byte move is recorded in the baseline's
note column as a known exception and tolerated at **exactly** its recorded size (the "rose" check
still fires above it). Splitting such a file is a separate, later change.

**The dependency-weight check** runs `cargo tree -p <crate> --prefix none | sort -u | wc -l` per
crate against `budget/deps.tsv` and fails when a crate gets heavier. Numbers measured, this run:

| crate | deps | baseline |
|---|---|---|
| `servelet-core` | 25 | 25 |
| `servelet-router` | 42 | 42 |
| `servelet-h1` | 45 | 45 |
| `servelet-tls` | 56 | 56 |

`biota-http-server` itself, same command on its own package, is **56** — the same as
`servelet-tls`, the crate that ends up holding the same rustls/tokio set. The four crates together
cover the spine and none is heavier than the one crate they came out of; that is the rule-6
baseline. Counts include the workspace crates themselves.

---

## 5. Tests: what moved, and what could not

`servelet-core` 8 · `servelet-router` 13 · `servelet-h1` 6 · `servelet-tls` 4 = **31 tests**, all
green. Counts measured by `grep -c '#\[test\]\|#\[tokio::test'` on each `crates/*/tests/*.rs`.

Baseline in biota at `4ce2dcd`: `kernel.rs` has **56** tests, all in one `mod tests` at line 3575
(to 5059) — none of them inside the moved ranges themselves (`kernel.rs` 60–1064, 2446–2815,
2816–3065, 3132–3197 and `kernel.rs` 1854–1968 each contain **0** `#[test]`/`#[tokio::test`).
The moved tests therefore come from two places: that `mod tests` block, and `kernel/runtime.rs`
2073–2320, which **does** contain 3 (they are inside the moved range and moved with it).

Tests in `kernel.rs`'s test module that test **spine** code and moved, with their biota names:
`method_reference_compares_equal_to_owned_method`, `connection_info_*` (3),
`derived_error_matches_prior_hand_written_behavior`, `native_http_types_replace_http_crate`,
`extensions_insert_get_remove_by_type` → core; `router_handle_emits_a_real_tracing_span_*`,
`router_handles_exact_method_path`, `extensions_survive_a_real_request_through_the_router`,
`router_matches_dynamic_path_params`, `router_matches_multi_segment_dynamic_path`,
`router_matches_wildcard_catch_all_route`, `router_nest_*`, `router_merge_*`,
`router_fallback_*`, `router_with_state_*`, `router_layer_wraps_every_handler`,
`router_layered_composes_an_arbitrary_layer` → router; `tls_server_config_*` (2),
`serve_tls_terminates_a_real_tls_connection` → tls; the 3 in `runtime.rs` 2073–2320 → h1.

**Tests that could not move, and why:**

| biota test | why not |
|---|---|
| `send_streaming_receives_a_body_written_incrementally`, `send_streaming_decodes_chunked_encoding` | these drive `Client::send_streaming` — the **outbound client**, which is `servelet-client`, not this unit. The h1 equivalent is covered instead by `a_streaming_body_goes_out_as_real_chunked_transfer_encoding` over a real socket. |
| `actix_path_extractor_reads_router_extracted_params` | depends on the `actix` compatibility masquerade (`kernel.rs` `pub mod actix`), which the README's "leave out entirely" list names for removal. Its subject, `PathParams` extraction, is covered by the router's dynamic/multi-segment/wildcard tests. |
| `masquerade_axum_router_surface`, `masquerade_http_crate_full_surface` | same — masquerade shims, named for removal under rule 4. |
| the 8 `client_*`, 5 `proxy_*`, 5 `load_balance_*`, `public_surface_covers_client_router_proxy_and_relationships`, `https_reaches_a_real_endpoint`, `cookie_*`, `multipart_*`, `http_date_*`, `rfc3339_*` | they test the client, proxy/pool, load-balancing, cookie and multipart code that stayed in biota. 45 of `kernel.rs`'s 56 tests are outside this unit. |

**Tests added by this extraction** (not moved; the moved code had no socket-level proof of the
split): `core_is_pure_data_and_names_no_async_runtime`, `router_public_surface_dispatches_and_reports_contains_route`
(added after `bf34eca`: the fallback test asserted nothing about its own route, so a mutation of the
fallback registration went unnoticed), and the five socket tests in
`crates/servelet-h1/tests/socket.rs` and `crates/servelet-tls/tests/socket.rs`.

### Real-socket proof

`crates/servelet-h1/tests/socket.rs` binds a real `TcpListener` on `127.0.0.1:0`, serves a real
`Router` through the moved `serve`, and drives it with a **raw `TcpStream`** — no client crate, no
`reqwest`. It proves: a route is served; a dynamic path segment routes; an unmounted path gets the
fallback 404; keep-alive serves two requests on one connection; **a streaming body goes out as real
chunked `Transfer-Encoding`**; `read_request` parses the three parts of the request line.

`crates/servelet-tls/tests/socket.rs` completes a **real rustls TLS 1.3 handshake** against the
moved `tls_server_config` and then reads the moved `write_response` bytes off the socket — which is
what proves that `serve_tls` runs the *same* h1 loop plain HTTP runs. It also pins TLS-1.3-only,
PEM rejection, and that a client not trusting the fixture cannot connect. The certificate is a
committed fixture, `tests/fixtures/server.cert.pem` + `server.key.pem`: an **ED25519 `CA:FALSE`
end-entity cert for `localhost` with a publicly known private key**, generated once by the exact
`openssl` command recorded at the top of the test file. ED25519 because the moved PEM parser
accepts only ed25519 and ECDSA-P256 PKCS#8 — the first fixture was RSA and all three handshake
tests failed on exactly that; the fixture was wrong, not the moved code. The client trusts it
explicitly rather than through the system store, so it cannot be mistaken for a server identity.

### Mutation checks — `scripts/mutation.sh`

A green suite means nothing unless a wrong implementation makes it red. Two mutations, each shown
failing then restored:

* **A.** `servelet-router`: a route registration is renamed (`"/known"` → `"/known-MUTATED"`) in
  `tests/moved.rs`. Caught.
* **B.** `servelet-h1`: the auto-written `Connection: keep-alive` header in `src/wire.rs` is
  flipped to `close`. Caught.

The script exits non-zero unless **both** were caught *and* the restored suite is green again.

### The budget gate actually fails

Adding a 1,300-line dummy `.rs` file under `crates/servelet-core/src/` makes `scripts/budget.sh`
report `FILE-OVER-1200` and exit 1; removing it returns the gate to green. NOT a claim:
`scripts/budget.sh` output is pasted in the worker report.

---

## 6. Line counts and rule 5

`budget/baseline.tsv` is the committed ratchet baseline. Measured:

| crate | lines | max file | budget |
|---|---|---|---|
| `servelet-core` | 1,218 | 648 | 3,000 / 1,200 |
| `servelet-router` | 414 | 372 | 3,000 / 1,200 |
| `servelet-h1` | 497 | 302 | 3,000 / 1,200 |
| `servelet-tls` | 133 | 116 | 3,000 / 1,200 |

No crate is over 3,000 and **no file is over 1,200**, so `budget/baseline.tsv` currently records no
known exceptions (every note is `-`). The spine split cleanly; no file needed an exception entry.

---

## 7. Not this unit

`servelet-sse`, `-ws`, `-cookie`, `-multipart`, `-static`, `-cors`, `-limits`, `-acme`,
`-authed`, `-openapi`, and `-h2`/`-client`. They are untouched in biota at `4ce2dcd`; what to keep
among them is the `evidence` unit's `docs/EXTRACTION.md` census, and this work does not wait for it.
No change was made to nexus.