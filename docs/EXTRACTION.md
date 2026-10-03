# docs/EXTRACTION.md — who actually uses the Ptyktos HTTP server

Evidence census for the servelet crate map. Every row cites a command or a `file:line`.
Anything not run is marked NOT RUN. Baseline: biota `4ce2dcd`, measured 2026-10-03.

## 0. Method, rev, and exclusions

Source read **only** at a rev (never the dirty working tree):

```
git -C ~/projects/biota show 4ce2dcd:http-server/src/lib.rs          # 7380 lines  (md5 644e812c9649b73c31d4f8e62e7593f3)
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel.rs       # 5059
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/runtime.rs   # 4822
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/platform.rs  # 2322
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/acme.rs      #  277
git -C ~/projects/biota show 4ce2dcd:http-server/src/helpers.rs      #  518
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/sangdb.rs   #   89 (not in the brief's list; it exists)
```

All six line counts match the brief exactly.

Caller grep (run from `~`, the "live" form used for every count below):

```
rg -c --no-messages -g '!**/target/**' -g '!**/node_modules/**' -g '!**/.git/**' \
  -g '!projects/fold-worktrees/**' -g '!projects/attic/**' -g '!projects/fold-memory/**' \
  -g '!projects/_archive/**' -g '!projects/_subsume/**' -g '!orca/workspaces/fold/**' \
  -g '!projects/biota/http-server/**' -g '!orca/workspaces/biota/**' -g '*.rs' \
  <pattern> projects orca/workspaces
```

Exclusions and why: `target/` `node_modules/` `.git/` are build/VCS noise; `attic/`,
`fold-worktrees/`, `fold-memory/`, `_archive/`, `_subsume/`, `orca/workspaces/fold/` are
dead worktrees. **Measured contribution of the dead set: 0** lines mentioning
`biota_http_server` (`rg -c 'biota_http_server' projects/fold-worktrees projects/attic
projects/fold-memory projects/_archive projects/_subsume orca/workspaces/fold` → empty).
Self-hits (the crate's own source + biota worktrees) = 6, all doc comments. Totals:
722 raw lines → **716 live external**.

Dependency declarations (`rg '^\s*biota-http-server\b' -g '**/Cargo.toml'`): **26**, of which
10 are nexus worktrees pinning the *same* rev `4ce2dcd`.

> **Path trap, load-bearing.** In this crate `multipart`, `cookie`, `sse`, `websocket`, `h2`,
> `h2_huffman_table`, `openapi`, `nel`, `x402` are nested inside `httpx`
> (`lib.rs:1609-1615` is the namespace; `lib.rs:1616` opens `multipart`). The import path is
> `biota_http_server::httpx::<name>`, never `biota_http_server::<name>`. Grepping the bare
> name reports a false 0. Counts below use the real path.

## 1. `lib.rs` public modules

| area (`lib.rs` span) | lines | who calls it (file:line, example) | calls | verdict |
|---|---|---|---|---|
| `actix` (7-863) | 857 | `nexus-foundation/nexus/src/http/sse.rs:22` (`HttpResponseBuilder`); `relayfold-control/src/app.rs:12` (`Json`,`Responder`); `ptyktos-api/src/agent.rs:527` (`to_handler1_async`) | 11 | **KEEP** — but only 4 of its items are live (see §6) |
| `web` (864-871) | 8 | — pure `pub use` re-export of `actix` items | 0 | **CANDIDATE-CUT** |
| `test` (872-899) | 28 | — `TestRequest` builder for the crate's own tests | 0 | **CANDIDATE-CUT** |
| `httpx` (1609-1615) | 7 | namespace only, no items | 0 (2 uses of the path) | keep as namespace |
| `httpx::multipart` (1616-1909) | 294 | — | 0 | **CANDIDATE-CUT** |
| `httpx::cookie` (1910-2136) | 227 | — externally 0; required internally by `HttpResponseBuilder.cookies: Vec<Cookie<'static>>` (`lib.rs:133`) | 0 | **KEEP** (internal edge → `servelet-cookie`) |
| `httpx::sse` (2137-2471) | 335 | `ptyktos-api/src/catalog.rs:382` `SseParser::new()`; `syndesi/src/web_router.rs:35,339,354` `Sse`/`Event`/`Data` (via bedrock copy) | 8 | **KEEP** |
| `httpx::websocket` (2472-2930) | 459 | `syndesi/src/infra.rs:132,140,177` `WebSocket::connect`/`Message` (via bedrock copy) | 3 | **KEEP** (not in §4 nexus set; syndesi is the only caller) |
| `httpx::h2` (2931-3823) | 893 | `syndesi/src/authzed.rs:2426` `use bedrock::httpsrv::httpx::h2::{…}` (via bedrock copy) | 1 | **KEEP**, deferred (see §7) |
| `httpx::h2_huffman_table` (3824-3881) | 58 | — reached only via `httpx::h2` | 0 direct | **KEEP** (private to `h2`) |
| `httpx::openapi` (3882-4153) | 272 | — | 0 | **CANDIDATE-CUT** |
| `httpx::nel` (4154-4715) | 562 | — | 0 | **CANDIDATE-CUT** |
| `httpx::x402` (4716-5310) | 595 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `graphql` (5311-5613) | 303 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `webhook` (5691-5970) | 280 | — | 0 | **CANDIDATE-CUT** |
| `s3_gateway` (6174-6291) | 118 | only self-referential doc comments (`http-server/src/lib.rs:6196`) | 0 | **CANDIDATE-CUT** |
| `masquerade` (6292-6453) | 162 | — | 0 | **CANDIDATE-CUT** (§5) |
| `http_masq` (6454-6493) | 40 | — | 0 | **CANDIDATE-CUT** (§5) |
| `reqwest_masq` (6494-6525) | 32 | — | 0 | **CANDIDATE-CUT** (§5) |
| `axum_masq` (6526-6551) | 26 | — | 0 | **CANDIDATE-CUT** (§5) |
| `pingora_masq` (6552-6571) | 20 | — | 0 | **CANDIDATE-CUT** (§5) |
| `authzed_masq` (6572-6590) | 19 | — | 0 | **CANDIDATE-CUT** (§5) |
| `filter` (6591-7204) | 614 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `kernel` (7373) | 1 | `caretaker-release/src/engines/searxng.rs:8` `kernel::Client` (same items as root) | 189 | see §2 |
| `helpers` (7374-7381) | 8 | `caretaker-release/src/engines/bing.rs:11` | 45 | **KEEP** — but see §6: 1 of 25 fns live |

Cross-checked against the **other copy**: `rg -c '(httpsrv|native|native_lib)::<mod>'` in
`~/projects/bedrock/src` over the same 18 areas → **0 for every one of them**. So none of the
19 zero-caller areas above is secretly alive in the deprecated copy.

## 2. `kernel.rs` areas

| area (`kernel.rs` span) | lines | who calls it (file:line, example) | calls | verdict |
|---|---|---|---|---|
| `Error` (60-85) | 26 | `nexus-foundation/nexus/src/http/cors.rs:25` `Error` | 7 | **KEEP** → `servelet-core` |
| Native http surface (86-731): `Method`,`Version`,`StatusCode`,`HeaderName`,`HeaderValue`,`header` | 646 | `Method` 114 brace-imports + 38 direct; `StatusCode` 119+52; `header` 80+6 (`nexus-foundation/nexus/src/app.rs:18`) | ~215 | **KEEP** → `servelet-core` |
| `Extensions` (732-830) | 99 | — `Version`/`HeaderName`/`HeaderValue`/`Extensions`/`Uri` direct-call counts are 0–1; `Request::extensions()`/`extensions_mut()` exist (`kernel.rs:904,908,1004`) but no consumer names them | 0 | **KEEP** (part of `servelet-core` surface; type-map is 99 lines) |
| `Request`/`Response` (831-1064) | 234 | `nexus-foundation/nexus/src/auth/json.rs:9` | 135+125 brace + 33+68 direct | **KEEP** → `servelet-core` |
| Reqwest face: `Client` (1065-1673) | 609 | `relayfold-control/tests/integration.rs:50` `Client::new()`; `caretaker-release/src/engines/bing.rs:8` | 34 | **KEEP** → `servelet-client` |
| Wire (1674-1853) | 180 | — no external name resolves here; `serve`/`serve_connection` are actually defined in the Axum face (`kernel.rs:2926`, `:2945`) | 0 direct | **KEEP** → `servelet-h1` (invoked by `serve`) |
| Server-side TLS (1854-1969) incl. `serve_tls` (1949) | 116 | `relayfold-helm/proxy-runtime/src/main.rs:146` `serve_tls`, `:96` `tls_server_config` | 4 | **KEEP** → `servelet-tls` |
| Connection pool (1970-2445) | 476 | — reached only through `Client` | 0 direct | **KEEP** → `servelet-client` |
| Axum face: `Router` (2446-3198) incl. `serve` (2926), `serve_connection` (2945) | 753 | `nexus-foundation/nexus/src/authed.rs:10` `Router`; `nexus-foundation/nexus/tests/http_cors.rs:121` `serve`; `relayfold-helm/proxy-runtime/tests/edge_guards.rs:61` `serve_connection` | 82+52+1 | **KEEP** → `servelet-router`, `servelet-h1` |
| Sangdb/Authzed face (3199-3260) | 62 | `Upstream` 5, `LoadBalance` 3 brace-imports | 8 | **KEEP-FOR-NEXUS** — thin re-export of `relayfold::{Tuple,Relationships,Upstream,Backends}` + `transport::load_balance` (`kernel.rs:3211,3220`). Do **not** reimplement; depend on relayfold/transport. |
| `httpsrv` alias (37-39) | 3 | — | 0 | **CANDIDATE-CUT** (namespace alias onto `actix`+`httpx`) |
| `lorelake_dataset` (27-28) | 2 | — `#[cfg(feature = "federation")]`; feature is not default and not declared in `http-server/Cargo.toml`'s `[features]` | 0 | **CANDIDATE-CUT** |
| `acme` (54) → `kernel/acme.rs` | 277 | — no consumer names `acme` | 0 | **KEEP** (`servelet-acme`) but **UNKNOWN priority** — see §7 |
| `platform` (16) → `kernel/platform.rs` | 2322 | `nexus-foundation/nexus/src/http/cors.rs:24` `platform::service::{Layer,Service}` | 7 | **KEEP** — 1,161 of 2,322 lines are `service`; rest is not HTTP (§3b) |
| `sangdb` (48) → `kernel/sangdb.rs` | 89 | — two string-escaping helpers only, per its own header | 0 | **CANDIDATE-CUT** (fold into `servelet-core` if wanted) |

## 3. (a) `runtime.rs` and `platform.rs` — HTTP or riding along?

Method: for each top-level item, strip `//` comments, then count references to the HTTP core
symbols (`Request|Response|Router|Method|StatusCode|HeaderMap|HeaderValue|Uri|header::`).

### 3a. `kernel/runtime.rs` — 4,822 lines

| item (span) | lines | http symbols | class | verdict |
|---|---|---|---|---|
| `alloc` (7-185) | 179 | `Request`2 `Response`2 `StatusCode`1 — all in `heap_handler` (`runtime.rs:124-137`), a Router-compatible `/debug/heap` route | **http (8-line adapter only)** | CANDIDATE-CUT (mimalloc/jemalloc is not HTTP) |
| `cache` (186-572) | 387 | `HeaderMap`26 `Method`34 `Response`17 `StatusCode`14 `Uri`14 `header::`15 | **http** (HTTP response cache) | KEEP-optional, but 0 callers → **CANDIDATE-CUT** for now |
| `cluster` (573-1094) | 522 | NONE | not-http (cluster) | **leave behind** |
| `cron` (1095-1849) | 755 | NONE | not-http (calendar) | **leave behind** |
| `daemon` (1850-2053) | 204 | NONE | not-http | **leave behind** |
| `graceful` (2054-2242) | 189 | `Router`3 `Method`2 `Response`2 `StatusCode`2 → `serve_gracefully(listener, router, …)` at `:2133` | **http** | KEEP — put in `servelet-h1` as `serve_gracefully` |
| `fiber` (2243-3138) | 896 | NONE | not-http (scheduler) | **leave behind** |
| `work` (3139-4213) | 1075 | NONE | not-http (opsfold tickets) | **leave behind** — already feature-gated `opsfold-work-items` |
| `task_metrics` (4214-4324) | 111 | NONE | not-http | **leave behind** |
| `metrics` (4325-4699) | 375 | `Router`2 `Method`3 `Response`4 `StatusCode`4 — all in `Registry::handler()` (`runtime.rs:4559-4566`) and its test | **http (8-line adapter only)** | CANDIDATE-CUT |
| `tracecontext` (4700-4821) | 122 | NONE (`parse_traceparent(header: &str)` is a plain string fn) | not-http | **leave behind** |

**Verdict: `runtime.rs` is ~94% not-HTTP.** Of 4,822 lines only `cache` (387) + `graceful`
(189) are HTTP logic, plus three 8-line Router adapters. Everything else is cluster, cron,
daemon, fiber, work items, metrics and trace context that rode along in the merge. servelet
should extract **~590 lines** from this file, not 4,822.

### 3b. `kernel/platform.rs` — 2,322 lines

| item (span) | lines | http symbols | class | verdict |
|---|---|---|---|---|
| `cli` (7-149) | 143 | NONE | not-http (arg parsing) | **leave behind** |
| `settings` (150-281) | 132 | NONE | not-http | **leave behind** |
| `service` (282-1442) | 1161 | `Response`56 `StatusCode`39 `Method`32 `Request`21 `Router`16 | **http** (tower/axum `Service`+`Layer` masquerade) | **KEEP** → fold into `servelet-router`; nexus uses `Layer`+`Service` |
| `service_info` (1443-1496) | 54 | NONE | not-http | **leave behind** |
| `harness_state` (1497-2143) | 647 | NONE | not-http (test harness state) | **leave behind** |
| `json` (2144-2321) | 178 | `Request`3 `Response`3 `StatusCode`2 `Router`1 `Method`2 | **http** (`Json`/`JsonError` extractor) | KEEP → `servelet-core` |

**Verdict: `platform.rs` is 976 lines not-HTTP, 1,339 HTTP.** The `service` module is the
single biggest HTTP piece after the router itself, and it is already a hard nexus dependency.

## 4. (d) The exact public API nexus uses — the contract to satisfy first

`rg -o 'biota_http_server::\{[A-Za-z0-9_, {}]*\}' -g '*.rs'` plus the single-name form, over
**all ten** nexus worktrees (not three — `nexus-{auth,crypto,domain,foundation,http,
kaneo-facade,operately,orpc,runs,store}/nexus`, all pinning rev `4ce2dcd`):

`Request, Response, Method, StatusCode, Router, header, serve, Error, BoxHandler, PathParams,
Uri, Client, Proxy, Upstream, LoadBalance, serve_tls, tls_server_config, serve_connection,
actix::{HttpResponseBuilder, Json, Responder, to_handler1_async},
platform::service::{Layer, Service}, httpx::sse::SseParser, helpers::percent_encode`

Per-root-name live counts: `Response` 68 · `Router` 59 · `serve` 52 · `StatusCode` 52 ·
`helpers` 45 · `Request` 33 · `Method` 38 · `Client` 34 · `actix` 11 · `platform` 7 ·
`header` 6 · `httpx` 1 · `PathParams` 1 · `serve_tls` 2 · `tls_server_config` 2 · `Proxy` 2 ·
`serve_connection` 1.

First-consumer detail, `nexus-foundation/nexus` (branch `yokoszn/nexus-phase1`, HEAD
`26384df`) — 26 live lines, 14 files:

| file:line | names |
|---|---|
| `src/app.rs:18` | `Method, Response, Router, StatusCode` |
| `src/authed.rs:10` | `Method, Request, Response, Router, StatusCode, header` |
| `src/http/cors.rs:24-25` | `platform::service::{Layer, Service}`; `Error, Method, Request, Response, Router, StatusCode, header` |
| `src/http/sse.rs:21-22` | `Method, Request, Response, StatusCode, header`; `actix::HttpResponseBuilder` |
| `src/http/limits.rs:21,79` | `BoxHandler, Request, Response, StatusCode, header`; `Method::POST` |
| `src/http/static_files.rs:18` | `Method, Request, Response, Router, StatusCode, header` |
| `src/auth/{authenticator,workspace,json,store}.rs` | `Request`, `Response`, `StatusCode`, `header`, `StatusCode::from_u16` |
| `tests/*.rs` (9 files) | `serve`, `Router`, `Response` |

**nexus uses 24 names total, all of them core.** It touches none of the 19 zero-caller areas.
That is the contract: `servelet-core`, `servelet-router`, `servelet-h1` (+`serve_gracefully`),
plus `servelet-cookie` for the `HttpResponseBuilder` it already reaches through `actix`.

## 5. (b) The five `*_masq` shims and `masquerade`

| module | lines | emulates | imported by | breaks if dropped |
|---|---|---|---|---|
| `masquerade` | 162 | umbrella doc: drop-in trait surfaces for `http`, `reqwest`, `axum`, `pingora` | 0 | nothing |
| `http_masq` | 40 | `http` crate v1.x → `HttpMethod::as_str`, `HttpStatus::as_u16` | 0 | nothing |
| `reqwest_masq` | 32 | `reqwest` → `RequestBuilder` (`header`,`body`,`send`) | 0 | nothing |
| `axum_masq` | 26 | `axum` → `RouterBuild::handle` | 0 | nothing |
| `pingora_masq` | 20 | `pingora` → `UpstreamPeer::url_for` | 0 | nothing |
| `authzed_masq` | 19 | `authzed` → `RelationshipStore::relate` | 0 | nothing |

All six are **trait definitions with no consumers** — 299 lines. Verified twice: 0 imports in
the live set (§1), and 0 `(httpsrv|native|native_lib)::*_masq` references in `~/projects/bedrock`.
Dropping them breaks nothing, and dropping `authzed_masq` loses nothing real: the live
relationship path is the `relayfold` re-export (`kernel.rs:3211`), which is a different thing.
Rule 4 already forbids them.

## 6. `helpers.rs` — 518 lines, one live function

Distinct `helpers::*` used across the live set: **`percent_encode` only, 58 call sites**
(`caretaker-release/src/engines/{bing,duckduckgo,google,searxng}.rs`). The other 24 public
functions (`esc`, `json`, `err`, `path_param`, `query_param`, `percent_decode`,
`field_str`, `field_i64`, `json_get_str`, `json_get_num`, `json_get_bool`,
`json_get_str_array`, `json_str_array`, `esc_quoted`, `jstr`, `jopt`, `jopt_num`, `opt_str`,
`opt_or`, `json_response`, `base_url`) have 0 external callers.

They are not idle in spirit — opsfold **re-implemented them**: 158 `platform::http` refs
(`~/projects/opsfold/src/{flowops.rs:31,alerting.rs:13,bizops.rs:46,netops.rs:20}`, total 158
measured) import `json_response`, `json_get_num`, `json_get_str`, `json_escape`. Those are
`crate::platform::http` — **opsfold's own module, not `biota_http_server`** (its Cargo.toml
declares no dependency). So `helpers.rs` is duplicated code, and collapsing it into
`servelet-core` would let opsfold delete its copy. `json`/`err`/`path_param` are the ones to
carry; the JSON-field getters can stay behind.

Likewise `actix`: 857 lines, but only `HttpResponseBuilder` (nexus ×7), `Json`+`Responder`
(relayfold-control ×3), `to_handler1_async` (ptyktos-api ×1) are live. `App`, `Data`, `Query`,
`Path`, `Form`, `block`, `Middleware`, `Header`, `ReqData` and the `HttpServer` type have 0
external callers — they are the actix-web compatibility surface and should not survive into
servelet (rule 4). `HttpResponseBuilder` must survive: nexus's SSE depends on
`HttpResponseBuilder::new(StatusCode::OK)` + `.streaming(mpsc_rx)`
(`nexus-foundation/nexus/src/http/sse.rs:304,307`), and it drags `Cookie` with it
(`lib.rs:133`).

## 7. (c) Minimum dependency set per candidate crate

Derived by reading `use`/path references in each span (comments stripped), **not guessed**.
Rule 5: no crate inherits biota-http-server's 15-entry dependency list.

| crate | from | min dependencies | why |
|---|---|---|---|
| `servelet-core` | `kernel.rs` 60-1064 | **none external** (std only) + `hashtrinity` (derive `Error` @`kernel.rs:66`, `Extensions` @791) | native surface/Request/Response measured NONE external |
| `servelet-router` | `kernel.rs` 2446-3210 + `platform.rs` 282-1442 | `tokio` (3), `tracing` (2) | no rustls/serde anywhere in either span |
| `servelet-h1` | `kernel.rs` 1674-1853, 2926-2960 + `runtime.rs` 2054-2242 | `tokio`, `rustls`, `tokio-rustls`, `rustls-native-certs` | Wire span pulls all four; `serve_gracefully` adds tokio |
| `servelet-tls` | `kernel.rs` 1854-1969 | `rustls`, `tokio-rustls`, `rustls-pki-types`, `tokio`, `hashtrinity` | exactly this set, nothing more |
| `servelet-h2` | `lib.rs` 2931-3881 | `tokio` (14) | h2 + huffman table together: huffman table is pure std, so `h2` alone |
| `servelet-client` | `kernel.rs` 1065-1673, 1970-2445 | `tokio`, `hashtrinity`, `tokio-rustls`, `rustls-pki-types` | pool span needs tokio-rustls/pki-types only |
| `servelet-sse` | `lib.rs` 2137-2471 + `HttpResponseBuilder` (130-228) + `lib.rs` 1910-2136 | `tokio` (4) + `servelet-cookie` + `servelet-core` | builder's `cookies: Vec<Cookie>` is the only cross-crate edge |
| `servelet-cookie` | `lib.rs` 1910-2136 | **none** (pure std + crate) | measured NONE |
| `servelet-ws` | `lib.rs` 2472-2930 | `tokio` (13) | SHA-1+base64 hand-rolled in-crate by design (doc `lib.rs:2476-2478`) |
| `servelet-multipart` | `lib.rs` 1616-1909 | `tokio` (2) | measured; **0 callers → not in the first spine** |
| `servelet-static` / `-cors` / `-limits` / `-authed` | nexus `http::*`, `authed.rs` | `servelet-router`, `servelet-core` only | ported from nexus, which already has them |
| `servelet-acme` | `kernel/acme.rs` | `tokio` (3 uses), `transport` (ACME client), `servelet-tls`, `servelet-core` | 0 callers today; see below |
| `servelet-openapi` | `lib.rs` 3882-4153 | `tokio`, `hashtrinity` | 0 callers → **CANDIDATE-CUT** |

`hashtrinity` must come from the GitLab mirror exactly as `nexus/Cargo.toml` has it
(`https://gitlab.tas.twn.network/twn/ptyktos/hashtrinity.git`, branch `main`) — the GitHub
copy does not unify with sangdb. NOT independently re-verified here (rule 5 states it as
given; verifying would need a network build).

**Capability gaps, verified against the source (not taken on trust):**
- WebSocket upgrade is **not** wired into `Router` dispatch — `lib.rs:2479-2481` says so
  verbatim ("not wired into `Router`'s normal dispatch…"). ~200 lines of integration missing.
- **No gzip/deflate implementation**: `grep -n 'gzip\|deflate\|content-encoding' lib.rs kernel.rs`
  → 7 hits, all header-name constants (`kernel.rs:416,491`) or test fixtures (`lib.rs:1190,
  3093,3096,3711`). 0 encoders/decoders.
- **No static file serving**: `grep -c 'serve_dir\|ServeDir\|static_files' lib.rs kernel.rs` → 0, 0.
- opsfold has **zero** WebSocket code — consistent with the §7 gap list in
  `~/projects/planning/unified-platform/runtime-auth.md` (read, sections 7-10).

## 8. Consumers checked that have **zero** callers

Verified by `rg -c 'biota_http_server' <dir>` → 0 and no `biota-http-server` in Cargo.toml:
`opsfold`, `margin`, `conduit`, `memoryfold`, `ai-gateway`, `saga`, `caretakerd`, `kleis`,
`telos`, `syndesi` (via *biota*; syndesi uses the **bedrock** copy), `peregrine-ng`, `ptyktos`,
`ptyktos-forge`.

**No biota member depends on `biota-http-server`** — `git grep 'biota-http-server' 4ce2dcd --
'*/Cargo.toml' Cargo.toml` returns only `http-server/Cargo.toml` itself. `biota-app` depends on
`bedrock` with `features = ["native"]`, i.e. **biota runs on the deprecated FSL-1.1 copy**.
So the "biota members are consumers" assumption in the crate map is false: app, auth, openapi,
sheets, content, techdocs, serve are all zero.

Live consumers that do exist: `ptyktos-api` (37 lines), `ptyktos-api-wallet-wiring` +
`caretaker-release`/`logto-kleis-wire`/`mpp-rollout-4-5` (29/27/30/30), `relayfold-control`
(30), `relayfold-helm/proxy-runtime` (20), `ptyktos-webgui` (13), `webfold-fleet` (3),
`sangdb-telemetry-wire` (2), `wachd-rust` (1), and the ten nexus worktrees (3-38 each).

## 9. Recommended cut list and extraction order

**Spine — extract in this order.** Each step is independently shippable and shrinks the next.

| # | crate | why now | evidence row |
|---|---|---|---|
| 1 | `servelet-core` | zero deps (std + `hashtrinity` derive only); every other crate and every consumer needs it; nexus uses 12 of its names | §2 rows 1-4, §7 |
| 2 | `servelet-router` | nexus's 6 `Router` users + `platform::service::{Layer,Service}` all land here; only `tokio`+`tracing` | §2 Axum face, §3b `service`, §7 |
| 3 | `servelet-h1` (+`serve_gracefully`) | nexus calls `serve` in 9 test files; gives nexus a working server | §2 Wire + Axum face, §3a `graceful` |
| 4 | `servelet-cookie` | pure std; forced by `HttpResponseBuilder` in step 5 | §1 `httpx::cookie`, §7 |
| 5 | `servelet-sse` | 8 live callers; nexus SSE depends on `HttpResponseBuilder` | §1 `httpx::sse`, §6, §7 |
| 6 | `servelet-h1`'s TLS half → `servelet-tls` | 4 live callers in proxy-runtime; independent of 1-3 | §2 TLS, §7 |
| 7 | `servelet-client` | 34 live callers (relayfold-control, caretaker engines); needs `pool` from the same file | §2 Client + pool, §7 |
| 8 | `servelet-limits` / `-cors` / `-static` / `-authed` | already exist inside nexus; moving them makes the swap mechanical | §4 file:line table |

Then, only if a consumer appears: `servelet-h2` + `servelet-ws` (syndesi, 1 and 3 calls, via
the bedrock copy) and `servelet-acme` (0 callers, UNKNOWN priority).

**Drop — zero live callers in both copies.** 9,110 lines total: 3,378 in `lib.rs`, 4,239 in
`runtime.rs`, 976 in `platform.rs`, and 517 of `helpers.rs`.

`x402` 595 · `nel` 562 · `filter` 614 · `h2` 893* · `websocket` 459* · `multipart` 294 ·
`openapi` 272 · `graphql` 303 · `webhook` 280 · `s3_gateway` 118 · `masquerade` 162 ·
`http_masq` 40 · `reqwest_masq` 32 · `axum_masq` 26 · `pingora_masq` 20 · `authzed_masq` 19 ·
`web` 8 · `test` 28 · `httpsrv` alias 3 · `lorelake_dataset` 2 · `runtime::{cluster,cron,
daemon,fiber,work,task_metrics,metrics,tracecontext,alloc}` 4,239 · `platform::{cli,settings,
service_info,harness_state}` 976 · `helpers` 517 of 518 (all but `percent_encode`).

\* `h2` and `websocket` are drop-*from-biota*-but **extract-for-syndesi**: they have 1 and 3
real callers through the bedrock copy. They are deferred, not discarded.

**Blocking fact for the coordinator:** `servelet` cannot be validated against biota's own
members, because none of them depend on this crate (§8). The only consumers that exercise
the API surface are nexus, ptyktos-api, relayfold-control, relayfold-helm/proxy-runtime and
the ptyktos-api-wallet-wiring family.
