# docs/EXTRACTION.md — who actually uses the Ptyktos HTTP server

Evidence census behind the servelet crate map. Every row cites a command that was run or a
`file:line`. Anything not run is labelled **NOT RUN**. Baseline: biota rev `4ce2dcd`
(origin/main), measured 2026-10-03. Supersedes the unverified draft lost to an Orca crash:
several of its "zero callers" verdicts were wrong (see §0.2).

## 0. Method, rev, exclusions

### 0.1 Source read

Always `git -C ~/projects/biota show 4ce2dcd:<path>` — the working tree is shared and dirty and was
never read for content, never written:

```
git -C ~/projects/biota show 4ce2dcd:http-server/src/lib.rs              -> 7380   (md5 644e812c9649b73c31d4f8e62e7593f3)
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel.rs           -> 5059
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/runtime.rs   -> 4822
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/platform.rs  -> 2322
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/acme.rs      ->  277
git -C ~/projects/biota show 4ce2dcd:http-server/src/helpers.rs          ->  518
git -C ~/projects/biota show 4ce2dcd:http-server/src/kernel/sangdb.rs     ->   89   (exists; not in the brief's list)
```
All six brief counts match exactly. `~/projects/bedrock` was read only to count callers
(§2 cross-check); nothing was copied from it (FSL-1.1).

### 0.2 What the crashed draft got wrong

Its census grepped **only** `biota_http_server::`. The bedrock copy (`bedrock::httpsrv::*`) is a
second live consumer of the same code, and it carries real callers for six areas the draft marked
zero-caller: `webhook` (opsfold, 135 sites), `x402` (biota `bin/`, 72), `h2` (opsfold + syndesi, 29),
`websocket` (appfold + syndesi, 93), `openapi` (sang-codspeed + spbench + immichfold, 22),
`s3_gateway` (biota `bin/`, 16). All verdicts below count **both** paths.

### 0.3 Caller grep and exclusions

```
rg -o --no-messages -g '*.rs' -F 'biota_http_server::<path>' ~/projects ~/orca/workspaces
rg -o --no-messages -g '*.rs' -F 'bedrock::httpsrv::<path>'      ~/projects ~/orca/workspaces
```
Excluded everywhere, with counts:
- `target/`, `node_modules/`, `.git/` — build/VCS noise (glob-excluded, never counted).
- dead worktrees `fold-worktrees/`, `fold-memory/`, `attic/`, `_archive/`, `_subsume/`,
  `orca/workspaces/fold/` — measured contribution to `biota_http_server` is **0**
  (`rg -c 'biota_http_server' projects/fold-worktrees projects/attic projects/fold-memory
  projects/_archive projects/_subsume orca/workspaces/fold` → empty). They *do* contain bedrock
  copy-paths, so they are excluded for the same reason the brief names them: stale branches of the
  pre-extraction tree.
- the crate's own source and biota's own checkouts (`projects/biota`, `orca/workspaces/biota/*`,
  3 worktrees) — self-hits.

Worktree duplicate pairs (same tree, two checkouts) are counted once in the tables below;
`reroute-*` / `nexus-*` siblings are the same content on different branches.

Baseline totals, unfiltered, `~/projects` + `~/orca/workspaces`, `-g '*.rs'`:
**905 lines** mention `biota_http_server`; **58 files** use a `bedrock::httpsrv::*` path.

### 0.4 Path traps (load-bearing)

- `multipart cookie sse websocket h2 h2_huffman_table openapi nel x402` are **nested inside
  `httpx`** (`lib.rs:1609` opens `httpx`, `lib.rs:1616` opens `multipart`). The path is
  `biota_http_server::httpx::<name>`. Grepping the bare name reports a false 0. `openapi`,
  `graphql`, `webhook`, `s3_gateway`, `filter`, `actix` are top-level; `kernel`/`helpers` are
  top-level too. The two exceptions are bedrock-era paths where the module sat beside `httpsrv`:
  `bedrock::httpsrv::openapi::` (sang-codspeed, spbench, immichfold) — **not**
  `httpsrv::httpx::openapi`.
- `url` appears ~60 times in these spans as a *field name* (`url: Uri`, `self.url`), never as the
  crate. Verified: `grep -c 'url::'` → 0 in every span. **`url` is not a dependency.**
- nexus imports are `use biota_http_server::…`, so a `pub use kernel::*` at `lib.rs:7380` means
  `Request`/`Response`/`Router`/… are reachable both as `biota_http_server::Request` and
  `biota_http_server::kernel::Request`. Counts below use the flat form.

## 1. `lib.rs` public modules — one row each

Counts are call sites (grep -o on the full path prefix), `~/projects` only, dead worktrees
excluded. "both" = the same row also matches through `bedrock::httpsrv::`.

| area (`lib.rs` span) | lines | who CALLS it (file:line, example) | calls | verdict |
|---|---|---|---|---|
| `actix` (7-863) | 857 | `opsfold`-side none; `relayfold-control/src/app.rs:12` `Json, Responder`; `ptyktos-api/src/agent.rs` `to_handler1_async`; `ptyktos-webgui/src/main.rs:11` `to_handler0_async,to_handler1_async,App,HttpServer`; `syndesi/src/web_router.rs` `Responder`; `biota/bin/src/epihogue/wire.rs` | 15 | **KEEP (partial)** — 7 of its items live, see §6 |
| `web` (864-871) | 8 | — | 0 | **CANDIDATE-CUT** (pure `pub use` of `actix`) |
| `test` (872-899) | 28 | — | 0 | **CANDIDATE-CUT** (`TestRequest` for the crate's own tests) |
| `httpx` (1609-1615) | 7 | namespace only, no items | 0 | keep as namespace |
| `httpx::multipart` (1616-1909) | 294 | — | 0 | **CANDIDATE-CUT** |
| `httpx::cookie` (1910-2136) | 227 | — externally 0; forced internally by `HttpResponseBuilder.cookies: Vec<Cookie<'static>>` (`lib.rs:133`) | 0 | **KEEP** (internal edge → `servelet-cookie`) |
| `httpx::sse` (2137-2471) | 335 | `ptyktos-api/src/catalog.rs:382` `SseParser::new()`; `syndesi/src/web_router.rs` `Sse/Event/Data::new` (via bedrock) | 14 | **KEEP** |
| `httpx::websocket` (2472-2930) | 459 | `syndesi/src/infra.rs` `WebSocket::connect, Message::Text`; `appfold/src/{lib,client,server}.rs` `connect, accept, Message::{Text,Close}` (via bedrock) | 93 | **KEEP** (deferred; not in the nexus set) |
| `httpx::h2` (2931-3823) | 893 | `opsfold/src/integrations.rs:1249` `use bedrock::httpsrv::httpx::h2::{…}`; `syndesi/src/authzed.rs` (via bedrock) | 29 | **KEEP** (deferred) |
| `httpx::h2_huffman_table` (3824-3881) | 58 | — reached only via `httpx::h2` | 0 direct | **KEEP** (private to `h2`) |
| `httpx::openapi` (3882-4153) | 272 | `sang-codspeed/src/main.rs:1652,1678,1731,1749,1750` `call, Connector, derive`; `spbench/src/main.rs`; `immichfold/src/spec.rs` (via `bedrock::httpsrv::openapi`) | 22 | **KEEP** (deferred) — the crashed draft's "0 callers" was wrong |
| `httpx::nel` (4154-4715) | 562 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `httpx::x402` (4716-5310) | 595 | `biota/bin/src/meteroid_sidecar.rs` `X402Config, X402Layer::new, Asset, AlwaysAcceptVerifier, HttpFacilitatorVerifier::new`; `bedrock/examples/x402_gateway.rs` (via bedrock) | 72 | **KEEP-OUTSIDE-SERVELET** — rule 4 forbids it in the server; meteroid_sidecar becomes a separate program that talks to servelet |
| `graphql` (5311-5613) | 303 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `webhook` (5691-5970) | 280 | `opsfold/src/{crm,bizops,integrations,inventory,netops,platform}.rs` `Endpoint::new, WebhookSecret::parse, Message::new, is_delivered, retry_delay` (via bedrock) | 135 | **KEEP-OUTSIDE-SERVELET** — rule 4; it is a *client* of an inbound webhook URL, not server logic. opsfold keeps it as its own crate and drops the bedrock dep. |
| `s3_gateway` (6174-6291) | 118 | `biota/bin/src/s3_gateway.rs` `S3Gateway, upstream_from_url` (via bedrock) | 16 | **CANDIDATE-CUT** (rule 4; the only caller is biota's own binary) |
| `masquerade` (6292-6453) | 162 | — | 0 | **CANDIDATE-CUT** (§5) |
| `http_masq` (6454-6493) | 40 | — | 0 | **CANDIDATE-CUT** (§5) |
| `reqwest_masq` (6494-6525) | 32 | — | 0 | **CANDIDATE-CUT** (§5) |
| `axum_masq` (6526-6551) | 26 | — | 0 | **CANDIDATE-CUT** (§5) |
| `pingora_masq` (6552-6571) | 20 | — | 0 | **CANDIDATE-CUT** (§5) |
| `authzed_masq` (6572-6590) | 19 | — | 0 | **CANDIDATE-CUT** (§5) |
| `filter` (6591-7204) | 614 | — | 0 | **CANDIDATE-CUT** (rule 4) |
| `kernel` (7373) | 1 | flat re-export; see §2 | 227 | see §2 |
| `helpers` (7374-7380) | 7 | `caretaker-release/src/engines/{bing,duckduckgo,google,searxng}.rs` `percent_encode` | 58 | **KEEP** — 1 of 25 fns live (§6) |

`pub mod` boundaries verified: `grep -n '^pub mod' lib.rs` (rev `4ce2dcd`) gives exactly the 26
starts in the table; each span ends one line before the next `pub mod`/`mod tests`.

## 2. `kernel.rs` areas — one row each

| area (`kernel.rs` span) | lines | who CALLS it (file:line, example) | calls | verdict |
|---|---|---|---|---|
| `Error` + `Result` (60-85) | 26 | `nexus/src/http/cors.rs:25`; every nexus layer | 9 | **KEEP** → `servelet-core` |
| native http surface (86-393): `Method`,`Version`,`StatusCode`,`HeaderName`,`HeaderValue` | 308 | `Method` 38+14, `StatusCode` 9+9, `header` 8 in the 12 nexus worktrees; `appfold`, `opsfold` via `bedrock::Method` | ~200 | **KEEP** → `servelet-core` |
| `header` module (394-510) | 117 | `nexus/src/app.rs:172` `header::CONTENT_TYPE` | 8 | **KEEP** → `servelet-core` |
| `HeaderMap`+`Uri`+`parse_uri`+`host_port` (511-656) | 146 | `Uri`/`parse_uri` reach clients via `Client`; no consumer names `Uri` directly | 0 direct | **KEEP** → `servelet-core` (needed by `servelet-client`) |
| `Extensions` (732-833) | 102 | — | 0 | **KEEP** (part of the core surface; 102 lines) |
| `Request`+`ConnectionInfo` (834-982) | 149 | `nexus/src/auth/{json.rs:9,workspace.rs:13,authenticator.rs:13}` | 22+ | **KEEP** → `servelet-core` |
| `Response` (983-1070) | 88 | `nexus/src/auth/json.rs:9`, `tests/auth_support.rs:142,151,157,164` | 65+ | **KEEP** → `servelet-core` |
| Reqwest face: `RetryPolicy`,`CookieJar`,`RequestBuilder`,`Client`,`ClientBuilder` (1071-1675) | 605 | `relayfold-control/tests/integration.rs` `Client::new()`; `caretaker-release/src/engines/bing.rs`; `ptyktos-webgui/src/backend.rs`; `opsfold/src/integrations.rs:40` `use bedrock::{Client, Method}` | 34 | **KEEP** → `servelet-client` |
| Wire: `Stream`,`StreamReader` + client-side `tls_config()` (1676-1915) | 240 | — reached only through `Client`/`serve_connection` | 0 direct | **KEEP** → `servelet-h1` (`Stream`/`StreamReader`) + the client half moves with `servelet-client` |
| Server-side TLS: `tls_server_config` (1916), `serve_tls` (1949) (1916-2282) | 367 | `relayfold/relayfold-helm/proxy-runtime/src/main.rs:96,146` | 4 | **KEEP** → `servelet-tls` |
| Connection pool + `StreamingResponse` (2283-2448) | 166 | — reached only through `Client` | 0 direct | **KEEP** → `servelet-client` |
| Axum face: `BoxHandler`(2449),`PathParams`(2522),`Router`(2552),`serve`(2926),`serve_connection`(2945) (2449-3210) | 762 | `nexus/src/{app.rs:18,authed.rs:10,http/*.rs}`; `nexus/tests/http_cors.rs:121`, `http_limits.rs:61`, `authed_routing.rs:5`, `src/bin/nexus.rs:34`; `relayfold-helm/proxy-runtime/tests/edge_guards.rs:61` | 59+46+ | **KEEP** → `servelet-router`, `servelet-h1` |
| Sangdb/Authzed face: relayfold re-export (3211), `transport::load_balance` (3220), `Proxy`(3225), `Session`(3504), `ProxyHttp`(3535) (3211-3573) | 363 | `nexus` uses **none** of it (verified, §4); `relayfold-control` uses `Proxy` | 2 | **KEEP-OUTSIDE-SERVELET** — thin re-export of `relayfold`/`transport` (line 3211/3220). Do not reimplement; depend on relayfold/transport if a consumer asks. |
| `platform` mod (16) → `kernel/platform.rs` | 2322 | `nexus/src/http/cors.rs:24` `platform::service::{Layer, Service}` | 9 | **KEEP** (partial) — see §3b |
| `acme` mod (54) → `kernel/acme.rs` | 277 | — no consumer names `acme` | 0 | **UNKNOWN priority** (§7) |
| `sangdb` mod (48) → `kernel/sangdb.rs` | 89 | `helpers.rs:206` `pub use crate::sangdb::{tsv_escape, tsv_unescape}` | 0 external | **CANDIDATE-CUT** (2 escaping helpers) |
| `lorelake_dataset` (27-28) | 2 | — `#[cfg(feature = "federation")]`; **no `federation` key in `http-server/Cargo.toml` `[features]`** | 0 | **CANDIDATE-CUT** |
| `httpsrv` alias (37-40) | 4 | — namespace alias onto `actix`+`httpx` | 0 | **CANDIDATE-CUT** |
| `#[cfg(test)] mod tests` (3574-5058) | 1485 | — | 0 | tests move with their crate (rule 9: byte-for-byte) |

**Note for the coordinator:** `kernel.rs` is 5,059 lines but only **3,573** are non-test code, and
`mod tests` alone is 1,485 (29%). The real extraction surface from `kernel.rs` is 3,573.

## 3. (a) `runtime.rs` / `platform.rs` — HTTP logic vs. what rode along

Method: for each top-level item, comments stripped (`sed 's://.*::'`), then count references to
the HTTP core symbols `Request|Response|Router|Method|StatusCode|HeaderMap|HeaderValue|Uri|header::`.
Item boundaries from `grep -n '^pub mod'` — all match the spans below exactly.

### 3a. `kernel/runtime.rs` — 4,822 lines

| item (span) | lines | http symbols | class | verdict |
|---|---|---|---|---|
| `alloc` (7-185) | 179 | only `heap_handler` (`runtime.rs:124-137`), an 8-line `/debug/heap` route | http adapter, 8 lines | **CANDIDATE-CUT** (mimalloc/jemalloc is not HTTP) |
| `cache` (186-572) | 387 | `Method`34 `HeaderMap`26 `Response`17 `Uri`14 `StatusCode`14 `header::`15 | **http** | KEEP-optional, **0 callers → CANDIDATE-CUT for now** |
| `cluster` (573-1094) | 522 | NONE | not-http | **leave behind** |
| `cron` (1095-1849) | 755 | NONE | not-http | **leave behind** |
| `daemon` (1850-2053) | 204 | NONE | not-http | **leave behind** |
| `graceful` (2054-2242) | 189 | `serve_gracefully(listener, router, …)` | **http** | **KEEP** → `servelet-h1` as `serve_gracefully` |
| `fiber` (2243-3138) | 896 | NONE | not-http | **leave behind** |
| `work` (3139-4213) | 1075 | NONE | not-http (opsfold tickets) | **leave behind** (already feature-gated) |
| `task_metrics` (4214-4324) | 111 | NONE | not-http | **leave behind** |
| `metrics` (4325-4699) | 375 | only `Registry::handler()` (`runtime.rs:4559-4566`), 8 lines | http adapter, 8 lines | **CANDIDATE-CUT** |
| `tracecontext` (4700-4821) | 122 | NONE (`parse_traceparent(&str)` is a plain string fn) | not-http | **leave behind** |

**`runtime.rs` is ~94% not-HTTP.** Only `cache` (387) + `graceful` (189) are HTTP logic worth
extracting; the three Router adapters are 24 lines. Extract **~576**, not 4,822.

### 3b. `kernel/platform.rs` — 2,322 lines

| item (span) | lines | http symbols | class | verdict |
|---|---|---|---|---|
| `cli` (7-149) | 143 | NONE | not-http | **leave behind** |
| `settings` (150-281) | 132 | NONE | not-http | **leave behind** |
| `service` (282-1442) | 1161 | `Response`56 `StatusCode`39 `Method`32 `Request`21 `Router`16 | **http** (tower/axum `Service`+`Layer`) | **KEEP** → fold into `servelet-router`; nexus needs `Layer`+`Service` |
| `service_info` (1443-1496) | 54 | NONE | not-http | **leave behind** |
| `harness_state` (1497-2143) | 647 | NONE | not-http | **leave behind** |
| `json` (2144-2321) | 178 | `Json`/`JsonError` extractor | **http** | KEEP → `servelet-core`; re-exported at `lib.rs:32` |

**`platform.rs` is 976 not-HTTP / 1,339 HTTP.** `service` is the largest single HTTP piece after the
router and is already a hard nexus dependency.

## 4. (d) The exact public API nexus uses — the contract to satisfy first

Measured over **all twelve** nexus worktrees
(`orca/workspaces/opsfold/{nexus-auth,crypto,domain,foundation,http,kaneo-facade,operately,orpc,runs,store,crm-contract,kaneo-web-recipe}/nexus`),
not the three the brief names; all pin rev `4ce2dcd`:

```
rg -oU -g '*.rs' 'use\s+biota_http_server::[^;]*;' orca/workspaces/opsfold/*/nexus | sort | uniq -c
```

**Exactly 12 distinct paths, 13 names:**

| name | import sites | needed by |
|---|---|---|
| `Method` | 14 | every handler |
| `Request` | 19 | handlers |
| `Response` | 65 | every handler |
| `Router` | 20 | app assembly |
| `StatusCode` | 9 | every response |
| `header` | 8 | `header::CONTENT_TYPE` etc. |
| `serve` | 10 | `src/bin/nexus.rs:34`, 3 test files |
| `Error` | 9 | layer result type |
| `BoxHandler` | 9 | `http/limits.rs:21` |
| `PathParams` | 1 | one route |
| `platform::service::{Layer, Service}` | 9 | `http/cors.rs:24` |
| `actix::HttpResponseBuilder` | 9 | `http/sse.rs:22` |

Verified **zero** in nexus (each grepped by name, 0 files): `Client`, `Proxy`, `Upstream`,
`LoadBalance`, `serve_tls`, `tls_server_config`, `serve_connection`, `Uri`, `Extensions`,
`httpx::sse::SseParser`, `helpers::percent_encode`, `actix::Json`, `to_handler1_async`.
The crashed draft listed all of these as "nexus" names — they are whole-workspace names.

First consumer in full — `nexus-foundation/nexus`, branch `yokoszn/nexus-phase1`, HEAD `26384df`,
44 matching lines across 14 files:

| file:line | names |
|---|---|
| `src/app.rs:18` | `Method, Response, Router, StatusCode` |
| `src/authed.rs:10` | `Method, Request, Response, Router, StatusCode, header` |
| `src/http/cors.rs:24-25` | `platform::service::{Layer, Service}` + `Error, Method, Request, Response, Router, StatusCode, header` |
| `src/http/sse.rs:21-22` | `Method, Request, Response, StatusCode, header` + `actix::HttpResponseBuilder` |
| `src/http/limits.rs:21,79` | `BoxHandler, Request, Response, StatusCode, header` + `Method::POST` |
| `src/http/static_files.rs:18` | `Method, Request, Response, Router, StatusCode, header` |
| `src/auth/{json.rs:9,store.rs:306,errors.rs:11,77,workspace.rs:13,authenticator.rs:13,endpoints.rs:21}` | `Request`, `Response`, `StatusCode`, `header` |
| `src/bin/nexus.rs:34` | `serve` |
| `tests/{auth_support.rs:14,142,151,157,164, http_cors.rs:8,121, http_sse_stream.rs:8,30, http_static_files.rs:5,29,33,37, http_limits.rs:8,61, authed_routing.rs:5, auth_authz.rs:10,19,204, auth_endpoints.rs:12, app_assembly.rs:4, auth_socket.rs:11}` | `Router`, `Response`, `Request`, `Method`, `StatusCode`, `header`, `serve` |

**The contract: `servelet-core` + `servelet-router` + `servelet-h1` (+`serve_gracefully`),
plus `servelet-sse` which needs `actix::HttpResponseBuilder` and therefore `servelet-cookie`.**
Nexus touches **none** of the 13 zero-caller areas.

## 5. (b) The `*_masq` shims and `masquerade`

| module | lines | what it emulates | imported by | breaks if dropped |
|---|---|---|---|---|
| `masquerade` (6292-6453) | 162 | umbrella doc: drop-in trait surfaces for `http`, `reqwest`, `axum`, `pingora`, `authzed` | 0 | nothing |
| `http_masq` (6454-6493) | 40 | `http` crate v1.x → `HttpMethod::as_str`, `HttpStatus::as_u16` | 0 | nothing |
| `reqwest_masq` (6494-6525) | 32 | `reqwest` → `RequestBuilder` (`header`,`body`,`send`) | 0 | nothing |
| `axum_masq` (6526-6551) | 26 | `axum` → `RouterBuild::handle` | 0 | nothing |
| `pingora_masq` (6552-6571) | 20 | `pingora` → `UpstreamPeer::url_for` | 0 | nothing |
| `authzed_masq` (6572-6590) | 19 | `authzed` → `RelationshipStore::relate` | 0 | nothing |

All six are **trait definitions with no consumers** — 299 lines. Verified twice: 0 hits for
`biota_http_server::{,httpsrv::}` `*_masq` across `~/projects` + `~/orca/workspaces`, and 0
`bedrock::httpsrv::*_masq` in `~/projects/bedrock`. Dropping `authzed_masq` loses nothing real:
the live relationship path is the `relayfold` re-export at `kernel.rs:3211`. Rule 4 already
forbids them.

## 6. `helpers.rs` and `actix` — one live name each

`helpers::*` used across the live set: **`percent_encode` only, 58 sites**
(`ptyktos-api-wallet-wiring/src/engines/{bing,duckduckgo,google,searxng}.rs`). The other 24 public
functions have 0 external callers.

They are not idle in spirit — **opsfold re-implemented them**. `rg -o 'platform::http' ~/projects/opsfold/{src,tests}`
→ **161 refs** (brief said 158; measured 161, including 1 in `tests/crm_front_compat.rs:1`), from
`src/bizops.rs:46, flowops.rs:26, netops.rs:20, alerting.rs:13, integrations.rs:10, estate.rs:9,
datalake.rs:9, crm.rs:7, captable.rs:6, inventory.rs:4, main.rs:2, vymanager.rs:1, om.rs:1,
lib.rs:1, crud.rs:1, bin/crm_etl_import.rs:1`. These are `crate::platform::http::{…}`
(`src/bizops.rs:964` is the import) — **opsfold's own module, not `biota_http_server`**:
`rg 'biota-http-server' ~/projects/opsfold/Cargo.toml` → 0. So `helpers.rs` is duplicated code;
collapsing the shared half into `servelet-core` would let opsfold delete its copy.

`actix`: 857 lines, but only 7 items are live — `HttpResponseBuilder` (nexus ×9),
`Json`+`Responder` (`relayfold-control/src/app.rs:12`), `to_handler0_async`+`to_handler1_async`+`App`+`HttpServer`
(`ptyktos-webgui/src/main.rs:11`). `Data`, `Query`, `Path`, `Form`, `block`, `Middleware`,
`Header`, `ReqData` have 0 external callers — the actix-web compatibility surface, out under rule 4.
`HttpResponseBuilder` must survive (nexus SSE: `HttpResponseBuilder::new(StatusCode::OK)` +
`.streaming(rx)`), and it drags `Cookie` (`lib.rs:133`) and `hashtrinity`+`tokio` with it.

## 7. (c) Minimum dependencies per candidate crate

Derived by reading imports/path references in each span with comments stripped — **not guessed**.
Rule 5: no crate inherits biota-http-server's dependency list.

```
sed 's://.*::' <span> | grep -oE '\b(tokio|rustls|rustls_pki_types|rustls_native_certs|tracing|serde|
  serde_json|bytes|base64|hashtrinity|transport|relayfold|sangdb|modelfold|mimalloc|tikv_jemallocator|url)\b'
```

| crate | from | measured minimum | notes |
|---|---|---|---|
| `servelet-core` | `kernel.rs` 60-1070 + `platform.rs` 2144-2321 | **`hashtrinity` only** (4 sites: `Error` derive, `Extensions`, `Json`) | no `tokio`, no `bytes`, no `url`. `bytes` hits are field names. |
| `servelet-router` | `kernel.rs` 2449-3210 + `platform.rs` 282-1442 | **`tokio` (3+6), `bytes` (2+2)** | no rustls/serde anywhere |
| `servelet-h1` | `kernel.rs` 1676-1915 (`Stream`/`StreamReader`) + `serve`(2926) + `serve_connection`(2945) + `runtime.rs` 2054-2242 | **`tokio` (12 in graceful), `tracing` (7)** | **no rustls**: the rustls in 1676-1915 is the *client* `tls_config()`, which moves with `servelet-client` |
| `servelet-tls` | `kernel.rs` 1916-2282 | **`rustls` (6), `rustls-pki-types` (5), `hashtrinity` (1), `bytes` (1), `tokio` (1)** | exactly this set |
| `servelet-client` | `kernel.rs` 1071-1675 + 2283-2448 + client `tls_config()` 1829-1852 | **`tokio`, `rustls` (5), `rustls-native-certs` (1), `hashtrinity` (1), `bytes` (1)** | `rustls-pemfile` explicitly refused at `kernel.rs:189` |
| `servelet-sse` | `lib.rs` 2137-2471 + `HttpResponseBuilder` (`lib.rs` 130-228) | **`tokio` (4+2), `hashtrinity` (4)** + `servelet-core`, `servelet-cookie` | the builder's `cookies: Vec<Cookie>` is the only cross-crate edge |
| `servelet-cookie` | `lib.rs` 1910-2136 | **none** (std only) | measured zero |
| `servelet-ws` | `lib.rs` 2472-2930 | **`tokio` (13), `bytes` (7)** | SHA-1+base64 hand-rolled in-crate by design (`lib.rs:2473-2478`) |
| `servelet-h2` | `lib.rs` 2931-3881 | **`tokio` (14), `bytes` (4), `transport` (1)** | huffman table is pure std |
| `servelet-multipart` | `lib.rs` 1616-1909 | **`tokio` (2), `bytes` (2)** | 0 callers → not in the first spine |
| `servelet-openapi` | `lib.rs` 3882-4153 | **`tokio` (2), `hashtrinity` (1)** | 22 bedrock-era callers |
| `servelet-acme` | `kernel/acme.rs` | **`transport` (6), `rustls` (16), `rustls-pki-types` (4), `tokio` (3), `tracing` (3), `hashtrinity` (2)** | heaviest crate by far; 0 callers → behind a feature (rule 6) |
| `servelet-static` / `-cors` / `-limits` / `-authed` | nexus `http/*`, `authed.rs` | **`servelet-router`, `servelet-core` only** | ported out of nexus |
| cut: `x402` | `lib.rs` 4716-5310 | would need `serde` (22), `serde_json` (9), `bytes` (14), `base64` (12), `url`(0 real), `hashtrinity` (2), `tokio` (0) | the heaviest cut; rule 4 keeps it out |
| cut: `nel` / `graphql` / `filter` / masqs | `lib.rs` 4154-4715 / 5311-5613 / 6591-7204 / 6292-6590 | `nel`: `url`(0), `tokio` (5), `hashtrinity` (1); `graphql`: `sangdb` (1), `hashtrinity` (2); `filter`+masqs: **none** | all zero-caller |

`hashtrinity` is pinned to the GitHub URL at rev `2c36b99`, the one form transport, relayfold, kleis
and hosting-runtime use, so the graph has one hashtrinity (it was the GitLab mirror on `branch =
"main"`; that URL is unreachable from builders and a branch is not a pin).

**Capability gaps, verified against the source (not taken on trust):**
- **WebSocket upgrade is not wired into `Router` dispatch.** `lib.rs:2479-2481` says so verbatim:
  "this is a standalone connect/accept pair … not wired into `Router`'s normal dispatch (a handler
  can't 'return' a WebSocket…)". ~200 lines of integration are missing.
- **No gzip/deflate.** `grep -n 'gzip|deflate|content_encoding|CONTENT_ENCODING' lib.rs kernel.rs`
  → 7 hits: header-name constants (`kernel.rs:416`, `kernel.rs:491`) and test fixtures
  (`lib.rs:1190,2482,3093,3711`). **0 encoders or decoders.**
- **No static file serving.** `grep -c 'serve_dir|ServeDir|static_files|serve_static' lib.rs kernel.rs`
  → `0` and `0`.
- Consistent with `~/projects/planning/unified-platform/runtime-auth.md` §7-10 (read).

## 8. Consumers checked by name — `biota_http_server` lines / `bedrock::httpsrv` sites

| consumer | `biota_http_server` | `bedrock::httpsrv::*` | verdict |
|---|---|---|---|
| `opsfold` (src + tests) | 0 | **74** | **LIVE** — `Client, Method, Router, Request` (`integrations.rs:40,552,553,555`), `httpx::h2` (1249), `webhook` (1556 + bizops/crm/inventory/netops). Also owns a duplicate `platform::http` (161 refs) |
| the 12 nexus worktrees | 44 each | 0 | **LIVE, first consumer** (§4) |
| `ptyktos-api` | 50 | 0 | **LIVE** — `actix::to_handler1_async`, `httpx::sse::SseParser` |
| `ptyktos-api-wallet-wiring` (+ `caretaker-release`, `logto-kleis-wire`, `mpp-rollout-4-5`) | 47 each | 0 | **LIVE** — `Client`, `helpers::percent_encode` |
| `relayfold` / `relayfold-control` | 50 / 30 | 0 | **LIVE** — `actix::{Json, Responder}`, `Client`, `Proxy` |
| `relayfold/relayfold-helm/proxy-runtime` | 20 | 0 | **LIVE** — `serve_tls`, `tls_server_config`, `serve_connection` (the only TLS users) |
| `ptyktos-webgui` | 13 | 0 | **LIVE** — `actix::{to_handler0_async,to_handler1_async,App,HttpServer}`, `Client` |
| `syndesi` | 0 | **16** | **LIVE (bedrock)** — `httpx::sse`, `httpx::websocket`, `httpx::h2`, `actix::Responder` |
| `appfold` | 0 | **14** | **LIVE (bedrock)** — `httpx::websocket` (5 items) |
| `sang-codspeed`, `spbench`, `immichfold` | 0 | 5 / 5 / — | **LIVE (bedrock)** — `openapi::{call, Connector, derive}` |
| `biota/bin` (`meteroid_sidecar`, `s3_gateway`, `epihogue`) | 0 | **~90** | **LIVE (bedrock)** — `x402`, `s3_gateway`, `actix`. Not a crate-map member: rule 4 |
| `kleis` | 0 | 23 | bedrock-era paths, mixed |
| `webfold-fleet` / `sangdb-bench` / `wachd-rust` | 3 / 2 / 1 | 0 | trivial `Client` users |
| `margin`, `conduit`, `memoryfold`, `ai-gateway`, `saga`, `caretakerd`, `telos`, `peregrine-ng`, `ptyktos`, `ptyktos-forge` | **0** | **0** | **ZERO consumers** |
| biota's own members: `app`, `auth`, `openapi`, `sheets`, `content`, `techdocs`, `serve` | **0** | **0** | **ZERO.** `git grep 'biota-http-server' 4ce2dcd -- '*/Cargo.toml'` returns only `http-server/Cargo.toml` itself. `biota/app/Cargo.toml:11` depends on **`bedrock` with `features=["native"]`**, i.e. biota runs on the deprecated FSL-1.1 copy |

**The crate map's premise is wrong:** "biota's own members are consumers" is false — none of them
depend on `biota-http-server`. Servelet cannot be validated against them; the validating consumers
are nexus, ptyktos-api, relayfold-control, relayfold-helm/proxy-runtime, ptyktos-webgui, opsfold,
syndesi and appfold.

## 9. Recommended cut list and extraction order

### 9.1 Spine — extract in this order (nexus switches over after step 8)

| # | crate | why now | evidence row |
|---|---|---|---|
| 1 | `servelet-core` | `hashtrinity` only; every other crate and every consumer needs it; nexus uses 6 of its names | §2 rows 1-6, §7 |
| 2 | `servelet-router` | nexus's 6 `Router` users + `platform::service::{Layer,Service}` land here; `tokio`+`bytes` only | §2 Axum face, §3b `service`, §7 |
| 3 | `servelet-h1` (+ `serve_gracefully`) | nexus calls `serve` in 4 places; this is what makes nexus run | §2 Wire/`serve`, §3a `graceful`, §7 |
| 4 | `servelet-cookie` | std only; forced by `HttpResponseBuilder` in step 5 | §1 `httpx::cookie`, §7 |
| 5 | `servelet-sse` | 14 live callers; nexus SSE depends on `HttpResponseBuilder` | §1 `httpx::sse`, §6, §7 |
| 6 | `servelet-tls` | 4 live callers in proxy-runtime; independent of 1-3 | §2 TLS, §7 |
| 7 | `servelet-client` | 34 live callers (relayfold-control, ptyktos-webgui, caretaker engines, opsfold); takes the pool + client TLS from the same file | §2 Client + pool + Wire-tail, §7 |
| 8 | `servelet-limits` / `-cors` / `-static` / `-authed` | already inside nexus; moving them makes the swap mechanical | §4 file:line table |

Then, only when a consumer asks: `servelet-h2` (29 bedrock-era callers), `servelet-ws` (93),
`servelet-openapi` (22), `servelet-acme` (0 callers, UNKNOWN priority, heaviest dependency set of
any candidate — rule 6 says it must be behind an off-by-default feature).

### 9.2 Drop from servelet — zero `biota_http_server` callers

9,110 lines: `x402` 595 · `nel` 562 · `filter` 614 · `multipart` 294 · `graphql` 303 ·
`s3_gateway` 118 · masquerade + 5 masqs 299 · `web` 8 · `test` 28 · `httpsrv` alias 4 ·
`lorelake_dataset` 2 · `kernel/sangdb.rs` 89 · `runtime::{alloc,cache,metrics,cluster,cron,daemon,
fiber,work,task_metrics,tracecontext}` 4,039 · `platform::{cli,settings,service_info,harness_state}` 976 ·
`helpers.rs` 517 of 518.

### 9.3 Not-dropped but out of scope (rule 4) — keep them as *other programs*

`webhook` (280, 135 opsfold call sites), `x402` (595, 72 in `biota/bin`), `s3_gateway` (118, 16 in
`biota/bin`), `nel`, `graphql`, `filter`. These have real callers; the answer is not "nobody uses
them" but "they are clients of an HTTP server, not server logic". opsfold and biota's binaries
should own them as separate crates and lose their `bedrock` dependency in the same change.

### 9.4 Blocking facts for the coordinator

1. No biota member depends on `biota-http-server` (§8) — the first validation target must be
   **nexus**, exactly as the brief says.
2. `kernel.rs` is 29% `#[cfg(test)]` and `runtime.rs` is 94% not-HTTP (§2, §3a). The extractable
   surface is roughly **8,000 lines**, not 19,583 — plan the crate map to that number.
3. **NOT RUN**: no build, no `cargo tree`, no test run, no line-count gate. This document is a
   read-only census only; every number in it is a `wc -l` or a `grep -c`.