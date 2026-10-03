# docs/EXTENSIONS.md — behaviour added after a move, and what a consumer does instead

README rule 9: **extraction is byte-for-byte.** A move is a move. Anything that *changes*
behaviour is a separate commit with its own tests, listed here. This file is the ledger of those
commits, and of the surfaces README rule 4 drops and their replacement.

Every "what a consumer does instead" is a real API that exists in this repo. No placeholders:
nothing reachable is `todo!()`.

## 1. `servelet-cookie`: `Domain`, `Partitioned`, and a refusing formatter

**Commit:** `feat(cookie): add Domain and Partitioned` (this unit). Parent commit is the pure move.

**Why:** `biota/http-server`'s `httpx::cookie` (`lib.rs:1910-2135`, rev `4ce2dcd`) sets only
`Secure`/`HttpOnly`/`SameSite`/`Max-Age`/`Path`; its own doc comment says so (`lib.rs:1913-1917`:
"`Domain`, `Expires`, and cookie-jar/signing helpers the real crate has are NOT ported").
`docs/EXTRACTION.md` §7 records the minimum dependencies and §1 records 0 external callers for
this module. The capability gap is also listed in
`~/projects/planning/unified-platform/runtime-auth.md` §5, and `nexus/src/cookie.rs:1-3` names it
in its first paragraph.

**Spec:** `nexus/src/cookie.rs` (`SetCookie`) and `nexus/tests/cookie.rs`, read-only at
`~/orca/workspaces/opsfold/nexus-foundation/nexus`. Every case in the nexus test appears in
`crates/servelet-cookie/tests/attributes.rs`, in this crate's own API shape.

**What was added:**
- `Cookie::domain(Option)` → `Domain=<v>`, serialized **before** `Path` (nexus and the real
  `cookie` crate both order it that way).
- `Cookie::partitioned(bool)` → `; Partitioned`, serialized **after** `SameSite` (CHIPS).
- `Cookie::try_encoded() -> Result<String, CookieError>` and `Cookie::expire(name)`.
- `CookieError::{InvalidToken, RequiresSecure}`.

**What deliberately did NOT change:** the order of the pre-existing attributes. biota emits
`Secure` then `HttpOnly`; nexus emits `HttpOnly` then `Secure`. This crate keeps biota's order, so
a cookie that never touches the new attributes serializes byte-for-byte as it did before the
move. The test `a_cookie_with_neither_attribute_encodes_exactly_as_it_did_before` pins that.

**Not added, on purpose:** `Expires` (a `Max-Age` covers every deletion this codebase does — see
the moved test `zero_max_age_is_a_real_deletion_marker_not_omitted`), cookie-jar storage, signing,
and `HttpOnly`-style prefixes. Rule 4: nothing that no caller asked for.

**Consumer impact:** none. `Cookie::encoded()` keeps its signature and its output for every cookie
that does not set `Domain`/`Partitioned`. Existing `CookieBuilder` chains compile unchanged.

## 2. Dropped under rule 4: the actix-web compatibility surface

**Dropped:** `Responder`, `to_handler0_async`, `to_handler1_async`, `App`, `HttpServer`, and the
rest of `biota/http-server`'s `actix` module (`lib.rs:7-863`, rev `4ce2dcd`). Census `docs/EXTRACTION.md`
§6 measured 857 lines and 15 call sites; only 7 items were live, and 5 of those 7 are this
compatibility surface:

| live item | call sites | replacement |
|---|---|---|
| `actix::HttpResponseBuilder` | 9, all nexus (`src/http/sse.rs:22`) | `servelet_sse::HttpResponseBuilder` — **kept**, in `servelet-sse` (see §3) |
| `actix::Json`, `actix::Responder` | 1 (`relayfold-control/src/app.rs:12`) | `Response::ok(serde_json_bytes)` / `Response::new(StatusCode::OK, body)`; `Json` itself is *not* in the spine yet (census §3b puts it in `platform.rs:2144-2321`, still unbuilt), so a consumer writes its own three-line extractor until `servelet-core` grows one |
| `to_handler0_async`, `to_handler1_async`, `App`, `HttpServer` | 1 (`ptyktos-webgui/src/main.rs:11`) | see below |

**What a consumer does instead — and this compiles.**
`crates/servelet-h1/examples/replace_actix.rs` is the whole replacement, side by side with the
actix-era call it replaces; `cargo test --workspace` builds it, so it cannot rot:

```rust
use servelet_core::{Method, Request, Response};
use servelet_h1::serve;
use servelet_router::Router;

// 1. Tests first. A handler is a plain function; drive it with a Request you build yourself.
async fn ping(_req: Request) -> Response { Response::ok("pong") }

// 2. `App` -> one Router, built by value.
fn app() -> Router {
    let inner = Router::new().route_sync(Method::POST, "/echo", |req| {
        Response::new(servelet_core::StatusCode::CREATED, req.body().to_vec())
    });
    Router::new().get("/api/ping", ping).nest("/v1", inner)
}

// 3. `HttpServer` -> one function. The router is the whole configuration surface.
async fn run(addr: &str) -> std::io::Result<()> { serve(addr, app()).await.map_err(/* .. */) }
```

Step by step, in the order a consumer hits them:

1. **Tests first.** Write the handler as a function and drive it with a `Request` you build
   yourself — no server, no framework, no runtime at all.
2. **`to_handlerN_async` → a closure or a plain `async fn`.** There is no macro and no wrapper
   type: a handler is any `Fn(Request) -> impl Future<Output = Response>` (`Router::route`,
   `crates/servelet-router/src/router.rs:153`), or `Fn(Request) -> Response` for a synchronous one
   (`route_sync`, same file line 163). Adapter code that wanted an arity-typed alias writes its own
   one-line function, in its own crate.
3. **`App` → `Router`.** One router, methods on it: `route`, `route_sync`, `get`, `post`, `nest`,
   `merge`, `fallback`, `with_state`, `layer`, `layered` (`crates/servelet-router/src/router.rs`).
   There is no `App` that owns an `HttpServer`; the two are separate crates, which is the point
   (rule 1).
4. **`HttpServer` → `servelet_h1::serve`, `serve_gracefully`, or `servelet_tls::serve_tls`.**
   Configuration that `HttpServer` used to carry in its builder becomes a function argument:
   `serve(addr, router)` (`crates/servelet-h1/src/wire.rs:115`) and
   `serve_gracefully(listener, router, drain_timeout)`
   (`crates/servelet-h1/src/graceful.rs:48`). Each takes what it needs and nothing else.
5. **`Responder` → nothing.** A consumer that implemented `Responder` to get `Into<Response>`
   returns a `Response` instead. Its constructors (`Response::ok`, `Response::new`,
   `Response::not_found`, `Response::with_header`, `Response::with_body`,
   `crates/servelet-core/src/message.rs:166-233`) cover every shape the trait produced.

**Migration cost, measured:** `ptyktos-webgui/src/main.rs:11` is the whole of it — one `use` line
and the `App`/`HttpServer` assembly in its `main`. The census (§8) lists the other framework-era
consumers; none of them is a biota member.

## 3. Where `HttpResponseBuilder` went, and why

The census is explicit and this unit follows it without splitting the difference.
`docs/EXTRACTION.md` §7's dependency table reads, verbatim:

> `servelet-sse` | `lib.rs` 2137-2471 + `HttpResponseBuilder` (`lib.rs` 130-228`) | **`tokio` (4+2),
> `hashtrinity` (4)** + `servelet-core`, `servelet-cookie` | the builder's `cookies: Vec<Cookie>` is
> the only cross-crate edge

So `HttpResponseBuilder` goes to **`servelet-sse`**, not `servelet-core`, and this is also the only
answer that keeps rule 1 true. Its two jobs are `streaming(..)` (the SSE streaming body) and
carrying `Set-Cookie` values, and the census measured its dependencies as *exactly* `servelet-sse`'s:
`tokio` (2 of `servelet-sse`'s 4 hits) plus `hashtrinity` (4, all of them). `servelet-core`
measured `hashtrinity` **only** — putting a `tokio`-using builder there would have forced a
runtime into the one crate that must work without one (`servelet-core/src/lib.rs`: "No tokio. No
reactor, no runtime, no sockets."). The only cross-crate edge is `cookies: Vec<Cookie<'static>>`,
and that edge points at `servelet-cookie`, which `servelet-sse` already depends on.

## 4. Still to be extracted by later units (recorded here so nothing is lost)

Not in this unit's scope, from `docs/EXTRACTION.md` §9.1, in census order: `servelet-h2` (29
bedrock-era callers), `servelet-ws` (93), `servelet-openapi` (22), `servelet-acme` (0 callers,
heaviest dependency set of any candidate — rule 6 says it must sit behind an off-by-default
feature), and the nexus-resident layers `servelet-limits`, `servelet-cors`, `servelet-static`,
`servelet-authed`.