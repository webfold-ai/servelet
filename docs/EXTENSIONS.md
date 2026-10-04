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

## 4. The formatter seam (`servelet-h1` ⇄ `servelet-sse`)

**Commits:** `feat(h1): a formatter seam…` and `feat(sse): servelet-sse…`.

**The problem.** In biota, `serve_connection` (kernel.rs) named `write_sse_response` (kernel.rs)
directly, because both were in one crate. `servelet-sse` needs to own the SSE framing and
`servelet-h1` must not depend on it (rule 2: no crate needs to know another exists unless it is
named in its `Cargo.toml`, and the reverse edge would make the wire crate know the framing crate).

**The seam.** A response carries the writer that should drain it. `servelet-h1` defines
`StreamFormatter` (`crates/servelet-h1/src/streaming.rs`); `serve_connection` takes one out of the
response's extensions if it is there, and runs its own chunked writer if it is not. The value
travels next to the body it writes, which is where the dispatch always started. No global, no
registry, no "installed once" (rule 3), and `servelet-h1` never names an SSE type.

**Two shapes, and why the second.** The first version passed the `StreamingBody` to the
formatter. That cannot work: an SSE body is a different type, and the crate that knows it is the
one that must be able to use it. The formatter now takes the whole `Response` and pulls its own
body out — the only shape that works without `servelet-h1` naming the body.

**Higher-ranked over the writer's lifetime.** The future writes to the stream it was handed, so
it borrows it. It is awaited in place, never spawned, which is why it does not need to be
`'static` and why nothing in the seam can outlive the connection.

**Proved, not claimed.** `crates/servelet-h1/tests/socket.rs` asserts over a real socket that a
stashed formatter's header and bytes reach the wire *and* that the chunked framing it did not ask
for is absent, and that a response with no formatter still gets the default writer.
`crates/servelet-sse/tests/socket.rs` then drives the SSE path end to end.

## 5. `servelet-client`: the three deviations, and the optional TLS feature

**Commit:** `feat(client): servelet-client…`. Parent is the pure move.

**1. `splitmix64` is defined in-crate.** biota re-exported it from `transport`
(`kernel.rs:3221`; `http-server/Cargo.toml:31`). The census (§7) measured `transport` at **zero**
hits in the client's span, and a five-line public-domain mixing function does not justify pulling
in a crate whose own tree carries TLS and a load balancer. Same algorithm, same constants,
byte-identical output. Copied from `transport/src/http_client.rs:21`.

**2. `connection_close` is duplicated.** biota had exactly **one** copy (`kernel.rs:3008`), in the
*server* half, and the client called it from across the same crate. It now lives in
`servelet-h1`, where the server half moved. Making `servelet-client` depend on `servelet-h1` to
read one header would drag the router, the accept loop and the graceful drain into an HTTP client.
Six lines, byte-identical expression.

**3. Visibility.** `CookieJar`, `StoredCookie`, `parse_http_date`, `parse_rfc3339`,
`cookie_path_matches` and `is_expired` were private inside one big crate and are `pub` here,
because the twelve moved tests reach them. No behaviour change.

**Client TLS is behind an off-by-default feature** (rule 6), and that is a measured claim:

| features | `cargo tree -p servelet-client --prefix none \| sort -u \| wc -l` |
|---|---|
| default (`[]`) | **36** |
| `tls` | **47** |

The census (§7) said client TLS was *optional*; it did not say it was cheap. It is eleven
packages — `rustls`, `ring`, `rustls-native-certs`, `rustls-pki-types` among them — which is
exactly what the feature exists to keep away from a plaintext consumer.

**Without the feature an `https://` URL returns `Error::Tls` naming the feature.** It does not
silently downgrade; a client that quietly spoke plaintext to a TLS port would be a security bug,
not a default. `crates/servelet-client/tests/tls_feature.rs` asserts both halves of that and runs
green with the feature on and off.

## 6. Still to be extracted by later units (recorded here so nothing is lost)

Not in this unit's scope, from `docs/EXTRACTION.md` §9.1, in census order: `servelet-h2` (29
bedrock-era callers), `servelet-ws` (93), `servelet-openapi` (22), `servelet-acme` (0 callers,
heaviest dependency set of any candidate — rule 6 says it must sit behind an off-by-default
feature), and the nexus-resident layers `servelet-limits`, `servelet-cors`, `servelet-static`,
`servelet-authed`.
## 7. The upgrade seam (`servelet-h1` ⇄ `servelet-ws`)

**Commits:** `feat(ws): servelet-ws…` and the upgrade seam added after it.

### The gap it closes

`biota/http-server` had `websocket::accept` and no way to reach it from a handler. `serve_connection`
reads a request, hands the **parsed `Request`** to the `Router`, writes a response and moves on — so
the `TcpStream` never leaves the function that owns it. A handler could compute a `101`, but the
socket stayed behind, and there is no WebSocket without the socket. The proof that this blocks
real work is `nexus/docs/runs.md` §8.1 on branch `yokoszn/nexus-runs`: cezar's two realtime topics
(health, host) and the kaneo board sockets — 2 of the 17 slice-1 routes — cannot be served.

### Why a response extension and not a Layer

A `Layer` sees `(Request, Response)` and never the stream, so a Layer structurally cannot do this:
the value the protocol needs is the connection itself, and a Layer is never handed it. The seam is
therefore a **value in the response's own `Extensions`** — the same shape as the formatter seam
(§4), so there is no second mechanism to learn and no global to install.

```rust
// 1. the handler decides whether this is an upgrade at all, and says no if it is not
fn ws_echo(req: Request) -> Response {
    if !req.headers().contains_key("sec-websocket-key") {
        return Response::new(StatusCode::BAD_REQUEST, "not an upgrade");  // 400, never upgraded
    }
    let req = Arc::new(req);            // `accept` reads Sec-WebSocket-Key out of the Request
    with_upgrade(Response::new(StatusCode::OK, Vec::new()), Arc::new(move |conn: Upgraded| {
        let req = req.clone();           // the callback is `Fn`: clone per call, before `async move`
        Box::pin(async move {
            let mut ws = accept(conn, &req, Vec::new()).await?;   // writes the 101 itself
            while let Ok(Message::Text(t)) = ws.recv().await {
                ws.send_text(t).await?;
            }
            Ok(())
        })
    }))
}
```

Three properties this buys, each of which a test pins:

- **A refusal stays a refusal.** A handler that does not upgrade returns an ordinary response and
  nothing in this path runs. `serve_connection` cannot upgrade a connection nobody asked to upgrade.
- **The `101` is the protocol's, not the writer's.** `with_upgrade` sets no status and no headers:
  `servelet_ws::accept` writes `101 Switching Protocols`, `Upgrade`, `Connection` and
  `Sec-WebSocket-Accept` itself, byte-for-byte from biota. The HTTP response writer, which knows
  nothing about switching protocols, stays out of the upgrade path entirely.
- **Pipelined bytes survive the handover.** The callback receives the `BufReader`, unread buffer and
  all — not the bare stream. A WebSocket client routinely puts its first frame in the same TCP
  read as the handshake; handing over the reader is what keeps those bytes out of a corrupt first
  `recv()`. (`servelet-ws`'s `WebSocket.pending` is the same problem one layer up, for the
  handshake's own reader.)

`serve_connection` uses `return`, not `break`, at the handover: past that point the reader belongs
to the callback, so the loop's clean-shutdown must not touch it and nothing more is written.

### Authorization is not optional, and it is not the seam's job

The seam gives a handler the power to take the socket, so something in front of the handler has to
be able to refuse — which is the auth layer's job, not this crate's, and it must run *before* the
handler returns an upgrade at all. `crates/servelet-ws/tests/upgrade.rs` puts a role-checked
`Layer` over the whole `Router` and asserts, over real sockets: no credentials → `401`, wrong role
→ `403`, missing `Sec-WebSocket-Key` → `400`, wrong `Origin` → `400`, and in every refusal case no
`101` appears on the wire.

One fact that shapes any real deployment is recorded there rather than worked around: **a browser's
WebSocket API cannot set a header on the handshake** (RFC 6455 §10.4). A real auth layer must also
accept the credential in a cookie or the query string; the test's layer reads `?token=` for exactly
that reason, and compares it in constant time.

### The cost, measured

`servelet-ws`'s **runtime** dependency count is unchanged at **38**. Its `cargo tree` figure is
**48** because `tests/upgrade.rs` drives the path a consumer actually uses — a `Router`, the auth
layer, `serve_connection`, a real listener — and those are dev-dependencies. `budget/deps.tsv` is
raised to 48 to match, and `scripts/mutation.sh` mutation **K** stops `serve_connection`
dispatching the upgrade at all and shows the real-socket tests going red, so the seam is pinned by
behaviour rather than by its own documentation.
