//! `App` + `HttpServer` + `to_handler1_async`, replaced — and this file compiles, so the
//! replacement in `docs/EXTENSIONS.md` §2 is evidence, not a claim.
//!
//! What the actix-era consumer wrote (measured, `biota/http-server` `lib.rs:7-863` at rev
//! `4ce2dcd`; live call site `ptyktos-webgui/src/main.rs:11`):
//!
//! ```ignore
//! use biota_http_server::actix::{App, HttpServer, to_handler1_async};
//! HttpServer::new(|| App::new().route("/api/ping", web::post().to(to_handler1_async(ping))))
//!     .bind(addr)?
//!     .run()
//!     .await
//! ```
//!
//! What it writes instead. A handler is a plain `Fn(Request) -> impl Future`, the router is a
//! value, and the server is one function argument:
//!
//! ```ignore
//! async fn ping(_req: Request) -> Response { Response::ok("pong") }
//! let app = Router::new().get("/api/ping", ping);
//! serve(addr, app).await
//! ```

use servelet_core::{Method, Request, Response};
use servelet_h1::serve;
use servelet_router::Router;

/// The `to_handler1_async` replacement: no macro, no wrapper type, no arity. Any
/// `Fn(Request) -> impl Future<Output = Response>` is a handler.
async fn ping(_req: Request) -> Response {
    Response::ok("pong")
}

/// The `App` replacement: one router, built by value.
fn app() -> Router {
    let inner = Router::new().route_sync(Method::POST, "/echo", |req| {
        let body = req.body().to_vec();
        Response::new(servelet_core::StatusCode::CREATED, body)
    });
    Router::new().get("/api/ping", ping).nest("/v1", inner)
}

/// The `HttpServer` replacement. One function; the router is the whole configuration surface.
/// Binds `127.0.0.1:0` and hands back the address it got, so the caller (or a test) can drive it.
async fn run(addr: &str) -> std::io::Result<()> {
    serve(addr, app()).await.map_err(|e| match e {
        servelet_core::Error::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    })
}

fn main() {
    // Not started by default: `cargo run --example replace_actix` would hang forever, and
    // examples in this repo are compiled by `cargo test --workspace`, not run.
    let _ = run;
    println!("see docs/EXTENSIONS.md section 2");
}