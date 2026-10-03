//! `servelet-router` — path routing with params and wildcards, `nest`, `merge`, `layer`.
//!
//! One job: turn a `Request` into the `Response` the route registered for its (method, path),
//! or a 404 / the router's `fallback`.
//!
//! Moved byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`, lines
//! 2446-2815 ("Axum face: router/handler"). Two pieces were brought with it:
//!   * `impl Service<Request> for Router`, from `kernel/platform.rs` lines 1127-1138 — without
//!     it `Router::layered` has nothing to wrap.
//!   * the `Service`/`Layer` traits it wraps with, which live in `servelet-core` (see that
//!     crate's `service.rs` for why they moved rather than being cut).
//!
//! This crate does not know TLS, sockets or bytes exist. It speaks `Request` in, `Response` out.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use servelet_core::{Extensions, Method, Request, Response, StatusCode};

// `CoordMap` for the literal-route fast path, `PHI` for the route coordinate.
use hashtrinity::{Coord, CoordMap, PHI};

mod router;

pub use router::{BoxHandler, PathParams, Router};

/// `Router` as a `Service<Request>` — this impl is what lets any `L: Layer<Router>` wrap the
/// whole router (see `Router::layered`). Moved from `kernel/platform.rs` lines 1126-1138.
impl servelet_core::Service<Request> for Router {
    type Response = Response;
    type Error = servelet_core::Error;

    async fn ready(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    async fn serve(&mut self, req: Request) -> std::result::Result<Self::Response, Self::Error> {
        Ok(self.handle(req).await)
    }
}