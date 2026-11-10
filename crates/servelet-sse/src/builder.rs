// DEVIATION, the module's `use` line only: biota's `pub mod actix` imported these for the whole
// module (lib.rs 29-33). Only the four names this file actually uses are imported here, from the
// two crates that now own them; nothing is re-declared or renamed.
use wirefold::codec::syntax::{AsTerm, SyntaxTerm};
use servelet_cookie::Cookie;
use servelet_core::{Response, StatusCode};

fn builder(status: StatusCode) -> HttpResponseBuilder {
HttpResponseBuilder { status, headers: servelet_core::HeaderMap::new(), cookies: Vec::new() }
}

/// actix's `HttpResponseBuilder` — chainable attribute setters, terminated by `.finish()`,
/// `.body(...)`, or `.json(...)`.
pub struct HttpResponseBuilder {
status: StatusCode,
headers: servelet_core::HeaderMap,
cookies: Vec<Cookie<'static>>,
}

impl HttpResponseBuilder {
/// actix's `HttpResponseBuilder::new(status)` — the general entry point `ResponseError`
/// impls use (they compute their own `StatusCode`, so they don't go through the per-status
/// `HttpResponse::Ok()`-style constructors above).
pub fn new(status: StatusCode) -> Self {
    builder(status)
}

pub fn insert_header(
    &mut self,
    header: (impl Into<servelet_core::HeaderName>, impl Into<servelet_core::HeaderValue>),
) -> &mut Self {
    self.headers.insert(header.0, header.1);
    self
}

/// Adds a header without replacing any existing value under the same name — actix's
/// `append_header`, distinct from `insert_header` (WWW-Authenticate/Set-Cookie-style
/// headers that can legally repeat).
pub fn append_header(
    &mut self,
    header: (impl Into<servelet_core::HeaderName>, impl Into<servelet_core::HeaderValue>),
) -> &mut Self {
    self.headers.append(header.0, header.1);
    self
}

pub fn content_type(&mut self, mime: impl Into<servelet_core::HeaderValue>) -> &mut Self {
    self.headers.insert(servelet_core::header::CONTENT_TYPE, mime);
    self
}

pub fn cookie(&mut self, cookie: Cookie<'static>) -> &mut Self {
    self.cookies.push(cookie);
    self
}

fn build(&self, status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = Response::new(status, body);
    for (name, value) in self.headers.iter() {
        resp.headers_mut().insert(name.to_string(), value.clone());
    }
    for cookie in &self.cookies {
        resp.headers_mut().append(servelet_core::header::SET_COOKIE, cookie.encoded());
    }
    resp
}

pub fn finish(&mut self) -> Response {
    self.build(self.status, Vec::new())
}

pub fn body(&mut self, body: impl Into<Vec<u8>>) -> Response {
    self.build(self.status, body.into())
}

/// actix's `HttpResponseBuilder::streaming(stream)` — an arbitrary byte stream piped into a
/// chunked response body, written to the wire as each chunk arrives (not buffered into
/// memory first). Scoped to an `mpsc::Receiver` rather than a generic `futures::Stream` (the
/// same choice `crate::sse::Sse` made): bedrock has no dependency on the `futures` ecosystem crate,
/// and every real caller (an S3 object proxy download) already has — or can trivially build —
/// a channel, by draining whatever stream type its own HTTP client returns into one first.
/// Errors are pre-stringified into the channel's `Err(String)` rather than kept generic, so
/// the stashed type (`StreamingBody`) stays concrete regardless of the caller's own error type.
pub fn streaming(&mut self, rx: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>) -> Response {
        let resp = self.build(self.status, Vec::new());
        // DEVIATION, one line, and it is the seam: biota stashed its own crate-private
        // `StreamingBody` here. `servelet-h1` owns that type (it is what its writer looks
        // for) and exposes `streaming(..)` to put one on a response. Same value, same place.
        servelet_h1::streaming(resp, rx)
}

pub fn json<T: AsTerm>(&mut self, value: T) -> Response {
    let term = value.to_term();
    let body = wirefold::codec::syntax::render_surface(&term, wirefold::codec::syntax::Surface::Json);
    self.content_type("application/json");
    self.build(self.status, body.into_bytes())
}

/// The reference-taking sibling of [`json`](Self::json) — `AsTerm::to_term` only ever needs
/// `&self`, so a caller holding a borrowed value (e.g. a `&'static` config singleton with no
/// `Clone`) shouldn't need to clone just to satisfy `json`'s by-value signature.
pub fn json_ref<T: AsTerm>(&mut self, value: &T) -> Response {
    let term = value.to_term();
    let body = wirefold::codec::syntax::render_surface(&term, wirefold::codec::syntax::Surface::Json);
    self.content_type("application/json");
    self.build(self.status, body.into_bytes())
}
}
