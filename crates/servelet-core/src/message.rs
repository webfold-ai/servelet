use super::*;

// -- Request / Response -------------------------------------------------

#[derive(Clone, Debug)]
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub extensions: Extensions,
    pub peer_addr: Option<std::net::SocketAddr>,
}

impl Request {
    pub fn new(method: Method, uri: Uri) -> Self {
        Request {
            method,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Vec::new(),
            extensions: Extensions::new(),
            peer_addr: None,
        }
    }

    /// The TCP peer's socket address — actix's `HttpRequest::connection_info().peer_addr()`
    /// equivalent, set once by `serve_connection` from the listener's `accept()` and otherwise
    /// `None` (constructed directly via `Request::new`, e.g. in a unit test). `with_peer_addr`
    /// exists for tests that need to exercise IP-derived logic without a real socket.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr
    }

    pub fn with_peer_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    /// actix's `HttpRequest::connection_info()` — bundles the raw TCP peer address with the
    /// proxy-aware "real" client address (`X-Forwarded-For`'s first hop, falling back to the
    /// peer address when absent). A fresh value per call (matching actix's own — it's a cheap,
    /// header-derived read, not cached state).
    pub fn connection_info(&self) -> ConnectionInfo {
        let peer_addr = self.peer_addr.map(|a| a.ip().to_string());
        let realip_remote_addr = self
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| peer_addr.clone());
        ConnectionInfo { peer_addr, realip_remote_addr }
    }
}

/// actix's `dev::ConnectionInfo` — see [`Request::connection_info`].
pub struct ConnectionInfo {
    peer_addr: Option<String>,
    realip_remote_addr: Option<String>,
}

impl ConnectionInfo {
    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }

    pub fn realip_remote_addr(&self) -> Option<&str> {
        self.realip_remote_addr.as_deref()
    }
}

impl Request {
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    pub fn path(&self) -> &str {
        self.uri.path()
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    // CUT (deviation, docs/SPINE.md): `Request::cookies()` / `Request::cookie()` moved out with
    // their only dependency, `crate::httpsrv::httpx::cookie::Cookie` — that module is
    // `servelet-cookie`, a LATER unit of this extraction (README crate map). They are not
    // reimplemented here as a stub: a stub would be a second home for cookie parsing, which
    // rule 1 ("one home per capability") forbids. They return unchanged when
    // `servelet-cookie` lands.
    //
    // Every cookie sent on the `Cookie:` request header — actix's `HttpRequest::cookies()`
    // (real crate returns a `Result`; every request header here is already valid UTF-8 by the
    // time it reaches `HeaderMap`, so there's nothing to fail on).

    /// actix's `HttpRequest::app_data::<T>()` — reads back whatever `Router::with_state`
    /// injected (the same `Arc<T>`-in-`Extensions` mechanism `App::app_data`/`Data<T>` use), by
    /// reference rather than a clone.
    pub fn app_data<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<Arc<T>>().map(|arc| arc.as_ref())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    pub fn with_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

// DEVIATION (docs/SPINE.md): the five fields below are `pub` where biota left them private.
// Reason: biota's `kernel.rs` was ONE module, so the wire writer in `servelet-h1` could touch
// `response.version`/`status`/`headers`/`body` directly. Splitting the module turns that
// privacy into a compile error. Making the fields `pub` is the smallest edit that preserves the
// exact same semantics (no added validation, no new accessor behaviour); the accessors above
// stay and remain the preferred API for consumers.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub url: Uri,
    pub extensions: Extensions,
}

impl Response {
    pub fn new(status: StatusCode, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: body.into(),
            url: "/".parse().expect("static URI parses"),
            extensions: Extensions::new(),
        }
    }

    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Response::new(StatusCode::OK, body)
    }

    pub fn not_found() -> Self {
        Response::new(StatusCode::NOT_FOUND, "not found")
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn url(&self) -> &Uri {
        &self.url
    }

    pub fn with_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub async fn text(self) -> Result<String> {
        String::from_utf8(self.body).map_err(|e| Error::Parse(e.to_string()))
    }

    pub async fn bytes(self) -> Vec<u8> {
        self.body
    }

    /// Create a streaming body from a byte chunk — replaces reqwest's `bytes_stream()`.
    /// Each call returns a single-chunk stream (the full buffered body). True streaming
    /// requires an un-buffered HTTP reader (future feature).
    pub fn stream_body(&self) -> Vec<u8> {
        self.body.clone()
    }
}
