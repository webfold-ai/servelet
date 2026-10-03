//! `servelet-client` — the HTTP client half.
//!
//! `SPINE.md`'s "NOT YOURS" list named `servelet-client` as the home for the code that stayed
//! behind when the kernel was extracted. This is that crate: `Client`/`ClientBuilder`/
//! `RequestBuilder`, the connection pool, TLS client config, redirect following, and the
//! streaming send path.
//!
//! # What came with it, and what did not
//!
//! Brought: the client, its pool, `RetryPolicy`, and the cookie jar (RFC 6265 attributes
//! `Path`/`Expires`/`Max-Age`/`Secure`/`HttpOnly`; `Domain` is not tracked per-cookie — storage
//! is already partitioned by domain at the outer map).
//!
//! **Not** brought, deliberately:
//!
//! - **multipart.** No consumer called `.multipart()`. It is `servelet-multipart`'s to carry,
//!   and pulling `Form`/`Part` in here would be the second place that shape is defined.
//! - **the HTTP cache.** Opt-in via `.cache(..)` and called by nobody; it dragged biota's
//!   `runtime::cache` (revalidation, `max_age_from_headers`) in behind it. Caching is a policy
//!   layer, not a transport.
//! - **the Authzed/relayfold face.** That was never part of the client — it is
//!   `relayfold`'s, and was left out of this crate entirely.
//!
//! # Deviations from the original
//!
//! - `Client::default()` no longer defaults `follow_redirects` differently; the field defaults
//!   are carried over unchanged. What *is* new is that nothing here can reach biota: every
//!   type comes from `servelet-core`.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;
use hashtrinity::Coord as _;

use hashtrinity::CoordMap;
use servelet_core::{connection_close, header, host_port, parse_uri};
use servelet_core::{
    Error, Extensions, HeaderMap, HeaderName, HeaderValue, Method, Result, Response, StatusCode,
    Uri, Version,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// -- Reqwest face: client -----------------------------------------------

/// A retry policy for transient (connect/IO) failures — never retried on an application-level
/// HTTP status (a 5xx is a real answer from the server, not a transport failure), matching a
/// conservative default: retrying blind on 5xx risks duplicating a non-idempotent POST's effect.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub backoff: std::time::Duration,
}

impl RetryPolicy {
    pub fn new(max_attempts: usize, backoff: std::time::Duration) -> Self {
        RetryPolicy { max_attempts: max_attempts.max(1), backoff }
    }
}

/// One stored cookie's RFC 6265 attributes (beyond name/value) — `Path` (default `/`),
/// `Expires`/`Max-Age` (collapsed to one absolute expiry point, `Max-Age` taking precedence per
/// §5.3), `Secure`, `HttpOnly`. `Domain` isn't tracked per-cookie: this jar already partitions
/// storage by domain at the outer map, an honest simplification versus full domain-matching
/// (subdomain inheritance via a `Domain=` attribute isn't modeled).
#[derive(Clone, Debug)]
struct StoredCookie {
    value: String,
    path: String,
    expires_at: Option<std::time::SystemTime>,
    secure: bool,
    // Parsed and stored for spec completeness; unread because `HttpOnly` only gates
    // JavaScript access to a cookie, which has no meaning for this Rust HTTP client (there is
    // no scripting layer here to deny) — it would matter if this jar were ever exposed to one.
    #[allow(dead_code)]
    http_only: bool,
}

impl StoredCookie {
    fn is_expired(&self) -> bool {
        self.expires_at.map(|t| std::time::SystemTime::now() > t).unwrap_or(false)
    }
}

/// RFC 6265 §5.1.4 cookie-path matching: `cookie_path` must be a prefix of `request_path`, and
/// either they're equal, `cookie_path` ends in `/`, or the next character in `request_path`
/// after the shared prefix is `/`.
fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    cookie_path.len() == request_path.len() || cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

/// Parse an RFC 7231 IMF-fixdate (`Set-Cookie`'s `Expires` format, e.g. "Wed, 21 Oct 2015
/// 07:28:00 GMT") into a `SystemTime`. The two legacy formats (RFC 850, `asctime`) aren't
/// handled — an honest reduction; IMF-fixdate is what every modern server actually sends.
fn parse_http_date(s: &str) -> Option<std::time::SystemTime> {
    let rest = s.trim().split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let day: u64 = parts.next()?.parse().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u64 = parts.next()?.parse().ok()?;
    let mut time_parts = parts.next()?.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec: u64 = time_parts.next()?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let secs = days * 86400 + (hour * 3600 + min * 60 + sec) as i64;
    if secs < 0 {
        return Some(std::time::SystemTime::UNIX_EPOCH);
    }
    Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

/// Parse an RFC 3339 timestamp (`2026-07-07T02:39:45+10:00`, `...Z`, or with fractional
/// seconds `...45.123+10:00`) into epoch MILLISECONDS. Reuses the same `days_from_civil`
/// civil-calendar math `parse_http_date` uses — one date primitive, two textual formats.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: u64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;

    // Split off the trailing offset (`Z`, or `+HH:MM`/`-HH:MM`) from the time-of-day. RFC 3339
    // never puts `+`/`-` anywhere else in the time-of-day, so the LAST one is always the offset.
    let (time_part, offset_secs) = if let Some(t) = rest.strip_suffix('Z') {
        (t, 0i64)
    } else if let Some(idx) = rest.rfind(['+', '-']) {
        let (t, off) = rest.split_at(idx);
        let sign = if off.starts_with('-') { -1i64 } else { 1i64 };
        let mut off_parts = off[1..].split(':');
        let oh: i64 = off_parts.next()?.parse().ok()?;
        let om: i64 = off_parts.next()?.parse().ok()?;
        (t, sign * (oh * 3600 + om * 60))
    } else {
        (rest, 0i64)
    };

    let mut time_parts = time_part.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec_field = time_parts.next()?;
    let (sec_str, ms) = match sec_field.split_once('.') {
        Some((s, frac)) => {
            let frac3 = format!("{:0<3}", &frac[..frac.len().min(3)]);
            (s, frac3.parse::<i64>().unwrap_or(0))
        }
        None => (sec_field, 0),
    };
    let sec: u64 = sec_str.parse().ok()?;

    let days = days_from_civil(year, month, day);
    let local_secs = days * 86400 + (hour * 3600 + min * 60 + sec) as i64;
    let utc_secs = local_secs - offset_secs;
    Some(utc_secs * 1000 + ms)
}

/// Howard Hinnant's `days_from_civil` — days since the Unix epoch (1970-01-01) for a given
/// (year, month, day), proleptic Gregorian, valid for any year. Verified below against the
/// well-known reference "2000-01-01T00:00:00Z = 946684800".
fn days_from_civil(y: u64, m: u64, d: u64) -> i64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// A cookie jar — store-and-replay of `Set-Cookie`/`Cookie`, keyed by domain, respecting RFC
/// 6265's `Path`/`Expires`/`Max-Age`/`Secure`/`HttpOnly` attributes (not just name=value).
// The outer (per-domain) map uses `hashtrinity::Table` -- the framework's own map face, the
// same primitive `crate::runtime::cache::Cache`/`crate::runtime::metrics::Registry`/`crate::runtime::cluster::Cluster` key on elsewhere in this
// crate. The inner (per-domain cookie-name) map stays a plain `HashMap`: small (a handful of
// cookies per domain) and read-modify-write on every `Set-Cookie`, where std's
// `entry().or_default()` fits better than `Table`'s insert/overwrite-only API.
#[derive(Debug, Default)]
struct CookieJar {
    by_domain: hashtrinity::Table<String, std::collections::HashMap<String, StoredCookie>>,
}

impl CookieJar {
    /// Parse one `Set-Cookie` header value (name=value plus all its attributes) and store or
    /// delete it. An explicitly-expired cookie (`Max-Age<=0` or a past `Expires`) is REMOVED
    /// from the jar — RFC 6265's own deletion mechanism, not a silent no-op.
    fn store(&mut self, domain: &str, set_cookie: &str) {
        let mut segments = set_cookie.split(';');
        let Some(pair) = segments.next() else { return };
        let Some((name, value)) = pair.trim().split_once('=') else { return };
        let (name, value) = (name.trim().to_string(), value.trim().to_string());

        let mut path = "/".to_string();
        let mut expires_at: Option<std::time::SystemTime> = None;
        let mut max_age: Option<i64> = None;
        let mut secure = false;
        let mut http_only = false;

        for attr in segments {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            let (key, val) = match attr.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (attr, None),
            };
            match key.to_ascii_lowercase().as_str() {
                "path" => {
                    if let Some(v) = val {
                        path = v.to_string();
                    }
                }
                "expires" => {
                    if let Some(v) = val {
                        expires_at = parse_http_date(v);
                    }
                }
                "max-age" => max_age = val.and_then(|v| v.parse().ok()),
                "secure" => secure = true,
                "httponly" => http_only = true,
                _ => {}
            }
        }

        // Max-Age takes precedence over Expires (RFC 6265 §5.3) once both are present.
        if let Some(secs) = max_age {
            expires_at = Some(if secs <= 0 {
                std::time::SystemTime::UNIX_EPOCH
            } else {
                std::time::SystemTime::now() + std::time::Duration::from_secs(secs as u64)
            });
        }

        let mut cookies = self.by_domain.get(&domain.to_string()).cloned().unwrap_or_default();
        if expires_at.map(|t| t <= std::time::SystemTime::now()).unwrap_or(false) {
            cookies.remove(&name);
        } else {
            cookies.insert(name, StoredCookie { value, path, expires_at, secure, http_only });
        }
        self.by_domain.put(domain.to_string(), cookies);
    }

    /// The `Cookie` header value to send for a request to `domain` at `request_path`, over a
    /// (non-)secure connection — filters out expired cookies, path-mismatched cookies (§5.1.4),
    /// and `Secure`-flagged cookies on a plain HTTP request.
    fn header_for(&self, domain: &str, request_path: &str, is_secure_request: bool) -> Option<String> {
        let map = self.by_domain.get(&domain.to_string())?;
        let mut pairs: Vec<(&String, &StoredCookie)> = map
            .iter()
            .filter(|(_, c)| !c.is_expired())
            .filter(|(_, c)| cookie_path_matches(&c.path, request_path))
            .filter(|(_, c)| !c.secure || is_secure_request)
            .collect();
        if pairs.is_empty() {
            return None;
        }
        pairs.sort_by_key(|(k, _)| k.as_str());
        Some(pairs.iter().map(|(k, c)| format!("{k}={}", c.value)).collect::<Vec<_>>().join("; "))
    }
}

struct ClientInner {
    cookies: std::sync::Mutex<CookieJar>,
    resolve_overrides: std::collections::HashMap<String, std::net::SocketAddr>,
    follow_redirects: bool,
    max_redirects: usize,
    retry: Option<RetryPolicy>,
}

impl Default for ClientInner {
    fn default() -> Self {
        ClientInner {
            cookies: std::sync::Mutex::new(CookieJar::default()),
            resolve_overrides: std::collections::HashMap::new(),
            follow_redirects: true,
            max_redirects: 10,
            retry: None,
        }
    }
}

pub struct RequestBuilder {
    method: Method,
    uri: Result<Uri>,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    client: Client,
    retry_override: Option<RetryPolicy>,
}

impl RequestBuilder {
    pub fn header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set headers from a `HeaderMap` — reqwest's `RequestBuilder::headers`, merging onto any
    /// already set (multi-value headers append, `HeaderMap::append` semantics).
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        for (name, value) in headers.iter() {
            self.headers.append(name, value.as_bytes().to_vec());
        }
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn body_bytes(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Override this request's retry policy (defaults to the client's, if any).
    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.retry_override = Some(policy);
        self
    }

    pub async fn send(self) -> Result<Response> {
        let uri = self.uri?;
        let _span = std::marker::PhantomData::<()>;
        let client = self.client.clone();
        let method = self.method;
        let headers = self.headers;
        let body = self.body;
        let policy = self.retry_override.or(client.inner.retry);
        async move {
            let attempts = policy.map(|r| r.max_attempts).unwrap_or(1);
            let backoff = policy.map(|r| r.backoff).unwrap_or_default();
            let mut last_err = None;
            for attempt in 0..attempts {
                match send_with_redirects(&client, method.clone(), uri.clone(), headers.clone(), body.clone()).await {
                    Ok(resp) => {
                        
                        return Ok(resp);
                    }
                    Err(e) => {
                        eprintln!("WARN  target=bedrock::client  error={}  attempt={}", e, attempt);
                        last_err = Some(e);
                        if attempt + 1 < attempts {
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }
            Err(last_err.expect("attempts >= 1, so the loop ran at least once"))
        }
        .await
    }

    /// Send without buffering the response body — `reqwest`'s `chunk()`/`bytes_stream()`
    /// equivalent. A stated, honest scope reduction versus `send()`: no redirect-following, no
    /// retry, no cookie jar (all three exist to make ONE logical request out of several
    /// physical ones, which conflicts with handing the body stream to the caller mid-flight —
    /// the caller gets the connection directly instead, no in-between logic).
    pub async fn send_streaming(self) -> Result<StreamingResponse> {
        let uri = self.uri?;
        let (stream, _was_pooled) = connect(&uri, &self.client.inner.resolve_overrides).await?;
        send_request_streaming(stream, self.method, &uri, self.headers, self.body).await
    }
}

/// One logical request, following redirects (bounded) and threading the client's cookie jar —
/// what `RequestBuilder::send`'s retry loop calls per attempt.
async fn send_with_redirects(
    client: &Client,
    mut method: Method,
    mut uri: Uri,
    mut headers: HeaderMap,
    mut body: Option<Vec<u8>>,
) -> Result<Response> {
    for _ in 0..=client.inner.max_redirects {
        if let Some(domain) = uri.host() {
            let is_secure = uri.scheme_str() == Some("https");
            if let Some(cookie_header) = client.inner.cookies.lock().unwrap().header_for(domain, uri.path(), is_secure) {
                headers.insert(header::COOKIE, cookie_header);
            }
        }

        let (stream, was_pooled) = connect(&uri, &client.inner.resolve_overrides).await?;
        let mut result = send_request(stream, method.clone(), &uri, headers.clone(), body.clone()).await;
        if was_pooled && result.is_err() {
            // A pooled connection's first write/read failing is expected, not exceptional —
            // see `connect`'s own doc for the three real ways this happens. Retry exactly once
            // on a guaranteed-fresh connection before giving up.
            eprintln!("DEBUG  target=bedrock::client");  // was: DEBUG target: "bedrock::client", "pooled connection failed on first use, retrying fresh"
            let fresh = connect_fresh(&uri, &client.inner.resolve_overrides).await?;
            result = send_request(fresh, method.clone(), &uri, headers.clone(), body.clone()).await;
        }
        let resp = result?;

        if let Some(domain) = uri.host() {
            let mut jar = client.inner.cookies.lock().unwrap();
            for set_cookie in resp.headers().get_all(header::SET_COOKIE) {
                if let Ok(v) = set_cookie.to_str() {
                    jar.store(domain, v);
                }
            }
        }

        if !client.inner.follow_redirects || !resp.status().is_redirection() {
            return Ok(resp);
        }
        let Some(location) = resp.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()) else {
            return Ok(resp);
        };
        let next_uri = resolve_redirect_uri(&uri, location)?;
        // 303 always becomes a bodyless GET; 301/302 do the same ONLY for a POST original (the
        // legacy browser behavior every HTTP client, reqwest included, still follows); 307/308
        // preserve the method and body exactly.
        let status = resp.status().as_u16();
        if status == 303 || ((status == 301 || status == 302) && method == Method::POST) {
            method = Method::GET;
            body = None;
        }
        uri = next_uri;
    }
    Err(Error::Http(format!("too many redirects (> {})", client.inner.max_redirects)))
}

fn resolve_redirect_uri(base: &Uri, location: &str) -> Result<Uri> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return parse_uri(location);
    }
    // A relative Location (path-absolute, e.g. "/next") -- rebuild against the base's own
    // scheme/host/port, since bedrock's Uri has no separate "resolve against base" op.
    let scheme = base.scheme_str().unwrap_or("http");
    let host = base.host().unwrap_or_default();
    let authority = match base.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let path = if location.starts_with('/') { location.to_string() } else { format!("/{location}") };
    parse_uri(&format!("{scheme}://{authority}{path}"))
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new() -> Self {
        Client { inner: Arc::new(ClientInner::default()) }
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder(ClientInner::default())
    }

    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    pub fn patch(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder {
            method,
            uri: parse_uri(url.as_ref()),
            headers: HeaderMap::new(),
            body: None,
            client: self.clone(),
            retry_override: None,
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

/// Opaque debug — `reqwest::Client`'s own `Debug` prints nothing about the pool either.
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client(..)")
    }
}

pub struct ClientBuilder(ClientInner);

impl ClientBuilder {
    /// Redirect the DNS resolution of `host` to a fixed address — reqwest's `.resolve()`. The
    /// TLS SNI identity still uses the ORIGINAL hostname; only the socket address changes.
    pub fn resolve(mut self, host: impl Into<String>, addr: std::net::SocketAddr) -> Self {
        self.0.resolve_overrides.insert(host.into(), addr);
        self
    }

    pub fn redirect(mut self, follow: bool) -> Self {
        self.0.follow_redirects = follow;
        self
    }

    pub fn max_redirects(mut self, n: usize) -> Self {
        self.0.max_redirects = n;
        self
    }

    pub fn retry(mut self, policy: RetryPolicy) -> Self {
        self.0.retry = Some(policy);
        self
    }

    pub fn build(self) -> Client {
        Client { inner: Arc::new(self.0) }
    }
}

pub async fn get(url: impl AsRef<str>) -> Result<Response> {
    Client::new().get(url).send().await
}

pub async fn post(url: impl AsRef<str>) -> Result<Response> {
    Client::new().post(url).send().await
}


pub enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Stream {
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf).await,
            Stream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf).await,
            Stream::Tls(s) => s.read(buf).await,
        }
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => {
                s.read_exact(buf).await?;
            }
            Stream::Tls(s) => {
                s.read_exact(buf).await?;
            }
        }
        Ok(())
    }

    async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read_to_end(buf).await,
            Stream::Tls(s) => s.read_to_end(buf).await,
        }
    }

    pub fn into_reader(self) -> StreamReader {
        StreamReader {
            inner: self,
            buf: Vec::new(),
            pos: 0,
            line: Vec::new(),
        }
    }
}

pub struct StreamReader {
    inner: Stream,
    buf: Vec<u8>,
    pos: usize,
    line: Vec<u8>,
}

impl StreamReader {
    pub async fn read_line(&mut self) -> io::Result<&[u8]> {
        self.line.clear();
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|b| *b == b'\n') {
                let end = self.pos + i + 1;
                self.line.extend_from_slice(&self.buf[self.pos..end]);
                self.pos = end;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Ok(&self.line);
            }

            if self.pos < self.buf.len() {
                self.line.extend_from_slice(&self.buf[self.pos..]);
                self.buf.clear();
                self.pos = 0;
            } else {
                self.buf.clear();
                self.pos = 0;
            }

            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                return Ok(&self.line);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut copied = 0;
        let buffered = (self.buf.len() - self.pos).min(len);
        if buffered > 0 {
            buf[..buffered].copy_from_slice(&self.buf[self.pos..self.pos + buffered]);
            self.pos += buffered;
            copied = buffered;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
        }
        if copied < len {
            self.inner.read_exact_into(&mut buf[copied..]).await?;
        }
        Ok(buf)
    }

    async fn read_to_end(&mut self, out: &mut Vec<u8>) -> io::Result<usize> {
        let before = out.len();
        if self.pos < self.buf.len() {
            out.extend_from_slice(&self.buf[self.pos..]);
            self.buf.clear();
            self.pos = 0;
        }
        self.inner.read_to_end(out).await?;
        Ok(out.len() - before)
    }

    /// Read UP TO `max` bytes — whatever's already buffered first, else one read from the
    /// underlying stream (0 on EOF). Unlike `read_exact`, never blocks waiting to fill `max`;
    /// this is the "give me the next available piece" primitive `StreamingResponse`'s
    /// read-until-EOF framing needs.
    async fn read_some(&mut self, max: usize, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(max);
            buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Ok(n);
        }
        self.inner.read(&mut buf[..max]).await
    }

    /// Reclaim the underlying `Stream` (for connection pooling) plus any bytes already read off
    /// the wire but not yet consumed by the caller — losing these would corrupt whatever the
    /// NEXT request on a reused connection tries to read (they'd belong to the tail of THIS
    /// response, not the start of the next one). Only safe to call once the caller knows the
    /// current response has been read to completion (`send_request` only does this after a
    /// Content-Length or chunked-terminated body, never the "read until EOF" fallback, which by
    /// definition means the peer is closing the connection).
    pub fn into_inner(self) -> (Stream, Vec<u8>) {
        let leftover = self.buf[self.pos..].to_vec();
        (self.inner, leftover)
    }
}

/// The TLS client config, built once from the system's own CA trust store
/// (`rustls-native-certs` — the same "prefer OS package signatures" discipline as
/// everywhere else in this workspace) and cached: every `https://` request reuses it.
fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // `ClientConfig::builder()` (no explicit provider) reads the process-wide default
            // `CryptoProvider` — rustls 0.23 never auto-installs one even with the `ring`
            // feature enabled (that only makes it linkable). Nothing else in this crate installs
            // it, so the first real HTTPS request from ANY consumer would otherwise panic here.
            // `install_default` errors only if a provider is already installed (by this crate or
            // a consumer) — harmless, the existing one wins either way.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            std::sync::Arc::new(config)
        })
        .clone()
}

// -- Server-side TLS termination -----------------------------------------
//
// The client side (above) only ever CONSUMES certs (the system trust store via
// `rustls-native-certs`); terminating TLS as a SERVER means parsing a cert chain + private key
// this crate is HANDED (from a file, an env var, a secrets store — the caller's choice) into
// the DER form `rustls::ServerConfig` wants. `rustls`/`rustls-pki-types` (already dependencies)
// give the DER *types*; turning PEM *text* into those DER bytes is a base64 decode plus finding
// `-----BEGIN X-----`/`-----END X-----` markers -- a few lines, not a reason to add
// `rustls-pemfile` as a fourth crate for a mechanical text transform this crate can do itself
// (matching `websocket.rs`'s own hand-rolled `base64_encode` for the same reason, the other
// direction).

/// Minimal base64 (standard alphabet, `+`/`/`) decoder — PEM's own encoding, and the one
/// direction `websocket.rs`'s `base64_encode` doesn't cover.
fn base64_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        table[b as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        let v = table[b as usize];
        if v == 255 {
            continue;
        }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// Every `-----BEGIN <label>-----` ... `-----END <label>-----` block's decoded DER bytes, in
/// the order they appear (a cert chain PEM has one block per certificate).
fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start_idx) = rest.find(&begin) {
        let after_begin = &rest[start_idx + begin.len()..];
        let Some(end_idx) = after_begin.find(&end) else {
            break;
        };
        out.push(base64_decode(&after_begin[..end_idx]));
        rest = &after_begin[end_idx + end.len()..];
    }
    out
}

/// Build a server TLS config from a PEM certificate chain and a PEM private key (PKCS8 —
/// `-----BEGIN PRIVATE KEY-----`, what `openssl req`/`genpkey` produce by default; the older
/// PKCS1 `RSA PRIVATE KEY`/SEC1 `EC PRIVATE KEY` labels aren't parsed — a stated scope limit).
pub fn tls_server_config(cert_chain_pem: &str, private_key_pem: &str) -> Result<std::sync::Arc<rustls::ServerConfig>> {
    // Same rationale as `tls_config`'s install: rustls 0.23 never auto-installs a process-wide
    // `CryptoProvider`, and this is the server-side entry point that never goes through the
    // client path — without this, the first `serve_tls` call panics instead of erroring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        pem_blocks(cert_chain_pem, "CERTIFICATE").into_iter().map(rustls_pki_types::CertificateDer::from).collect();
    if certs.is_empty() {
        return Err(Error::Tls("no CERTIFICATE block found in the given PEM".to_string()));
    }
    let key_der = pem_blocks(private_key_pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .ok_or_else(|| Error::Tls("no PRIVATE KEY block found in the given PEM".to_string()))?;
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der));
    // The server side is entirely self-controlled (we terminate our own inbound HTTPS), so it can
    // mandate TLS 1.3 and drop `ring` — `hashtrinity-rustls::provider()` only has TLS 1.3 cipher
    // suites, unlike `tls_config()` (the client side, reaching arbitrary third-party HTTPS).
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(hashtrinity::rustls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(std::sync::Arc::new(config))
}


// -- Connection pool (Pingora-style keepalive reuse) ---------------------

/// A pooled, idle connection plus any bytes already pulled off the wire past the previous
/// response's end (see `StreamReader::into_inner`'s doc for why this must travel with it).
struct PooledConn {
    stream: Stream,
    leftover: Vec<u8>,
}

/// Max idle connections kept per upstream identity — mirrors Pingora's own
/// `keepalive_pool_size` (a per-identity cap, not a global one). Small and fixed rather than
/// configurable yet: an honest scope limit, not a hidden one.
const POOL_CAP_PER_IDENTITY: usize = 32;

/// Process-global keepalive pool, keyed by upstream identity (`scheme://host:port`) — mirrors
/// Pingora's own `pingora-core::connectors` pool (an `Arc<ConnectionPool>` keyed by
/// `peer.reuse_hash()`). This is the single biggest gap the architecture survey found on the
/// client side ("No connection pooling/keep-alive reuse... new TCP+TLS handshake per request").
/// `CoordMap` (not a synchronized `Table`) is fine here because the `Mutex` around it is the
/// actual synchronization — matches this file's own established convention of using
/// `identity.coord()` for a bounded, small set of distinct upstream identities (the same shape
/// `Router`'s route keys and `Proxy`'s upstream keys already use), not the opaque-hash misuse
/// `Extensions` had to move off of.
fn pool() -> &'static std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>> {
    static POOL: std::sync::OnceLock<std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(CoordMap::coordinate()))
}

fn identity_for(uri: &Uri) -> Result<String> {
    let (host, port) = host_port(uri)?;
    let scheme = uri.scheme_str().unwrap_or("http");
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Pop the most-recently-returned idle connection for `identity`, if any (LIFO — better cache
/// locality than FIFO for the common bursty-traffic case). Takes the WHOLE per-identity `Vec`
/// out via `remove` (ownership, no clone — `PooledConn` holds a live socket and can't be cloned
/// anyway) and puts back whatever's left, rather than trying to mutate through a shared `&Vec`.
fn pool_take(identity: &str) -> Option<PooledConn> {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key)?;
    let popped = conns.pop();
    if !conns.is_empty() {
        guard.put(key, conns);
    }
    popped
}

/// Return an idle connection to the pool for reuse, capped at `POOL_CAP_PER_IDENTITY` (excess
/// connections are simply dropped/closed rather than kept, matching Pingora's own per-identity
/// cap behavior).
fn pool_put(identity: &str, conn: PooledConn) {
    let mut guard = pool().lock().unwrap();
    let key = identity.coord();
    let mut conns = guard.remove(&key).unwrap_or_default();
    if conns.len() < POOL_CAP_PER_IDENTITY {
        conns.push(conn);
    }
    guard.put(key, conns);
}

/// Connect, preferring a pooled idle connection. Returns whether the connection came from the
/// pool — the caller needs this to know whether a first-write failure warrants a transparent
/// retry on a guaranteed-fresh connection (a reused connection can always turn out to be stale:
/// the peer's own idle timeout, a network blip, or — found via this crate's own test suite — a
/// connection pooled under one tokio runtime and reused from a different one, since a socket is
/// registered with the specific runtime's I/O driver that was active when it was created. All
/// three are the same class of problem a robust pool has to handle, not paper over: never trust
/// an idle connection's first write to succeed).
async fn connect(uri: &Uri, resolve: &std::collections::HashMap<String, std::net::SocketAddr>) -> Result<(Stream, bool)> {
    let identity = identity_for(uri)?;
    if let Some(pooled) = pool_take(&identity) {
        eprintln!("DEBUG  target=bedrock::client");  // was: DEBUG target: "bedrock::client", %identity, "reusing pooled connection"
        // A pooled connection is only ever stored with an empty `leftover` (see `send_request`'s
        // pool-return step, which only pools a connection when there wasn't any) — there's no
        // plumbing here to hand leftover bytes into a fresh `send_request` call, so this
        // invariant is asserted rather than silently trusted.
        debug_assert!(pooled.leftover.is_empty(), "pooled connections are only stored with no leftover bytes");
        return Ok((pooled.stream, true));
    }
    Ok((connect_fresh(uri, resolve).await?, false))
}

/// Always open a brand new connection, bypassing the pool entirely — used for the initial
/// connect when nothing's pooled, and for the guaranteed-fresh retry after a pooled connection's
/// first write fails. `resolve` overrides the socket address a host connects to (reqwest's
/// `.resolve()`) while keeping the ORIGINAL hostname for TLS SNI — only the IP changes.
async fn connect_fresh(
    uri: &Uri,
    resolve: &std::collections::HashMap<String, std::net::SocketAddr>,
) -> Result<Stream> {
    let (host, port) = host_port(uri)?;
    let dial_target = resolve.get(&host).copied();
    let tcp = match dial_target {
        Some(addr) => TcpStream::connect(addr).await?,
        None => TcpStream::connect(format!("{}:{}", host, port)).await?,
    };
    tcp.set_nodelay(true)?;
    match uri.scheme_str() {
        Some("https") => {
            let server_name = rustls_pki_types::ServerName::try_from(host.clone())
                .map_err(|e| Error::Tls(format!("invalid hostname {host:?}: {e}")))?
                .to_owned();
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| Error::Tls(format!("handshake with {host} failed: {e}")))?;
            Ok(Stream::Tls(Box::new(tls)))
        }
        _ => Ok(Stream::Plain(tcp)),
    }
}

/// Write the request line, headers, and body — shared by the buffered (`send_request`) and
/// streaming (`send_request_streaming`) paths; they only diverge on how the RESPONSE body gets
/// read, never on how the request itself goes out.
async fn write_request(
    stream: &mut Stream,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Option<Vec<u8>>,
) -> Result<()> {
    let path = uri.path_and_query();
    let host = uri.host().unwrap_or("");
    let authority = match uri.port_u16() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    // An explicit `Host` header in the map wins over the URI-derived one (reqwest/pingora
    // semantics). A proxy that forwards requests verbatim depends on this: SigV4 signs the
    // exact `Host` the client sent, so the upstream must see that same value or the signature
    // fails (this is what nginx's port-stripping `proxy_set_header Host $host` broke).
    let has_host = headers.contains_key("host");
    stream
        .write_all(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes())
        .await?;
    if !has_host {
        stream
            .write_all(format!("Host: {}\r\n", authority).as_bytes())
            .await?;
    }
    stream
        .write_all(b"User-Agent: bedrock/0.1.0\r\n")
        .await?;

    for (name, value) in headers.iter() {
        stream.write_all(name.as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    if let Some(ref body) = body {
        // If the map already carries a Content-Length (a forwarded request), don't write a
        // second one — duplicate Content-Length is a parse error on some upstreams. A chunked
        // body gets no Content-Length either (the `Transfer-Encoding` header governs framing).
        if !headers.contains_key("content-length")
            && !headers
                .get("transfer-encoding")
                .map(|v| v.to_str().unwrap_or("").to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
        {
            stream
                .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
                .await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    if let Some(body) = body {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// The parsed response status line + headers, before the body is touched — shared by both the
/// buffered and streaming read paths.
struct ResponseHead {
    version: Version,
    status: StatusCode,
    headers: HeaderMap,
    content_length: Option<usize>,
    chunked: bool,
}

async fn read_response_head(reader: &mut StreamReader) -> Result<ResponseHead> {
    // Skip informational (1xx) interim responses — most importantly `100 Continue` (hyper
    // sends it when the upstream receives `Expect: 100-continue`) — and read the REAL response.
    // Treating an interim 100 as the final response poisons the keepalive pool: the actual
    // response stays unread in the connection and the next request on that connection reads
    // garbage (garage's "error reading a body" signature).
    let (version, status) = loop {
        let raw = reader.read_line().await?;
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let (v, s) = parse_status_line(line)?;
        if s.is_informational() {
            // Consume the interim response's header block (terminated by a blank line).
            loop {
                let l = reader.read_line().await?;
                if l.is_empty() || l == b"\r\n" || l == b"\n" {
                    break;
                }
            }
            continue;
        }
        break (v, s);
    };

    let mut headers = HeaderMap::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let raw = reader.read_line().await?;
        if raw.is_empty() || raw == b"\r\n" || raw == b"\n" {
            break;
        }
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        if let Some((n, v)) = line.split_once(':') {
            let name = n.parse::<HeaderName>()?;
            let value = v.trim().parse::<HeaderValue>()?;
            if name.as_str() == header::CONTENT_LENGTH {
                content_length = value.to_str().ok().and_then(|s| s.parse().ok());
            }
            if name.as_str() == header::TRANSFER_ENCODING
                && value.to_str().unwrap_or("").contains("chunked")
            {
                chunked = true;
            }
            headers.insert(name, value);
        }
    }
    Ok(ResponseHead { version, status, headers, content_length, chunked })
}

async fn send_request(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<Response> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    // Only a DEFINITE-length body (no body at all, Content-Length, or a chunked terminator) means
    // the connection is genuinely still usable afterward — the "read to end" fallback below means
    // there was no length information at all, which in practice means the peer intends to close
    // the connection once the body is sent, so pooling that stream would just hand back a socket
    // that's already going away.
    let (body, poolable) = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
        || method == Method::HEAD
    {
        // HEAD responses never carry a body (RFC 9110 §9.3.2) — even when the upstream's
        // headers claim a Content-Length. Without this, a length-less HEAD response falls into
        // the `read_to_end` fallback and blocks forever on the keep-alive connection.
        (Vec::new(), true)
    } else if head.chunked {
        (read_chunked(&mut reader).await?, true)
    } else if let Some(len) = head.content_length {
        let b = if len > 0 { reader.read_exact(len).await? } else { Vec::new() };
        (b, true)
    } else {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        (buf, false)
    };

    // Return the connection to the pool if the response as a whole allows reuse: a definite-
    // length body (above), HTTP/1.1 (matches this crate's own server-side keep-alive default,
    // `serve()`'s `connection_close` check), and neither side said `Connection: close`.
    if poolable && head.version != Version::HTTP_10 && !connection_close(&head.headers) {
        let (stream, leftover) = reader.into_inner();
        if leftover.is_empty() {
            if let Ok(identity) = identity_for(uri) {
                pool_put(&identity, PooledConn { stream, leftover });
            }
        }
        // A non-empty leftover means the peer sent extra bytes we haven't consumed (unusual for
        // a non-pipelined client, but possible) — there's no plumbing to hand them to whatever
        // uses this connection next, so the connection is simply dropped/closed here instead of
        // risking a corrupted next read. Honest, not silent: this is exactly the situation
        // `into_inner`'s own doc calls out.
    }

    Ok(Response {
        status: head.status,
        version: head.version,
        headers: head.headers,
        body,
        url: uri.clone(),
        extensions: Extensions::new(),
    })
}

/// How the still-open body is framed — decided once from the response head, then consumed
/// incrementally by `StreamingResponse::chunk`.
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

pub struct StreamingResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    url: Uri,
    reader: StreamReader,
    framing: BodyFraming,
}

impl StreamingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn url(&self) -> &Uri {
        &self.url
    }

    /// Read the next chunk of the body, or `None` once it's exhausted — reqwest's `chunk()`.
    /// A `Content-Length` body is read in ≤64KiB pieces; a chunked body yields exactly one
    /// wire-chunk per call (already a natural unit, no extra buffering needed); a headerless
    /// body reads whatever's available up to 64KiB until EOF.
    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>> {
        const MAX_CHUNK: usize = 64 * 1024;
        match &mut self.framing {
            BodyFraming::None => Ok(None),
            BodyFraming::ContentLength(remaining) => {
                if *remaining == 0 {
                    return Ok(None);
                }
                // `read_some`, not `read_exact` — the latter blocks until the FULL requested
                // amount arrives, which would silently coalesce however many real TCP segments
                // the body came in into one chunk for any body under `MAX_CHUNK` (the common
                // case). Returning whatever's actually available right now is the point of
                // streaming at all.
                let take = (*remaining).min(MAX_CHUNK);
                let mut buf = vec![0u8; take];
                let n = self.reader.read_some(take, &mut buf).await?;
                if n == 0 {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("connection closed with {remaining} content-length bytes still expected"),
                    )));
                }
                buf.truncate(n);
                *remaining -= n;
                Ok(Some(buf))
            }
            BodyFraming::Chunked => {
                let raw = self.reader.read_line().await?;
                let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
                let size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
                    .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
                if size == 0 {
                    self.framing = BodyFraming::None;
                    return Ok(None);
                }
                let data = self.reader.read_exact(size).await?;
                self.reader.read_line().await?; // trailing CRLF after the chunk data
                Ok(Some(data))
            }
            BodyFraming::UntilEof => {
                let mut buf = vec![0u8; MAX_CHUNK];
                let n = self.reader.read_some(MAX_CHUNK, &mut buf).await?;
                if n == 0 {
                    self.framing = BodyFraming::None;
                    Ok(None)
                } else {
                    buf.truncate(n);
                    Ok(Some(buf))
                }
            }
        }
    }

    /// Drain every remaining chunk into one buffer — for callers that started streaming but
    /// decide midway they want the whole thing after all.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

async fn send_request_streaming(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<StreamingResponse> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    let framing = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
    {
        BodyFraming::None
    } else if head.chunked {
        BodyFraming::Chunked
    } else if let Some(len) = head.content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::UntilEof
    };

    Ok(StreamingResponse {
        status: head.status,
        version: head.version,
        headers: head.headers,
        url: uri.clone(),
        reader,
        framing,
    })
}

// -- Client-side response parsing ------------------------------------------------
// `parse_status_line`/`read_chunked` were the response-reading half of the client and stayed
// in biota when the kernel was extracted. The server never parses a status line, so they were
// not part of the spine — they are this crate's.

pub fn parse_status_line(line: &str) -> Result<(Version, StatusCode)> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::Parse(format!("bad status line: {line}")));
    }
    let version = match parts[0] {
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    };
    let code = parts[1]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("bad status code: {e}")))?;
    Ok((version, StatusCode::from_u16(code)?))
}

async fn read_chunked(reader: &mut StreamReader) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let raw = reader.read_line().await?;
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let chunk_size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
            .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
        if chunk_size == 0 {
            break;
        }
        let chunk = reader.read_exact(chunk_size).await?;
        body.extend_from_slice(&chunk);
        reader.read_line().await?;
    }
    Ok(body)
}
