use super::*;

// -- Native http-crate surface ------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    CONNECT,
    TRACE,
    Other(String),
}

/// `req.method()` returns `&Method`; real rauthy handler/middleware code (written against the
/// `http` crate's `Method`, which supports this) compares it directly against an owned value —
/// `req.method() == Method::GET`, not `req.method() == &Method::GET`. `#[derive(PartialEq)]`
/// alone only gives `Method: PartialEq<Method>`, not this cross (reference, owned) comparison.
impl PartialEq<Method> for &Method {
    fn eq(&self, other: &Method) -> bool {
        *self == other
    }
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::DELETE => "DELETE",
            Method::PATCH => "PATCH",
            Method::HEAD => "HEAD",
            Method::OPTIONS => "OPTIONS",
            Method::CONNECT => "CONNECT",
            Method::TRACE => "TRACE",
            Method::Other(s) => s.as_str(),
        }
    }

    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        )
    }

    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Method::GET
                | Method::HEAD
                | Method::OPTIONS
                | Method::TRACE
                | Method::PUT
                | Method::DELETE
        )
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            "CONNECT" => Method::CONNECT,
            "TRACE" => Method::TRACE,
            other if !other.is_empty() => Method::Other(other.to_string()),
            _ => return Err(Error::Parse("empty method".into())),
        })
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    HTTP_10,
    HTTP_11,
    HTTP_2,
    HTTP_3,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const OK: StatusCode = StatusCode(200);
    pub const CREATED: StatusCode = StatusCode(201);
    pub const ACCEPTED: StatusCode = StatusCode(202);
    pub const NO_CONTENT: StatusCode = StatusCode(204);
    pub const RESET_CONTENT: StatusCode = StatusCode(205);
    pub const PARTIAL_CONTENT: StatusCode = StatusCode(206);
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode(301);
    pub const FOUND: StatusCode = StatusCode(302);
    pub const NOT_MODIFIED: StatusCode = StatusCode(304);
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const NOT_ACCEPTABLE: StatusCode = StatusCode(406);
    pub const PRECONDITION_REQUIRED: StatusCode = StatusCode(428);
    pub const TOO_MANY_REQUESTS: StatusCode = StatusCode(429);
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode(500);
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode(503);

    pub fn from_u16(code: u16) -> Result<Self> {
        if (100..=999).contains(&code) {
            Ok(StatusCode(code))
        } else {
            Err(Error::Parse(format!("bad status code: {code}")))
        }
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }

    pub fn is_informational(self) -> bool {
        (100..200).contains(&self.0)
    }

    pub fn is_success(self) -> bool {
        (200..300).contains(&self.0)
    }

    pub fn is_redirection(self) -> bool {
        (300..400).contains(&self.0)
    }

    pub fn is_client_error(self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn is_server_error(self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn status_reason(status: StatusCode) -> &'static str {
    match status.as_u16() {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderName(String);

impl HeaderName {
    pub fn from_static(s: &'static str) -> Self {
        HeaderName(normalize_header_name(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for HeaderName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for HeaderName {
    fn from(value: &str) -> Self {
        HeaderName(normalize_header_name(value))
    }
}

impl From<String> for HeaderName {
    fn from(value: String) -> Self {
        HeaderName(normalize_header_name(&value))
    }
}

impl FromStr for HeaderName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(Error::Parse(format!("bad header name: {s}")));
        }
        Ok(HeaderName(normalize_header_name(s)))
    }
}

impl std::fmt::Display for HeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderValue(Vec<u8>);

impl HeaderValue {
    pub fn from_static(s: &'static str) -> Self {
        HeaderValue(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_str(&self) -> std::result::Result<&str, str::Utf8Error> {
        str::from_utf8(&self.0)
    }
}

impl From<&str> for HeaderValue {
    fn from(value: &str) -> Self {
        HeaderValue(value.as_bytes().to_vec())
    }
}

impl From<String> for HeaderValue {
    fn from(value: String) -> Self {
        HeaderValue(value.into_bytes())
    }
}

impl From<Vec<u8>> for HeaderValue {
    fn from(value: Vec<u8>) -> Self {
        HeaderValue(value)
    }
}

impl From<u32> for HeaderValue {
    fn from(value: u32) -> Self {
        HeaderValue::from(value.to_string())
    }
}

impl From<i64> for HeaderValue {
    fn from(value: i64) -> Self {
        HeaderValue::from(value.to_string())
    }
}

impl FromStr for HeaderValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(HeaderValue::from(s))
    }
}

impl std::fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_str() {
            Ok(s) => f.write_str(s),
            Err(_) => write!(f, "{:?}", self.0),
        }
    }
}

fn normalize_header_name(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

pub mod header {
    pub const ACCEPT: &str = "accept";
    pub const ACCEPT_ENCODING: &str = "accept-encoding";
    pub const AUTHORIZATION: &str = "authorization";
    pub const CONNECTION: &str = "connection";
    pub const CONTENT_LENGTH: &str = "content-length";
    pub const CONTENT_TYPE: &str = "content-type";
    pub const HOST: &str = "host";
    pub const TRANSFER_ENCODING: &str = "transfer-encoding";
    pub const USER_AGENT: &str = "user-agent";
    pub const COOKIE: &str = "cookie";
    pub const SET_COOKIE: &str = "set-cookie";
    pub const LOCATION: &str = "location";
    pub const CACHE_CONTROL: &str = "cache-control";
    pub const ETAG: &str = "etag";
    pub const ACCEPT_LANGUAGE: &str = "accept-language";
    pub const ACCESS_CONTROL_ALLOW_CREDENTIALS: &str = "access-control-allow-credentials";
    pub const ACCESS_CONTROL_ALLOW_HEADERS: &str = "access-control-allow-headers";
    pub const ACCESS_CONTROL_ALLOW_METHODS: &str = "access-control-allow-methods";
    pub const ACCESS_CONTROL_ALLOW_ORIGIN: &str = "access-control-allow-origin";
    pub const ACCESS_CONTROL_EXPOSE_HEADERS: &str = "access-control-expose-headers";
    pub const ACCESS_CONTROL_MAX_AGE: &str = "access-control-max-age";
    pub const CONTENT_ENCODING: &str = "content-encoding";
    pub const CONTENT_SECURITY_POLICY: &str = "content-security-policy";
    pub const ORIGIN: &str = "origin";
    pub const WWW_AUTHENTICATE: &str = "www-authenticate";
    pub const IF_NONE_MATCH: &str = "if-none-match";
    pub const VARY: &str = "vary";

    /// Strip a `;q=0.8`-style quality parameter (and any other `;param=value` suffix) off one
    /// comma-separated `Accept`/`Accept-Encoding` entry, trimming whitespace either side.
    fn strip_params(entry: &str) -> &str {
        entry.split(';').next().unwrap_or(entry).trim()
    }

    /// `actix_web::http::header::Accept` — a parsed `Accept:` request header. Scope, stated
    /// honestly: quality values are parsed off (so the list order reflects the header's own
    /// order, not a quality-sorted one) since every real call site only checks *membership*
    /// (`.iter().any(|p| p.item.essence_str() == "text/html")`), never picks "the best match".
    #[derive(Debug, Clone, Default)]
    pub struct Accept(pub Vec<QualityItem<MediaType>>);

    impl Accept {
        pub fn parse(raw: &str) -> Self {
            Accept(
                raw.split(',')
                    .map(strip_params)
                    .filter(|s| !s.is_empty())
                    .map(|s| QualityItem { item: MediaType(s.to_string()) })
                    .collect(),
            )
        }

        pub fn iter(&self) -> impl Iterator<Item = &QualityItem<MediaType>> {
            self.0.iter()
        }
    }

    /// One `Accept`/`Accept-Encoding` entry, quality value already stripped (see [`Accept`]'s
    /// doc comment) — the real crate's `QualityItem<T>` shape, minus the quality field nothing
    /// here reads.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct QualityItem<T> {
        pub item: T,
    }

    /// A bare `type/subtype` media type — real crate's `mime::Mime`, scoped to the one method
    /// (`essence_str`) every call site actually uses.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MediaType(String);

    impl MediaType {
        pub fn essence_str(&self) -> &str {
            &self.0
        }
    }

    /// `actix_web::http::header::AcceptEncoding` — a parsed `Accept-Encoding:` request header.
    #[derive(Debug, Clone, Default)]
    pub struct AcceptEncoding(pub Vec<QualityItem<Encoding>>);

    impl AcceptEncoding {
        pub fn parse(raw: &str) -> Self {
            AcceptEncoding(
                raw.split(',')
                    .map(strip_params)
                    .filter(|s| !s.is_empty())
                    .map(|s| QualityItem { item: Encoding(s.to_string()) })
                    .collect(),
            )
        }

        pub fn contains(&self, enc: &Encoding) -> bool {
            self.0.iter().any(|q| &q.item == enc)
        }
    }

    /// One content-coding token (`"br"`/`"gzip"`/`"deflate"`/...) — real crate's `Encoding`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Encoding(String);

    impl std::str::FromStr for Encoding {
        type Err = std::convert::Infallible;

        fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
            Ok(Encoding(s.trim().to_string()))
        }
    }
}

#[derive(Clone, Debug)]
struct HeaderEntry {
    name: String,
    values: Vec<HeaderValue>,
}

#[derive(Clone, Debug)]
pub struct HeaderMap {
    inner: CoordMap<u64, HeaderEntry>,
}

impl Default for HeaderMap {
    fn default() -> Self {
        HeaderMap::new()
    }
}

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap {
            inner: CoordMap::coordinate(),
        }
    }

    pub fn insert(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        let name = name.into().0;
        self.inner.put(
            header_coord(&name),
            HeaderEntry {
                name,
                values: vec![value.into()],
            },
        );
    }

    pub fn append(&mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) {
        let name = name.into().0;
        self.inner.insert_with(
            header_coord(&name),
            HeaderEntry {
                name,
                values: vec![value.into()],
            },
            |mut new, mut old| {
                old.values.append(&mut new.values);
                old
            },
        );
    }

    pub fn get(&self, name: impl AsRef<str>) -> Option<&HeaderValue> {
        self.inner
            .get(&header_coord(name.as_ref()))
            .and_then(|entry| entry.values.first())
    }

    pub fn get_all(&self, name: impl AsRef<str>) -> &[HeaderValue] {
        self.inner
            .get(&header_coord(name.as_ref()))
            .map(|entry| entry.values.as_slice())
            .unwrap_or(&[])
    }

    pub fn contains_key(&self, name: impl AsRef<str>) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &HeaderValue)> {
        self.inner.iter().flat_map(|(_, entry)| {
            let name = entry.name.as_str();
            entry.values.iter().map(move |value| (name, value))
        })
    }

    pub fn len(&self) -> usize {
        self.inner.iter().map(|(_, entry)| entry.values.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// actix-web's real `HeaderMap` implements `IntoIterator` for `&HeaderMap` directly (so `for (k,
/// v) in req.headers()` works without an explicit `.iter()`) — matched here rather than making
/// every caller add `.iter()`.
impl<'a> IntoIterator for &'a HeaderMap {
    type Item = (&'a str, &'a HeaderValue);
    type IntoIter = Box<dyn Iterator<Item = (&'a str, &'a HeaderValue)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

fn header_coord(s: &str) -> u64 {
    let s = s.trim();
    let mut acc = 0u64;
    for b in s.bytes() {
        acc = acc.rotate_left(5) ^ (b.to_ascii_lowercase() as u64).wrapping_mul(PHI);
    }
    acc ^ (s.len() as u64).wrapping_mul(PHI)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uri {
    raw: String,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path_and_query: String,
}

impl Uri {
    pub fn scheme_str(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn port_u16(&self) -> Option<u16> {
        self.port
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    /// The path alone, query string stripped — what route matching needs. `path_and_query`
    /// stays available for handlers that want the query (`req.uri().path_and_query()`).
    pub fn path(&self) -> &str {
        self.path_and_query
            .split_once('?')
            .map_or(&self.path_and_query[..], |(p, _)| p)
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for Uri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        parse_uri(s)
    }
}

pub fn parse_uri(s: &str) -> Result<Uri> {
    if s.is_empty() {
        return Err(Error::Url("empty URI".into()));
    }

    let (scheme, rest) = match s.find("://") {
        Some(i) => (Some(s[..i].to_ascii_lowercase()), &s[i + 3..]),
        None => (None, s),
    };

    let (authority, path) = if scheme.is_some() {
        match rest.find(|c| c == '/' || c == '?') {
            Some(i) => {
                let path = if rest[i..].starts_with('?') {
                    format!("/{}", &rest[i..])
                } else {
                    rest[i..].to_string()
                };
                (&rest[..i], path)
            }
            None => (rest, "/".to_string()),
        }
    } else {
        ("", s.to_string())
    };

    let (host, port) = parse_authority(authority)?;
    let path_and_query = if path.is_empty() { "/".into() } else { path };

    Ok(Uri {
        raw: s.to_string(),
        scheme,
        host,
        port,
        path_and_query,
    })
}

fn parse_authority(authority: &str) -> Result<(Option<String>, Option<u16>)> {
    if authority.is_empty() {
        return Ok((None, None));
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::Url("bad IPv6 authority".into()))?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .map(str::parse::<u16>)
            .transpose()
            .map_err(|e| Error::Url(format!("bad port: {e}")))?;
        return Ok((Some(host), port));
    }

    match authority.rsplit_once(':') {
        Some((host, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            let port = p
                .parse::<u16>()
                .map_err(|e| Error::Url(format!("bad port: {e}")))?;
            Ok((Some(host.to_string()), Some(port)))
        }
        _ => Ok((Some(authority.to_string()), None)),
    }
}

pub fn host_port(uri: &Uri) -> Result<(String, u16)> {
    let host = uri.host().ok_or_else(|| Error::Url("no host".into()))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    Ok((host.to_string(), port))
}

