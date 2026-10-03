//! `servelet-cookie` — parse a `Cookie:` request header, build a `Set-Cookie` response cookie.
//!
//! One job: cookies. It does not route, does not write a response, and does not know a
//! `Request` or a `Response` exists — `servelet-sse`'s `HttpResponseBuilder` and any consumer
//! pass it `Cookie<'static>` values.
//!
//! Moved byte-for-byte from `biota/http-server`'s `lib.rs` at rev `4ce2dcd`, lines 1910-2135
//! (the `pub mod cookie { .. }` body). The six `#[cfg(test)]` tests moved with it to
//! `tests/moved.rs`. `Domain` and `Partitioned` were added afterwards, in their own commit;
//! see `docs/EXTENSIONS.md`.
//!
//! std only: zero dependencies, measured over the whole span (census section 7).

#![forbid(unsafe_code)]

//! cookie — an HTTP cookie parser/builder matching the `cookie` crate's public shape (the one
//! actix-web re-exports as `actix_web::cookie`), native against this crate's own types, no
//! third-party dependency. Scope, stated honestly: the RFC 6265 attributes rauthy's own cookie
//! wrapper (`ApiCookie`) actually sets — `Secure`/`HttpOnly`/`SameSite`/`Max-Age`/`Path` — plus
//! parsing an incoming `Cookie:` request header into individual name/value pairs. `Domain`,
//! `Expires`, and cookie-jar/signing helpers the real crate has are NOT ported; nothing in this
//! codebase's server path uses them.

use std::borrow::Cow;

/// `crate::httpsrv::httpx::cookie::SameSite` — the three legal values, matching the real crate's naming and
/// `Set-Cookie` wire serialization exactly (`Strict`/`Lax`/`None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// `crate::httpsrv::httpx::cookie::time::Duration` — real crate's `Cookie::max_age` type. Scoped to what `ApiCookie`
/// actually constructs: a non-negative, whole-second duration (`ZERO` or `seconds(n)`), not the
/// full signed/sub-second `time` crate type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(i64);

impl Duration {
    pub const ZERO: Duration = Duration(0);

    pub fn seconds(secs: i64) -> Duration {
        Duration(secs)
    }

    pub fn whole_seconds(self) -> i64 {
        self.0
    }
}

/// `crate::httpsrv::httpx::cookie::time` — the real crate nests `Duration` under a `time` submodule
/// (`crate::httpsrv::httpx::cookie::time::Duration::ZERO`); this mirrors that path exactly so call sites don't change.
pub mod time {
    pub use super::Duration;
}

/// One HTTP cookie — `crate::httpsrv::httpx::cookie::Cookie<'c>`. Parsed from a `Cookie:` request header (name/value
/// only — a request-header cookie carries no attributes, per RFC 6265 §5.4) or built via
/// [`Cookie::build`] for a `Set-Cookie` response header (name/value + the attributes above).
#[derive(Clone, Debug)]
pub struct Cookie<'c> {
    name: Cow<'c, str>,
    value: Cow<'c, str>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
    max_age: Option<Duration>,
    path: Option<Cow<'c, str>>,
}

impl<'c> Cookie<'c> {
    /// A bare name/value cookie with no attributes — the shape a parsed request cookie has.
    pub fn new(name: impl Into<Cow<'c, str>>, value: impl Into<Cow<'c, str>>) -> Self {
        Cookie {
            name: name.into(),
            value: value.into(),
            secure: false,
            http_only: false,
            same_site: None,
            max_age: None,
            path: None,
        }
    }

    /// Start a builder for a `Set-Cookie` response cookie — real crate's `Cookie::build(name,
    /// value) -> CookieBuilder`.
    pub fn build(name: impl Into<Cow<'c, str>>, value: impl Into<Cow<'c, str>>) -> CookieBuilder<'c> {
        CookieBuilder { cookie: Cookie::new(name, value) }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    /// Format as a `Set-Cookie` header value: `name=value; Attr; Attr=val; ...`.
    pub fn encoded(&self) -> String {
        let mut s = format!("{}={}", self.name, self.value);
        if let Some(path) = &self.path {
            s.push_str(&format!("; Path={path}"));
        }
        if let Some(max_age) = self.max_age {
            s.push_str(&format!("; Max-Age={}", max_age.whole_seconds()));
        }
        if self.secure {
            s.push_str("; Secure");
        }
        if self.http_only {
            s.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            s.push_str(&format!("; SameSite={}", same_site.as_str()));
        }
        s
    }

    /// Parse a single `Cookie:` request header value (`"a=1; b=2"`) into name/value pairs, each
    /// trimmed of surrounding whitespace. No percent-decoding — RFC 6265 cookie values are opaque
    /// bytes on the wire; this crate's own callers base64-encode/decrypt their own payloads.
    pub fn parse_header(header_value: &str) -> Vec<Cookie<'static>> {
        header_value
            .split(';')
            .filter_map(|pair| {
                let pair = pair.trim();
                if pair.is_empty() {
                    return None;
                }
                let (name, value) = pair.split_once('=')?;
                Some(Cookie::new(name.trim().to_string(), value.trim().to_string()))
            })
            .collect()
    }
}

/// `crate::httpsrv::httpx::cookie::CookieBuilder` — chainable attribute setters, terminated by [`CookieBuilder::finish`].
pub struct CookieBuilder<'c> {
    cookie: Cookie<'c>,
}

impl<'c> CookieBuilder<'c> {
    pub fn secure(mut self, secure: bool) -> Self {
        self.cookie.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.cookie.http_only = http_only;
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.cookie.same_site = Some(same_site);
        self
    }

    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.cookie.max_age = Some(max_age);
        self
    }

    pub fn path(mut self, path: impl Into<Cow<'c, str>>) -> Self {
        self.cookie.path = Some(path.into());
        self
    }

    pub fn finish(self) -> Cookie<'c> {
        self.cookie
    }
}
