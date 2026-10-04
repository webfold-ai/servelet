//! `Domain`, `Partitioned` and the refusing formatter — the behaviour added AFTER the
//! byte-for-byte move (see `docs/EXTENSIONS.md`). Spec: nexus's `SetCookie`
//! (`src/cookie.rs`) and `tests/cookie.rs`, read-only at nexus HEAD; these are the
//! same cases in this crate's own API shape.

use servelet_cookie::{Cookie, CookieError, Duration, SameSite};

#[test]
fn domain_is_serialized_before_path() {
    let h = Cookie::build("sid", "t")
        .domain(".example.com")
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .finish()
        .encoded();
    // Secure-then-HttpOnly is biota's order and is kept: the move must not rewrite the wire
    // format of cookies that never touch the new attributes.
    assert_eq!(h, "sid=t; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=None");
}

#[test]
fn partitioned_lands_after_same_site() {
    let h = Cookie::build("sid", "t")
        .domain(".example.com")
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .partitioned(true)
        .finish()
        .encoded();
    assert!(h.contains("Domain=.example.com"), "{h}");
    assert!(h.ends_with("; SameSite=None; Partitioned"), "{h}");
}

#[test]
fn a_cookie_with_neither_attribute_encodes_exactly_as_it_did_before() {
    // The added fields default to absent/false, so the moved wire format is unchanged.
    let h = Cookie::build("session", "abc")
        .path("/auth")
        .max_age(Duration::seconds(60))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .finish()
        .encoded();
    assert_eq!(h, "session=abc; Path=/auth; Max-Age=60; Secure; HttpOnly; SameSite=Lax");
}

#[test]
fn same_site_none_and_partitioned_require_secure() {
    assert_eq!(
        Cookie::build("a", "b").same_site(SameSite::None).finish().try_encoded(),
        Err(CookieError::RequiresSecure("SameSite=None"))
    );
    assert_eq!(
        Cookie::build("a", "b").partitioned(true).finish().try_encoded(),
        Err(CookieError::RequiresSecure("Partitioned"))
    );
}

#[test]
fn injection_attempts_are_refused_not_escaped() {
    for bad in ["x; HttpOnly", "x\r\nSet-Cookie: evil=1", "a b", "q\"r", "c,d", "back\\slash", "tab\tx"] {
        assert_eq!(
            Cookie::build("n", bad).finish().try_encoded(),
            Err(CookieError::InvalidToken("value")),
            "value {bad:?}"
        );
    }
    for bad in ["", "a=b", "n;x", "n\r\n", "sp ace"] {
        assert_eq!(
            Cookie::build(bad, "v").finish().try_encoded(),
            Err(CookieError::InvalidToken("name")),
            "name {bad:?}"
        );
    }
    assert_eq!(
        Cookie::build("n", "v").path("/;evil").finish().try_encoded(),
        Err(CookieError::InvalidToken("path"))
    );
    assert_eq!(
        Cookie::build("n", "v").domain("a.com\r\nX: y").finish().try_encoded(),
        Err(CookieError::InvalidToken("domain"))
    );
}

#[test]
fn expire_deletes_with_max_age_zero_and_empty_value() {
    assert_eq!(Cookie::expire("sid").encoded(), "sid=; Max-Age=0");
    assert_eq!(
        Cookie::build("sid", "").path("/").max_age(Duration::ZERO).finish().encoded(),
        "sid=; Path=/; Max-Age=0"
    );
}

#[test]
fn parsed_request_cookies_still_carry_no_attributes() {
    // parse_header is RFC 6265 §5.4: a request cookie is name/value only. Domain and
    // Partitioned are response attributes and must never leak into a parsed cookie.
    let c = &Cookie::parse_header("a=1")[0];
    assert_eq!(c.encoded(), "a=1");
}
