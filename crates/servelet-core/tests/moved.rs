//! The tests moved out of `biota/http-server`'s `kernel.rs` `mod tests` (rev `4ce2dcd`,
//! lines 3575-3613, 3933-3957, 4066-4086, 4183-4223), verbatim.
//!
//! Nothing here was rewritten to suit the split. The only edit is the
//! `triggers_io_error` path string, which still contains "bedrock" because changing it would
//! change nothing about what the test proves and the test is moved byte-for-byte.

use super::*;

mod moved {
    use super::*;

    /// `req.method() == Method::GET` (comparing `&Method` to an owned `Method`) is how real
    /// rauthy handler/middleware code written against the `http` crate's `Method` compares
    /// methods — must compile and be correct here too, not just the `&Method == &Method` shape.
    #[test]
    fn method_reference_compares_equal_to_owned_method() {
        let req = Request::new(Method::GET, "/".parse().unwrap());
        assert!(req.method() == Method::GET);
        assert!(req.method() != Method::POST);
    }

    /// `connection_info()` reads the real peer address set by `with_peer_addr` when there's no
    /// `X-Forwarded-For`, and prefers the forwarded value's first hop when there is one — the
    /// exact two branches `real_ip_from_req`-shaped callers (rauthy's own) depend on.
    #[test]
    fn connection_info_falls_back_to_peer_addr_without_forwarded_header() {
        let req = Request::new(Method::GET, "/".parse().unwrap()).with_peer_addr("203.0.113.5:4242".parse().unwrap());
        let info = req.connection_info();
        assert_eq!(info.peer_addr(), Some("203.0.113.5"));
        assert_eq!(info.realip_remote_addr(), Some("203.0.113.5"));
    }

    #[test]
    fn connection_info_prefers_forwarded_for_first_hop() {
        let req = Request::new(Method::GET, "/".parse().unwrap())
            .with_peer_addr("10.0.0.1:8080".parse().unwrap())
            .with_header("x-forwarded-for", "198.51.100.9, 10.0.0.1");
        let info = req.connection_info();
        assert_eq!(info.peer_addr(), Some("10.0.0.1"));
        assert_eq!(info.realip_remote_addr(), Some("198.51.100.9"));
    }

    #[test]
    fn connection_info_with_no_peer_addr_set_is_none() {
        let req = Request::new(Method::GET, "/".parse().unwrap());
        let info = req.connection_info();
        assert_eq!(info.peer_addr(), None);
        assert_eq!(info.realip_remote_addr(), None);
    }

    /// The `#[derive(hashtrinity::Error)]` replacement must produce IDENTICAL behavior to the
    /// hand-written impls it replaced: the same Display text, real `?`-operator conversion from
    /// `io::Error` via `#[from]`, and a genuine `source()` chain for the Io variant.
    #[test]
    fn derived_error_matches_prior_hand_written_behavior() {
        let http_err = Error::Http("bad gateway".to_string());
        assert_eq!(http_err.to_string(), "HTTP: bad gateway");
        let parse_err = Error::Parse("bad byte".to_string());
        assert_eq!(parse_err.to_string(), "parse: bad byte");

        fn triggers_io_error() -> Result<()> {
            std::fs::read("/definitely/does/not/exist/bedrock-test")?;
            Ok(())
        }
        let err = triggers_io_error().unwrap_err();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().starts_with("I/O: "));
        assert!(std::error::Error::source(&err).is_some(), "the #[from] field must be the source");
    }

    #[test]
    fn native_http_types_replace_http_crate() {
        let uri: Uri = "http://example.com:8080/a?b=c".parse().unwrap();
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.host(), Some("example.com"));
        assert_eq!(uri.port_u16(), Some(8080));
        assert_eq!(uri.path_and_query(), "/a?b=c");

        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, "sanguine");
        headers.append(header::ACCEPT, "text/plain");
        headers.append(header::ACCEPT, "application/json");
        assert_eq!(
            headers.get(header::USER_AGENT).unwrap().to_str().unwrap(),
            "sanguine"
        );
        assert_eq!(headers.get_all(header::ACCEPT).len(), 2);
    }

    /// Mirrors the real `http` crate's `Extensions` — proof it's insert/get/remove-exact by
    /// type, distinguishes distinct types stored at once, and survives a real `Clone`.
    #[test]
    fn extensions_insert_get_remove_by_type() {
        #[derive(Clone, Debug, PartialEq)]
        struct UserId(u64);
        #[derive(Clone, Debug, PartialEq)]
        struct RequestId(String);

        let mut ext = Extensions::new();
        assert_eq!(ext.get::<UserId>(), None);

        let prev = ext.insert(UserId(42));
        assert_eq!(prev, None, "first insert has nothing to displace");
        ext.insert(RequestId("abc".into()));

        assert_eq!(ext.get::<UserId>(), Some(&UserId(42)));
        assert_eq!(ext.get::<RequestId>(), Some(&RequestId("abc".into())));

        let prev = ext.insert(UserId(43));
        assert_eq!(prev, Some(UserId(42)), "insert returns the value it displaced");
        assert_eq!(ext.get::<UserId>(), Some(&UserId(43)));

        let cloned = ext.clone();
        assert_eq!(cloned.get::<UserId>(), Some(&UserId(43)), "Extensions survives Clone");
        assert_eq!(cloned.get::<RequestId>(), Some(&RequestId("abc".into())));

        let removed = ext.remove::<UserId>();
        assert_eq!(removed, Some(UserId(43)));
        assert_eq!(ext.get::<UserId>(), None);
        assert_eq!(ext.get::<RequestId>(), Some(&RequestId("abc".into())), "removing one type leaves the other");
    }
}

/// Added by this extraction, not moved: `servelet-core` is required to carry NO tokio. This test
/// is the proof, and it fails at compile time if a `tokio` dependency is ever added — a test
/// that cannot fail by running can still fail by building.
#[test]
fn core_is_pure_data_and_names_no_async_runtime() {
    // `Extensions`, `Request`, `Response` and the header map are all constructible and fully
    // usable from a plain synchronous function with no executor in scope at all.
    fn build_and_read_without_an_executor() -> String {
        let mut req = Request::new(Method::POST, "http://h:1/p?q=1".parse().unwrap());
        req.headers_mut().insert(header::CONTENT_TYPE, "text/plain");
        req.with_body("hi");
        req.extensions_mut().insert(7u32);
        let resp = Response::ok(req.into_body());
        String::from_utf8(resp.body.clone()).unwrap()
    }
    assert_eq!(build_and_read_without_an_executor(), "hi");
}