//! The six cookie tests moved out of `biota/http-server`'s `lib.rs` `pub mod cookie`'s
//! `#[cfg(test)] mod tests` at rev `4ce2dcd` (lines 2081-2134), verbatim.
//!
//! The only edit at this seam: biota's `mod tests` sat inside `pub mod cookie` and read its own
//! names out of that module. As an integration test the file has to name the crate
//! explicitly, and `mod tests` became `mod moved` so it is obviously a moved file.

use servelet_cookie::*;

mod moved {
    use super::*;

    #[test]
    fn builder_encodes_all_attributes_in_actix_order() {
        let cookie = Cookie::build("session", "abc123")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(Duration::seconds(3600))
            .path("/auth")
            .finish();
        assert_eq!(
            cookie.encoded(),
            "session=abc123; Path=/auth; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn bare_cookie_encodes_name_value_only() {
        let cookie = Cookie::new("id", "42");
        assert_eq!(cookie.encoded(), "id=42");
    }

    #[test]
    fn zero_max_age_is_a_real_deletion_marker_not_omitted() {
        let cookie = Cookie::build("session", "").max_age(Duration::ZERO).finish();
        assert!(cookie.encoded().contains("Max-Age=0"), "Max-Age=0 must be explicit — it's how a cookie is cleared");
    }

    #[test]
    fn parse_header_splits_multiple_cookies() {
        let cookies = Cookie::parse_header("a=1; b=2;c=3 ");
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies[0].name(), "a");
        assert_eq!(cookies[0].value(), "1");
        assert_eq!(cookies[1].name(), "b");
        assert_eq!(cookies[1].value(), "2");
        assert_eq!(cookies[2].name(), "c");
        assert_eq!(cookies[2].value(), "3");
    }

    #[test]
    fn parse_header_skips_empty_segments() {
        let cookies = Cookie::parse_header("a=1;; b=2");
        assert_eq!(cookies.len(), 2);
    }

    #[test]
    fn parse_header_on_empty_string_is_empty() {
        assert!(Cookie::parse_header("").is_empty());
    }
}
