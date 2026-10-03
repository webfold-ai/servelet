//! The two tests for these functions, moved out of `biota/http-server`'s `helpers.rs`
//! `mod tests` at rev `4ce2dcd` (lines 465-482), verbatim.
//!
//! The only edit at this seam: biota's `mod tests` sat inside the module and read its own names
//! out of it. As an integration test the file has to name the crate explicitly.

use servelet_uri::*;

    #[test]
    fn percent_decode_handles_plus_and_hex() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("100%25"), "100%");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn percent_encode_round_trips_and_keeps_unreserved() {
        assert_eq!(percent_encode("abc-_.~"), "abc-_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("metadata['x']"), "metadata%5B%27x%27%5D");
        assert_eq!(
            percent_decode(&percent_encode("hello world + café")),
            "hello world + café"
        );
    }
