# Security policy

Report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab of this
repository). Do not open a public issue for a suspected vulnerability. Include the crate, version or
commit, and a reproduction. Expect an acknowledgement within a few working days.

The server crates parse untrusted network input (HTTP/1, WebSocket, URI, cookies, TLS). Findings in
those parsers are in scope. `crates/servelet-tls/tests/fixtures/` holds a throwaway key and
certificate for `localhost`, committed on purpose for tests; it protects nothing.
