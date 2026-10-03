# servelet-client

An outbound HTTP client with a connection pool and a retry policy.

One job: make requests. It is the mirror image of `servelet-h1`, and shares nothing with it but
the types both speak (`Method`, `Uri`, `HeaderMap`, `StatusCode`, `Version`, `Error`).

## Weight is a feature (rule 6)

Client TLS is **off by default**. Measured on this workspace:

| features | `cargo tree -p servelet-client --prefix none \| sort -u \| wc -l` |
|---|---|
| default (`[]`) | **36** |
| `tls` | **47** |

So a consumer that only speaks plaintext links no TLS stack at all — 11 fewer packages, which
includes `rustls`, `ring`, `rustls-native-certs` and `rustls-pki-types`. The default number (36)
is the one committed in `budget/deps.tsv` and enforced by `scripts/gates.sh`.

Without the feature an `https://` URL returns `Error::Tls` whose message names the feature. It
does **not** silently downgrade to plaintext — that would be a security bug, not a default.
`crates/servelet-client/tests/tls_feature.rs` asserts both halves of that, and runs green with
the feature on and off.

## What was moved

Byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`:

| to | from | what |
|---|---|---|
| `src/reqwest.rs` | 1065-1673 | `RetryPolicy`, the cookie jar, `Part`/`Form`, `RequestBuilder`, `Client`, `ClientBuilder` |
| `src/stream.rs` | 1674-1825 + 1826-1852 | `Stream`/`StreamReader`, and the client `tls_config()` |
| `src/pool.rs` | 1970-2083 | `pool`, `pool_take`, `pool_put`, `connect`, `connect_fresh` |
| `src/send.rs` | 2085-2444 | `write_request`, `read_response_head`, `send_request`, `BodyFraming`, `StreamingResponse`, `parse_status_line`, `read_chunked` |

Tests moved: **12 of 12** (kernel.rs 3616-4066, the ones that exercise the client, the pool, the
streaming response and the cookie jar). Every one of them binds a real local socket: `#[test]`
alone could not tell you the pool reuses connections, and one of them counts real `accept()` calls
to prove it.

## Deviations, and why each one

All three are listed with their reason in `docs/EXTENSIONS.md` §5, and every line is enumerated in
`scripts/verify_move.py`:

1. **`splitmix64` is in-crate.** biota re-exported it from `transport` (`kernel.rs:3221`). The
   census measured `transport` at zero hits in the client's span, and pulling that dependency in
   behind a five-line public-domain mixing function would be the opposite of rule 6. Same
   algorithm, same constants, byte-identical output.
2. **`connection_close` is duplicated.** biota had exactly one copy (kernel.rs:3008) in the
   *server* half and the client called it from across the same crate. It now lives in
   `servelet-h1`; a client that pulled the whole server stack in to read one header would be the
   wrong dependency. Six lines, byte-identical.
3. **Visibility.** Items the moved tests reach (`CookieJar`, `StoredCookie`, `parse_http_date`,
   `parse_rfc3339`, `cookie_path_matches`, `is_expired`) are `pub` here where they were private in
   one big crate. No behaviour change.
