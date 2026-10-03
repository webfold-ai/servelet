# servelet-cookie

Cookie parse from a `Cookie:` request header, and `Set-Cookie` build.

One job, one sentence, no "and" that means two things: this crate turns bytes into cookies and
cookies into bytes. It does not route, does not write a response, and does not know `Request` or
`Response` exist.

**Dependencies: none.** Measured over the whole moved span (`biota/http-server` `lib.rs`
1910-2135 at rev `4ce2dcd`) with census section 7's symbol grep: zero references to `tokio`,
`rustls`, `hashtrinity`, `serde`, `bytes`, `base64`, `transport`, `sangdb` or `modelfold`.
std only — this crate is usable from a synchronous `main` or a build script.

`cargo tree -p servelet-cookie --prefix none | sort -u | wc -l` → **1** (the crate itself).
The number is committed in `budget/deps.tsv` and `scripts/gates.sh` fails if it grows.

## What was moved

Byte-for-byte from `biota/http-server` `lib.rs` `pub mod cookie` at rev `4ce2dcd`:
lines 1910-2135, of which 1911-2134 are the module body (`crates/servelet-cookie/src/lib.rs`)
and 2081-2134 are the six `#[cfg(test)]` tests (`tests/moved.rs`). Test count moved: 6 of 6.

`Domain` and `Partitioned` were added afterwards, in their own commit, with their own tests.
See `docs/EXTENSIONS.md`.
