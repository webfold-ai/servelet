#!/usr/bin/env python3
"""Rule-9 check: the moved code is byte-for-byte the code it claims to come from.

Reads biota at rev 4ce2dcd through `git show` only (the working tree of that checkout is
shared and dirty and must never be read or written). For every file in the spine it builds
the set of non-comment, trimmed source lines of the exact biota line ranges recorded in
`budget/ranges.tsv`, then reports how many of the crate file's own code lines appear in
that set verbatim.

It is a *line-level* check, not a token/AST check: it proves "this line is the line biota
has at that range" and it does NOT prove the ranges are used exactly once, nor that no
extra code was added. Those are covered by the mutation checks in docs/SPINE.md.

Usage: scripts/verify_move.py [--biota <path>] [--rev <rev>]
Exit 0 when every file's unmatched-line count is within --tolerance (default 0).
"""
import argparse
import os
import re
import subprocess
import sys

# crate file -> [(biota file, first line, last line), ...]   1-indexed, inclusive.
# These are the ranges committed in budget/ranges.tsv and narrated in docs/SPINE.md.
RANGES = {
    # lib.rs `pub mod sse` (2137-2470): the streaming half 2138-2285 and the parse/emit half
    # 2286-2418, both with their own `use` line's targets rewritten to the crates that own them.
    "servelet-sse/src/sse.rs": [("lib.rs", 2138, 2285), ("lib.rs", 2286, 2418)],
    # lib.rs: the `builder()` free fn and `HttpResponseBuilder`. 224-238 (`StreamingBody` and
    # `Response::streaming_body`) is NOT here -- it belongs to servelet-h1 and moved there.
    "servelet-sse/src/builder.rs": [("lib.rs", 92, 94), ("lib.rs", 128, 222)],
    # kernel.rs: the SSE writer that `serve_connection` dispatched to. 3059-3065 is its doc
    # comment, which is prose about this crate; the code is 3066-3130.
    "servelet-sse/src/wire.rs": [("kernel.rs", 3059, 3130)],
    # kernel.rs: the Reqwest face, the wire, the client TLS config, the pool, and the send path.
    "servelet-client/src/reqwest.rs": [("kernel.rs", 1065, 1673)],
    "servelet-client/src/stream.rs": [("kernel.rs", 1674, 1825), ("kernel.rs", 1826, 1852)],
    "servelet-client/src/pool.rs": [("kernel.rs", 1970, 2083)],
    "servelet-client/src/send.rs": [("kernel.rs", 2085, 2444)],
    # helpers.rs: `percent_decode` (77-111) and `percent_encode` (113-131).
    "servelet-uri/src/lib.rs": [("helpers.rs", 77, 111), ("helpers.rs", 113, 131)],
    "servelet-cookie/src/lib.rs": [("lib.rs", 1911, 2134)],
    "servelet-core/src/error.rs": [("kernel.rs", 60, 84)],
    "servelet-core/src/types.rs": [("kernel.rs", 86, 731)],
    "servelet-core/src/extensions.rs": [("kernel.rs", 732, 830)],
    "servelet-core/src/message.rs": [("kernel.rs", 831, 1064)],
    # kernel/platform.rs -- the Layer/Service traits Router::layered wraps with.
    "servelet-core/src/service.rs": [("kernel/platform.rs", 353, 440), ("kernel/platform.rs", 484, 573)],
    "servelet-router/src/router.rs": [("kernel.rs", 2446, 2815)],
    "servelet-router/src/lib.rs": [("kernel/platform.rs", 1126, 1138)],
    # kernel.rs "Wire" + serve* (2816-3065) and the chunked/streaming writers (3132-3197).
    # 3066-3130 (write_sse_response/write_sse_chunk) is CUT: servelet-sse's, a later unit.
    "servelet-h1/src/wire.rs": [("kernel.rs", 2816, 3065), ("kernel.rs", 3132, 3197)],
    # Response::streaming / StreamingBody: lib.rs, not kernel.rs.
    "servelet-h1/src/streaming.rs": [("lib.rs", 200, 203), ("lib.rs", 229, 238)],
    # kernel/runtime.rs -- serve_gracefully and its ConnectionCounter/bind_reuseport.
    "servelet-h1/src/graceful.rs": [("kernel/runtime.rs", 2073, 2320)],
    "servelet-tls/src/tls.rs": [("kernel.rs", 1854, 1968)],
    # lib.rs `pub mod websocket` (2472-2929): the handshake half, the frame codec, the client
    # half, the server half (which landed in this crate's ROOT, because it is the server-side
    # entry point and one sentence with no "and"), and its five tests.
    "servelet-ws/src/handshake.rs": [("lib.rs", 2490, 2598)],
    "servelet-ws/src/frame.rs": [("lib.rs", 2600, 2734)],
    "servelet-ws/src/client.rs": [("lib.rs", 2736, 2785)],
    "servelet-ws/src/lib.rs": [("lib.rs", 2787, 2808)],
    "servelet-ws/tests/moved.rs": [("lib.rs", 2814, 2927)],
}

# Lines that are never in biota verbatim because they are a *deliberate, documented*
# deviation (see docs/SPINE.md "Deviations"). Each is an exact, whole-line match.
KNOWN_DEVIATIONS = {
    "servelet-uri/src/lib.rs": ["#![forbid(unsafe_code)]"],
    # NOTE on the entries below that appear many times: `KNOWN_DEVIATIONS` is a SET of whole
    # lines, so a line repeated five times is accounted for once and matched five times. The
    # arms it covers are the `#[cfg(feature = "tls")]`-guarded `Stream::Tls(..)` match arms in
    # `stream.rs`, and the `#[cfg(not(feature = "tls"))]` https arm in `pool.rs`.
    # The client's `use` lines (biota kept them once at the top of kernel.rs), the TLS arms
    # behind the crate's off-by-default `tls` feature, and the items the moved tests reach that
    # were `fn`/`struct` inside the one big crate and are `pub` here.
    "servelet-client/src/reqwest.rs": [
        "fn splitmix64(x: u64) -> u64 {",
        "pub struct CookieJar {",
        "pub struct StoredCookie {",
        "pub fn parse_http_date(s: &str) -> Option<std::time::SystemTime> {",
        "    pub fn is_expired(&self) -> bool {",
        "pub fn cookie_path_matches(cookie_path: &str, request_path: &str) -> bool {",
        "    pub fn store(&mut self, domain: &str, set_cookie: &str) {",
        "    pub fn header_for(&self, domain: &str, request_path: &str, is_secure_request: bool) -> Option<String> {",
        # splitmix64, verbatim from transport's http_client.rs (Ptyktos/transport) -- the crate
        # biota re-exported it from. Documented in the source and in docs/EXTENSIONS.md.
        "#![forbid(unsafe_code)]",
        "    let x = x.wrapping_add(0x9E3779B97F4A7C15);",
        "    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);",
        "    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);",
        "    z ^ (z >> 31)",
        "#[cfg(feature = \"tls\")]",          # column 0 (the `match uri.scheme_str()` arm)
        '        #[cfg(feature = "tls")]',    # column 8 (inside `connect_fresh`)
        '        #[cfg(not(feature = "tls"))]',
    ],
    "servelet-client/src/stream.rs": [
        "use std::io;",
        "use tokio::io::{AsyncReadExt, AsyncWriteExt};",
        "use tokio::net::TcpStream;",
        "    #[cfg(feature = \"tls\")]",
        "pub(crate) fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {",
        "    pub async fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<()> {",
        "    pub async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {",
        "    pub async fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {",
        "    pub async fn read_to_end(&mut self, out: &mut Vec<u8>) -> io::Result<usize> {",
        "    pub async fn read_some(&mut self, max: usize, buf: &mut [u8]) -> io::Result<usize> {",
        '    #[cfg(feature = "tls")]',
        '            #[cfg(feature = "tls")]',
    ],
    "servelet-client/src/pool.rs": [
        "use std::collections::HashMap;",
        "use std::sync::{Arc, Mutex, OnceLock};",
        "use hashtrinity::{Coord, CoordMap, PHI};",
        "use tokio::net::TcpStream;",
        "use crate::stream::Stream;",
        "#[cfg(feature = \"tls\")]",
        "use crate::stream::tls_config;",
        "use servelet_core::{host_port, Error, Result, Uri};",
        "pub(crate) struct PooledConn {",
        "    pub(crate) stream: Stream,",
        "    pub(crate) leftover: Vec<u8>,",
        "pub(crate) fn pool() -> &'static std::sync::Mutex<CoordMap<u64, Vec<PooledConn>>> {",
        "pub(crate) fn identity_for(uri: &Uri) -> Result<String> {",
        "pub(crate) async fn connect(uri: &Uri, resolve: &std::collections::HashMap<String, std::net::SocketAddr>) -> Result<(Stream, bool)> {",
        "pub(crate) async fn connect_fresh(",
        "pub(crate) fn pool_take(identity: &str) -> Option<PooledConn> {",
        "pub(crate) fn pool_put(identity: &str, conn: PooledConn) {",
        "#[cfg(feature = \"tls\")]",
        "#[cfg(not(feature = \"tls\")]",
        '        Some("https") => Err(Error::Tls(',
        '            "an https:// URL needs this crate\'s `tls` feature (rustls, tokio-rustls and the \\',
        "             system trust store); it is off by default so a plaintext consumer links no TLS \\",
        '             stack -- turn it on with `features = [\\"tls\\"]`".to_string(),',
        "        )),",
        "#[cfg(feature = \"tls\")]",
        '        #[cfg(feature = "tls")]',
        '        #[cfg(not(feature = "tls"))]',
    ],
    "servelet-client/src/send.rs": [
        "use std::io;",
        "use std::str;",
        "use servelet_core::{header, Error, Extensions, HeaderMap, HeaderName, HeaderValue, Method, Response, Result, StatusCode, Uri, Version};",
        "use crate::pool::{identity_for, pool_put, PooledConn};",
        "use crate::stream::{Stream, StreamReader};",
        "fn connection_close(headers: &HeaderMap) -> bool {",
        "    headers",
        "        .get(header::CONNECTION)",
        "        .and_then(|v| v.to_str().ok())",
        "        .map(|v| v.to_ascii_lowercase().contains(\"close\"))",
        "pub(crate) async fn send_request(",
        "pub(crate) async fn send_request_streaming(",
    ],
    # `crate::` -> the crate that owns the name now, `Responder`/`impl crate::Response` became
    # an inherent method and a free function (rule 4 drops the actix trait), and the fields the
    # sibling `wire.rs` reads went from `pub(crate)` to `pub` within this crate.
    "servelet-sse/src/sse.rs": [
        "    pub fn respond_to(self, _req: &servelet_core::Request) -> servelet_core::Response {",
        "        let mut resp = servelet_core::Response::new(servelet_core::StatusCode::OK, Vec::new());",
        "pub fn sse_body(resp: &servelet_core::Response) -> Option<SseBody> {",
        "    resp.extensions().get::<SseBody>().cloned()",
        "        let req = servelet_core::Request::new(servelet_core::Method::GET, \"/events/stream\".parse().unwrap());",
        "        let body = sse_body(&resp).expect(\"SseBody must be stashed by respond_to\");",
        "pub struct SseBody {",
        "    pub rx: std::sync::Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Event>>>>,",
        "    pub keep_alive: Option<Duration>,",
        "    pub retry: Option<Duration>,",
        "    pub fn render_for_wire(&self) -> String {",
        "    pub(crate) fn render(&self) -> String {",
    ],
    # `crate::HeaderMap`/`HeaderName`/`HeaderValue`/`header::` -> `servelet_core::`; and
    # `streaming` now calls servelet-h1's `streaming(..)` instead of stashing its own
    # crate-private `StreamingBody` (that type is servelet-h1's, and is what its writer looks for).
    "servelet-sse/src/builder.rs": [
        "HttpResponseBuilder { status, headers: servelet_core::HeaderMap::new(), cookies: Vec::new() }",
        "headers: servelet_core::HeaderMap,",
        "    header: (impl Into<servelet_core::HeaderName>, impl Into<servelet_core::HeaderValue>),",
        "pub fn content_type(&mut self, mime: impl Into<servelet_core::HeaderValue>) -> &mut Self {",
        "    self.headers.insert(servelet_core::header::CONTENT_TYPE, mime);",
        "        resp.headers_mut().append(servelet_core::header::SET_COOKIE, cookie.encoded());",
        "        let resp = self.build(self.status, Vec::new());",
        "        servelet_h1::streaming(resp, rx)",
    ],
    # The moved `use` lines of `kernel.rs`, and `crate::httpsrv::httpx::sse::SseBody` ->
    # `crate::sse::SseBody` (same crate now).
    "servelet-sse/src/wire.rs": [
        "    sse_body: crate::sse::SseBody,",
        "pub(crate) async fn write_sse_response<W: AsyncWriteExt + Unpin>(",
    ],
    # `#![forbid(unsafe_code)]` — the crate-level lint every servelet crate opens with.
    "servelet-cookie/src/lib.rs": [
        "#![forbid(unsafe_code)]",
        # The Domain/Partitioned additions: two struct fields, two constructor lines, three
        # serializer lines and two builder setters. Everything else that commit added sits
        # after the POST_MOVE_MARKER and is counted separately by the script.
        "    domain: Option<Cow<'c, str>>,",
        "    partitioned: bool,",
        "            domain: None,",
        "            partitioned: false,",
        "        if let Some(domain) = &self.domain {",
        '            s.push_str(&format!("; Domain={domain}"));',
        "        if self.partitioned {",
        '            s.push_str("; Partitioned");',
        "    pub fn domain(mut self, domain: impl Into<Cow<'c, str>>) -> Self {",
        "        self.cookie.domain = Some(domain.into());",
        "    pub fn partitioned(mut self, partitioned: bool) -> Self {",
        "        self.cookie.partitioned = partitioned;",
    ],
    # servelet-ws. The four handshake functions are `pub` because the moved tests are a
    # SEPARATE crate here (`tests/moved.rs`) where biota's `#[cfg(test)] mod tests` had them for
    # free; `crate::splitmix64` -> `super::splitmix64` (biota's crate-root helper, this crate's
    # own copy -- the same 4 lines servelet-client carries, and the same reason).
    "servelet-ws/src/handshake.rs": [
        "pub fn sha1(data: &[u8]) -> [u8; 20] {",
        "pub fn base64_encode(data: &[u8]) -> String {",
        "pub fn compute_accept_key(client_key: &str) -> String {",
        "pub fn generate_key() -> String {",
        "        x = super::splitmix64(x);",
    ],
    # `WebSocket` is generic over its stream. biota hard-coded `TcpStream` in the field and in
    # `accept`/`connect`; here the same codec drives a TLS stream and -- the reason this unit
    # exists -- `servelet-h1`'s upgraded connection, which is a `Box<dyn AsyncRead + AsyncWrite>`
    # and never a `TcpStream`. The field TYPE changed; the frame logic around it did not.
    "servelet-ws/src/frame.rs": [
        "pub struct WebSocket<S> {",
        "    pub(crate) stream: S,",
        "    pub(crate) is_client: bool,",
        "    pub(crate) pending: Vec<u8>,",
        "impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {",
    ],
    # `crate::parse_uri`/`host_port` -> `servelet_core::` (path rewrite at the crate seam);
    # `crate::Stream` -> `servelet_client::Stream` (the socket type moved crates with its
    # `into_reader`/`into_inner`, which is the only reason the client half could move verbatim
    # instead of re-implementing a reclaiming line reader); and `Result<WebSocket>` ->
    # `Result<WebSocket<TcpStream>>` (the generic, named).
    "servelet-ws/src/client.rs": [
        "    let uri = servelet_core::parse_uri(&url.replacen(\"ws://\", \"http://\", 1))?;",
        "    let (host, port) = servelet_core::host_port(&uri)?;",
        "    let mut stream = servelet_client::Stream::Plain(TcpStream::connect(format!(\"{host}:{port}\")).await.map_err(Error::Io)?);",
        "        let servelet_client::Stream::Plain(stream) = stream else {",
        "    #[allow(irrefutable_let_patterns)]",
        "pub async fn connect(url: &str) -> Result<WebSocket<TcpStream>> {",
    ],
    # `accept(mut stream: TcpStream, ..)` -> generic over the stream, one parameter per line.
    "servelet-ws/src/lib.rs": [
        "pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(",
        "    mut stream: S,",
        "    req: &Request,",
        "    pending: Vec<u8>,",
        ") -> Result<WebSocket<S>> {",
        # splitmix64, verbatim from transport's http_client.rs -- see the source comment.
        "fn splitmix64(x: u64) -> u64 {",
        "#![forbid(unsafe_code)]",
        "    let x = x.wrapping_add(0x9E3779B97F4A7C15);",
        "    let z = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);",
        "    let z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);",
        "    z ^ (z >> 31)",
    ],
    # `fn status_reason` -> `pub fn`: servelet-h1's write_response lives in another crate.
    "servelet-core/src/types.rs": ["pub fn status_reason(status: StatusCode) -> &'static str {"],
    # Request/Response fields were private (only crate-internal accessors read them);
    # cross-crate field reads need them visible. Visibility only, no behaviour.
    "servelet-core/src/message.rs": [
        "    pub method: Method,", "    pub uri: Uri,", "    pub version: Version,",
        "    pub headers: HeaderMap,", "    pub body: Vec<u8>,",
        "    pub extensions: Extensions,", "    pub peer_addr: Option<std::net::SocketAddr>,",
        "    pub status: StatusCode,", "    pub url: Uri,",
    ],
    # `crate::` -> `servelet_core::` (path rewrite at the crate seam).
    "servelet-router/src/router.rs": [
        "        L: servelet_core::Layer<Router>,",
        "        L::Service: servelet_core::Service<Request, Response = Response, Error = servelet_core::Error> + Send + Sync + 'static,",
        "                if let Err(e) = servelet_core::Service::ready(&mut *svc).await {",
        "                match servelet_core::Service::serve(&mut *svc, req).await {",
    ],
    # Same rewrite, on the moved `impl Service<Request> for Router`.
    "servelet-router/src/lib.rs": [
        "#![forbid(unsafe_code)]",
        "impl servelet_core::Service<Request> for Router {",
        "    type Error = servelet_core::Error;",
        "    async fn ready(&mut self) -> std::result::Result<(), Self::Error> {",
        "    async fn serve(&mut self, req: Request) -> std::result::Result<Self::Response, Self::Error> {",
    ],
    # `crate::httpsrv::actix::StreamingBody` -> this crate's own `crate::StreamingBody`.
    "servelet-h1/src/wire.rs": [
        "        let mut resp = router.handle(req).await;",
        # The upgrade seam (docs/EXTENSIONS.md §7): six lines of dispatch between the handler
        # and the response writers. `return` rather than `break` so the clean-shutdown below
        # does not run on a connection the callback now owns.
        "        if let Some(upgrade) = crate::upgrade::take_upgrade(&mut resp) {",
        "            let upgraded = crate::upgrade::Upgraded::new(Box::new(reader));",
        "            if let Err(e) = upgrade(upgraded).await {",
        # (`return;` needs no entry: biota's own serve_connection has that exact line inside
        # the moved range, so the line-level check already counts it as verbatim.)
        '                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "the upgraded connection ended in an error"',
        "        if let Some(formatter) = crate::streaming::take_formatter(&mut resp) {",
        "            let mut writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send) = &mut reader;",
        "            let written = (formatter)(&mut writer, resp).await;",
        "            if let Err(e) = written {",
        "pub async fn write_chunk<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {",
        "        if let Some(streaming_body) = crate::streaming_body(&resp) {",
        "    streaming_body: crate::StreamingBody,",
        "    let mut rx = crate::streaming::take_receiver(streaming_body).await?;",
    ],
    # `HttpResponseBuilder::streaming(&mut self, ..)` (lib.rs) became a free `streaming(..)`
    # so it can live in servelet-h1 instead of on a builder type that stays in servelet-core,
    # and `pub(crate)` -> `pub` so servelet-h1's own writer can name it across the module
    # boundary. `take_receiver` is new: the inline lock/take/expect in
    # write_streaming_response (kernel.rs 3177-3183) extracted so streaming.rs and wire.rs
    # share one copy.
    "servelet-h1/src/streaming.rs": [
        "pub struct StreamingBody {",
        "pub fn streaming(mut resp: Response, rx: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>) -> Response {",
        "pub fn streaming_body(resp: &Response) -> Option<StreamingBody> {",
        "    resp.extensions().get::<StreamingBody>().cloned()",
        "pub async fn take_receiver(body: StreamingBody) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>> {",
        "    Ok(body", "        .rx", "        .lock()", "        .await", "        .take()",
        "        .expect(\"StreamingBody's receiver is stashed exactly once per response and consumed exactly once, here\"))",
    ],
    # `crate::Result` -> `std::result::Result` in the two trait signatures (the trait's Error
    # is its own associated type, so the crate-local alias was never right here), and the
    # documented `+ Send` on the two RPITIT returns so a Service is drivable from
    # Router::layered's Arc<Mutex<_>> inside a Send future.
    "servelet-core/src/service.rs": [
        "    fn ready(&mut self) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send;",
        "    ) -> impl Future<Output = std::result::Result<Self::Response, Self::Error>> + Send;",
        "pub async fn oneshot<S, Req>(svc: &mut S, req: Req) -> std::result::Result<S::Response, S::Error>",
        "    S::Error: Send + From<Error>,",
        "    async fn ready(&mut self) -> std::result::Result<(), Self::Error> {",
        "            return Err(S::Error::from(Error::Http(",
        "    async fn serve(&mut self, req: Req) -> std::result::Result<Self::Response, Self::Error> {",
    ],
}

# A file may carry code that was added AFTER the byte-for-byte move (README rule 9:
# a behaviour change is its own commit with its own tests). Those lines are not in
# biota and must not be counted as "unaccounted" -- but they must not be silently
# accepted either: the script reports how many there are, and the marking line is
# itself a comment line that no amount of editing can smuggle past unnoticed, because
# the whole tail of the file is what's excluded.
POST_MOVE_MARKER = {
    "servelet-cookie/src/lib.rs": "// -- Added after the byte-for-byte move",
    "servelet-h1/src/streaming.rs": "// -- The formatter seam (added after the move)",
}

SKIP_PREFIX = re.compile(r"^\s*(use |#\[forbid|mod |pub mod |pub use |//! )")


def git_show(biota, rev, path):
    return subprocess.run(["git", "-C", biota, "show", "%s:http-server/src/%s" % (rev, path)],
                          check=True, capture_output=True, text=True).stdout.split("\n")


def code_line(line):
    s = line.strip()
    return None if (not s or s.startswith("//")) else s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--biota", default=os.path.expanduser("~/projects/biota"))
    ap.add_argument("--rev", default="4ce2dcd")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    args = ap.parse_args()

    sources = {name: git_show(args.biota, args.rev, name)
               for name in ("kernel.rs", "kernel/platform.rs", "lib.rs", "kernel/runtime.rs", "helpers.rs")}

    total_ok = total = 0
    failures = 0
    for rel, ranges in RANGES.items():
        pool = set()
        for name, a, b in ranges:
            for line in sources[name][a - 1:b]:
                c = code_line(line)
                if c is not None:
                    pool.add(c)
        # Compared STRIPPED, like the biota pool above: a deviation is about WHICH line it is,
        # not about how far the moved crate happens to indent it. (Three of the client's
        # deviations are bare `#[cfg(feature = "tls")]` lines at three different indents.)
        known = set(KNOWN_DEVIATIONS.get(rel, []))
        known = {l.strip() for l in known}
        seen_known = set()
        unmatched = []
        n = 0
        added = 0
        after = False
        for line in open(os.path.join(args.root, "crates", rel)):
            if rel in POST_MOVE_MARKER and line.startswith(POST_MOVE_MARKER[rel]):
                after = True
            if after:
                c = code_line(line)
                if c is not None:
                    added += 1
            if after:
                continue
            if SKIP_PREFIX.match(line):
                continue
            c = code_line(line)
            if c is None:
                continue
            n += 1
            if c in pool:
                continue
            s = line.rstrip("\n")
            if c in known:
                seen_known.add(c)
                continue
            unmatched.append(s)
        pct = 100.0 * (n - len(unmatched)) / max(n, 1)
        total_ok += n - len(unmatched)
        total += n
        if added:
            print("     (%s: %d code lines were added after the move, in their own commit, and are"
                  " not expected in biota)" % (rel, added))
        status = "OK  " if not unmatched else "FAIL"
        if unmatched:
            failures += 1
        print("%s %-34s code-lines=%4d verbatim=%4d documented-deviations=%2d unaccounted=%3d (%.1f%%)"
              % (status, rel, n, n - len(unmatched) - len(seen_known), len(seen_known),
                 len(unmatched), pct))
        for line in unmatched:
            print("       unaccounted: %s" % line)
        for line in sorted(known - seen_known):
            # A `use` line or a doc comment is skipped before it is ever compared (SKIP_PREFIX),
            # so it can never appear in `seen_known`. Reporting those as stale would bury the
            # real signal -- an entry that no longer matches because the code moved on.
            if SKIP_PREFIX.match(line) or line.startswith("//"):
                continue
            print("       note: documented deviation no longer present (stale entry): %s" % line)
    print("TOTAL %d/%d code lines verbatim in biota at %s" % (total_ok, total, args.rev))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
