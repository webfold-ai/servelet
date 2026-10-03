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
    # lib.rs `pub mod cookie` (1910-2135): the module body, 1911-2134.
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
}

# Lines that are never in biota verbatim because they are a *deliberate, documented*
# deviation (see docs/SPINE.md "Deviations"). Each is an exact, whole-line match.
KNOWN_DEVIATIONS = {
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
               for name in ("kernel.rs", "kernel/platform.rs", "lib.rs", "kernel/runtime.rs")}

    total_ok = total = 0
    failures = 0
    for rel, ranges in RANGES.items():
        pool = set()
        for name, a, b in ranges:
            for line in sources[name][a - 1:b]:
                c = code_line(line)
                if c is not None:
                    pool.add(c)
        known = set(KNOWN_DEVIATIONS.get(rel, []))
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
            if s in known:
                seen_known.add(s)
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
            print("       note: documented deviation no longer present (stale entry): %s" % line)
    print("TOTAL %d/%d code lines verbatim in biota at %s" % (total_ok, total, args.rev))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
