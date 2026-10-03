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
    # `#![forbid(unsafe_code)]` — the crate-level lint every servelet crate opens with.
    "servelet-cookie/src/lib.rs": ["#![forbid(unsafe_code)]"],
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
        "pub(crate) async fn take_receiver(body: StreamingBody) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>> {",
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
        for line in open(os.path.join(args.root, "crates", rel)):
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
