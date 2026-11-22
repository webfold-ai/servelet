#!/usr/bin/env bash
# The mutation checks, as a script, so they are re-runnable rather than a claim in a doc.
#
# A green test suite only means something if a wrong implementation makes it red. This
# script mutates the code in two places that the tests are supposed to pin, shows each
# test FAILING, restores, and shows the suite green again.
#
#   A. servelet-router: rename a registered route in the fallback test's fixture.
#   B. servelet-h1:     flip the auto-written `Connection: keep-alive` header to `close`.
#   C. servelet-cookie: emit `SameSite=Loose`, a value RFC 6265bis does not define.
#   D. servelet-cookie: stop enforcing "Partitioned requires Secure".
#   E. servelet-sse:    mislabel the keep-alive comment chunk on the wire.
#   F. servelet-uri:    stop escaping the space in a URL component.
#   G. servelet-client: cap the keepalive pool at zero, so nothing is ever reused.
#   H. servelet-ws:    drop the WS_GUID from the accept key, so every 101 computes the wrong
#                      Sec-WebSocket-Accept (the single value RFC 6455 makes a server prove).
#   I. servelet-ws:    mask every outgoing client byte with mask_key[0] instead of key[i % 4].
#   J. servelet-ws:    unmask every incoming byte with key[0] instead of key[i % 4].
#   K. servelet-h1:    stop dispatching the upgrade at all, so no route can ever take the socket.
#
# The hardening unit added L-X, one per LIMIT it introduced, because a limit nothing pins is a
# limit that gets deleted in the next refactor. Each is the smallest possible edit that stops the
# ceiling being enforced -- never a compile error, since a mutation that cannot build has proved
# nothing.
#
# Exit 0 only if every mutation was caught AND the restored suite is green.
set -uo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
export CARGO_INCREMENTAL=0

caught=0; total=24
LOG=$(mktemp)
trap 'cp /tmp/mutation.bak "$RESTORE" 2>/dev/null || true' EXIT
RESTORE=""

# Run the suite and report whether it went red.
#
# This deliberately captures cargo's output to a log file and greps the FILE, rather than
# piping `cargo test | grep -q "test result: FAILED"`. Under `set -o pipefail`, `grep -q` exits the
# instant it matches, cargo takes a SIGPIPE on its next write, and the pipeline reports cargo's
# 141 instead of grep's 0 -- so a mutation that WAS caught was reported as having survived. That
# bug is why this script exists rather than being a claim in a doc; it hid a real failure for one
# run, and the fix is a temp file.
suite_is_red() {
  cargo test --workspace -j3 >"$LOG" 2>&1
  # Decide from the TEST OUTPUT, not from cargo's exit code: cargo prints a trailing
  # `error: test failed, to rerun pass ...` after a red suite, which an `^error` grep matches and
  # would misreport as "did not compile". Only when no test binary reported at all is it a build
  # failure -- and then the tests never ran, so nothing was proven either way.
  if grep -q "^test result:" "$LOG"; then
    grep -q "test result: FAILED" "$LOG"
  else
    echo "  (no test binary reported -- the build failed, so the tests never ran;"
    echo "   treating as NOT a caught mutation, because a mutation that cannot be"
    echo "   compiled has not been shown to be detected)"
    return 1
  fi
}

show_red_tests() { grep -E "^test .* FAILED|^test result: FAILED" "$LOG" | head -6| sed 's/^/  /'; }

run_mut() { # run_mut <name> <file> <old> <new>
  local name="$1" f="$2" old="$3" new="$4"
  RESTORE="$f"
  cp "$f" /tmp/mutation.bak
  python3 - "$f" "$old" "$new" <<'PY' || { echo "  anchor not found -- refusing to run the mutation"; cp /tmp/mutation.bak "$f"; return 1; }
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert old in s, "anchor not found"
open(p,'w').write(s.replace(old, new, 1))
PY
  echo "mutation $name applied to $f"
  if suite_is_red; then
    echo "PASS: mutation $name was caught (suite went red)"; show_red_tests; caught=$((caught+1))
  else
    echo "FAIL: mutation $name SURVIVED -- the suite stayed green, so nothing pins this behaviour"
  fi
  cp /tmp/mutation.bak "$f"
}

echo "=== mutation A: delete a route registration in the router test ==="
run_mut "A" crates/servelet-router/tests/moved.rs \
  '.route_sync(Method::GET, "/known", |_req| Response::ok("known"))' \
  '.route_sync(Method::GET, "/known-MUTATED", |_req| Response::ok("known"))'

echo
echo "=== mutation B: flip a header in the h1 writer ==="
run_mut "B" crates/servelet-h1/src/wire.rs \
  'response.headers.insert(header::CONNECTION, "keep-alive");' \
  'response.headers.insert(header::CONNECTION, "close");'

echo
echo "=== mutation C: mislabel a SameSite value in the cookie crate ==="
run_mut "C" crates/servelet-cookie/src/lib.rs \
  'SameSite::Lax => "Lax",' \
  'SameSite::Lax => "Loose",'

echo
echo "=== mutation D: drop the Partitioned-requires-Secure rule ==="
run_mut "D" crates/servelet-cookie/src/lib.rs \
  'return Err(CookieError::RequiresSecure("Partitioned"));' \
  'return Ok(self.encoded());'

echo
echo "=== mutation E: mislabel the SSE keep-alive chunk ==="
run_mut "E" crates/servelet-sse/src/wire.rs \
  'write_sse_chunk(writer, ": keep-alive\n\n".to_string()).await?;' \
  'write_sse_chunk(writer, ": KA\n\n".to_string()).await?;'

echo
echo "=== mutation F: stop escaping a space in percent_encode ==="
run_mut "F" crates/servelet-uri/src/lib.rs \
  "b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {" \
  "b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b' ' => {"

echo
echo "=== mutation G: stop reusing pooled connections (cap them at zero) ==="
run_mut "G" crates/servelet-client/src/pool.rs \
  'const POOL_CAP_PER_IDENTITY: usize = 32;' \
  'const POOL_CAP_PER_IDENTITY: usize = 0;'

echo
echo "=== mutation H: compute Sec-WebSocket-Accept without the RFC 6455 GUID ==="
# The one mutation that breaks every WebSocket connection on the planet at once, and the reason
# the handshake test pins the RFC's own worked example rather than a round trip: a round trip
# would pass with a self-consistent-but-wrong accept key on both sides.
run_mut "H" crates/servelet-ws/src/handshake.rs \
  'input.extend_from_slice(WS_GUID.as_bytes());' \
  'input.extend_from_slice(b"");'

echo
echo "=== mutation I: mask every client byte with mask_key[0] ==="
run_mut "I" crates/servelet-ws/src/frame.rs \
  'frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask_key[i % 4]));' \
  'frame.extend(payload.iter().enumerate().map(|(_, b)| b ^ mask_key[0]));'

echo
echo "=== mutation J: unmask every inbound byte with key[0] ==="
run_mut "J" crates/servelet-ws/src/frame.rs \
  '*b ^= key[i % 4];' \
  '*b ^= key[0];'

echo
echo "=== mutation K: never hand the connection to an upgrade callback ==="
# The seam is the whole point of this unit, so it gets its own mutation: if `serve_connection`
# stopped dispatching, every real-socket upgrade test must go red. Typed as `None::<UpgradeFn>`
# so it COMPILES -- a mutation that fails to build has proved nothing about the tests.
run_mut "K" crates/servelet-h1/src/wire.rs \
  'if let Some(upgrade) = crate::upgrade::take_upgrade(&mut resp) {' \
  'if let Some(upgrade) = None::<crate::upgrade::UpgradeFn> {'

echo "=== mutation L: stop enforcing the WebSocket frame-size ceiling ==="
# The one that does not merely fail a test: with the guard gone the 2^63 test panics inside the
# allocator. That is the denial of service this unit exists to remove, caught live.
run_mut "L" crates/servelet-ws/src/frame.rs \
  'if len > self.limits.max_frame_bytes || len > usize::MAX as u64 {' \
  'if false && (len > self.limits.max_frame_bytes || len > usize::MAX as u64) {'

echo
echo "=== mutation M: accept fragmented and oversized control frames ==="
run_mut "M" crates/servelet-ws/src/frame.rs \
  'if is_control && (!fin || len > 125) {' \
  'if false && is_control && (!fin || len > 125) {'

echo
echo "=== mutation N: stop enforcing the total-message cap across fragments ==="
run_mut "N" crates/servelet-ws/src/frame.rs \
  'if total > self.limits.max_message_bytes {' \
  'if false && total > self.limits.max_message_bytes {'

echo
echo "=== mutation O: accept a text message that is not valid UTF-8 ==="
run_mut "O" crates/servelet-ws/src/frame.rs \
  'match String::from_utf8(payload) {' \
  'match Ok::<String, std::string::FromUtf8Error>(String::from_utf8_lossy(&payload).into_owned()) {'

echo
echo "=== mutation P: stop bounding the request line ==="
run_mut "P" crates/servelet-h1/src/wire.rs \
  'read_line_limited(reader, &mut line_buf, limits.max_request_line_bytes).await?;' \
  'read_line_limited(reader, &mut line_buf, usize::MAX).await?;'

echo
echo "=== mutation Q: stop counting header lines ==="
run_mut "Q" crates/servelet-h1/src/wire.rs \
  'if header_count > limits.max_header_count {' \
  'if false && header_count > limits.max_header_count {'

echo
echo "=== mutation R: stop bounding the total header block ==="
run_mut "R" crates/servelet-h1/src/wire.rs \
  'if header_bytes > limits.max_header_bytes {' \
  'if false && header_bytes > limits.max_header_bytes {'

echo
echo "=== mutation S: stop bounding the request body ==="
run_mut "S" crates/servelet-h1/src/wire.rs \
  'if content_length > limits.max_body_bytes {' \
  'if false && content_length > limits.max_body_bytes {'

echo
echo "=== mutation T: give the slow-read timeout an effectively infinite deadline ==="
run_mut "T" crates/servelet-h1/src/wire.rs \
  'tokio::time::timeout(limits.read_timeout, read_request_buffered(&mut reader, &limits))' \
  'tokio::time::timeout(std::time::Duration::from_secs(86400), read_request_buffered(&mut reader, &limits))'

echo
echo "=== mutation U: accept a request carrying BOTH Content-Length and Transfer-Encoding ==="
run_mut "U" crates/servelet-h1/src/wire.rs \
  'if content_length.is_some() && te_chunked {' \
  'if false && content_length.is_some() && te_chunked {'

echo
echo "=== mutation V: silently take the last of two differing Content-Lengths ==="
run_mut "V" crates/servelet-h1/src/wire.rs \
  '(Some(previous), Some(this)) if previous != this => {' \
  '(Some(previous), Some(this)) if previous != this && false => {'

echo
echo "=== mutation W: accept a bare LF in the header block ==="
run_mut "W" crates/servelet-h1/src/wire.rs \
  'One rule, both places: CRLF only.
        if !ends_crlf(&line_buf) {' \
  'One rule, both places: CRLF only.
        if false {'

echo
echo "=== mutation X: leave a lone carriage return inside an SSE field value ==="
run_mut "X" crates/servelet-sse/src/sse.rs \
  "if c == '\\r' {" \
  "if false && c == '\\r' {"

echo
echo "=== restored suite ==="
if suite_is_red; then
  echo "FAIL: the suite is still red after restore"; show_red_tests; exit 1
fi
echo "green again after restore"

echo
echo "mutations caught: $caught/$total"
[ "$caught" -eq "$total" ]