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
#
# Exit 0 only if both mutations were caught AND the restored suite is green.
set -uo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/home/ctown/.cache/cargo-target-servelet-spine}"
export CARGO_INCREMENTAL=0

caught=0; total=3
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
echo "=== restored suite ==="
if suite_is_red; then
  echo "FAIL: the suite is still red after restore"; show_red_tests; exit 1
fi
echo "green again after restore"

echo
echo "mutations caught: $caught/$total"
[ "$caught" -eq "$total" ]