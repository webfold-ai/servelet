#!/usr/bin/env bash
# The mutation checks, as a script, so they are re-runnable rather than a claim in a doc.
#
# A green test suite only means something if a wrong implementation makes it red. This
# script mutates the code in two places that the tests are supposed to pin, shows each
# test FAILING, restores, and shows the suite green again.
#
#   A. servelet-router: rename a registered route in the fallback test's fixture.
#   B. servelet-h1:     flip the auto-written `Connection: keep-alive` header to `close`.
#
# Exit 0 only if both mutations were caught AND the restored suite is green.
set -uo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/home/ctown/.cache/cargo-target-servelet-spine}"
export CARGO_INCREMENTAL=0

caught=0; total=2

run_mut() { # run_mut <name> <file> <python-replace-tuple...>
  local name="$1"; shift
  local f="$1"; shift
  cp "$f" /tmp/mutation.bak
  python3 - "$f" "$@" <<'PY' || { echo "  anchor not found -- refusing to run the mutation"; cp /tmp/mutation.bak "$f"; return 1; }
import sys
p=sys.argv[1]; s=open(p).read(); old=sys.argv[2]; new=sys.argv[3]
assert old in s, "anchor not found"
open(p,'w').write(s.replace(old,new,1))
PY
  echo "mutation $name applied to $f"
  if cargo test --workspace -j3 2>&1 | grep -q "test result: FAILED"; then
    echo "PASS: mutation $name was caught (suite went red)"; caught=$((caught+1))
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
echo "=== restored suite ==="
if cargo test --workspace -j3 2>&1 | grep -q "test result: FAILED"; then
  echo "FAIL: the suite is still red after restore"; exit 1
fi
echo "green again after restore"

echo
echo "mutations caught: $caught/$total"
[ "$caught" -eq "$total" ]