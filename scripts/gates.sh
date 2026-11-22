#!/usr/bin/env bash
# The three gates, in the order that fails fastest. Run from anywhere:
#   scripts/gates.sh
#
#   1. cargo test --workspace -j3        (behaviour)
#   2. scripts/budget.sh                 (README rule 5, the line ratchet)
#   3. the dependency-weight check       (README rule 6, weight is a feature)
#
# The dependency check runs `cargo tree -p <crate> --prefix none | sort -u | wc -l` per crate
# and fails when a crate is heavier than the number committed in budget/deps.tsv.
set -uo pipefail
cd "$(dirname "$0")/.."

# Shared machine, tight memory/disk: the coordinator's build discipline applies to gates too.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
export CARGO_INCREMENTAL=0

rc=0
echo "=== gate 1/3: cargo test --workspace -j3 ==============================="
cargo test --workspace -j3 || { echo "GATE 1 FAILED"; rc=1; }

echo
echo "=== gate 2/3: scripts/budget.sh (rule 5 line ratchet) =================="
scripts/budget.sh || { echo "GATE 2 FAILED"; rc=1; }

echo
echo "=== gate 3/3: dependency weight (rule 6) =============================="
printf 'crate\tdeps\tbudget\tstatus\n'
# Skip the header row and comments. Reading the header as data used to print a bogus
# "crate 0 deps ok" row and a `[ 0: deps: integer expected` error into the middle of the gate
# output -- noise in the one place whose whole job is to be read.
while IFS=$'\t' read -r c budget; do
  [ -z "$c" ] && continue
  case "$c" in \#*|crate) continue ;; esac
  case "$budget" in ''|*[!0-9]*) echo "malformed row: $c $budget"; rc=1; continue ;; esac
  n=$(cargo tree -p "$c" --prefix none 2>/dev/null | sort -u | wc -l)
  if [ "$n" -gt "$budget" ]; then st="HEAVIER"; rc=1; else st=ok; fi
  printf '%s\t%s\t%s\t%s\n' "$c" "$n" "$budget" "$st"
done < budget/deps.tsv

echo
if [ "$rc" -eq 0 ]; then echo "ALL GATES PASSED"; else echo "GATES FAILED"; fi
exit "$rc"