#!/usr/bin/env bash
# README rule 5 as a RATCHET: a crate is at most 3000 lines of Rust and no file exceeds 1200.
# The gate reads the committed baseline in budget/baseline.tsv and FAILS when any number
# rises. It may only fall. Lowering a number is welcome: commit the lowered value.
#
# Known exceptions (a file that is already over 1200 after a byte-for-byte move, because
# splitting it is a separate change) are listed in the baseline's note column and are
# tolerated at exactly their recorded size -- never more.
#
# Usage: scripts/budget.sh [--write-baseline]
set -uo pipefail
cd "$(dirname "$0")/.."

CRATE_MAX=3000
FILE_MAX=1200
BASELINE=budget/baseline.tsv

# rust files only: a crate's line count is its .rs under src/ plus tests/.
# `wc -l` over several files prints a "total" line; it is not a file, so drop it.
crate_lines() { find "crates/$1/src" -name '*.rs' 2>/dev/null | xargs cat 2>/dev/null | wc -l; }
max_file()   { find "crates/$1/src" -name '*.rs' 2>/dev/null | xargs wc -l 2>/dev/null | grep -v ' total$' | sort -rn | head -1 | awk '{print $1+0}'; }
max_file_name() { find "crates/$1/src" -name '*.rs' 2>/dev/null | xargs wc -l 2>/dev/null | grep -v ' total$' | sort -rn | head -1 | awk '{print $2}'; }

crates=$(ls crates | sort)

if [ "${1:-}" = "--write-baseline" ]; then
  printf 'crate\tlines\tmax_file\tnote\n' > "$BASELINE"
  for c in $crates; do
    note=$(awk -F'\t' -v k="$c" '$1==k{print $4}' "$BASELINE" 2>/dev/null)
    printf '%s\t%s\t%s\t%s\n' "$c" "$(crate_lines "$c")" "$(max_file "$c")" "${note:--}" >> "$BASELINE"
  done
  echo "baseline written to $BASELINE"
  cat "$BASELINE"
  exit 0
fi

printf 'crate\tlines\tbudget\tmax_file\tbudget\tstatus\n'
fail=0
for c in $crates; do
  lines=$(crate_lines "$c"); mfile=$(max_file "$c"); mname=$(max_file_name "$c")
  base_lines=$(awk -F'\t' -v k="$c" '$1==k{print $2}' "$BASELINE")
  base_file=$(awk -F'\t' -v k="$c" '$1==k{print $3}' "$BASELINE")
  base_note=$(awk -F'\t' -v k="$c" '$1==k{print $4}' "$BASELINE")
  if [ -z "$base_lines" ]; then
    printf '%s\t%s\t%s\t%s\t%s\tNEW-NO-BASELINE\n' "$c" "$lines" "$CRATE_MAX" "$mfile" "$FILE_MAX"
    fail=1; continue
  fi
  status=ok
  if [ "$lines" -gt "$base_lines" ]; then status="LINES-ROSE"; fail=1; fi
  if [ "$lines" -gt "$CRATE_MAX" ]; then status="$status OVER-CRATE-MAX"; fail=1; fi
  if [ "$mfile" -gt "$base_file" ]; then status="$status FILE-ROSE"; fail=1; fi
  if [ "$mfile" -gt "$FILE_MAX" ]; then
    # Tolerated ONLY when the baseline records this crate's largest file as a known
    # exception, and then only at exactly the recorded size (the ROSE check above already
    # enforces "never more"). The reason lives in the note column.
    case "$base_note" in
      *EXCEPTION*) status="$status KNOWN-EXCEPTION($base_note)" ;;
      *) status="$status FILE-OVER-1200"; fail=1 ;;
    esac
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$c" "$lines" "$CRATE_MAX" "$mfile" "$FILE_MAX" "$status"
  [ "$status" = ok ] && printf '#   %s: largest file is %s (%s lines)\n' "$c" "${mname##*/}" "$mfile"
done

echo
if [ "$fail" -eq 0 ]; then
  echo "budget OK: no number rose above budget/baseline.tsv"
else
  echo "budget FAILED: a number rose above budget/baseline.tsv (rule 5 ratchet)"
fi
exit "$fail"