#!/usr/bin/env bash
# Regenerate nix/Cargo.lock for the tree the flake actually builds (the workspace
# crates and manifest, see flake.nix). Needs network (cargo resolves crates.io and the git
# dependencies). Lock-update job only.
#   nix/gen-lock.sh            sync nix/Cargo.lock with the manifest, keeping locked versions
#   nix/gen-lock.sh --update   re-resolve everything to the newest versions
#   nix/gen-lock.sh --check    fail if nix/Cargo.lock does not match the manifest
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"; trap 'chmod -R u+w "$tmp"; rm -rf "$tmp"' EXIT
cp -r "$(nix build .#servelet-tree --no-link --print-out-paths)/." "$tmp/"
chmod -R u+w "$tmp"
case "${1:-}" in
  --check)  cp nix/Cargo.lock "$tmp/Cargo.lock"
            (cd "$tmp" && cargo metadata --locked --format-version 1 >/dev/null) && echo "nix/Cargo.lock is current" ;;
  --update) (cd "$tmp" && cargo generate-lockfile >/dev/null)      # re-resolve everything to the newest versions
            cp "$tmp/Cargo.lock" nix/Cargo.lock; echo "regenerated nix/Cargo.lock" ;;
  *)        cp nix/Cargo.lock "$tmp/Cargo.lock"                     # keep every locked version, only add/remove entries
            (cd "$tmp" && cargo metadata --format-version 1 >/dev/null)
            cp "$tmp/Cargo.lock" nix/Cargo.lock; echo "synced nix/Cargo.lock" ;;
esac
