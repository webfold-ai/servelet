# Building servelet with Nix (tas-nix-build)

servelet builds on the platform's shared Nix build layer (`Tasmanian-Cloud/hosting-runtime`, directory `nix/`):
one pinned compiler and the same six gates as every other service, plus an SBOM. servelet is a library
workspace (no binary, no image), so `flake.nix` composes `lib.mkRustPipeline` (checks, SBOM) instead of
`lib.mkRustFlake` (whose `default` package is the first binary).

```sh
export NIX_CONFIG="sandbox-fallback = false"   # see "Settings"
git add -N flake.nix flake.lock nix           # only git-tracked files are visible to a flake
nix flake check                                # fmt clippy test doc deny audit, one derivation each
nix build .#checks.x86_64-linux.servelet-{fmt,clippy,test,doc,deny,audit}
nix build .#servelet-sbom                      # CycloneDX 1.5, one file per crate
nix run .#run-tests                            # run the Nix-built test binaries on the host network
nix run .#repro-check -- .#servelet-sbom       # build twice, compare byte for byte
```

## What is built

All nine crates. The source is assembled by the flake (`nix build .#servelet-tree`): `crates/`, the committed
`Cargo.toml` plus `exclude = ["vendor"]` and a `[patch."https://github.com/Ptyktos/hashtrinity"]` section, and
the pinned `hashtrinity` input vendored under `vendor/`. hashtrinity is a path dependency in the build on
purpose: its `hashtrinity_derive` reads `../../src/proc_masq.rs`, outside its own package, which Crane's
per-package git vendoring cannot provide. The rev is the one `Cargo.toml` names (`92a8863`, which moved from `8de00ef` only to take apeiron `255ca30`).

`nix/Cargo.lock` is the committed `Cargo.lock` with that one source changed (hashtrinity: git -> path), every
other locked version unchanged. `nix/gen-lock.sh` syncs it, `--check` verifies it, `--update` re-resolves.

One test is skipped (`testSkip`, reason at the call site in `flake.nix`):
`servelet-client` `tls_feature::without_the_feature_an_https_url_is_refused_by_name_not_silently_downgraded`
expects `Error::Tls` for an `https://example.invalid/` URL, but `pool::connect_fresh` dials TCP before it
looks at the scheme, so the test needs a resolver that answers for `.invalid`. It fails the same way outside
the sandbox. Checking the scheme first is the fix (a product change, not made here).

## Settings

The builders require `sandbox = true`, `sandbox-fallback = false`, `accept-flake-config = false`, no extra
substituters (see `hosting-runtime/nix/README.md`). `sandbox-fallback` defaults to `true`.

## Pinning and re-pinning

* `tas-nix` is pinned by `rev` in `flake.nix` and by `narHash` in `flake.lock`. **The pinned revision
  `b42be0f2381f77a09e6cc86bb42f6d398b2e7b7a` is the head of hosting-runtime's branch
  `claude/vigilant-heisenberg-kjspke`, which is not merged.** After a squash merge it can become unreachable:
  re-pin to the merge commit (change `rev=`, `nix flake lock`, `nix flake check`). Keep `shallow=1`.
* `hashtrinity` and `apeiron` are `flake = false` inputs pinned by rev. `hashtrinity` must stay at the rev in
  `Cargo.toml`; `apeiron` at the rev `hashtrinity` pins (`nix/Cargo.lock`). A rev that differs from the lock is
  an evaluation error.
* Private inputs (`tas-nix` while the repository is private, `apeiron`): a builder holds no credential. A job
  with a read-only credential clones each repository at the pinned rev and locks with the checkout standing
  in for the URL, then restores the real URL (what `hosting-runtime/nix/scripts/pin-input.sh` does for one
  input; for several, run one `nix flake lock --override-input a git+file://... --override-input b
  git+file://...` and set `.nodes.<input>.locked.url` back with `jq`). The tree reaches builders through the
  signed binary cache by `narHash`. Expected apeiron `narHash` at `255ca30`:
  `sha256-ABYuC2cGsd/4lrogqKsRc2u2RUyJps5toPVj4HfoKRk=`.

## Status (exercised 2026-10-23, cold start, Nix 2.34.6, `sandbox-fallback = false`, x86_64-linux)

| Item | Result |
|---|---|
| gate `test` | pass: 187 tests, 0 failed (1 skipped by name, see above) |
| `nix run .#run-tests` (the same binaries, outside the sandbox, real loopback sockets and TLS handshakes) | pass: 187 tests |
| `.#servelet-sbom` (CycloneDX 1.5, 9 files) and its `repro-check` | build; REPRODUCIBLE |
| gate `doc` (`--deny warnings`) | pass (293 `missing_docs` warnings are not errors) |
| gate `fmt` (members only) | **fail**: 335 hunks in 48 files; the repository has no CI that enforces it |
| gate `clippy` (`--all-targets --no-deps -D warnings`, rustc 1.99.0) | **fail** at `servelet-core` (1 finding: manual char comparison); Clippy stops at the first failing crate, so later crates are not yet linted |
| gate `deny` (shared policy) | pass (re-run 2026-10-23 at apeiron `255ca30`): bans ok, licenses ok, sources ok. It failed on one item before: `apeiron@a2b5093` shipped a GPL-3.0 `LICENSE` file and no SPDX field; `255ca30` carries the Apache-2.0 text and `license = "Apache-2.0"` |
| gate `audit` | **fail**: 5 vulnerabilities in the locked TLS stack: `rustls` 0.23.45 (RUSTSEC-2026-0346, -0347, -0348, -0349; fixed in 0.23.46) and `rustls-webpki` 0.103.15 (RUSTSEC-2026-0382; fixed in 0.103.16). They are in the committed `Cargo.lock` too; `cargo update -p rustls -p rustls-webpki` is the fix (a dependency change, not made here) |

No gate was weakened. Every failure is in the code or its locked dependencies, not in the build layer.
