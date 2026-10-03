# Migration: who moves to servelet, in what order

Measured 2026-10-03 by `git grep` at HEAD of each repo (worktree copies collapsed into their repo;
Cargo comments that merely mention a crate do not count). Rerouting a consumer means: depend on the
specific `servelet-*` crates it uses, change its imports, prove its own tests still pass, delete nothing
yet. When the last consumer of an old copy has moved, the old copy is deleted in the same change.

## Wave 1: users of `biota-http-server` (8)

| repo | imports from `biota_http_server::` | notes |
|---|---|---|
| ptyktos-api | 50 | largest; HTTP + auth surface |
| relayfold | 34 | plus `relayfold-control` (29), `relayfold-helm/proxy-runtime`, `relayfold-bench` (3): one repo |
| ptyktos-webgui | 13 | |
| webfold-fleet | 3 | path dependency on a local biota checkout |
| sangdb-bench | 2 | path dependency on a local biota checkout |
| wachd-rust | 0 | dead dependency: delete the line, no reroute needed |
| nexus (opsfold/nexus) | its `authed`, `http::*` modules | first consumer; defines the spine's contract |
| biota (members) | 0 | no member uses it; the crate is deleted from biota (branch `yokoszn/remove-http-server`, be13032) |

## Wave 2: users of bedrock's HTTP code (about 10 of 30 dependents)

| repo | http-ish imports | notes |
|---|---|---|
| opsfold | 385 | does not build at origin/main (`platform::http` deleted); superseded by nexus: do not reroute, retire |
| kleis, sauthy | 280 each | same code appears in both; decide the home first |
| syndesi | 92 | being retired into intent: do not reroute |
| spbench | 67 | |
| sang-codspeed | 62 | |
| appfold | 32 | |
| investfold | 12 | |
| hosting-runtime | 8 | |

The other ~20 bedrock dependents use non-HTTP parts (ontology, sangdb helpers, spend). They are out of
scope here and keep their dependency until bedrock itself is dismantled.

## Rule for each reroute

A worker moves ONE repo on its own branch in its own worktree, never pushes, and proves: (1) the repo's
tests give the same pass/fail counts before and after (counts pasted), (2) `cargo tree` shows the
`biota-http-server`/`bedrock` HTTP dependency gone and what replaced it, (3) the dependency weight did not
grow. Pin servelet by `rev`, never a floating branch.
