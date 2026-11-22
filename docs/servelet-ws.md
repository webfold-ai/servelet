# `servelet-ws` + the `servelet-h1` upgrade seam

Unit report. Branch `yokoszn/servelet-spine`. Everything here was run in this worktree on
2026-10-04 unless a line says otherwise.

## What exists

**`servelet-ws`** — the RFC 6455 frame codec and the handshake, moved byte-for-byte from
`biota/http-server` rev `4ce2dcd`, `lib.rs` `pub mod websocket`:

| file | biota `lib.rs` | lines |
|---|---|---|
| `src/handshake.rs` | 2490-2598 — `WS_GUID`, `sha1`, `base64_encode`, `compute_accept_key`, `generate_key` | 109 |
| `src/frame.rs` | 2600-2734 — `Message`, opcodes, `WebSocket`, `read_n`, `write_frame`, `send_*`, `ping`, `close`, `recv` | 139 |
| `src/client.rs` | 2736-2785 — `connect` | 64 |
| `src/lib.rs` | 2787-2808 — `accept` | 74 |
| `tests/moved.rs` | 2814-2927 — five tests, two over real TCP | 122 |

**The upgrade seam**, `crates/servelet-h1/src/upgrade.rs` (123 lines) — `with_upgrade(resp, cb)`,
`UpgradeFn`, `Connection`, `Upgraded` — plus six lines of dispatch in `wire.rs` and nine in
`lib.rs`. Documented in `docs/EXTENSIONS.md` §7 with a worked example. This is what makes
`servelet-ws` reachable from a route at all: `biota` had `websocket::accept`, and `serve_connection`
handed the `Router` only the parsed `Request`, so the stream never reached a handler.

**`crates/servelet-ws/tests/upgrade.rs`** (393 lines) — six new real-socket tests: a route upgrades
and echoes text and binary, the codec answers a ping, the close handshake completes both ways;
missing `Sec-WebSocket-Key` → 400; wrong `Origin` → 400; no credentials → 401; wrong role → 403,
with no `101` on the wire in any refusal; and a constant-time token comparison that rejects a
prefix of a valid token. Every route sits behind a role-checked `Layer` over the whole `Router`.

## Line counts, before and after

| | before (`biota lib.rs` 2472-2929) | after (`servelet-ws`) |
|---|---|---|
| module total, src + doc comments + tests | 458 | **901** (386 src + 515 tests) |
| `src/` lines | 458 | **386** |
| test lines | 114 (in-module `#[cfg(test)]`) | **515** (122 moved + 393 new) |
| code lines verified verbatim | 355 | **355 of 355** |

Plus `servelet-h1` 556 → **703** lines, largest file 313 → **328** (`wire.rs`).

The total roughly doubles and that is the point of the unit: 393 of the 515 test lines are the six
new real-socket upgrade tests, which is the behaviour biota had no way to express at all. The
`src/` figure is *smaller* than the module it came from because doc comments moved to the crate
README and four moved `use` lines now name the crates that own them.

## Numbers, with the commands

```
scripts/gates.sh        -> ALL GATES PASSED      (gate 1 tests, gate 2 line ratchet,
                                                    gate 3 dependency weight)
cargo test --workspace -j3 -> 86 passed, 0 failed   (servelet-ws alone: 5 moved + 6 new = 11)
scripts/verify_move.py  -> TOTAL 3421/3421 code lines verbatim in biota at 4ce2dcd
                            0 unaccounted; servelet-ws 355/355
scripts/mutation.sh     -> mutations caught: 11/11, restored suite green
```

The four mutations this unit added, all caught:

| | mutation | caught by |
|---|---|---|
| H | drop the RFC 6455 `WS_GUID` from the accept key | `accept_key_matches_rfc6455_worked_example` |
| I | mask every client byte with `mask_key[0]` | `websocket_handshake_and_frames_round_trip_over_real_tcp` |
| J | unmask every inbound byte with `key[0]` | the same |
| K | `serve_connection` stops dispatching the upgrade at all | `a_route_upgrades_over_a_real_socket_echoes_text_and_closes_cleanly` |

**H is the one that matters most.** A round-trip test would pass against a
self-consistent-but-wrong accept key on both sides, which is why the moved test pins the RFC's own
worked example instead. **K** exists because the seam is this unit's new behaviour and would
otherwise be pinned only by its own documentation.

## Two ratchets raised, deliberately

Both are consequences of the work above, each raised to a measured value with its reason written
into the budget file itself:

- `servelet-h1` 556 → 703 lines, max file 313 → 328.
- `servelet-ws` 38 → 48 deps. **38 of those are runtime.** The other 10 are the dev-only edge
  (`servelet-h1`, `servelet-router`, tokio's `rt-multi-thread`/`time`) that lets the upgrade be
  tested over a real socket behind a real auth layer rather than a stub. Nothing in
  `servelet-ws/src/` names any of them.

## No new third-party crates

SHA-1 and base64 came from biota with the rest of the module and are the documented exception the
task allows: RFC 6455 §1.3 *is* `base64(sha1(key + GUID))`, both algorithms are fully specified and
short, and a handshake verifier is exactly the wrong place to trust someone else's dependency tree.
`sha1_matches_known_vectors` pins the implementation against the FIPS 180-1 vectors. `servelet-ws`'s
whole runtime tree is `servelet-core` + `servelet-client` + `tokio`.

## Deliberately not done

- **Fragmented messages.** `recv` treats one frame as one message and a continuation frame as
  binary; that is biota's stated reduction, kept as-is by rule 9 rather than silently "fixed".
  `permessage-deflate` is likewise absent. **A consumer that needs RFC-compliant fragmentation still
  has to write it.**
- **`wss://` on the client half.** The client speaks plaintext `ws://` only. The *server* side is
  fine over TLS: `accept` is generic over `AsyncRead + AsyncWrite` and the seam hands it whatever
  connection it had, decrypted or not. **The client is the gap.**
- **Backpressure and idle timeouts on an upgraded connection.** Once the callback owns the socket,
  `serve_connection`'s keep-alive machinery is out of the picture by design; a route that needs a
  ping period writes one. **Not implemented, not tested.**
- **A `servelet-authed` crate.** The auth layer in `tests/upgrade.rs` is the shape that crate will
  own (README rule 7), written inline as a test fixture. **`servelet-authed` itself is not
  extracted here**, so the layer a consumer copies today lives in a test file.
- **Frame-size limits.** A length header can ask `read_n` for up to 2^64-1 bytes. That is biota's
  code unchanged, but on an internet-facing upgrade it is a denial-of-service lever. **Not
  addressed; flagged for whoever puts this in front of the open internet.**

## Notes on the state I inherited

The worktree already contained a `wip: … (unverified)` snapshot commit when I started — a previous
run of this unit had died. I re-measured rather than restarted: all of it held. One thing in it
looked like a defect and is not: the `eprintln!` in `wire.rs` that drops
its error binding, but `git show 4ce2dcd:http-server/src/kernel.rs` has that exact line with the
same comment — upstream's own `tracing::debug!` was stripped when these fixtures were prepared, so
keeping it is what "byte-for-byte" requires.

## NOT RUN

- **No `cargo fmt` / `cargo clippy`.** The repo records a deliberate decision not to run them
  (`docs/SPINE.md`); the build emits ~30 warnings, all of them `unused import`/`unused variable`
  carried over verbatim from biota's stripped source.
- **No CI.** Billing-blocked org-wide.
- **Windows, or any non-Linux target.** Tests bind real `127.0.0.1` sockets only.
- **`wss://` and TLS-terminated upgrades** are argued from the type signatures, not tested — no
  `servelet-ws` test opens a TLS socket.