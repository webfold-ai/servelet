# servelet-ws

WebSocket: the RFC 6455 frame codec and the upgrade handshake, client and server.

One job. It turns bytes into `Message`s and back, and it performs the handshake on both sides —
`connect` for the client, `accept` for the server. It does not route, does not decide *whether* a
connection upgrades, and does not own the socket loop: `servelet-h1` reads the request, hands the
connection over after the `101`, and stops touching it.

## Why it exists

`biota/http-server` had `websocket::accept`, and `serve_connection` handed the `Router` only the
parsed `Request` — the `TcpStream` never reached a handler, so nothing routed could upgrade. The
proof is `nexus/docs/runs.md` §8.1 on branch `yokoszn/nexus-runs`: cezar's two realtime topics
(health, host) and the kaneo board sockets (2 of the 17 slice-1 routes) are unservable without it.
This crate plus `servelet-h1`'s upgrade seam (`docs/EXTENSIONS.md` §6) is that fix.

## What is in it

| file | from `biota/http-server` rev `4ce2dcd` | lines |
|---|---|---|
| `src/handshake.rs` | `lib.rs` 2490-2598 — `WS_GUID`, `sha1`, `base64_encode`, `compute_accept_key`, `generate_key` | 109 |
| `src/frame.rs` | `lib.rs` 2600-2734 — `Message`, opcodes, `WebSocket`, `read_n`, `write_frame`, `send_text`, `send_binary`, `ping`, `close`, `recv` | 135 |
| `src/client.rs` | `lib.rs` 2736-2785 — `connect` | 50 |
| `src/lib.rs` | `lib.rs` 2787-2808 — `accept` | 78 |
| `tests/moved.rs` | `lib.rs` 2814-2927 — five tests, two of them over real TCP | 114 |

`scripts/verify_move.py` reports **91+105+40+28+91 = 355 code lines, 355 verbatim** (the rest of
each file's code lines are the documented deviations, counted separately): TOTAL 3414/3414 across
the repo, 0 unaccounted.

## Weight

`cargo tree -p servelet-ws --prefix none | sort -u | wc -l` — see `budget/deps.tsv`. It is
`servelet-core` + `servelet-client` + `tokio` and nothing else: **no third-party crate was added
for this unit**. SHA-1 and base64 are in `src/handshake.rs`, moved verbatim from biota, and are
the documented exception README rule 8 asks for: RFC 6455 §1.3 *is* `base64(sha1(key + GUID))`,
both algorithms are fully specified and short, and a handshake verifier is exactly the wrong place
to trust someone else's dependency tree. `sha1_matches_known_vectors` pins the implementation
against the FIPS 180-1 vectors, and `accept_key_matches_rfc6455_worked_example` pins the composed
value against the RFC's own worked example.

## Deliberately not here

- **Fragmented messages.** `recv` treats one frame as one message and a continuation frame as
  binary; that is biota's stated reduction, kept as-is by rule 9 rather than silently "fixed".
  permessage-deflate is likewise absent.
- **`wss://`.** The client half speaks plaintext `ws://` only. Server side, a TLS stream works
  because `accept` is generic over `AsyncRead + AsyncWrite` — the `servelet-h1` upgrade seam hands
  it whatever connection it had, decrypted or not.
- **A router integration.** This crate has no opinion about routes, origins or sessions; the
  upgrade seam in `servelet-h1` and the auth layer in front of it do that.