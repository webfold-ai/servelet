use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use servelet_core::{Error, Result};

use crate::limits::{
    WsLimits, CLOSE_GOING_AWAY, CLOSE_INVALID_PAYLOAD, CLOSE_PROTOCOL_ERROR, CLOSE_TOO_BIG,
};

/// A decoded WebSocket message.
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// An established WebSocket connection — one frame per `send`/`recv`, no fragmentation (an
/// honest reduction from the full spec, stated in this module's own header doc).
pub struct WebSocket<S> {
    pub(crate) stream: S,
    /// Client connections MUST mask every frame they send (RFC 6455 §5.1); server connections
    /// MUST NOT. One connection is always exactly one side, fixed at construction.
    pub(crate) is_client: bool,
    /// Bytes already read off the socket while parsing the HTTP handshake but belonging to the
    /// FIRST WebSocket frame, not the handshake itself. A buffered line-reader (needed to find
    /// `\r\n\r\n`) can easily read past the handshake in one underlying TCP read if the peer
    /// sends a frame immediately after — losing these would corrupt the very first `recv()`.
    /// Drained before any fresh socket read (`read_n`), same pattern as `lib.rs`'s own
    /// `StreamReader`/pooled-connection leftover handling.
    pub(crate) pending: Vec<u8>,
    /// The inbound size ceilings for this connection. Not a constant: an application that
    /// legitimately carries video frames raises them per connection, and one that cannot be
    /// raised is a limit that gets disabled somewhere less visible. Checked on the DECLARED
    /// length, before the payload is read — see `limits.rs` for why that ordering is the whole
    /// point.
    pub(crate) limits: WsLimits,
    /// Reassembly buffer for a fragmented message (RFC 6455 §5.4): a `TEXT`/`BINARY` frame with
    /// FIN clear starts the message, `CONTINUATION` frames carry its middle, and the frame with
    /// FIN set ends it. The moved `recv` had no such state and returned a continuation frame as
    /// `Message::Binary`, which is why `docs/servelet-ws.md` listed RFC-compliant fragmentation as
    /// "deliberately not done" — on a public port, a peer can now make this grow.
    pub(crate) msg_buf: Vec<u8>,
    /// The opcode of the message being reassembled — `OP_TEXT` or `OP_BINARY`. A continuation
    /// carries no opcode of its own, so this is the only record of what the finished message is,
    /// and it is what the UTF-8 check at the end has to consult.
    pub(crate) msg_opcode: u8,
    /// Whether a fragmented message is currently open. Distinguishes "the first continuation of
    /// a message" from "a continuation with nothing to continue", which is a protocol error.
    pub(crate) msg_active: bool,
    /// How long a read may make no progress before the connection is reclaimed. `None` (the
    /// default) means no deadline at all -- see [`WebSocket::with_idle_timeout`].
    pub(crate) idle_timeout: Option<std::time::Duration>,
    /// When no bytes have arrived for this long, send a Ping and keep waiting. `None` (the
    /// default) means no keepalive -- see [`WebSocket::with_ping_interval`].
    pub(crate) ping_interval: Option<std::time::Duration>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocket<S> {
    /// Set the inbound size ceilings for this connection. The default is
    /// [`WsLimits::default`]; this is how an application that needs a different ceiling says so.
    pub fn with_limits(mut self, limits: WsLimits) -> Self {
        self.limits = limits;
        self
    }

    /// This connection's current size ceilings.
    pub fn limits(&self) -> &WsLimits {
        &self.limits
    }

    /// Reclaim the connection if no bytes arrive for `timeout`.
    ///
    /// OFF by default, deliberately. A deadline that expires closes a connection that may have
    /// been quiet but perfectly alive, and a library that picks that deadline for the
    /// application gets it wrong for somebody. What the library owes is a way to set one, and
    /// the fact that without one a peer can hold a connection open forever.
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Send a Ping when no bytes have arrived for `interval`, and keep waiting.
    ///
    /// The ping is the polite half of the same problem: a NAT or a load balancer drops an idle
    /// flow after a few tens of seconds, and RFC 6455 §5.5.2 requires the endpoint to answer a
    /// ping with a pong, so a ping every so often keeps the path open AND proves the peer is
    /// still there. It does not end the connection -- that is [`Self::with_idle_timeout`], and
    /// it should be set to comfortably more than the ping interval, or the connection will be
    /// closed between two pings.
    pub fn with_ping_interval(mut self, interval: std::time::Duration) -> Self {
        self.ping_interval = Some(interval);
        self
    }

    /// Read exactly `n` bytes, under whatever idle timeout and ping interval this connection
    /// carries.
    ///
    /// The moved `read_n` waited forever, so a peer that completed the handshake and then went
    /// quiet held the connection, its buffers and its task for as long as it liked. Two
    /// optional behaviours fix that, and the order between them is the whole design:
    ///
    ///   * if there is a ping interval AND it is shorter than the read timeout, wait that long;
    ///     if nothing has arrived, send a Ping and wait again;
    ///   * if the read timeout as a whole elapses with nothing arriving, close with 1001 and
    ///     report why.
    ///
    /// With neither configured this is exactly the moved behaviour, one extra branch.
    async fn read_n(&mut self, n: usize) -> Result<Vec<u8>> {
        let Some(idle) = self.idle_timeout else {
            return self.read_n_raw(n).await;
        };
        let keepalive = self.ping_interval.filter(|p| *p < idle);
        loop {
            let first = match keepalive {
                Some(p) => p,
                None => idle,
            };
            // Bound to a local so the mutable borrow of `self` ends before the timeout arm can
            // call back into `self` to write a Ping or a Close.
            let outcome = tokio::time::timeout(first, self.read_n_raw(n)).await;
            match outcome {
                Ok(result) => return result,
                Err(_) => {
                    if let Some(p) = keepalive {
                        let _ = self.write_frame(OP_PING, &[]).await;
                        continue;
                    }
                    self.close_with_code(CLOSE_GOING_AWAY).await;
                    return Err(Error::Http(format!(
                        "no data from the peer within {idle:?}"
                    )));
                }
            }
        }
    }

    /// Read exactly `n` bytes — from `pending` first, then the socket for the rest. The moved
    /// body, unchanged; [`Self::read_n`] is the version with the deadline.
    async fn read_n_raw(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        let from_pending = self.pending.len().min(n);
        if from_pending > 0 {
            out[..from_pending].copy_from_slice(&self.pending[..from_pending]);
            self.pending.drain(..from_pending);
        }
        if from_pending < n {
            self.stream.read_exact(&mut out[from_pending..]).await.map_err(Error::Io)?;
        }
        Ok(out)
    }

    async fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode); // FIN=1, no extension bits, opcode

        let mask_bit = if self.is_client { 0x80 } else { 0x00 };
        if payload.len() < 126 {
            frame.push(mask_bit | payload.len() as u8);
        } else if payload.len() <= 0xFFFF {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }

        if self.is_client {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
            let mask_key = crate::splitmix64(now).to_le_bytes();
            frame.extend_from_slice(&mask_key[..4]);
            frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask_key[i % 4]));
        } else {
            frame.extend_from_slice(payload);
        }

        self.stream.write_all(&frame).await.map_err(Error::Io)
    }

    pub async fn send_text(&mut self, text: impl AsRef<str>) -> Result<()> {
        let bytes = text.as_ref().as_bytes().to_vec();
        self.write_frame(OP_TEXT, &bytes).await
    }

    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.write_frame(OP_BINARY, data).await
    }

    pub async fn ping(&mut self, data: &[u8]) -> Result<()> {
        self.write_frame(OP_PING, data).await
    }

    pub async fn close(&mut self) -> Result<()> {
        self.write_frame(OP_CLOSE, &[]).await
    }

    /// Send a Close frame carrying an RFC 6455 §7.4.1 status code.
    ///
    /// Used by the refusals in [`Self::recv`]: a peer that is told *why* it was disconnected can
    /// report it, and a peer that just sees the socket die retries forever. Best effort — a peer
    /// that has already vanished must not turn a protocol refusal into a different error, so the
    /// write result is deliberately discarded here and the caller returns its own error.
    async fn close_with_code(&mut self, code: u16) {
        let _ = self.write_frame(OP_CLOSE, &code.to_be_bytes()).await;
    }

    /// Read one frame and decode it into a `Message`. Automatically answers a peer `Ping` with a
    /// `Pong` (RFC 6455 §5.5.2 requires this) before returning it to the caller as `Message::Ping`.
    ///
    /// HARDENING (fragmentation, control frames, UTF-8): the moved version of this function
    /// treated one frame as one message and handed a `CONTINUATION` frame back as
    /// `Message::Binary`. Three things follow from that on a public port, and all three are
    /// refusals here, each with its RFC 6455 close code on the wire:
    ///
    ///   * **Control frames must not be fragmented and must carry at most 125 bytes**
    ///     (§5.5). A fragmented control frame or an oversized one is a `1002` protocol error.
    ///     The 125-byte rule is what keeps a ping/pong usable while a huge data frame is in
    ///     flight — without it, a peer could interleave an unbounded "control" frame.
    ///   * **A message is capped in total, across all of its frames** (§5.4), not per frame. The
    ///     per-frame ceiling bounds one `alloc`; this one bounds what reassembly accumulates,
    ///     which is a peer sending a million 1-byte continuations.
    ///   * **A `TEXT` message must be valid UTF-8** (§5.6). The moved code did check this, but on
    ///     a single frame only; now it is checked on the ASSEMBLED message, which is the only
    ///     place it can be checked correctly — a multi-byte character split across a fragment
    ///     boundary is valid, and a per-frame check would refuse it.
    ///
    /// The loop, rather than a recursive call, is what lets a fragmented message keep reading
    /// frames until it finds the FIN: `recv` still returns exactly one `Message` per call.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            let header = self.read_n(2).await?;
            let fin = header[0] & 0x80 != 0;
            let opcode = header[0] & 0x0F;
            let masked = header[1] & 0x80 != 0;
            let mut len = (header[1] & 0x7F) as u64;

            if len == 126 {
                let ext = self.read_n(2).await?;
                len = u16::from_be_bytes([ext[0], ext[1]]) as u64;
            } else if len == 127 {
                let ext = self.read_n(8).await?;
                len = u64::from_be_bytes(ext.try_into().unwrap());
            }

            // HARDENING (control frames, RFC 6455 §5.5): FIN must be set and the payload must
            // fit in the 7-bit length field. Checked BEFORE the size guard below, because a
            // control frame is never allowed to be big enough for the guard to be the right
            // answer — an oversized ping is a protocol error (1002), not a too-big message
            // (1009), and telling a peer the wrong thing sends it looking in the wrong place.
            let is_control = opcode & 0x08 != 0;
            if is_control && (!fin || len > 125) {
                self.close_with_code(CLOSE_PROTOCOL_ERROR).await;
                return Err(Error::Parse(format!(
                    "control frame (opcode {opcode:#x}) must have FIN set and at most 125 bytes of payload, got FIN={fin} len={len}"
                )));
            }

            // HARDENING: the declared length is checked HERE, before the mask key and before any
            // payload byte is read, and before `read_n` can reach the `vec![0u8; n]` that this value
            // used to go straight into. The moved code had no such check, so a ten-byte frame header
            // claiming 2^63 bytes asked the process to allocate an exabyte — an abort on Linux, not
            // an `Err`, and therefore not something a caller could survive. The two arms are one
            // condition: on a 32-bit target `len` can also exceed `usize`, which would truncate.
            if len > self.limits.max_frame_bytes || len > usize::MAX as u64 {
                self.close_with_code(CLOSE_TOO_BIG).await;
                return Err(Error::Http(format!(
                    "inbound frame declares {len} bytes, which exceeds this connection's {} byte frame limit",
                    self.limits.max_frame_bytes
                )));
            }

            let mask_key = if masked {
                let key = self.read_n(4).await?;
                Some([key[0], key[1], key[2], key[3]])
            } else {
                None
            };

            let mut payload = self.read_n(len as usize).await?;
            if let Some(key) = mask_key {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= key[i % 4];
                }
            }

            // Control frames are answered here, in the middle of a fragmented message if that is
            // where they arrived — which RFC 6455 §5.4 explicitly permits, and which is the whole
            // reason control frames exist: a liveness check must not have to wait for a large
            // message to finish.
            if is_control {
                return match opcode {
                    OP_CLOSE => Ok(Message::Close),
                    OP_PING => {
                        self.write_frame(OP_PONG, &payload).await?;
                        Ok(Message::Ping(payload))
                    }
                    OP_PONG => Ok(Message::Pong(payload)),
                    other => {
                        self.close_with_code(CLOSE_PROTOCOL_ERROR).await;
                        Err(Error::Parse(format!("unknown control opcode {other}")))
                    }
                };
            }

            match opcode {
                OP_TEXT | OP_BINARY => {
                    // A data frame inside an open fragmented message ends it abnormally
                    // (§5.4): there is no way to know where the peer thought the previous one
                    // stopped, so the message boundaries are no longer trustworthy.
                    if self.msg_active {
                        self.close_with_code(CLOSE_PROTOCOL_ERROR).await;
                        return Err(Error::Parse(format!(
                            "a new {} frame arrived inside a fragmented message",
                            if opcode == OP_TEXT { "text" } else { "binary" }
                        )));
                    }
                    if payload.len() as u64 > self.limits.max_message_bytes {
                        self.close_with_code(CLOSE_TOO_BIG).await;
                        return Err(Error::Http(format!(
                            "message of {} bytes exceeds this connection's {} byte message limit",
                            payload.len(),
                            self.limits.max_message_bytes
                        )));
                    }
                    if !fin {
                        self.msg_active = true;
                        self.msg_opcode = opcode;
                        self.msg_buf = payload;
                        continue;
                    }
                    return self.finish_message(opcode, payload).await;
                }
                OP_CONTINUATION => {
                    // A continuation with nothing to continue. The moved code returned this as
                    // `Message::Binary`, which is how a peer could inject bytes into whatever the
                    // application thought was the next message.
                    if !self.msg_active {
                        self.close_with_code(CLOSE_PROTOCOL_ERROR).await;
                        return Err(Error::Parse(
                            "continuation frame with no fragmented message in progress".to_string(),
                        ));
                    }
                    let total = self.msg_buf.len() as u64 + payload.len() as u64;
                    if total > self.limits.max_message_bytes {
                        self.close_with_code(CLOSE_TOO_BIG).await;
                        return Err(Error::Http(format!(
                            "fragmented message of {total} bytes exceeds this connection's {} byte message limit",
                            self.limits.max_message_bytes
                        )));
                    }
                    let opcode = self.msg_opcode;
                    self.msg_buf.extend_from_slice(&payload);
                    if !fin {
                        continue;
                    }
                    self.msg_active = false;
                    let complete = std::mem::take(&mut self.msg_buf);
                    return self.finish_message(opcode, complete).await;
                }
                other => {
                    self.close_with_code(CLOSE_PROTOCOL_ERROR).await;
                    return Err(Error::Parse(format!("unknown WebSocket opcode {other}")));
                }
            }
        }
    }

    /// Turn a fully assembled message into a `Message`, refusing a `TEXT` one that is not valid
    /// UTF-8 with close code 1007 (RFC 6455 §7.4.1).
    ///
    /// Called with the WHOLE message, never per frame: a multi-byte UTF-8 character split across
    /// a fragment boundary is perfectly legal, and neither half is valid on its own.
    async fn finish_message(&mut self, opcode: u8, payload: Vec<u8>) -> Result<Message> {
        if opcode == OP_TEXT {
            match String::from_utf8(payload) {
                Ok(text) => Ok(Message::Text(text)),
                Err(e) => {
                    self.close_with_code(CLOSE_INVALID_PAYLOAD).await;
                    // The error names the position and nothing else about the bytes: a text frame
                    // is application data, and an error message that echoes it back is a way to
                    // get untrusted bytes into a log line.
                    Err(Error::Parse(format!(
                        "text message is not valid UTF-8 (bad byte at offset {})",
                        e.utf8_error().valid_up_to()
                    )))
                }
            }
        } else {
            Ok(Message::Binary(payload))
        }
    }
}
