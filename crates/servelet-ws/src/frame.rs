use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use servelet_core::{Error, Result};

use crate::limits::{WsLimits, CLOSE_TOO_BIG};

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

    /// Read exactly `n` bytes — from `pending` first, then the socket for the rest.
    async fn read_n(&mut self, n: usize) -> Result<Vec<u8>> {
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
    pub async fn recv(&mut self) -> Result<Message> {
        let header = self.read_n(2).await?;
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

        match opcode {
            OP_TEXT => Ok(Message::Text(String::from_utf8(payload).map_err(|e| Error::Parse(e.to_string()))?)),
            OP_BINARY | OP_CONTINUATION => Ok(Message::Binary(payload)),
            OP_CLOSE => Ok(Message::Close),
            OP_PING => {
                self.write_frame(OP_PONG, &payload).await?;
                Ok(Message::Ping(payload))
            }
            OP_PONG => Ok(Message::Pong(payload)),
            other => Err(Error::Parse(format!("unknown WebSocket opcode {other}"))),
        }
    }
}
