//! The inbound size limits — added by the hardening unit, NOT part of the biota move.
//!
//! WHY THIS FILE EXISTS: the moved `recv` reads the 64-bit payload length straight out of the
//! frame header and hands it to `vec![0u8; n]`. Nothing between those two lines asks whether the
//! peer is entitled to the number it just wrote. A peer that sends a header claiming 2^63 bytes
//! gets the server to try to allocate an exabyte, which on Linux is an allocation failure that
//! ABORTS THE PROCESS, not an error a handler can catch. That is a one-frame denial of service
//! on any socket that ever accepts a WebSocket, which is why `docs/servelet-ws.md` listed it as
//! the first thing to fix before this crate faces the internet.
//!
//! The fix is two ceilings, checked BEFORE the allocation, with a Close frame carrying 1009
//! ("Message Too Big", RFC 6455 §7.4.1) on the wire so the peer learns why rather than seeing the
//! connection die. Both defaults are configurable per connection: an application streaming video
//! frames legitimately needs more than a chat server does, and a limit that cannot be raised is
//! a limit that gets disabled at the firewall instead.

/// Close code: the message was too big to process (RFC 6455 §7.4.1).
pub const CLOSE_TOO_BIG: u16 = 1009;
/// Close code: the frame violated the protocol (RFC 6455 §7.4.1).
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
/// Close code: the payload was not the kind the opcode promised (RFC 6455 §7.4.1).
pub const CLOSE_INVALID_PAYLOAD: u16 = 1007;
/// Close code: the endpoint is going away (RFC 6455 §7.4.1) -- used when the read deadline
/// expires and the connection is being reclaimed.
pub const CLOSE_GOING_AWAY: u16 = 1001;

/// The two ceilings on what one peer may send this crate, per connection.
///
/// Defaults, and why these numbers:
///
/// * [`Self::DEFAULT_MAX_FRAME_BYTES`] — 1 MiB. Comfortably above any single chat message,
///   base64 avatar, or JSON document, and below the point where one connection's worth of
///   buffering matters next to the other sockets the process is holding.
/// * [`Self::DEFAULT_MAX_MESSAGE_BYTES`] — 16 MiB. A message may arrive as many frames (RFC 6455
///   fragmentation), so it needs its own, larger ceiling than a single frame.
///
/// The frame ceiling exists to bound a single `alloc`; the message ceiling exists to bound how
/// much a peer can make the process hold at once while reassembling fragments. Both are checked
/// on the declared length, before any payload byte is read, so an over-limit header costs one
/// 14-byte read rather than the allocation it was asking for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsLimits {
    /// Largest single frame payload accepted, in bytes.
    pub max_frame_bytes: u64,
    /// Largest total message accepted across all of its frames, in bytes.
    pub max_message_bytes: u64,
}

impl WsLimits {
    /// 1 MiB — see the type's own doc comment for the reasoning.
    pub const DEFAULT_MAX_FRAME_BYTES: u64 = 1 << 20;
    /// 16 MiB — see the type's own doc comment for the reasoning.
    pub const DEFAULT_MAX_MESSAGE_BYTES: u64 = 16 << 20;

    /// The defaults, spelled as a function as well as through [`Default`] so a caller that never
    /// touches limits still says so at the call site.
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise or lower the per-frame ceiling.
    pub fn with_max_frame_bytes(mut self, bytes: u64) -> Self {
        self.max_frame_bytes = bytes;
        self
    }

    /// Raise or lower the per-message ceiling.
    pub fn with_max_message_bytes(mut self, bytes: u64) -> Self {
        self.max_message_bytes = bytes;
        self
    }
}

impl Default for WsLimits {
    fn default() -> Self {
        WsLimits {
            max_frame_bytes: Self::DEFAULT_MAX_FRAME_BYTES,
            max_message_bytes: Self::DEFAULT_MAX_MESSAGE_BYTES,
        }
    }
}