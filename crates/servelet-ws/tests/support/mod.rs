//! A raw WebSocket client, shared by the hardening test files.
//!
//! WHY HAND-WRITTEN RATHER THAN `servelet_ws::connect`: this crate's own client is a correct,
//! well-behaved peer, and every test in here is about what happens when a peer is NOT well
//! behaved — a 64-bit length header claiming 2^63 bytes, a control frame with FIN clear, a text
//! frame that is not valid UTF-8. `connect` cannot produce any of those, and the tests would then
//! be testing the client rather than the server.
//!
//! It is still a REAL client: a real `TcpStream`, a real RFC 6455 handshake, real masked frames
//! on the wire. `RawWs::handshake` writes the handshake by hand rather than calling `connect`
//! only because it needs to read the response head itself and keep any bytes that arrive in the
//! same TCP read.

#![allow(dead_code)] // Each hardening test file uses a different subset of this harness.

use std::net::SocketAddr;
use std::time::Duration;

use servelet_core::{Method, Request};
use servelet_ws::{WsLimits, accept_with_limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A fixed client mask key. RFC 6455 requires clients to mask; the value itself is free, and a
/// constant keeps the on-wire bytes in a failing test readable.
pub const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// The RFC 6455 §1.3 example key, so a handshake here is recognisable in a hex dump.
pub const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Run one server connection with `limits`, handing every `recv` result — success or error — to
/// the returned channel so a test can assert on the ERROR the codec produced, not only on the
/// bytes it put on the wire.
///
/// The server drives `recv` in a loop until it errors, which is what a real route does, and
/// reports every `Message` it decoded along the way.
pub async fn spawn_ws_server(limits: WsLimits) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        eprintln!("SERVER task started");
        let (mut stream, _) = listener.accept().await.unwrap();
        eprintln!("SERVER accepted");
        let req = match read_handshake_request(&mut stream).await {
            Some(r) => r,
            None => {
                let _ = tx.send("error handshake head incomplete".to_string());
                return;
            }
        };
        eprintln!("SERVER head: {:?}", req.headers().get("sec-websocket-key"));
        let mut ws = match accept_with_limits(stream, &req, Vec::new(), limits).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("SERVER accept failed: {e}");
                let _ = tx.send(format!("error accept failed: {e}"));
                return;
            }
        };
        loop {
            match ws.recv().await {
                Ok(msg) => {
                    let _ = tx.send(format!("message {msg:?}"));
                }
                Err(e) => {
                    let _ = tx.send(format!("error {e}"));
                    return;
                }
            }
        }
    });
    (addr, rx)
}

/// Read the client's upgrade request head off the socket and build the `Request` `accept` needs.
/// Returns `None` if the peer hung up mid-head.
pub async fn read_handshake_request(stream: &mut TcpStream) -> Option<Request> {
    let mut head = Vec::new();
    let mut one = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut one))
            .await
            .ok()?
            .ok()?;
        let _ = n;
        head.push(one[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.lines();
    let mut req = Request::new(Method::GET, "/ws".parse().unwrap());
    for line in lines.skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            req = req.with_header(k.trim().to_string(), v.trim().to_string());
        }
    }
    Some(req)
}

/// A hand-rolled, deliberately-abusable WebSocket client over a real socket.
pub struct RawWs {
    stream: TcpStream,
    /// Bytes read past a frame boundary. A single TCP read can carry two frames, and dropping
    /// the tail is how a "the server sent the wrong thing" test starts failing for the wrong
    /// reason.
    buf: Vec<u8>,
}

impl RawWs {
    /// Connect and perform a real RFC 6455 handshake; assert the server answered `101`.
    pub async fn connect(addr: SocketAddr) -> RawWs {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut ws = RawWs { stream, buf: Vec::new() };
        let head = ws.fill_until_head().await;
        ws.buf.extend_from_slice(&head);
        assert!(
            String::from_utf8_lossy(&ws.buf).starts_with("HTTP/1.1 101"),
            "the handshake must be answered with a 101: {:?}",
            String::from_utf8_lossy(&ws.buf)
        );
        ws.buf.drain(..4);
        ws.buf.drain(..ws.head_end());
        ws
    }

    /// Read until the response head's blank line, returning the head's bytes.
    async fn fill_until_head(&mut self) -> Vec<u8> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = self.stream.read(&mut head).await.unwrap();
            assert!(n > 0, "the server closed before finishing its handshake response");
        }
        head
    }

    /// Offset just past the `\r\n\r\n` of the 101 head, computed over whatever is buffered.
    fn head_end(&self) -> usize {
        self.buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("the head terminator was just read")
            + 4
    }

    /// Send a masked frame with a real payload. `fin_opcode` carries FIN in bit 7 and the opcode
    /// in the low nibble, so a fragmented or invalid frame is written the same way.
    pub async fn send_frame(&mut self, fin_opcode: u8, payload: &[u8]) {
        let mut frame = vec![fin_opcode];
        let n = payload.len();
        if n < 126 {
            frame.push(0x80 | n as u8);
        } else if n <= 0xFFFF {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
        frame.extend_from_slice(&MASK);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
    }

    /// Send ONLY a 64-bit-length frame header plus its mask key, and no payload at all.
    ///
    /// This is the whole point of the oversize test: the declared length is absurd, so sending a
    /// matching payload is impossible. A server that allocates before checking will try to read
    /// 2^63 bytes from a socket that will never send them — and, worse, will have already tried
    /// to allocate them.
    pub async fn send_oversize_length_header(&mut self, fin_opcode: u8, declared_len: u64) {
        let mut frame = vec![fin_opcode, 0x80 | 127];
        frame.extend_from_slice(&declared_len.to_be_bytes());
        frame.extend_from_slice(&MASK);
        self.stream.write_all(&frame).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// Send a header declaring `declared_len` bytes, then exactly `to_send` bytes of payload.
    /// A server that correctly refuses never reads the payload; one that does not, does.
    pub async fn send_frame_with_truncated_payload(&mut self, fin_opcode: u8, declared_len: u64, to_send: &[u8]) {
        let mut frame = vec![fin_opcode, 0x80 | 127];
        frame.extend_from_slice(&declared_len.to_be_bytes());
        frame.extend_from_slice(&MASK);
        frame.extend(to_send.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// Read one frame off the wire: `(fin_and_opcode, payload)`, unmasked if the server masked.
    pub async fn read_frame(&mut self) -> (u8, Vec<u8>) {
        let b0 = self.read_byte().await;
        let b1 = self.read_byte().await;
        let masked = b1 & 0x80 != 0;
        let mut len = (b1 & 0x7F) as usize;
        if len == 126 {
            let a = self.read_byte().await as usize;
            let b = self.read_byte().await as usize;
            len = (a << 8) | b;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            for slot in ext.iter_mut() {
                *slot = self.read_byte().await;
            }
            len = u64::from_be_bytes(ext) as usize;
        }
        let key = if masked {
            let mut k = [0u8; 4];
            for slot in k.iter_mut() {
                *slot = self.read_byte().await;
            }
            Some(k)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        self.read_exact_into(&mut payload).await;
        if let Some(k) = key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= k[i % 4];
            }
        }
        (b0, payload)
    }

    async fn read_byte(&mut self) -> u8 {
        let mut one = [0u8; 1];
        self.read_exact_into(&mut one).await;
        one[0]
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) {
        let mut got = 0;
        while got < buf.len() {
            if self.buf.is_empty() {
                let n = self.stream.read(&mut self.buf).await.unwrap();
                assert!(n > 0, "the server closed the connection mid-frame");
            }
            let take = (buf.len() - got).min(self.buf.len());
            buf[got..got + take].copy_from_slice(&self.buf[..take]);
            self.buf.drain(..take);
            got += take;
        }
    }

    /// True once the server has closed its half of the connection.
    pub async fn is_closed(&mut self) -> bool {
        self.stream.read(&mut self.buf).await.map(|n| n == 0).unwrap_or(true)
    }
}

/// Read the next thing the server reported through the channel, or `None` if it has gone quiet.
pub async fn next_report(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> Option<String> {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.ok().flatten()
}