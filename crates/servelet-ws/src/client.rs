use std::str;

use tokio::net::TcpStream;

use servelet_core::{Error, Result};

use crate::frame::WebSocket;
use crate::handshake::{compute_accept_key, generate_key};

/// Client side: perform the HTTP Upgrade handshake against `ws://host:port/path` (or
/// `wss://` is NOT supported here — TLS-wrapped WebSocket is a stated reduction, plain `ws://`
/// only) and return an established `WebSocket`.
pub async fn connect(url: &str) -> Result<WebSocket<TcpStream>> {
    let uri = servelet_core::parse_uri(&url.replacen("ws://", "http://", 1))?;
    let (host, port) = servelet_core::host_port(&uri)?;
    let mut stream = servelet_client::Stream::Plain(TcpStream::connect(format!("{host}:{port}")).await.map_err(Error::Io)?);

    let key = generate_key();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        uri.path_and_query(),
    );
    stream.write_all(request.as_bytes()).await.map_err(Error::Io)?;

    // A line-buffered reader that can reclaim any leftover bytes (`into_inner`) is required
    // here, not a plain `tokio::io::BufReader`: the server can write its 101 response and the
    // first WebSocket frame back-to-back, and a single underlying TCP read can capture both --
    // losing the tail past the header terminator would corrupt the very first `recv()`.
    let mut reader = stream.into_reader();
    let status_line = reader.read_line().await.map_err(Error::Io)?;
    let status_line = str::from_utf8(&status_line).map_err(|e| Error::Parse(e.to_string()))?.to_string();
    if !status_line.contains("101") {
        return Err(Error::Http(format!("WebSocket upgrade rejected: {}", status_line.trim())));
    }
    let mut accept = None;
    loop {
        let raw = reader.read_line().await.map_err(Error::Io)?;
        if raw.is_empty() || raw == b"\r\n" || raw == b"\n" {
            break;
        }
        let line = str::from_utf8(&raw).map_err(|e| Error::Parse(e.to_string()))?;
        if line.to_ascii_lowercase().starts_with("sec-websocket-accept:") {
            // Case-insensitive match on the HEADER NAME only -- the value (a base64 token) is
            // case-sensitive and must come from the ORIGINAL line, not a lowercased copy.
            let value_start = line.find(':').map(|i| i + 1).unwrap_or(line.len());
            accept = Some(line[value_start..].trim().to_string());
        }
    }
    let expected = compute_accept_key(&key);
    let (stream, pending) = reader.into_inner();
    // `Stream` grows a `Tls` arm when `servelet-client`'s off-by-default `tls` feature is on;
    // without it the `let ... else` below is irrefutable, which rustc warns about and this
    // crate's clippy gate treats as an error. The arm is kept either way: it is what makes the
    // match total the day a consumer turns that feature on, and the `unreachable!` says so.
    #[allow(irrefutable_let_patterns)]
    let servelet_client::Stream::Plain(stream) = stream else {
        unreachable!("connect() only ever builds a Plain stream")
    };
    match accept {
        Some(a) if a == expected => Ok(WebSocket { stream, is_client: true, pending }),
        Some(a) => Err(Error::Http(format!("Sec-WebSocket-Accept mismatch: got {a}, expected {expected}"))),
        None => Err(Error::Http("server response missing Sec-WebSocket-Accept".to_string())),
    }
}
