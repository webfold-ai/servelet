//! The wire, byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`.

use super::*;

async fn read_request_buffered<R: AsyncReadExt + AsyncWriteExt + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Request> {
    let mut line_buf = Vec::new();
    reader.read_until(b'\n', &mut line_buf).await?;
    if line_buf.is_empty() {
        return Err(Error::Parse("empty request".into()));
    }
    let line = str::from_utf8(&line_buf).map_err(|e| Error::Parse(e.to_string()))?;
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(Error::Parse(format!("bad request line: {line}")));
    }

    let method = parts[0].parse::<Method>()?;
    let uri = parts[1].parse::<Uri>()?;
    let version = match parts[2] {
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    };

    let mut headers = HeaderMap::new();
    let mut content_length = 0usize;
    let mut te_chunked = false;
    loop {
        line_buf.clear();
        reader.read_until(b'\n', &mut line_buf).await?;
        if line_buf == b"\r\n" || line_buf == b"\n" || line_buf.is_empty() {
            break;
        }
        let line = str::from_utf8(&line_buf).map_err(|e| Error::Parse(e.to_string()))?;
        if let Some((n, v)) = line.split_once(':') {
            let name = n.parse::<HeaderName>()?;
            let value = v.trim().parse::<HeaderValue>()?;
            if name.as_str() == header::CONTENT_LENGTH {
                content_length = value
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
            if name.as_str() == header::TRANSFER_ENCODING
                && value.to_str().unwrap_or("").to_ascii_lowercase().contains("chunked")
            {
                te_chunked = true;
            }
            headers.insert(name, value);
        }
    }

    let mut body = Vec::new();
    if headers.contains_key("expect") {
        // Answer `Expect: 100-continue` immediately (botocore sends it for every file-like S3
        // body, Content-Length or chunked). This is the standard proxy behavior (nginx/hyper
        // both do it): the client sends its body right away, and the real response follows
        // later — no client-side expect-wait race. The forwarded request never carries
        // `Expect` (see `forward_raw` — the body is fully buffered here, so the upstream must
        // never wait for it).
        reader
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .map_err(Error::Io)?;
    }
    if content_length > 0 {
        body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
    } else if te_chunked {
        // `Transfer-Encoding: chunked` request body (botocore's S3 streaming checksum mode
        // sends `aws-chunked` framing: `Transfer-Encoding: chunked` + `Content-Encoding:
        // aws-chunked` + `X-Amz-Trailer` — NO Content-Length). Read the RAW chunked bytes
        // verbatim (chunk-size lines, data, final 0-chunk, trailers) and forward them
        // untouched: the upstream (e.g. garage) validates the aws-chunked framing and the
        // per-chunk SigV4 signatures itself, exactly as if the client had connected directly.
        loop {
            let mut size_line = Vec::new();
            reader.read_until(b'\n', &mut size_line).await?;
            body.extend_from_slice(&size_line);
            let size_str = std::str::from_utf8(&size_line).unwrap_or("").trim();
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("0").trim(), 16)
                .map_err(|e| Error::Parse(format!("bad chunk size {size_str:?}: {e}")))?;
            if size == 0 {
                // Trailers (incl. the `X-Amz-Trailer` checksum) — read raw until blank line.
                loop {
                    let mut tl = Vec::new();
                    reader.read_until(b'\n', &mut tl).await?;
                    body.extend_from_slice(&tl);
                    if tl == b"\r\n" || tl == b"\n" || tl.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; size + 2]; // data + CRLF
            reader.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
        }
    }

    Ok(Request {
        method,
        uri,
        version,
        headers,
        body,
        extensions: Extensions::new(),
        peer_addr: None,
    })
}
pub async fn serve<A: ToSocketAddrs>(addr: A, router: Router) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("INFO  bedrock::serve  listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let router = router.clone();
        tokio::spawn(
            serve_connection(stream, router, Some(peer))
                ,
        );
    }
}

/// One connection's whole request/response loop (HTTP/1.1 keep-alive) — shared by `serve`,
/// `serve_tls`, and `crate::runtime::graceful::serve_gracefully` so the wire-level behavior can't drift between
/// entry points. Generic over the stream (`TcpStream` for plain HTTP, `tokio_rustls::server::
/// TlsStream<TcpStream>` for `serve_tls` after the handshake completes) — the request/response
/// loop itself has no idea whether TLS termination happened underneath it.
pub async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    router: Router,
    peer_addr: Option<std::net::SocketAddr>,
) {
    let mut reader = BufReader::with_capacity(8192, stream);
    // CUT (docs/SPINE.md "Deviations"): the h2c-preface sniff (RFC 7540 3.4, "prior knowledge")
    // that stood here is `servelet-h2`'s to reinstate. It matched
    // `crate::httpsrv::httpx::h2::PREFACE`, another crate's constant. Everything after the sniff
    // is HTTP/1.1 line framing, byte-for-byte unchanged.
    loop {
        let req = match read_request_buffered(&mut reader).await {
            Ok(req) => match peer_addr {
                Some(addr) => req.with_peer_addr(addr),
                None => req,
            },
            Err(e) => {
                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "connection closed while reading request"
                break;
            }
        };
        let keep = req.version() != Version::HTTP_10 && !connection_close(req.headers());
        let mut resp = router.handle(req).await;
        // An upgraded connection (a WebSocket, today): the handler stashed a callback on the
        // response and the connection is now ITSS. The `BufReader` goes with it, unread buffer
        // and all -- whatever the client pipelined behind the request head (a WebSocket client's
        // first frame very often arrives in the same read) is still in there, and handing over
        // the reader rather than the bare stream is what keeps those bytes. `return`, not
        // `break`: past this point `reader` belongs to the callback, so the clean-shutdown at
        // the end of this function must not touch it, and no `101` is written here either --
        // the protocol owns its own first bytes (`servelet_ws::accept` writes the 101 itself).
        if let Some(upgrade) = crate::upgrade::take_upgrade(&mut resp) {
            let upgraded = crate::upgrade::Upgraded::new(Box::new(reader));
            if let Err(e) = upgrade(upgraded).await {
                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "the upgraded connection ended in an error"
            }
            return;
        }
        // CUT (docs/SPINE.md "Deviations"): the SSE branch that stood here is `servelet-sse`'s
        // to reinstate. It dispatched on `Response::sse_body()`, a method whose type
        // (`crate::httpsrv::httpx::sse::SseBody`) is another crate's. The generic streaming branch
        // below is untouched: an SSE body is stashed the same way and, without its formatter,
        // still goes out as real chunked bytes.
        // A response that carries a writer for its own body (SSE does; `servelet-sse`) is
        // written by that writer. Erasing the concrete reader type here is what lets a writer
        // written against any `AsyncWrite` be stored in the response and used here.
        if let Some(formatter) = crate::streaming::take_formatter(&mut resp) {
            let mut writer: &mut (dyn tokio::io::AsyncWrite + Unpin + Send) = &mut reader;
            let written = (formatter)(&mut writer, resp).await;
            if let Err(e) = written {
                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "connection closed during streaming response"
            }
            break;
        }
        if let Some(streaming_body) = crate::streaming_body(&resp) {
            if let Err(e) = write_streaming_response(&mut reader, resp, streaming_body).await {
                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "connection closed during streaming response"
            }
            break;
        }
        if let Err(e) = write_response(&mut reader, resp).await {
            eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "connection closed while writing response"
            break;
        }
        if !keep {
            break;
        }
    }
    // A clean shutdown (TLS's `close_notify` alert, over a plain TCP stream just a normal FIN)
    // rather than dropping the stream bare -- an abrupt drop over TLS reads as a truncation
    // attack to the PEER's reader (rustls's own docs: "peer closed connection without sending
    // TLS close_notify"), not merely a latency/cosmetic difference.
    let _ = reader.shutdown().await;
}

fn connection_close(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("close"))
        .unwrap_or(false)
}

pub async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let mut reader = BufReader::new(stream);
    read_request_buffered(&mut reader).await
}

pub async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    mut response: Response,
) -> Result<()> {
    if !response.headers.contains_key(header::CONTENT_LENGTH) {
        response
            .headers
            .insert(header::CONTENT_LENGTH, response.body.len().to_string());
    }
    if response.version != Version::HTTP_10 && !response.headers.contains_key(header::CONNECTION) {
        response.headers.insert(header::CONNECTION, "keep-alive");
    }

    // One buffer, one write — a status line + N header lines + body as separate write_all calls
    // is a genuine latency bug on a non-pipelining client: Nagle holds each small write back
    // waiting for an ack, the peer's delayed-ACK timer holds that ack back (up to 40ms) waiting
    // to piggyback on its own next write, and the two waits deadlock into one stall per response.
    let mut buf = Vec::with_capacity(128 + response.body.len());
    buf.extend_from_slice(
        format!(
            "{} {} {}\r\n",
            response.version.as_str(),
            response.status.as_u16(),
            status_reason(response.status)
        )
        .as_bytes(),
    );
    for (name, value) in response.headers.iter() {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(&response.body);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Writes an SSE response as real chunked transfer-encoding, one chunk per event, as they
/// arrive from the channel `crate::httpsrv::httpx::sse::Sse::respond_to` stashed — not a buffered fake. The
/// connection is dedicated to this stream until the channel closes (or a keep-alive period
/// elapses with nothing to send, in which case a `: keep-alive\n\n` comment chunk goes out
/// instead of a real event) — see `serve_connection`, which never falls through to its normal
/// keep-alive request loop after this returns.

/// One HTTP chunked-transfer-encoding frame (`{hex-len}\r\n{data}\r\n`) — shared by the SSE and
/// generic streaming writers, the two response paths that write a body incrementally rather than
/// all at once.
pub async fn write_chunk<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    writer.write_all(format!("{:x}\r\n", data.len()).as_bytes()).await?;
    writer.write_all(data).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await?;
    Ok(())
}

/// Writes an arbitrary byte stream as real chunked transfer-encoding, one chunk per item from the
/// channel `HttpResponseBuilder::streaming` stashed — not buffered into memory first (the whole
/// point: an S3 object proxy download shouldn't hold the entire object in RAM). Ends the
/// connection when the channel closes or yields an error (there's no way to signal a mid-stream
/// failure to the client other than stopping — the same honest limitation any chunked HTTP
/// response has).
async fn write_streaming_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    mut response: Response,
    streaming_body: crate::StreamingBody,
) -> Result<()> {
    response.headers.insert(header::TRANSFER_ENCODING, "chunked");
    response.headers.insert(header::CONNECTION, "close");

    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(
        format!(
            "{} {} {}\r\n",
            response.version.as_str(),
            response.status.as_u16(),
            status_reason(response.status)
        )
        .as_bytes(),
    );
    for (name, value) in response.headers.iter() {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    writer.write_all(&head).await?;
    writer.flush().await?;

    let mut rx = crate::streaming::take_receiver(streaming_body).await?;

    while let Some(next) = rx.recv().await {
        match next {
            Ok(bytes) => write_chunk(writer, &bytes).await?,
            Err(e) => {
                eprintln!("DEBUG  target=bedrock::serve");  // was: DEBUG target: "bedrock::serve", error = %e, "streaming source reported an error mid-stream, ending the response"
                break;
            }
        }
    }

    writer.write_all(b"0\r\n\r\n").await?;
    writer.flush().await?;
    Ok(())
}
