//! The wire, byte-for-byte from `biota/http-server`'s `kernel.rs` at rev `4ce2dcd`.

use super::*;

/// Read one header line into `out`, refusing to grow past `limit` bytes.
///
/// REPLACES the moved `reader.read_until(b'\n', &mut line_buf)`, which is the single reason a
/// peer could make this process allocate whatever it liked: `read_until` grows the buffer until
/// it finds the newline, so a 10 MB header line is 10 MB of allocation before anything has
/// decided the request is legitimate. The limit is checked as bytes ARRIVE, from the `BufReader`'s
/// own buffer, so the worst case is `limit` bytes plus one `BufReader` capacity — never the
/// peer's chosen length.
///
/// Returns `false` at EOF with nothing read (the caller turns that into an error) and `true`
/// when a line, however empty, was read.
async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<bool> {
    loop {
        let available = reader.fill_buf().await.map_err(Error::Io)?;
        if available.is_empty() {
            return Ok(!out.is_empty());
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(at) => {
                if out.len() + at + 1 > limit {
                    return Err(Error::Parse(format!(
                        "header line of more than {limit} bytes"
                    )));
                }
                out.extend_from_slice(&available[..=at]);
                let taken = at + 1;
                reader.consume(taken);
                return Ok(true);
            }
            None => {
                let taken = available.len();
                if out.len() + taken > limit {
                    return Err(Error::Parse(format!("header line of more than {limit} bytes")));
                }
                out.extend_from_slice(available);
                reader.consume(taken);
            }
        }
    }
}

/// A header block ended by CRLF. A bare LF is NOT a line terminator here (RFC 9112 §2.2), and
/// accepting one is half of the request-smuggling problem: a front proxy that splits on CRLF and
/// a backend that splits on LF disagree about where the request ends, and the bytes between
/// their two answers are a second request this server never authorised.
fn ends_crlf(line: &[u8]) -> bool {
    line.ends_with(b"\r\n")
}

async fn read_request_buffered<R: AsyncReadExt + AsyncWriteExt + Unpin>(
    reader: &mut BufReader<R>,
    limits: &crate::limits::RequestLimits,
) -> Result<Request> {
    let mut line_buf = Vec::new();
    read_line_limited(reader, &mut line_buf, limits.max_request_line_bytes).await?;
    if line_buf.is_empty() {
        return Err(Error::Parse("empty request".into()));
    }
    if !ends_crlf(&line_buf) {
        return Err(Error::Parse(
            "request line must end with CRLF, not a bare LF".into(),
        ));
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
    let mut content_length: Option<usize> = None;
    let mut te_chunked = false;
    // Total bytes seen across every header line, and how many there have been. Both are
    // checked as bytes ARRIVE rather than at the end, so a peer sending an endless header
    // block is cut off at the ceiling instead of after it has read everything.
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    loop {
        line_buf.clear();
        if !read_line_limited(reader, &mut line_buf, limits.max_header_bytes).await? {
            return Err(Error::Parse("connection closed inside the header block".into()));
        }
        if line_buf == b"\r\n" || line_buf.is_empty() {
            break;
        }
        // HARDENING (request smuggling): the moved code accepted `b"\n"` as a header line AND as
        // the end of the header block. A front proxy that frames on CRLF and this server that
        // frames on LF then disagree about where the request ends, and the gap between their
        // two answers is a request nobody authorised. One rule, both places: CRLF only.
        if !ends_crlf(&line_buf) {
            return Err(Error::Parse(
                "header line must end with CRLF, not a bare LF".into(),
            ));
        }
        header_count += 1;
        if header_count > limits.max_header_count {
            return Err(Error::Parse(format!(
                "more than {} header lines",
                limits.max_header_count
            )));
        }
        header_bytes += line_buf.len();
        if header_bytes > limits.max_header_bytes {
            return Err(Error::Parse(format!(
                "header block of more than {} bytes",
                limits.max_header_bytes
            )));
        }
        let line = str::from_utf8(&line_buf).map_err(|e| Error::Parse(e.to_string()))?;
        let Some((n, v)) = line.split_once(':') else { continue };
        let name = n.parse::<HeaderName>()?;
        let value = v.trim().parse::<HeaderValue>()?;
        if name.as_str() == header::CONTENT_LENGTH {
            // HARDENING (request smuggling, duplicate Content-Length): the moved code
            // overwrote `content_length` on every occurrence, so a request carrying
            // `Content-Length: 5` and `Content-Length: 500` was served with the LAST value and
            // no complaint. Two values that agree are harmless and are accepted; two that
            // disagree are the shape of a smuggling attempt and are refused. RFC 9112 §6.3.
            let parsed = value.to_str().ok().and_then(|s| s.parse::<usize>().ok());
            match (content_length, parsed) {
                (Some(previous), Some(this)) if previous != this => {
                    return Err(Error::Parse(format!(
                        "two different Content-Length values ({previous} and {this})"
                    )));
                }
                (_, this) => content_length = this,
            }
        }
        if name.as_str() == header::TRANSFER_ENCODING
            && value.to_str().unwrap_or("").to_ascii_lowercase().contains("chunked")
        {
            te_chunked = true;
        }
        headers.insert(name, value);
    }

    // HARDENING (request smuggling, Content-Length + Transfer-Encoding): the moved code set
    // `content_length` OR `te_chunked` and then preferred the content length, silently ignoring
    // the chunked framing the peer also declared. RFC 9112 §6.1 is unambiguous that a message
    // with both is ambiguous, and that the recipient must refuse it rather than pick. A front
    // proxy that picks the other one is the whole attack.
    if content_length.is_some() && te_chunked {
        return Err(Error::Parse(
            "both Content-Length and Transfer-Encoding: chunked present".into(),
        ));
    }
    let content_length = content_length.unwrap_or(0);

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
    // HARDENING: the moved code did `vec![0u8; content_length]` with no ceiling, so
    // `Content-Length: 18446744073709551615` was an allocation request the peer wrote. The
    // bound is checked on the DECLARED length, before the allocation, exactly as the WebSocket
    // frame bound is in `servelet-ws`.
    if content_length > limits.max_body_bytes {
        return Err(Error::Parse(format!(
            "Content-Length of {content_length} exceeds the {} byte body limit",
            limits.max_body_bytes
        )));
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
            read_line_limited(reader, &mut size_line, limits.max_header_bytes).await?;
            body.extend_from_slice(&size_line);
            let size_str = std::str::from_utf8(&size_line).unwrap_or("").trim();
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("0").trim(), 16)
                .map_err(|e| Error::Parse(format!("bad chunk size {size_str:?}: {e}")))?;
            if size == 0 {
                // Trailers (incl. the `X-Amz-Trailer` checksum) — read raw until blank line.
                loop {
                    let mut tl = Vec::new();
                    if !read_line_limited(reader, &mut tl, limits.max_header_bytes).await? {
                        break;
                    }
                    body.extend_from_slice(&tl);
                    if tl == b"\r\n" || tl.is_empty() {
                        break;
                    }
                    // HARDENING: trailers are header lines too, and an endless trailer block
                    // is the same unbounded-accumulation lever the header bound closes.
                    if body.len() > limits.max_body_bytes {
                        return Err(Error::Parse(format!(
                            "chunked body of more than {} bytes",
                            limits.max_body_bytes
                        )));
                    }
                }
                break;
            }
            // HARDENING: a chunk size line can itself claim anything at all, and the moved code
            // allocated `size + 2` from it unchecked. Checked before the allocation.
            if body.len() + size + 2 > limits.max_body_bytes {
                return Err(Error::Parse(format!(
                    "chunked body of more than {} bytes",
                    limits.max_body_bytes
                )));
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
    eprintln!("INFO  servelet::serve  listening");
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
    serve_connection_with_limits(stream, router, peer_addr, crate::limits::RequestLimits::default()).await
}

/// [`serve_connection`] with the request-head, body and slow-read ceilings stated by the caller.
///
/// The defaulted [`serve_connection`] is what a consumer gets and is the moved signature,
/// unchanged; this is the one to reach for when a deployment's requests are legitimately bigger
/// or slower than the published defaults. Every limit and its default is in
/// `docs/HARDENING.md`.
pub async fn serve_connection_with_limits<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    router: Router,
    peer_addr: Option<std::net::SocketAddr>,
    limits: crate::limits::RequestLimits,
) {
    let mut reader = BufReader::with_capacity(8192, stream);
    // CUT (docs/SPINE.md "Deviations"): the h2c-preface sniff (RFC 7540 3.4, "prior knowledge")
    // that stood here is `servelet-h2`'s to reinstate. It matched
    // `crate::httpsrv::httpx::h2::PREFACE`, another crate's constant. Everything after the sniff
    // is HTTP/1.1 line framing, byte-for-byte unchanged.
    loop {
        // HARDENING: the whole of one request gets a deadline. The moved code had none, so a
        // peer that opened a connection and sent one byte every ten seconds held the stream, its
        // `BufReader` and its task open for as long as it liked -- which is a connection-exhaustion
        // lever that costs the attacker one byte at a time.
        let read = tokio::time::timeout(limits.read_timeout, read_request_buffered(&mut reader, &limits)).await;
        let parsed = match read {
            Ok(Ok(req)) => Ok(req),
            Ok(Err(e)) => Err(e),
            // A timeout, not a parse error: the peer did not send a malformed request, it sent a
            // slow one. The refusal below is the same, which is what a client can act on.
            Err(_) => Err(Error::Parse(format!(
                "the request did not arrive within {:?}",
                limits.read_timeout
            ))),
        };
        let req = match parsed {
            Ok(req) => match peer_addr {
                Some(addr) => req.with_peer_addr(addr),
                None => req,
            },
            Err(e) => {
                eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "connection closed while reading request"
                // HARDENING: the moved code broke here and closed the socket with nothing said,
                // so a client could not tell a malformed request from a dropped connection. A
                // `400` with a zero-length body costs one small write and is the only thing
                // standing between "your request was refused" and "retry forever".
                write_bad_request(&mut reader, &e).await;
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
                eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "the upgraded connection ended in an error"
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
                eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "connection closed during streaming response"
            }
            break;
        }
        if let Some(streaming_body) = crate::streaming_body(&resp) {
            if let Err(e) = write_streaming_response(&mut reader, resp, streaming_body).await {
                eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "connection closed during streaming response"
            }
            break;
        }
        if let Err(e) = write_response(&mut reader, resp).await {
            eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "connection closed while writing response"
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

pub async fn read_request(stream: &mut TcpStream) -> Result<Request> {
    read_request_with_limits(stream, crate::limits::RequestLimits::default()).await
}

/// [`read_request`] under caller-stated ceilings — the single-request read a proxy uses when it
/// is reading a request it is going to forward rather than serve.
pub async fn read_request_with_limits(
    stream: &mut TcpStream,
    limits: crate::limits::RequestLimits,
) -> Result<Request> {
    let mut reader = BufReader::new(stream);
    read_request_buffered(&mut reader, &limits).await
}

/// The refusal written when a request will not parse. Deliberately tiny and deliberately a
/// `400`: the body names the rule that was broken and nothing else, because the input it was
/// derived from is attacker-chosen and this string can end up in a log.
async fn write_bad_request<W: AsyncWriteExt + Unpin>(writer: &mut W, why: &Error) {
    let body = why.to_string();
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.write_all(response.as_bytes()).await;
    let _ = writer.flush().await;
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
                eprintln!("DEBUG  target=servelet::serve");  // was: DEBUG target: "servelet::serve", error = %e, "streaming source reported an error mid-stream, ending the response"
                break;
            }
        }
    }

    writer.write_all(b"0\r\n\r\n").await?;
    writer.flush().await?;
    Ok(())
}
