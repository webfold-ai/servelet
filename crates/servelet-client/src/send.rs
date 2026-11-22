// DEVIATION, the `use` lines only: biota's `kernel.rs` had them at the top of the file (lines
// 1-16). Nothing is re-declared or renamed.
use std::io;
use std::str;

// `connection_close` lives in servelet-core, not in servelet-h1. A previous pass put it in
// h1 on the reasoning that a client must not depend on the server stack to read one header —
// that reasoning is right, and h1 is the wrong answer to it, because h1 *is* the server stack.
// `servelet-core` is already a dependency of this crate, so hoisting it there satisfies the
// constraint instead of violating it. One expression, two call sites, one answer.
use servelet_core::{connection_close, header, Error, Extensions, HeaderMap, HeaderName, HeaderValue, Method, Response, Result, StatusCode, Uri, Version};

use crate::pool::{identity_for, pool_put, PooledConn};
use crate::stream::{Stream, StreamReader};

/// Write the request line, headers, and body — shared by the buffered (`send_request`) and
/// streaming (`send_request_streaming`) paths; they only diverge on how the RESPONSE body gets
/// read, never on how the request itself goes out.
async fn write_request(
    stream: &mut Stream,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Option<Vec<u8>>,
) -> Result<()> {
    let path = uri.path_and_query();
    let host = uri.host().unwrap_or("");
    let authority = match uri.port_u16() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };

    // An explicit `Host` header in the map wins over the URI-derived one (reqwest/pingora
    // semantics). A proxy that forwards requests verbatim depends on this: SigV4 signs the
    // exact `Host` the client sent, so the upstream must see that same value or the signature
    // fails (this is what nginx's port-stripping `proxy_set_header Host $host` broke).
    let has_host = headers.contains_key("host");
    stream
        .write_all(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes())
        .await?;
    if !has_host {
        stream
            .write_all(format!("Host: {}\r\n", authority).as_bytes())
            .await?;
    }
    stream
        .write_all(concat!("User-Agent: servelet-client/", env!("CARGO_PKG_VERSION"), "\r\n").as_bytes())
        .await?;

    for (name, value) in headers.iter() {
        stream.write_all(name.as_bytes()).await?;
        stream.write_all(b": ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }

    if let Some(ref body) = body {
        // If the map already carries a Content-Length (a forwarded request), don't write a
        // second one — duplicate Content-Length is a parse error on some upstreams. A chunked
        // body gets no Content-Length either (the `Transfer-Encoding` header governs framing).
        if !headers.contains_key("content-length")
            && !headers
                .get("transfer-encoding")
                .map(|v| v.to_str().unwrap_or("").to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
        {
            stream
                .write_all(format!("Content-Length: {}\r\n", body.len()).as_bytes())
                .await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    if let Some(body) = body {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// The parsed response status line + headers, before the body is touched — shared by both the
/// buffered and streaming read paths.
struct ResponseHead {
    version: Version,
    status: StatusCode,
    headers: HeaderMap,
    content_length: Option<usize>,
    chunked: bool,
}

async fn read_response_head(reader: &mut StreamReader) -> Result<ResponseHead> {
    // Skip informational (1xx) interim responses — most importantly `100 Continue` (hyper
    // sends it when the upstream receives `Expect: 100-continue`) — and read the REAL response.
    // Treating an interim 100 as the final response poisons the keepalive pool: the actual
    // response stays unread in the connection and the next request on that connection reads
    // garbage (garage's "error reading a body" signature).
    let (version, status) = loop {
        let raw = reader.read_line().await?;
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let (v, s) = parse_status_line(line)?;
        if s.is_informational() {
            // Consume the interim response's header block (terminated by a blank line).
            loop {
                let l = reader.read_line().await?;
                if l.is_empty() || l == b"\r\n" || l == b"\n" {
                    break;
                }
            }
            continue;
        }
        break (v, s);
    };

    let mut headers = HeaderMap::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let raw = reader.read_line().await?;
        if raw.is_empty() || raw == b"\r\n" || raw == b"\n" {
            break;
        }
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        if let Some((n, v)) = line.split_once(':') {
            let name = n.parse::<HeaderName>()?;
            let value = v.trim().parse::<HeaderValue>()?;
            if name.as_str() == header::CONTENT_LENGTH {
                content_length = value.to_str().ok().and_then(|s| s.parse().ok());
            }
            if name.as_str() == header::TRANSFER_ENCODING
                && value.to_str().unwrap_or("").contains("chunked")
            {
                chunked = true;
            }
            headers.insert(name, value);
        }
    }
    Ok(ResponseHead { version, status, headers, content_length, chunked })
}

pub(crate) async fn send_request(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<Response> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    // Only a DEFINITE-length body (no body at all, Content-Length, or a chunked terminator) means
    // the connection is genuinely still usable afterward — the "read to end" fallback below means
    // there was no length information at all, which in practice means the peer intends to close
    // the connection once the body is sent, so pooling that stream would just hand back a socket
    // that's already going away.
    let (body, poolable) = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
        || method == Method::HEAD
    {
        // HEAD responses never carry a body (RFC 9110 §9.3.2) — even when the upstream's
        // headers claim a Content-Length. Without this, a length-less HEAD response falls into
        // the `read_to_end` fallback and blocks forever on the keep-alive connection.
        (Vec::new(), true)
    } else if head.chunked {
        (read_chunked(&mut reader).await?, true)
    } else if let Some(len) = head.content_length {
        let b = if len > 0 { reader.read_exact(len).await? } else { Vec::new() };
        (b, true)
    } else {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        (buf, false)
    };

    // Return the connection to the pool if the response as a whole allows reuse: a definite-
    // length body (above), HTTP/1.1 (matches this crate's own server-side keep-alive default,
    // `serve()`'s `connection_close` check), and neither side said `Connection: close`.
    if poolable && head.version != Version::HTTP_10 && !connection_close(&head.headers) {
        let (stream, leftover) = reader.into_inner();
        if leftover.is_empty() {
            if let Ok(identity) = identity_for(uri) {
                pool_put(&identity, PooledConn { stream, leftover });
            }
        }
        // A non-empty leftover means the peer sent extra bytes we haven't consumed (unusual for
        // a non-pipelined client, but possible) — there's no plumbing to hand them to whatever
        // uses this connection next, so the connection is simply dropped/closed here instead of
        // risking a corrupted next read. Honest, not silent: this is exactly the situation
        // `into_inner`'s own doc calls out.
    }

    Ok(Response {
        status: head.status,
        version: head.version,
        headers: head.headers,
        body,
        url: uri.clone(),
        extensions: Extensions::new(),
    })
}

/// How the still-open body is framed — decided once from the response head, then consumed
/// incrementally by `StreamingResponse::chunk`.
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

/// A response whose body has NOT been read yet — `reqwest::Response::chunk`/`bytes_stream`'s
/// equivalent. Never pools its connection (a caller can stop draining partway through; pooling
/// would then hand the next request a stream mid-body), a deliberate, conservative simplicity
/// over squeezing pooling out of the streaming path too.
pub struct StreamingResponse {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    url: Uri,
    reader: StreamReader,
    framing: BodyFraming,
}

impl StreamingResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn url(&self) -> &Uri {
        &self.url
    }

    /// Read the next chunk of the body, or `None` once it's exhausted — reqwest's `chunk()`.
    /// A `Content-Length` body is read in ≤64KiB pieces; a chunked body yields exactly one
    /// wire-chunk per call (already a natural unit, no extra buffering needed); a headerless
    /// body reads whatever's available up to 64KiB until EOF.
    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>> {
        const MAX_CHUNK: usize = 64 * 1024;
        match &mut self.framing {
            BodyFraming::None => Ok(None),
            BodyFraming::ContentLength(remaining) => {
                if *remaining == 0 {
                    return Ok(None);
                }
                // `read_some`, not `read_exact` — the latter blocks until the FULL requested
                // amount arrives, which would silently coalesce however many real TCP segments
                // the body came in into one chunk for any body under `MAX_CHUNK` (the common
                // case). Returning whatever's actually available right now is the point of
                // streaming at all.
                let take = (*remaining).min(MAX_CHUNK);
                let mut buf = vec![0u8; take];
                let n = self.reader.read_some(take, &mut buf).await?;
                if n == 0 {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("connection closed with {remaining} content-length bytes still expected"),
                    )));
                }
                buf.truncate(n);
                *remaining -= n;
                Ok(Some(buf))
            }
            BodyFraming::Chunked => {
                let raw = self.reader.read_line().await?;
                let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
                let size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
                    .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
                if size == 0 {
                    self.framing = BodyFraming::None;
                    return Ok(None);
                }
                let data = self.reader.read_exact(size).await?;
                self.reader.read_line().await?; // trailing CRLF after the chunk data
                Ok(Some(data))
            }
            BodyFraming::UntilEof => {
                let mut buf = vec![0u8; MAX_CHUNK];
                let n = self.reader.read_some(MAX_CHUNK, &mut buf).await?;
                if n == 0 {
                    self.framing = BodyFraming::None;
                    Ok(None)
                } else {
                    buf.truncate(n);
                    Ok(Some(buf))
                }
            }
        }
    }

    /// Drain every remaining chunk into one buffer — for callers that started streaming but
    /// decide midway they want the whole thing after all.
    pub async fn bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

pub(crate) async fn send_request_streaming(
    mut stream: Stream,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
) -> Result<StreamingResponse> {
    write_request(&mut stream, &method, uri, &headers, &body).await?;
    let mut reader = stream.into_reader();
    let head = read_response_head(&mut reader).await?;

    let framing = if head.status == StatusCode::NO_CONTENT
        || head.status == StatusCode::NOT_MODIFIED
        || head.status.is_informational()
    {
        BodyFraming::None
    } else if head.chunked {
        BodyFraming::Chunked
    } else if let Some(len) = head.content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::UntilEof
    };

    Ok(StreamingResponse {
        status: head.status,
        version: head.version,
        headers: head.headers,
        url: uri.clone(),
        reader,
        framing,
    })
}

fn parse_status_line(line: &str) -> Result<(Version, StatusCode)> {
    let line = line.trim();
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::Parse(format!("bad status line: {line}")));
    }
    let version = match parts[0] {
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    };
    let code = parts[1]
        .parse::<u16>()
        .map_err(|e| Error::Parse(format!("bad status code: {e}")))?;
    Ok((version, StatusCode::from_u16(code)?))
}

async fn read_chunked(reader: &mut StreamReader) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let raw = reader.read_line().await?;
        let line = str::from_utf8(raw).map_err(|e| Error::Parse(e.to_string()))?;
        let chunk_size = usize::from_str_radix(line.trim_end_matches("\r\n"), 16)
            .map_err(|e| Error::Parse(format!("bad chunk size: {e}")))?;
        if chunk_size == 0 {
            break;
        }
        let chunk = reader.read_exact(chunk_size).await?;
        body.extend_from_slice(&chunk);
        reader.read_line().await?;
    }
    Ok(body)
}
