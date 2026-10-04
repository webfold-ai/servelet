//! The client tests moved out of `biota/http-server`'s `kernel.rs` `mod tests` at rev `4ce2dcd`
//! (lines 3616-4066, the twelve that exercise the client, the pool, the streaming response and
//! the cookie jar), verbatim.
//!
//! The only edit at this seam: biota's `mod tests` sat inside `kernel.rs` and read its own names
//! out of the enclosing module. As an integration test the file has to name the crate
//! explicitly; `mod moved` (kept from the original nesting) then does `use super::*` as before.

use servelet_client::*;

mod moved {
    use std::sync::Arc;

    use super::*;
    use servelet_core::StatusCode;


    /// Direct proof the connection pool actually reuses TCP connections, not just that the code
    /// compiles: a real local server counts real `accept()` calls; N sequential keep-alive
    /// requests through the client must produce FEWER accepts than requests once pooling kicks
    /// in (the very first request still pays a fresh accept — nothing to reuse yet).
    #[tokio::test]
    async fn client_pools_and_reuses_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_accept_count = accept_count.clone();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                server_accept_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(&mut stream);
                    loop {
                        let mut line = String::new();
                        // Read + discard the request line and headers up to the blank line.
                        if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap_or(0) == 0 {
                            break; // peer closed
                        }
                        loop {
                            let mut hline = String::new();
                            let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut hline).await.unwrap_or(0);
                            if n == 0 || hline == "\r\n" || hline == "\n" {
                                break;
                            }
                        }
                        let body = b"ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            body.len()
                        );
                        if tokio::io::AsyncWriteExt::write_all(&mut reader.get_mut(), resp.as_bytes()).await.is_err() {
                            break;
                        }
                        if tokio::io::AsyncWriteExt::write_all(&mut reader.get_mut(), body).await.is_err() {
                            break;
                        }
                        // No `Connection: close` sent -- server keeps this connection open for
                        // another request, exactly the condition the pool relies on.
                    }
                });
            }
        });

        let url = format!("http://{addr}/");
        const REQUESTS: usize = 10;
        for _ in 0..REQUESTS {
            let resp = get(&url).await.expect("request should succeed");
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Give the server's spawned handler a moment to register the (re)used connection.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let accepts = accept_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            accepts < REQUESTS,
            "expected fewer TCP accepts ({accepts}) than requests ({REQUESTS}) if pooling is working -- got one accept per request"
        );
        assert!(accepts >= 1, "at least the first request must open a real connection");
    }


    /// Real end-to-end proof the client follows a redirect: a real local server answers the
    /// first path with 302+Location, the second (redirected) path with 200 -- `send()` must
    /// return the FINAL response, not the 302.
    #[tokio::test]
    async fn client_follows_redirect_to_a_real_second_server_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(&mut stream);
                    let mut line = String::new();
                    if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut hline = String::new();
                        let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut hline).await.unwrap_or(0);
                        if n == 0 || hline == "\r\n" || hline == "\n" {
                            break;
                        }
                    }
                    let resp = if line.contains("/start") {
                        "HTTP/1.1 302 Found\r\nLocation: /finish\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    } else {
                        let body = b"arrived";
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\narrived", body.len())
                    };
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut reader.get_mut(), resp.as_bytes()).await;
                });
            }
        });

        let resp = get(format!("http://{addr}/start")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "arrived");
    }


    /// Real end-to-end proof of the cookie jar: a real server sets a cookie on the first
    /// request; the SECOND request through the SAME client must carry it back in the `Cookie`
    /// header -- verified by the server itself echoing back what it received.
    #[tokio::test]
    async fn client_stores_and_replays_cookies_across_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(&mut stream);
                    let mut line = String::new();
                    if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut cookie_seen = String::new();
                    loop {
                        let mut hline = String::new();
                        let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut hline).await.unwrap_or(0);
                        if n == 0 || hline == "\r\n" || hline == "\n" {
                            break;
                        }
                        if let Some(v) = hline.strip_prefix("cookie: ") {
                            cookie_seen = v.trim().to_string();
                        }
                    }
                    let body = if cookie_seen.is_empty() { "no-cookie".to_string() } else { format!("saw:{cookie_seen}") };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut reader.get_mut(), resp.as_bytes()).await;
                });
            }
        });

        let client = Client::new();
        let url = format!("http://{addr}/");
        let first = client.get(&url).send().await.unwrap();
        assert_eq!(first.text().await.unwrap(), "no-cookie");

        let second = client.get(&url).send().await.unwrap();
        assert_eq!(second.text().await.unwrap(), "saw:session=abc123", "the second request must replay the cookie the first response set");
    }


    /// Real end-to-end proof of retry: a real server refuses (closes with no response) the
    /// first 2 connections, then answers normally on the 3rd -- `RetryPolicy::new(3, ..)` must
    /// still return the eventual success rather than the earlier failures.
    #[tokio::test]
    async fn client_retries_past_transient_failures_to_a_real_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_count = accept_count.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let n = server_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 2 {
                    drop(stream); // simulate a transient failure: close with no response at all
                    continue;
                }
                tokio::spawn(async move {
                    let mut stream = stream;
                    let body = b"finally";
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nfinally", body.len());
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
                });
            }
        });

        let client = Client::builder().retry(RetryPolicy::new(4, std::time::Duration::from_millis(10))).build();
        let resp = client.get(format!("http://{addr}/")).send().await.expect("must eventually succeed within retry budget");
        assert_eq!(resp.text().await.unwrap(), "finally");
        assert!(accept_count.load(std::sync::atomic::Ordering::SeqCst) >= 3, "must have actually retried past the first 2 failures");
    }


    /// Real end-to-end proof of DNS override: a hostname that does NOT resolve via real DNS
    /// (`fake.sanguine.test`) is redirected, via `ClientBuilder::resolve`, to a real local
    /// server's actual address -- proving the override genuinely changes the dial target, not
    /// just that the API compiles.
    #[tokio::test]
    async fn client_resolve_override_redirects_a_fake_hostname_to_a_real_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = b"resolved";
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nresolved", body.len());
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
        });

        let client = Client::builder().resolve("fake.sanguine.test", addr).build();
        let resp = client.get("http://fake.sanguine.test/").send().await.expect("resolve override must redirect to the real server");
        assert_eq!(resp.text().await.unwrap(), "resolved");
    }


    /// Real proof of streaming: a real server writes its body in 3 SEPARATE `write_all` calls
    /// with delays between them (a genuinely incremental send, not one buffered blob) -- the
    /// client must observe MULTIPLE chunks via `.chunk()`, not one call that already has
    /// everything (which would mean `send_streaming` secretly buffered the whole body anyway).
    #[tokio::test]
    async fn send_streaming_receives_a_body_written_incrementally() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let parts = ["AAAA", "BBBB", "CCCC"];
            let total_len: usize = parts.iter().map(|p| p.len()).sum();
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                format!("HTTP/1.1 200 OK\r\nContent-Length: {total_len}\r\n\r\n").as_bytes(),
            )
            .await;
            for part in parts {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, part.as_bytes()).await;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });

        let mut resp = Client::new().get(format!("http://{addr}/")).send_streaming().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut chunks = Vec::new();
        let mut assembled = Vec::new();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            assembled.extend_from_slice(&chunk);
            chunks.push(chunk);
        }
        assert_eq!(assembled, b"AAAABBBBCCCC", "the assembled body must match exactly regardless of chunk boundaries");
        assert!(chunks.len() >= 2, "a body written in 3 separate real writes must arrive as more than one chunk, got {}", chunks.len());
    }


    /// Real proof of chunked-encoding streaming: the server sends `Transfer-Encoding: chunked`
    /// with 2 real wire-chunks -- the client must decode each chunk's length-prefix framing
    /// correctly and yield exactly those chunks' data.
    #[tokio::test]
    async fn send_streaming_decodes_chunked_encoding() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, wire.as_bytes()).await;
        });

        let mut resp = Client::new().get(format!("http://{addr}/")).send_streaming().await.unwrap();
        let mut assembled = Vec::new();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            assembled.extend_from_slice(&chunk);
        }
        assert_eq!(assembled, b"hello world");
    }


    /// Real end-to-end proof of multipart encoding: a real server reads the actual bytes the
    /// client sent and verifies the wire form is genuinely well-shaped multipart/form-data --
    /// boundary markers, Content-Disposition per field, the file part's filename, and the
    /// terminating boundary -- not just that `Form`/`Part` compile.
    #[tokio::test]
    async fn multipart_form_encodes_a_real_wire_body_a_server_can_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_received = received.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                let n = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await.unwrap_or(0);
                if n == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            let _ = tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await;
            *server_received.lock().unwrap() = body;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut reader.get_mut(), b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        });

        let form = Form::new()
            .text("username", "lucas")
            .part("avatar", Part::bytes(b"PNGDATA".to_vec()).file_name("pic.png").mime("image/png"));

        let resp = Client::new().post(format!("http://{addr}/")).multipart(form).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = String::from_utf8(received.lock().unwrap().clone()).unwrap();
        assert!(body.contains("Content-Disposition: form-data; name=\"username\""), "body: {body}");
        assert!(body.contains("lucas"), "body: {body}");
        assert!(body.contains("name=\"avatar\"; filename=\"pic.png\""), "body: {body}");
        assert!(body.contains("Content-Type: image/png"), "body: {body}");
        assert!(body.contains("PNGDATA"), "body: {body}");
        assert!(body.trim_end().ends_with("--"), "body must end with the terminating boundary's trailing --: {body}");
    }


    /// Reference check for `days_from_civil`/`parse_http_date`: the well-known
    /// "2000-01-01T00:00:00Z = 946684800" timestamp, end-to-end through the actual date parser.
    #[test]
    fn http_date_parses_the_well_known_reference_timestamp() {
        let t = parse_http_date("Sat, 01 Jan 2000 00:00:00 GMT").unwrap();
        assert_eq!(t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 946_684_800);
        // RFC 7231's own worked example.
        let t2 = parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        assert_eq!(t2.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 1_445_412_480);
    }


    #[test]
    fn cookie_path_matching_follows_rfc_6265_5_1_4() {
        assert!(cookie_path_matches("/", "/anything"));
        assert!(cookie_path_matches("/api", "/api"));
        assert!(cookie_path_matches("/api", "/api/users"));
        assert!(cookie_path_matches("/api/", "/api/users"));
        assert!(!cookie_path_matches("/api", "/apiv2"), "prefix without a boundary must NOT match");
        assert!(!cookie_path_matches("/admin", "/api"));
    }


    #[test]
    fn cookie_jar_respects_path_secure_and_expiry() {
        let mut jar = CookieJar::default();
        jar.store("example.com", "session=abc123; Path=/app; HttpOnly");
        jar.store("example.com", "pub=xyz; Path=/");
        jar.store("example.com", "secure_only=s1; Secure");

        // path-scoped: /app/dashboard gets session+pub, / only gets pub.
        let for_app = jar.header_for("example.com", "/app/dashboard", true).unwrap();
        assert!(for_app.contains("session=abc123"), "for_app: {for_app}");
        assert!(for_app.contains("pub=xyz"), "for_app: {for_app}");
        let for_root = jar.header_for("example.com", "/", true).unwrap();
        assert!(!for_root.contains("session=abc123"), "for_root: {for_root}");
        assert!(for_root.contains("pub=xyz"), "for_root: {for_root}");

        // Secure: sent over https, withheld over plain http.
        let https = jar.header_for("example.com", "/", true).unwrap();
        assert!(https.contains("secure_only=s1"), "https: {https}");
        let http = jar.header_for("example.com", "/", false).unwrap();
        assert!(!http.contains("secure_only=s1"), "http: {http}");

        // Max-Age=0 deletes.
        jar.store("example.com", "pub=xyz; Path=/; Max-Age=0");
        let after_delete = jar.header_for("example.com", "/", true);
        assert!(after_delete.map(|h| !h.contains("pub=")).unwrap_or(true));

        // A future Expires is retained; a past one is dropped on store.
        jar.store("example.com", "future=f1; Path=/; Expires=Wed, 01 Jan 2099 00:00:00 GMT");
        jar.store("example.com", "past=p1; Path=/; Expires=Wed, 01 Jan 2000 00:00:00 GMT");
        let final_header = jar.header_for("example.com", "/", true).unwrap();
        assert!(final_header.contains("future=f1"), "final_header: {final_header}");
        assert!(!final_header.contains("past="), "final_header: {final_header}");
    }


    /// End-to-end: a real server sets a Path-scoped cookie via `Set-Cookie`, the real `Client`
    /// stores it and replays it correctly on a subsequent request to a matching path.
    #[tokio::test]
    async fn client_cookie_jar_respects_path_scope_through_real_requests() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = vec![0u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await.unwrap_or(0);
                let req_text = String::from_utf8_lossy(&buf[..n]);
                let first_line = req_text.lines().next().unwrap_or("");
                let resp = if first_line.contains("/set") {
                    "HTTP/1.1 200 OK\r\nSet-Cookie: scoped=v1; Path=/app\r\nContent-Length: 0\r\n\r\n".to_string()
                } else {
                    let cookie_line = req_text.lines().find(|l| l.to_ascii_lowercase().starts_with("cookie:")).unwrap_or("").to_string();
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", cookie_line.len(), cookie_line)
                };
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
            }
        });

        let client = Client::new();
        client.get(format!("http://{addr}/set")).send().await.unwrap();

        let matching = client.get(format!("http://{addr}/app/page")).send().await.unwrap();
        let matching_body = matching.text().await.unwrap();
        assert!(matching_body.to_ascii_lowercase().contains("scoped=v1"), "matching_body: {matching_body}");

        let nonmatching = client.get(format!("http://{addr}/other")).send().await.unwrap();
        let nonmatching_body = nonmatching.text().await.unwrap();
        assert!(!nonmatching_body.to_ascii_lowercase().contains("scoped=v1"), "nonmatching_body: {nonmatching_body}");
    }
}
