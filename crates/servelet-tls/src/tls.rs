use super::*;

// -- Server-side TLS termination -----------------------------------------
//
// The client side (above) only ever CONSUMES certs (the system trust store via
// `rustls-native-certs`); terminating TLS as a SERVER means parsing a cert chain + private key
// this crate is HANDED (from a file, an env var, a secrets store — the caller's choice) into
// the DER form `rustls::ServerConfig` wants. `rustls`/`rustls-pki-types` (already dependencies)
// give the DER *types*; turning PEM *text* into those DER bytes is a base64 decode plus finding
// `-----BEGIN X-----`/`-----END X-----` markers -- a few lines, not a reason to add
// `rustls-pemfile` as a fourth crate for a mechanical text transform this crate can do itself
// (matching `websocket.rs`'s own hand-rolled `base64_encode` for the same reason, the other
// direction).

/// Minimal base64 (standard alphabet, `+`/`/`) decoder — PEM's own encoding, and the one
/// direction `websocket.rs`'s `base64_encode` doesn't cover.
fn base64_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        table[b as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        let v = table[b as usize];
        if v == 255 {
            continue;
        }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

/// Every `-----BEGIN <label>-----` ... `-----END <label>-----` block's decoded DER bytes, in
/// the order they appear (a cert chain PEM has one block per certificate).
fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start_idx) = rest.find(&begin) {
        let after_begin = &rest[start_idx + begin.len()..];
        let Some(end_idx) = after_begin.find(&end) else {
            break;
        };
        out.push(base64_decode(&after_begin[..end_idx]));
        rest = &after_begin[end_idx + end.len()..];
    }
    out
}

/// Build a server TLS config from a PEM certificate chain and a PEM private key (PKCS8 —
/// `-----BEGIN PRIVATE KEY-----`, what `openssl req`/`genpkey` produce by default; the older
/// PKCS1 `RSA PRIVATE KEY`/SEC1 `EC PRIVATE KEY` labels aren't parsed — a stated scope limit).
pub fn tls_server_config(cert_chain_pem: &str, private_key_pem: &str) -> Result<std::sync::Arc<rustls::ServerConfig>> {
    // Same rationale as `tls_config`'s install: rustls 0.23 never auto-installs a process-wide
    // `CryptoProvider`, and this is the server-side entry point that never goes through the
    // client path — without this, the first `serve_tls` call panics instead of erroring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        pem_blocks(cert_chain_pem, "CERTIFICATE").into_iter().map(rustls_pki_types::CertificateDer::from).collect();
    if certs.is_empty() {
        return Err(Error::Tls("no CERTIFICATE block found in the given PEM".to_string()));
    }
    let key_der = pem_blocks(private_key_pem, "PRIVATE KEY")
        .into_iter()
        .next()
        .ok_or_else(|| Error::Tls("no PRIVATE KEY block found in the given PEM".to_string()))?;
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key_der));
    // The server side is entirely self-controlled (we terminate our own inbound HTTPS), so it can
    // mandate TLS 1.3 and drop `ring` — `hashtrinity-rustls::provider()` only has TLS 1.3 cipher
    // suites, unlike `tls_config()` (the client side, reaching arbitrary third-party HTTPS).
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(hashtrinity::rustls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(std::sync::Arc::new(config))
}

/// `serve`'s TLS-terminating twin: accepts a TCP connection, completes the TLS handshake against
/// `tls_config` (built via `tls_server_config`), then runs the SAME request/response loop
/// (`serve_connection`, generic over the stream) HTTPS gets for free — the h2c-over-plaintext
/// preface-sniff still applies, so this doubles as the h2-over-TLS entry point too, once a peer
/// negotiates it via that preface post-handshake (ALPN-based `h2` negotiation isn't wired up —
/// a stated scope limit).
pub async fn serve_tls<A: ToSocketAddrs>(addr: A, router: Router, tls_config: std::sync::Arc<rustls::ServerConfig>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    eprintln!("INFO  bedrock::serve  listening (tls)");
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let router = router.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(
            async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => serve_connection(tls_stream, router, Some(peer)).await,
                    Err(e) => eprintln!("DEBUG  target=bedrock::serve  error={}", e),
                }
            }
            ,
        );
    }
}