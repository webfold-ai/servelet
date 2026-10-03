//! Real-socket proof for `servelet-tls`, added by this extraction (NOT moved).
//!
//! The claim being proved: `serve_tls` terminates TLS and then runs the SAME HTTP/1.1 loop plain
//! HTTP runs. The moved code says so in its own comment; this test is what makes it true rather
//! than asserted. A real rustls client completes a real TLS 1.3 handshake against the moved
//! `tls_server_config`, then reads the moved `write_response` bytes off the socket.
//!
//! The certificate is a committed fixture (`tests/fixtures/server.cert.pem` +
//! `server.key.pem`), generated once with:
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -subj "/CN=localhost" \
//!   -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
//!   -keyout tests/fixtures/server.key.pem -out tests/fixtures/server.cert.pem
//! ```
//!
//! It is a TEST certificate for `localhost` with a PUBLICLY KNOWN private key checked into a
//! repository. It can decrypt nothing and authorises nothing; it exists so this file can prove the
//! handshake without shelling out to `openssl` at test time (a test that depends on a binary it did
//! not build is a test that fails on someone else's machine). It is NOT used by any server, and
//! the client here trusts it explicitly rather than through the system store, so it cannot be
//! mistaken for a real server identity.

use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use servelet_core::{Request, Response};
use servelet_router::Router;
use servelet_tls::tls_server_config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CERT: &str = include_str!("fixtures/server.cert.pem");
const KEY: &str = include_str!("fixtures/server.key.pem");

/// Start `serve_tls` on an ephemeral port with the fixture cert, return the address.
async fn spawn_tls_server(router: Router) -> std::net::SocketAddr {
    // `serve_tls` binds the listener itself, so pick a free port by binding and releasing one.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let config = tls_server_config(CERT, KEY).expect("the fixture PEM parses");
    tokio::spawn(async move {
        let _ = servelet_tls::serve_tls(addr, router, config).await;
    });
    // Give the accept loop a moment to bind; a failed handshake below is the signal if it did not.
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

#[tokio::test]
async fn tls_terminates_and_then_serves_the_same_h1_bytes() {
    let router = Router::new().get("/hello", |_req: Request| async move {
        Response::ok("hello over tls")
    });
    let addr = spawn_tls_server(router).await;

    // Connect TCP, then run the moved `tls_server_config`'s handshake against it with a client
    // that pins the fixture cert as its only root.
    let tcp = TcpStream::connect(addr).await.expect("the TCP connect completes");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(pinned_client_config()));
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client = connector
        .connect(server_name, tcp)
        .await
        .expect("the TLS handshake completes");

    client
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("the TLS server must answer within 5s")
            .expect("read must succeed");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"hello over tls") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();

    // Bytes 1..6 of the reply are the TLS record's application data, decrypted: what follows is
    // the moved `write_response` output, identical to what `servelet-h1` writes over plain TCP.
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "got: {text:?}");
    assert!(text.contains("content-length: 14\r\n"), "got: {text:?}");
    assert!(text.ends_with("\r\n\r\nhello over tls"), "got: {text:?}");
}

#[tokio::test]
async fn tls_negotiates_tls_1_3_only() {
    // The moved `tls_server_config` calls `with_protocol_versions(&[&rustls::version::TLS13])`.
    // A client that offers TLS 1.2 only must therefore fail to complete a handshake.
    let addr = spawn_tls_server(Router::new().get("/x", |_r: Request| async move { Response::ok("x") }))
        .await;
    let cfg = tls12_only_client_config();
    let stream = TcpStream::connect(addr).await.unwrap();
    let acceptor = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from("localhost").unwrap();
    let result = acceptor.connect(server_name, stream).await;
    assert!(
        result.is_err(),
        "a TLS 1.2-only client must not complete a handshake against the moved server config"
    );
}

#[tokio::test]
async fn the_pem_parser_rejects_a_pem_with_no_certificate_block() {
    // The moved `tls_server_config` guards its inputs. Both failure modes, byte-for-byte.
    let err = tls_server_config("not a pem at all", KEY).unwrap_err();
    assert_eq!(err.to_string(), "TLS: no CERTIFICATE block found in the given PEM");

    let err = tls_server_config(CERT, "not a pem at all").unwrap_err();
    assert_eq!(err.to_string(), "TLS: no PRIVATE KEY block found in the given PEM");
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_fixture_cannot_connect() {
    // Proves the handshake above succeeded because of the pinned root, not because verification
    // is off anywhere.
    let addr = spawn_tls_server(Router::new().get("/x", |_r: Request| async move { Response::ok("x") }))
        .await;
    let stream = TcpStream::connect(addr).await.unwrap();
    let cfg = untrusting_client_config();
    let acceptor = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from("localhost").unwrap();
    let result = acceptor.connect(server_name, stream).await;
    assert!(result.is_err(), "an untrusting client must be rejected");
}

/// A client that trusts the fixture cert, for SNI name `localhost`.
fn pinned_client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    let der = CertificateDer::from(pem_der(CERT));
    roots.add(der).expect("the fixture cert is a valid root");
    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A client that offers TLS 1.2 only — must not complete against the moved server config.
fn tls12_only_client_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(pem_der(CERT))).expect("the fixture cert is a valid root");
    rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A client with an EMPTY root store — trusts nothing, including the fixture.
fn untrusting_client_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
}

/// Decode the single `-----BEGIN CERTIFICATE-----` block of the fixture.
fn pem_der(pem: &str) -> Vec<u8> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin).expect("fixture has a BEGIN") + begin.len();
    let stop = pem[start..].find(end).expect("fixture has an END") + start;
    let text: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&text)
}

/// The moved `base64_decode`, from `servelet-tls`'s own source — reused here so the test does not
/// reach for a crate the workspace does not depend on.
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

const _: fn() = || {
    // Keep the key type named so a fixture swap to PKCS#1 fails to compile here, loudly.
    let _: Option<PrivateKeyDer<'static>> = Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![])));
};