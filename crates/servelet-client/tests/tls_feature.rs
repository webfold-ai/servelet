//! Client TLS is optional, and this file is the proof that "optional" means off, not broken:
//! it runs the same assertions with the feature on and off.
//!
//! The default build must SAY SO for an `https://` URL — a client that silently spoke
//! plaintext to a TLS port would be a security bug, so the error names the feature to turn on.

use servelet_client::{Client, RetryPolicy};
use servelet_core::{Error, Response};

fn client() -> Client {
    Client::builder().retry(RetryPolicy::new(2, std::time::Duration::from_millis(1))).build()
}

#[tokio::test]
async fn a_plaintext_request_still_works_with_and_without_the_tls_feature() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let n = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
        let _ = n;
    });
    let resp = client().get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(resp.status(), servelet_core::StatusCode::OK);
    assert_eq!(resp.bytes().await, b"ok");
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn without_the_feature_an_https_url_is_refused_by_name_not_silently_downgraded() {
    match client().get("https://example.invalid/").send().await {
        Err(Error::Tls(msg)) => {
            assert!(msg.contains("`tls` feature"), "the error must say what to turn on: {msg}");
        }
        other => panic!("expected Error::Tls naming the feature, got {other:?}"),
    }
}

/// With the feature on, an https request to a port that is not speaking TLS fails in the
/// HANDSHAKE, with the host named -- not with "this build has no TLS", which is what the
/// feature-off build says. Two different failures, two different messages.
#[cfg(feature = "tls")]
#[tokio::test]
async fn with_the_feature_an_https_url_fails_in_the_handshake_and_names_the_host() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept and immediately drop: a plaintext server where a TLS client expected one.
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    // One attempt only: a handshake failure is transient as far as the retry policy is
    // concerned, so with retries on it would reconnect (and be refused), and the error a caller
    // saw would be the reconnect's, not the handshake's.
    let once = Client::builder().retry(RetryPolicy::new(1, std::time::Duration::from_millis(1))).build();
    match once.get(format!("https://{addr}/")).send().await {
        Err(Error::Tls(msg)) => assert!(msg.contains(&addr.ip().to_string()), "{msg}"),
        other => panic!("expected Error::Tls naming the host, got {other:?}"),
    }
}
