// -- Wire ----------------------------------------------------------------

// DEVIATION, the `use` lines only: biota's `kernel.rs` had them at the top of the file (lines
// 1-16). Nothing is re-declared or renamed.
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum Stream {
    Plain(TcpStream),
    // The TLS arm is behind the crate's off-by-default `tls` feature (rule 6). A consumer that
    // only speaks plaintext never links a TLS stack at all; `Error::Tls` is how an https URL
    // says so, and the message says which feature to turn on.
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Stream {
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf).await,
            #[cfg(feature = "tls")]
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf).await,
            #[cfg(feature = "tls")]
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(buf).await,
        }
    }

    pub async fn read_exact_into(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => {
                s.read_exact(buf).await?;
            }
            #[cfg(feature = "tls")]
            #[cfg(feature = "tls")]
            Stream::Tls(s) => {
                s.read_exact(buf).await?;
            }
        }
        Ok(())
    }

    pub async fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read_to_end(buf).await,
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read_to_end(buf).await,
        }
    }

    pub fn into_reader(self) -> StreamReader {
        StreamReader {
            inner: self,
            buf: Vec::new(),
            pos: 0,
            line: Vec::new(),
        }
    }
}

pub struct StreamReader {
    inner: Stream,
    buf: Vec<u8>,
    pos: usize,
    line: Vec<u8>,
}

impl StreamReader {
    pub async fn read_line(&mut self) -> io::Result<&[u8]> {
        self.line.clear();
        loop {
            if let Some(i) = self.buf[self.pos..].iter().position(|b| *b == b'\n') {
                let end = self.pos + i + 1;
                self.line.extend_from_slice(&self.buf[self.pos..end]);
                self.pos = end;
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                return Ok(&self.line);
            }

            if self.pos < self.buf.len() {
                self.line.extend_from_slice(&self.buf[self.pos..]);
                self.buf.clear();
                self.pos = 0;
            } else {
                self.buf.clear();
                self.pos = 0;
            }

            let mut chunk = [0u8; 8192];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                return Ok(&self.line);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub async fn read_exact(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut copied = 0;
        let buffered = (self.buf.len() - self.pos).min(len);
        if buffered > 0 {
            buf[..buffered].copy_from_slice(&self.buf[self.pos..self.pos + buffered]);
            self.pos += buffered;
            copied = buffered;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
        }
        if copied < len {
            self.inner.read_exact_into(&mut buf[copied..]).await?;
        }
        Ok(buf)
    }

    pub async fn read_to_end(&mut self, out: &mut Vec<u8>) -> io::Result<usize> {
        let before = out.len();
        if self.pos < self.buf.len() {
            out.extend_from_slice(&self.buf[self.pos..]);
            self.buf.clear();
            self.pos = 0;
        }
        self.inner.read_to_end(out).await?;
        Ok(out.len() - before)
    }

    /// Read UP TO `max` bytes — whatever's already buffered first, else one read from the
    /// underlying stream (0 on EOF). Unlike `read_exact`, never blocks waiting to fill `max`;
    /// this is the "give me the next available piece" primitive `StreamingResponse`'s
    /// read-until-EOF framing needs.
    pub async fn read_some(&mut self, max: usize, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.buf.len() {
            let n = (self.buf.len() - self.pos).min(max);
            buf[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            return Ok(n);
        }
        self.inner.read(&mut buf[..max]).await
    }

    /// Reclaim the underlying `Stream` (for connection pooling) plus any bytes already read off
    /// the wire but not yet consumed by the caller — losing these would corrupt whatever the
    /// NEXT request on a reused connection tries to read (they'd belong to the tail of THIS
    /// response, not the start of the next one). Only safe to call once the caller knows the
    /// current response has been read to completion (`send_request` only does this after a
    /// Content-Length or chunked-terminated body, never the "read until EOF" fallback, which by
    /// definition means the peer is closing the connection).
    pub fn into_inner(self) -> (Stream, Vec<u8>) {
        let leftover = self.buf[self.pos..].to_vec();
        (self.inner, leftover)
    }
}

#[cfg(feature = "tls")]
/// The TLS client config, built once from the system's own CA trust store
/// (`rustls-native-certs` — the same "prefer OS package signatures" discipline as
/// everywhere else in this workspace) and cached: every `https://` request reuses it.
pub(crate) fn tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<std::sync::Arc<rustls::ClientConfig>> =
        std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // `ClientConfig::builder()` (no explicit provider) reads the process-wide default
            // `CryptoProvider` — rustls 0.23 never auto-installs one even with the `ring`
            // feature enabled (that only makes it linkable). Nothing else in this crate installs
            // it, so the first real HTTPS request from ANY consumer would otherwise panic here.
            // `install_default` errors only if a provider is already installed (by this crate or
            // a consumer) — harmless, the existing one wins either way.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            std::sync::Arc::new(config)
        })
        .clone()
}
