//! sse — Server-Sent Events, matching `actix_web_lab::sse`'s public shape (`Sse`, `Event`,
//! `Data`), native against this crate's own `Response`/connection loop, no third-party
//! dependency. Real streaming, not a buffered fake: the response body is genuinely written to
//! the wire incrementally, chunk by chunk, as the backing channel produces events — see
//! `write_sse_response` in `lib.rs`, which `serve_connection`'s request loop dispatches to
//! whenever a response carries an [`SseBody`] (stashed in `Response`'s extensions by
//! [`Sse::respond_to`]).
//!
//! Scope, stated honestly: HTTP/1.1 only (chunked transfer-encoding) — h2c connections
//! (`h2.rs`) don't route through this path, since HTTP/2 has its own native stream framing and
//! nothing in this codebase's real call site (`events.rs`'s SSE endpoint) needs it there.
//! `Event` only has the `Data` variant (the one real call site ever constructs;
//! `Event::Comment`/`::Retry`-as-a-per-event-variant aren't ported).

use servelet_core::header;
use std::time::Duration;
use tokio::sync::mpsc;

/// One `data: ...\n\n` SSE field — `actix_web_lab::sse::Data`. `Clone` matches the real crate
/// (rauthy's own `events/listener.rs` broadcasts one `Event` to multiple registered clients via   CITATION-EXEMPT: rauthy, a tree outside `fold`
/// `.clone()`, fanning one domain event out to every open SSE connection).
#[derive(Clone)]
pub struct Data(String);

impl Data {
    pub fn new(data: impl Into<String>) -> Self {
        Data(data.into())
    }

    /// Render as the wire form: `data: line1\ndata: line2\n\n` (each internal newline in the
    /// payload gets its own `data:` prefix, per the SSE spec — a payload can't contain a bare
    /// `\n\n`, which would be read as the field terminator).
    pub(crate) fn render(&self) -> String {
        let mut out = String::with_capacity(self.0.len() + 8);
        for line in self.0.split('\n') {
            out.push_str("data: ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
        out
    }
}

/// One SSE stream item — `actix_web_lab::sse::Event`. Only the `Data` variant is ported (the
/// only one this codebase's real call site constructs); extend here if a real caller needs
/// `Comment`/named `event:`/`id:` fields.
#[derive(Clone)]
pub enum Event {
    Data(Data),
}

impl Event {
    /// The wire form (`data: ...\n\n`) — `lib.rs`'s `write_sse_response` calls this per event.
    pub fn render_for_wire(&self) -> String {
        match self {
            Event::Data(d) => d.render(),
        }
    }
}

/// The streaming source stashed in a `Response`'s extensions — `serve_connection` looks for this
/// (via `Response::sse_body`) to decide whether to hand the response to `write_sse_response`
/// instead of the normal buffered `write_response`. Wrapped in `Arc<Mutex<Option<...>>>` because
/// `Extensions::insert` requires `T: Clone` (app-wide/per-response state is normally read many
/// times; a streaming receiver is consumed exactly once, hence the `Option` + `.take()`).
#[derive(Clone)]
pub struct SseBody {
    pub rx: std::sync::Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Event>>>>,
    pub keep_alive: Option<Duration>,
    pub retry: Option<Duration>,
}

/// `actix_web_lab::sse::Sse` — an SSE response builder over an `mpsc::Receiver<Event>`.
pub struct Sse {
    rx: mpsc::Receiver<Event>,
    keep_alive: Option<Duration>,
    retry: Option<Duration>,
}

impl Sse {
    pub fn from_infallible_receiver(rx: mpsc::Receiver<Event>) -> Self {
        Sse { rx, keep_alive: None, retry: None }
    }

    pub fn with_keep_alive(mut self, period: Duration) -> Self {
        self.keep_alive = Some(period);
        self
    }

    pub fn with_retry_duration(mut self, retry: Duration) -> Self {
        self.retry = Some(retry);
        self
    }
}

impl Sse {
    pub fn respond_to(self, _req: &servelet_core::Request) -> servelet_core::Response {
        let mut resp = servelet_core::Response::new(servelet_core::StatusCode::OK, Vec::new());
        resp.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream");
        resp.headers_mut().insert("cache-control", "no-cache");
        resp.extensions_mut().insert(SseBody {
            rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(self.rx))),
            keep_alive: self.keep_alive,
            retry: self.retry,
        });
        resp
    }
}

/// Read back the streaming source `Sse::respond_to` stashed, if this response is an SSE
/// stream rather than an ordinary buffered one. `serve_connection`'s own dispatch point.
pub fn sse_body(resp: &servelet_core::Response) -> Option<SseBody> {
    resp.extensions().get::<SseBody>().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_event_renders_one_line_per_payload_line() {
        let rendered = Data::new("line one\nline two").render();
        assert_eq!(rendered, "data: line one\ndata: line two\n\n");
    }

    #[test]
    fn single_line_data_renders_with_one_data_prefix() {
        assert_eq!(Data::new("hello").render(), "data: hello\n\n");
    }

    #[tokio::test]
    async fn respond_to_sets_event_stream_content_type_and_stashes_the_receiver() {
        let (_tx, rx) = mpsc::channel::<Event>(4);
        let sse = Sse::from_infallible_receiver(rx).with_keep_alive(Duration::from_secs(15));
        let req = servelet_core::Request::new(servelet_core::Method::GET, "/events/stream".parse().unwrap());
        let resp = sse.respond_to(&req);

        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap(), "text/event-stream");
        let body = sse_body(&resp).expect("SseBody must be stashed by respond_to");
        assert_eq!(body.keep_alive, Some(Duration::from_secs(15)));
        assert!(body.rx.lock().await.is_some());
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// High-level wire helpers — wasm-safe (std only, no tokio). The line-buffered
// parser + encoder that syndesi's gateway, opsfold's `ingest`, and opsfold's
// `paging` all use instead of hand-rolling per call site. The streaming
// primitive above (Sse/Event/Data/SseBody) is the native response half; these
// are the parse/emit half.
// ─────────────────────────────────────────────────────────────────────────────

/// `text/event-stream` content type.
pub fn content_type() -> &'static str {
    "text/event-stream"
}

/// Encode one SSE event as wire bytes (with trailing `\n\n`).
///
/// ```text
/// event: msg
/// data: hello
///
/// ```
pub fn encode_event(data: &str, event: Option<&str>, id: Option<&str>) -> String {
    let mut out = String::with_capacity(data.len() + 32);
    if let Some(id) = id {
        out.push_str("id: ");
        out.push_str(id);
        out.push('\n');
    }
    if let Some(event) = event {
        out.push_str("event: ");
        out.push_str(event);
        out.push('\n');
    }
    for line in data.lines() {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

/// One parsed SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

/// Line-buffered SSE parser. Feed raw chunks; yields complete events when blank
/// lines arrive. Multiple `data:` lines in one event concatenate with `\n`.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
}

impl SseParser {
    pub fn new() -> Self {
        SseParser {
            buffer: String::new(),
        }
    }

    /// Feed a chunk of wire bytes; returns any events completed by this chunk.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        let mut events = Vec::new();
        loop {
            // Event boundary: a blank line (`\n\n` or `\r\n\r\n`).
            let boundary_len = if self.buffer.contains("\n\n") {
                2
            } else if self.buffer.contains("\r\n\r\n") {
                4
            } else {
                break;
            };
            let end = self
                .buffer
                .find("\n\n")
                .or_else(|| self.buffer.find("\r\n\r\n"))
                .unwrap();
            let block = self.buffer[..end].to_string();
            self.buffer = self.buffer[end + boundary_len..].to_string();
            if let Some(ev) = Self::parse_block(&block) {
                events.push(ev);
            }
        }
        events
    }

    /// Flush any remaining partial event (no trailing blank line).
    pub fn flush(&mut self) -> Option<SseEvent> {
        if self.buffer.trim().is_empty() {
            return None;
        }
        let block = std::mem::take(&mut self.buffer);
        Self::parse_block(block.trim_end_matches('\n').trim_end_matches('\r'))
    }

    /// CR, LF and CRLF are three spellings of ONE line terminator in the event-stream grammar
    /// (WHATWG HTML §"Interpreting an event stream"), but Rust's `str::lines` knows only about
    /// `\n` and strips a single trailing `\r`. A lone CR in the middle of a field therefore
    /// survives into the parsed value — and a lone CR is a line break to every consumer
    /// downstream that matters (a log writer, a terminal, a CSV reader), which makes a field
    /// value carrying one a forgery primitive rather than a cosmetic bug.
    ///
    /// CRLF collapses to a single LF rather than becoming two: otherwise a peer could inject a
    /// blank line with a `\r` and split one event into two, which is exactly what this function
    /// exists to prevent.
    fn normalise_line_endings(block: &str) -> String {
        let mut out = String::with_capacity(block.len());
        let mut chars = block.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\r' {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            } else {
                out.push(c);
            }
        }
        out
    }

    fn parse_block(block: &str) -> Option<SseEvent> {
        if block.trim().is_empty() {
            return None;
        }
        let normalised = Self::normalise_line_endings(block);
        let mut event = None;
        let mut data = String::new();
        let mut id = None;
        let mut saw_data = false;
        for line in normalised.lines() {
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f.trim(), v.trim_start()),
                None => (line.trim(), ""),
            };
            match field {
                "event" => event = Some(value.to_string()),
                "data" => {
                    if saw_data {
                        data.push('\n');
                    }
                    data.push_str(value);
                    saw_data = true;
                }
                "id" => id = Some(value.to_string()),
                "retry" | "" | ":" => {}
                _ => {}
            }
        }
        if !saw_data {
            return None;
        }
        Some(SseEvent { event, data, id })
    }
}
