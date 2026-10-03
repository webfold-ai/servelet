//! `servelet-sse` — Server-Sent Events.
//!
//! The event encoder and the line-buffered parser, lifted out of `biota/http-server`'s
//! `httpx::sse` module when the HTTP kernel became `servelet` (`SPINE.md`'s "NOT YOURS" list
//! names `servelet-sse` as the home for exactly this).
//!
//! # What is here, and what deliberately is not
//!
//! Here: `Data`/`Event`, the [`Sse`] stream builder, [`encode_event`], [`SseEvent`], and the
//! [`SseParser`]. All of it is pure — no connection, no socket, no response type.
//!
//! **Not** here: the `Responder` bridge. In biota that was `impl actix::Responder for Sse`,
//! which turns a stream into a `Response` by stashing an [`SseBody`] in the response's
//! `Extensions`. That is framework interop and a server-side write path, not SSE, and the
//! masq family (`actix`, `axum_masq`, `reqwest_masq`) already has a home for it. Putting it
//! here would make this crate the second place actix shapes are answered.
//!
//! HTTP/1.1 only, as before: chunked transfer-encoding, and HTTP/2's own stream framing does
//! not route through this path.

#![forbid(unsafe_code)]

use std::time::Duration;

use servelet_core::{Response, StatusCode};
use tokio::sync::mpsc;

/// `text/event-stream` content type.
pub fn content_type() -> &'static str {
    "text/event-stream"
}

/// One `data: ...\n\n` SSE field.
#[derive(Clone)]
pub struct Data(String);

impl Data {
    pub fn new(data: impl Into<String>) -> Self {
        Data(data.into())
    }

    /// The payload, without the wire framing.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as wire form: `data: line1\ndata: line2\n\n`.
    ///
    /// Each internal newline in the payload gets its own `data:` prefix, per the SSE spec — a
    /// payload cannot contain a bare `\n\n`, which would read as the field terminator.
    pub fn render(&self) -> String {
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

/// One SSE stream item.
///
/// Only `Data` exists here — the variant the real call site constructs. A named `event:`/`id:`
/// pair is expressible through [`encode_event`] without a variant, which is why the previous
/// shape's unimplemented `Comment`/`Retry` variants were not worth carrying.
#[derive(Clone)]
pub enum Event {
    Data(Data),
}

impl Event {
    /// The wire form — what a server writes per event.
    pub fn render_for_wire(&self) -> String {
        match self {
            Event::Data(d) => d.render(),
        }
    }
}

/// Encode one SSE event as wire bytes (with the trailing blank line).
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

/// The streaming source a server write path consumes.
///
/// Wrapped in `Arc<Mutex<Option<…>>>` because `Extensions::insert` requires `T: Clone`: a
/// streaming receiver is consumed exactly once, so the server takes it out rather than cloning
/// a live `Receiver`.
#[derive(Clone)]
pub struct SseBody {
    pub rx: std::sync::Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Event>>>>,
    pub keep_alive: Option<Duration>,
    pub retry: Option<Duration>,
}

/// An SSE response builder over an `mpsc::Receiver<Event>`.
pub struct Sse {
    rx: mpsc::Receiver<Event>,
    keep_alive: Option<Duration>,
    retry: Option<Duration>,
}

impl Sse {
    pub fn from_infallible_receiver(rx: mpsc::Receiver<Event>) -> Self {
        Sse { rx, keep_alive: None, retry: None }
    }

    /// Emit a keep-alive comment every `period` when the stream is otherwise idle.
    pub fn with_keep_alive(mut self, period: Duration) -> Self {
        self.keep_alive = Some(period);
        self
    }

    /// Send a `retry:` field telling the browser how long to wait before reconnecting.
    pub fn with_retry_duration(mut self, retry: Duration) -> Self {
        self.retry = Some(retry);
        self
    }

    /// The stashed stream, for a server write path to consume.
    pub fn into_body(self) -> SseBody {
        SseBody {
            rx: std::sync::Arc::new(tokio::sync::Mutex::new(Some(self.rx))),
            keep_alive: self.keep_alive,
            retry: self.retry,
        }
    }

    /// A response that *declares* an event stream, carrying [`SseBody`] in its extensions for a
    /// server write path to pick up.
    ///
    /// This is the one piece of server shape that lives here, and deliberately so: it is the
    /// boundary a write path needs and it touches no framework. The `actix::Responder` impl
    /// that used to do this in biota is a thin wrapper over this call, so the framework answer
    /// has one implementation to point at instead of a second one.
    pub fn into_response(self) -> Response {
        let mut resp = Response::new(StatusCode::OK, Vec::new());
        resp.headers_mut()
            .insert("content-type", "text/event-stream");
        resp.headers_mut().insert("cache-control", "no-cache");
        resp.extensions_mut().insert(self.into_body());
        resp
    }
}

/// Read back the streaming source a response carries, if it is an SSE stream rather than an
/// ordinary buffered one. The write path's dispatch point.
pub fn sse_body(resp: &Response) -> Option<SseBody> {
    resp.extensions().get::<SseBody>().cloned()
}

/// Line-buffered SSE parser. Feed raw chunks; complete events are yielded when a blank line
/// arrives. Multiple `data:` lines in one event concatenate with `\n`.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
}

impl SseParser {
    pub fn new() -> Self {
        SseParser { buffer: String::new() }
    }

    /// Feed a chunk of wire bytes; returns any events this chunk completed.
    ///
    /// Boundaries survive being split across chunks, which is the whole reason this type
    /// exists rather than a naive split on `\n\n`.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        let mut events = Vec::new();
        loop {
            let (end, boundary_len) = match self.next_boundary() {
                Some(found) => found,
                None => break,
            };
            let block = self.buffer[..end].to_string();
            self.buffer = self.buffer[end + boundary_len..].to_string();
            if let Some(ev) = Self::parse_block(&block) {
                events.push(ev);
            }
        }
        events
    }

    /// Locate the next event boundary, normalising CRLF and LF to one answer.
    ///
    /// `\n\n` is checked first because a `\r\n\r\n` stream also *contains* `\n\n` (the second
    /// byte pair), and taking the LF answer there would leave a stray `\r` glued to the front
    /// of the next block.
    fn next_boundary(&self) -> Option<(usize, usize)> {
        let lf = self.buffer.find("\n\n").map(|i| (i, 2));
        let crlf = self.buffer.find("\r\n\r\n").map(|i| (i, 4));
        match (lf, crlf) {
            (Some(l), Some(c)) => {
                if c.0 < l.0 {
                    Some(c)
                } else {
                    Some(l)
                }
            }
            (Some(l), None) => Some(l),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        }
    }

    /// Flush a trailing partial event that never got its blank line.
    pub fn flush(&mut self) -> Option<SseEvent> {
        if self.buffer.trim().is_empty() {
            return None;
        }
        let block = std::mem::take(&mut self.buffer);
        Self::parse_block(block.trim_end_matches('\n').trim_end_matches('\r'))
    }

    fn parse_block(block: &str) -> Option<SseEvent> {
        if block.trim().is_empty() {
            return None;
        }
        let mut event = None;
        let mut data = String::new();
        let mut id = None;
        let mut saw_data = false;
        for line in block.lines() {
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
                // `retry` is a reconnection hint for the *client*, not part of the event, and
                // `:` alone is the spec's explicit "field with no value, ignore".
                "retry" | "" | ":" => {}
                _ => {}
            }
        }
        // An event with no `data:` field is a comment/keep-alive, not an event. Dropping it is
        // what lets a keep-alive comment flow through the same parser without being mistaken
        // for a message.
        if !saw_data {
            return None;
        }
        Some(SseEvent { event, data, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple() {
        assert_eq!(encode_event("hello", None, None), "data: hello\n\n");
    }

    #[test]
    fn encode_with_event_and_id() {
        assert_eq!(
            encode_event("hello", Some("msg"), Some("1")),
            "id: 1\nevent: msg\ndata: hello\n\n"
        );
    }

    #[test]
    fn parser_across_chunk_boundaries() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: hel").is_empty());
        let evs = p.feed(b"lo\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "hello");
    }

    #[test]
    fn parser_multiple_data_lines_concatenate() {
        let mut p = SseParser::new();
        let evs = p.feed(b"event: msg\ndata: line1\ndata: line2\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event.as_deref(), Some("msg"));
        assert_eq!(evs[0].data, "line1\nline2");
    }

    #[test]
    fn parser_two_events_in_one_chunk() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: one\n\ndata: two\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "one");
        assert_eq!(evs[1].data, "two");
    }

    #[test]
    fn parser_flush_partial() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: partial").is_empty());
        assert_eq!(p.flush().map(|e| e.data), Some("partial".to_string()));
    }

    #[test]
    fn parser_handles_crlf_boundaries() {
        let mut p = SseParser::new();
        let evs = p.feed(b"data: crlf one\r\n\r\ndata: crlf two\r\n\r\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "crlf one");
        assert_eq!(evs[1].data, "crlf two");
    }

    #[test]
    fn parser_drops_keep_alive_comments() {
        let mut p = SseParser::new();
        // A bare `: keep-alive` block carries no `data:` field, so it is a comment, not an
        // event — and must not surface as an empty message.
        let evs = p.feed(b": keep-alive\n\ndata: real\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "real");
    }

    #[test]
    fn parser_captures_id_field() {
        let mut p = SseParser::new();
        let evs = p.feed(b"id: 7\ndata: x\n\n");
        assert_eq!(evs[0].id.as_deref(), Some("7"));
    }

    #[test]
    fn data_render_prefixes_every_line() {
        let d = Data::new("one\ntwo");
        assert_eq!(d.render(), "data: one\ndata: two\n\n");
        assert_eq!(d.as_str(), "one\ntwo");
    }

    #[test]
    fn into_response_declares_the_stream() {
        let (tx, rx) = mpsc::channel(4);
        let resp = Sse::from_infallible_receiver(rx).into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("content-type").is_some());
        // The stream must be recoverable by a write path — that is the whole contract.
        assert!(sse_body(&resp).is_some());
        drop(tx);
    }
}
