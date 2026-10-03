// DEVIATION, the module's `use` lines only: biota's `kernel.rs` had them at the top of the file
// (lines 1-16). Nothing is re-declared or renamed.
use tokio::io::AsyncWriteExt;

use servelet_core::{header, status_reason, Response, Result};
use servelet_h1::write_chunk;


/// Writes an SSE response as real chunked transfer-encoding, one chunk per event, as they
/// arrive from the channel ``Sse::respond_to`` stashed — not a buffered fake. The
/// connection is dedicated to this stream until the channel closes (or a keep-alive period
/// elapses with nothing to send, in which case a `: keep-alive\n\n` comment chunk goes out
/// instead of a real event) — see `serve_connection`, which never falls through to its normal
/// keep-alive request loop after this returns.
pub(crate) async fn write_sse_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    mut response: Response,
    sse_body: crate::sse::SseBody,
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

    let mut rx = sse_body
        .rx
        .lock()
        .await
        .take()
        .expect("SseBody's receiver is stashed exactly once per response and consumed exactly once, here");

    if let Some(retry) = sse_body.retry {
        write_sse_chunk(writer, format!("retry: {}\n\n", retry.as_millis())).await?;
    }

    loop {
        let event = match sse_body.keep_alive {
            Some(period) => match tokio::time::timeout(period, rx.recv()).await {
                Ok(next) => next,
                Err(_elapsed) => {
                    write_sse_chunk(writer, ": keep-alive\n\n".to_string()).await?;
                    continue;
                }
            },
            None => rx.recv().await,
        };

        match event {
            Some(event) => write_sse_chunk(writer, event.render_for_wire()).await?,
            None => break,
        }
    }

    writer.write_all(b"0\r\n\r\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_sse_chunk<W: AsyncWriteExt + Unpin>(writer: &mut W, data: String) -> Result<()> {
    write_chunk(writer, data.as_bytes()).await
}
