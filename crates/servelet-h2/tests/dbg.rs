use servelet_core::{Request, Response};
use servelet_h2::{
    encode_message_header, grpc_unary, hpack_decode, hpack_encode, serve_h2c_connection,
    FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, FrameType, HField,
};
use servelet_router::Router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[tokio::test]
async fn dbg() {
    eprintln!("[DBG] test starting");
    let echo = |req: Request| async move { Response::ok(req.into_body()) };
    let router = Router::new().fallback(grpc_unary(echo));
    eprintln!("[DBG] router built");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    eprintln!("[DBG] listener bound: {addr}");

    let server = tokio::spawn(async move {
        eprintln!("[SRV] accepting");
        if let Ok((mut stream, _)) = listener.accept().await {
            eprintln!("[SRV] connection accepted");
            let mut preface = [0u8; 24];
            if stream.read_exact(&mut preface).await.is_err() {
                eprintln!("[SRV] preface read failed");
                return;
            }
            if &preface[..] != PREFACE {
                eprintln!("[SRV] preface mismatch");
                return;
            }
            eprintln!("[SRV] preface ok, dispatching");
            serve_h2c_connection(stream, router).await;
            eprintln!("[SRV] done");
        }
    });

    let mut sock = TcpStream::connect(addr).await.unwrap();
    eprintln!("[DBG] connected");
    sock.write_all(PREFACE).await.unwrap();
    eprintln!("[DBG] preface sent");
    let mut hdr = [0u8; 9];
    let settings = Frame::new(FrameType::Settings, 0, 0, Vec::new());
    sock.write_all(&settings.to_bytes()).await.unwrap();
    eprintln!("[DBG] settings sent");

    let req_headers = hpack_encode(&[
        (":method", "POST"),
        (":path", "/pkg.Svc/Echo"),
        (":scheme", "http"),
        ("content-type", "application/grpc"),
    ]);
    let h = Frame::new(FrameType::Headers, FLAG_END_HEADERS, 1, req_headers);
    sock.write_all(&h.to_bytes()).await.unwrap();
    eprintln!("[DBG] headers sent");

    let mut data_payload: Vec<u8> = Vec::new();
    data_payload.extend_from_slice(&encode_message_header(false, 5));
    data_payload.extend_from_slice(b"hello");
    let d = Frame::new(FrameType::Data, FLAG_END_STREAM, 1, data_payload);
    sock.write_all(&d.to_bytes()).await.unwrap();
    eprintln!("[DBG] data sent");

    eprintln!("[DBG] waiting for server settings");
    sock.read_exact(&mut hdr).await.unwrap();
    eprintln!("[DBG] got hdr1: {:?}", hdr);
    let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 { sock.read_exact(&mut payload).await.unwrap(); }

    eprintln!("[DBG] test ending");
}
