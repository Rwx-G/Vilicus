//! The acknowledgement collector: a small HTTP server that receives the one-time id back from
//! the phone.
//!
//! - `POST /ack` with the notification text (or just the id) as the body;
//! - `POST /ack/<id>` with any body;
//! - either with an optional query `t=<phone time>`, Unix seconds or milliseconds.
//!
//! The answer is 204 for a well-formed id, 400 otherwise; whether the id was ever sent is not
//! revealed. `GET /healthz` answers 200.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::now_ms;
use crate::records::AckRecord;
use crate::token::{find_alert_id, is_alert_id};

/// Largest acknowledgement body read; a notification text is far smaller.
const MAX_BODY: usize = 2048;
/// Below this a phone time is read as Unix seconds (it would be year 5138 in seconds).
const SECONDS_LIMIT: u64 = 100_000_000_000;

/// What the collector does with each acknowledgement.
pub type AckSink = Arc<dyn Fn(AckRecord) + Send + Sync>;

/// Serves acknowledgements on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, sink: AckSink) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // Out of file descriptors or a reset before accept: back off instead of spinning.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let sink = Arc::clone(&sink);
        tokio::spawn(async move {
            let service = service_fn(move |request| handle(request, Arc::clone(&sink)));
            // A connection error concerns only that client.
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn reply(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response
}

fn phone_time(query: Option<&str>) -> Option<u64> {
    let value = query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("t="))?
        .parse::<u64>()
        .ok()?;
    Some(if value < SECONDS_LIMIT {
        value * 1000
    } else {
        value
    })
}

async fn handle(
    request: Request<Incoming>,
    sink: AckSink,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let arrival_ms = now_ms();
    let path = request.uri().path().to_owned();
    let phone_ms = phone_time(request.uri().query());
    match (request.method(), path.as_str()) {
        (&Method::GET, "/healthz") => return Ok(reply(StatusCode::OK, "ok\n")),
        (&Method::POST, "/ack") => {}
        (&Method::POST, p) if p.starts_with("/ack/") => {}
        _ => return Ok(reply(StatusCode::NOT_FOUND, "not found\n")),
    }
    let body = match Limited::new(request.into_body(), MAX_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return Ok(reply(StatusCode::PAYLOAD_TOO_LARGE, "too large\n")),
    };
    let id = match path.strip_prefix("/ack/") {
        Some(from_path) => is_alert_id(from_path).then(|| from_path.to_owned()),
        None => std::str::from_utf8(&body)
            .ok()
            .and_then(find_alert_id)
            .map(str::to_owned),
    };
    match id {
        Some(id) => {
            sink(AckRecord {
                id,
                arrival_ms,
                phone_ms,
            });
            Ok(reply(StatusCode::NO_CONTENT, ""))
        }
        None => Ok(reply(StatusCode::BAD_REQUEST, "no alert id\n")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_time_accepts_seconds_and_milliseconds() {
        assert_eq!(phone_time(Some("t=1700000000")), Some(1_700_000_000_000));
        assert_eq!(
            phone_time(Some("x=1&t=1700000000123")),
            Some(1_700_000_000_123)
        );
        assert_eq!(phone_time(Some("t=soon")), None);
        assert_eq!(phone_time(None), None);
    }
}
