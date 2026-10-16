//! The sender, the collector, the probe and the results file in one process, against a mock
//! push server that plays the phone by posting each alert body back to the collector.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use push_delivery::collector::{self, AckSink};
use push_delivery::config::Config;
use push_delivery::http;
use push_delivery::payload::is_content_free_body;
use push_delivery::records::{AckRecord, ServerKind, read_records};
use push_delivery::report::{Verdict, compute};
use push_delivery::sender;
use push_delivery::token::{new_alert_id, new_topic};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Clone, Copy)]
enum Behaviour {
    /// Accept and post the body to the collector, like a phone that received it.
    Deliver,
    /// Accept and never deliver.
    Swallow,
    /// Refuse the publish.
    Refuse,
}

#[derive(Clone, Debug)]
struct Published {
    path: String,
    header_names: Vec<String>,
    authorization: Option<String>,
    body: String,
}

struct MockPush {
    url: String,
    published: Arc<Mutex<Vec<Published>>>,
}

async fn mock_push(behaviour: Behaviour, collector_url: String) -> MockPush {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let published = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&published);
    let client = http::client(None).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (log, client, collector_url) =
                (Arc::clone(&log), client.clone(), collector_url.clone());
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let (log, client, collector_url) =
                        (Arc::clone(&log), client.clone(), collector_url.clone());
                    async move {
                        let path = request.uri().path().to_owned();
                        let header_names = request
                            .headers()
                            .keys()
                            .map(|k| k.as_str().to_owned())
                            .collect();
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .map(|v| v.to_str().unwrap().to_owned());
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8(body.to_vec()).unwrap();
                        log.lock().unwrap().push(Published {
                            path,
                            header_names,
                            authorization,
                            body: body.clone(),
                        });
                        let status = match behaviour {
                            Behaviour::Deliver => {
                                tokio::spawn(async move {
                                    http::request_to_end(
                                        &client,
                                        Method::POST,
                                        &format!("{collector_url}/ack"),
                                        None,
                                        body,
                                    )
                                    .await
                                    .unwrap();
                                });
                                StatusCode::OK
                            }
                            Behaviour::Swallow => StatusCode::OK,
                            Behaviour::Refuse => StatusCode::FORBIDDEN,
                        };
                        let mut response = Response::new(Full::new(Bytes::from_static(b"{}")));
                        *response.status_mut() = status;
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    MockPush { url, published }
}

/// A free local port for the collector: bound, read and released.
async fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn results_path() -> PathBuf {
    std::env::temp_dir().join(format!("push-delivery-test-{}.tsv", new_alert_id()))
}

fn config(text: &str) -> Config {
    Config::parse(text, |_| None).unwrap()
}

#[tokio::test]
async fn probe_publishes_content_free_alerts_and_sees_the_acknowledgements() {
    let listen = free_addr().await;
    let push = mock_push(Behaviour::Deliver, format!("http://{listen}")).await;
    let public_topic = new_topic();
    let config = config(&format!(
        "listen {listen}\n\
         target phone-1 self-hosted {url} protected-topic tk_test_token_only\n\
         target phone-1 public {url} {public_topic} -\n\
         target phone-2 public {url} {other} -\n",
        url = push.url,
        other = new_topic(),
    ));
    let phone = "phone-1".parse().unwrap();
    let all_acknowledged = sender::probe(&config, Some(&phone), Duration::from_secs(5))
        .await
        .unwrap();
    assert!(all_acknowledged);

    let published = push.published.lock().unwrap().clone();
    // Only phone-1's two targets were probed.
    assert_eq!(published.len(), 2);
    for p in &published {
        assert!(is_content_free_body(&p.body), "{}", p.body);
        for name in &p.header_names {
            assert!(
                matches!(
                    name.as_str(),
                    "host" | "content-type" | "content-length" | "authorization"
                ),
                "unexpected header {name}"
            );
        }
    }
    let protected = published
        .iter()
        .find(|p| p.path == "/protected-topic")
        .unwrap();
    assert_eq!(
        protected.authorization.as_deref(),
        Some("Bearer tk_test_token_only")
    );
    let public = published
        .iter()
        .find(|p| p.path == format!("/{public_topic}"))
        .unwrap();
    assert_eq!(public.authorization, None);
}

#[tokio::test]
async fn probe_reports_a_swallowed_or_refused_alert() {
    for behaviour in [Behaviour::Swallow, Behaviour::Refuse] {
        let listen = free_addr().await;
        let push = mock_push(behaviour, format!("http://{listen}")).await;
        let config = config(&format!(
            "listen {listen}\ntarget phone-1 public {} {} -\n",
            push.url,
            new_topic()
        ));
        let all_acknowledged = sender::probe(&config, None, Duration::from_millis(500))
            .await
            .unwrap();
        assert!(!all_acknowledged);
    }
}

#[tokio::test]
async fn a_run_records_sends_and_acknowledgements_and_the_report_reads_them() {
    let listen = free_addr().await;
    let delivering = mock_push(Behaviour::Deliver, format!("http://{listen}")).await;
    let refusing = mock_push(Behaviour::Refuse, format!("http://{listen}")).await;
    let results = results_path();
    let (topic_a, topic_b) = (new_topic(), new_topic());
    let config = config(&format!(
        "results {}\n\
         listen {listen}\n\
         mean_interval_ms 40\n\
         deadline_ms 500\n\
         window_ms 1000\n\
         min_alerts 10\n\
         target phone-1 self-hosted {} {topic_a} tk_secret_value\n\
         target phone-1 public {} {topic_b} -\n",
        results.display(),
        delivering.url,
        refusing.url,
    ));
    sender::run(&config, Some(Duration::from_millis(1_500)))
        .await
        .unwrap();

    let records = read_records(&results).unwrap();
    let text = std::fs::read_to_string(&results).unwrap();
    for secret in [
        topic_a.as_str(),
        topic_b.as_str(),
        "tk_secret_value",
        "127.0.0.1",
        "http",
    ] {
        assert!(!text.contains(secret), "results file holds `{secret}`");
    }

    let targets: Vec<_> = config
        .targets
        .iter()
        .map(|t| (t.phone.clone(), t.server))
        .collect();
    let report = compute(
        &targets,
        &records,
        config.criterion,
        config.night,
        push_delivery::now_ms(),
    );
    let phone = "phone-1".parse().unwrap();
    let delivered = report.target(&phone, ServerKind::SelfHosted).unwrap();
    assert!(delivered.evaluated() >= 10, "{report}");
    assert_eq!(delivered.in_time(), delivered.evaluated(), "{report}");
    assert_eq!(delivered.pending, 0);
    assert_eq!(delivered.verdict, Verdict::Pass, "{report}");
    let refused = report.target(&phone, ServerKind::Public).unwrap();
    assert_eq!(refused.unpublished(), refused.evaluated());
    assert_eq!(refused.verdict, Verdict::Fail, "{report}");
    assert_eq!(report.e13, Verdict::Pass);
    assert!(report.to_string().contains("criterion=simulation"));
    assert_eq!(
        delivering.published.lock().unwrap().len() as u64,
        delivered.evaluated()
    );
}

#[tokio::test]
async fn collector_accepts_ids_only_and_reveals_nothing_else() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (acks, mut received) = mpsc::unbounded_channel::<AckRecord>();
    let sink: AckSink = Arc::new(move |ack| acks.send(ack).unwrap());
    tokio::spawn(collector::serve(listener, sink));
    let client = http::client(None).unwrap();
    let call = |method: Method, path: &str, body: String| {
        let (client, url) = (client.clone(), format!("{base}{path}"));
        async move {
            http::request_to_end(&client, method, &url, None, body)
                .await
                .unwrap()
                .0
        }
    };

    let id = new_alert_id();
    let status = call(
        Method::POST,
        "/ack?t=1700000000",
        format!("Vilicus security alert. ref {id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let ack = received.recv().await.unwrap();
    assert_eq!(ack.id, id);
    assert_eq!(ack.phone_ms, Some(1_700_000_000_000));

    let other = new_alert_id();
    assert_eq!(
        call(Method::POST, &format!("/ack/{other}"), String::new()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(received.recv().await.unwrap().id, other);

    assert_eq!(
        call(Method::POST, "/ack", "no id".to_owned()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(Method::POST, "/ack/not-an-id", String::new()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(Method::POST, "/ack", "x".repeat(4096)).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        call(Method::GET, "/ack", String::new()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(Method::GET, "/healthz", String::new()).await,
        StatusCode::OK
    );
    assert!(received.try_recv().is_err());
}
