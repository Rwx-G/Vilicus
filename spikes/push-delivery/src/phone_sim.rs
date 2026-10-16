//! A simulated phone for the test network: it subscribes to its topics the way the ntfy app
//! does in instant-delivery mode (a long-lived JSON stream, `since=<last id>` on reconnect) and
//! acknowledges each alert to the collector, the way the automation on a real phone does.
//!
//! Faults it can inject per subscription:
//! - a processing delay before each acknowledgement, with an optional share of slow ones
//!   (a phone in doze);
//! - outages: the connection is dropped for a while; on `resume` the phone reconnects with the
//!   last id it saw, so the server replays what it missed (late alerts), on `lossy` it reconnects
//!   without it, so alerts sent during the outage are lost (missing alerts).

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::http::{self, HttpClient};
use crate::now_ms;
use crate::records::{PhoneLabel, ServerKind};
use crate::token::{chance_per_mille, uniform_ms};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outage {
    pub start_after_ms: u64,
    pub duration_ms: u64,
    pub lossy: bool,
}

impl Outage {
    /// Parses `<start>+<duration>:<resume|lossy>`, both in ms from the simulation start.
    pub fn parse(text: &str) -> Result<Outage, String> {
        let error = || format!("outage `{text}` is not `<start_ms>+<duration_ms>:<resume|lossy>`");
        let (window, mode) = text.split_once(':').ok_or_else(error)?;
        let (start, duration) = window.split_once('+').ok_or_else(error)?;
        Ok(Outage {
            start_after_ms: start.parse().map_err(|_| error())?,
            duration_ms: duration.parse().map_err(|_| error())?,
            lossy: match mode {
                "resume" => false,
                "lossy" => true,
                _ => return Err(error()),
            },
        })
    }
}

/// Processing delay before acknowledging: uniform in `normal_ms`, except a `slow_per_mille`
/// share drawn uniformly in `slow_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delay {
    pub normal_ms: (u64, u64),
    pub slow_per_mille: u64,
    pub slow_ms: (u64, u64),
}

impl Delay {
    fn draw(&self) -> Duration {
        let (low, high) = if chance_per_mille(self.slow_per_mille) {
            self.slow_ms
        } else {
            self.normal_ms
        };
        Duration::from_millis(uniform_ms(low, high))
    }
}

/// Parses `<low>-<high>` in ms.
pub fn parse_range(text: &str) -> Result<(u64, u64), String> {
    let error = || format!("`{text}` is not `<low_ms>-<high_ms>`");
    let (low, high) = text.split_once('-').ok_or_else(error)?;
    let range = (
        low.parse().map_err(|_| error())?,
        high.parse().map_err(|_| error())?,
    );
    if range.0 > range.1 {
        return Err(error());
    }
    Ok(range)
}

#[derive(Clone, Debug)]
pub struct Subscription {
    pub phone: PhoneLabel,
    pub server: ServerKind,
    pub topic_url: String,
    pub token: Option<String>,
    pub delay: Delay,
    pub outages: Vec<Outage>,
}

/// Runs every subscription for `duration`, acknowledging to `collector_url`.
pub async fn run(subscriptions: Vec<Subscription>, collector_url: String, duration: Duration) {
    let client = match http::client(None) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("event=phone-sim-failed error={e}");
            return;
        }
    };
    let start = Instant::now();
    let end = start + duration;
    let mut tasks = JoinSet::new();
    for subscription in subscriptions {
        tasks.spawn(subscribe(
            subscription,
            client.clone(),
            collector_url.clone(),
            start,
            end,
        ));
    }
    while tasks.join_next().await.is_some() {}
}

#[derive(Clone, Copy)]
enum StreamEnd {
    Outage,
    Closed,
    TimeUp,
}

async fn subscribe(
    mut subscription: Subscription,
    client: HttpClient,
    collector_url: String,
    start: Instant,
    end: Instant,
) {
    subscription.outages.sort_by_key(|o| o.start_after_ms);
    let mut outages = subscription.outages.clone().into_iter().peekable();
    // The topics are fresh for each run, so `all` replays only this run's alerts.
    let mut since = Some("all".to_owned());
    let mut last_id: Option<String> = None;
    let mut acks = JoinSet::new();
    loop {
        let stop = match outages.peek() {
            Some(o) if start + Duration::from_millis(o.start_after_ms) < end => (
                start + Duration::from_millis(o.start_after_ms),
                StreamEnd::Outage,
            ),
            _ => (end, StreamEnd::TimeUp),
        };
        let stream = stream_until(
            &subscription,
            &client,
            &collector_url,
            since.as_deref(),
            &mut last_id,
            &mut acks,
            stop,
        )
        .await;
        match stream {
            StreamEnd::TimeUp => break,
            StreamEnd::Closed => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                since = last_id.clone().or(Some("all".to_owned()));
            }
            StreamEnd::Outage => {
                let Some(outage) = outages.next() else {
                    break;
                };
                let start_ms = now_ms();
                tokio::time::sleep(Duration::from_millis(outage.duration_ms)).await;
                println!(
                    "outage phone={} server={} start_ms={start_ms} end_ms={} mode={}",
                    subscription.phone,
                    subscription.server,
                    now_ms(),
                    if outage.lossy { "lossy" } else { "resume" }
                );
                since = if outage.lossy {
                    None
                } else {
                    last_id.clone().or(Some("all".to_owned()))
                };
            }
        }
        if Instant::now() >= end {
            break;
        }
    }
    while acks.join_next().await.is_some() {}
}

/// Reads the topic's JSON stream until the stop time or until the stream ends, acknowledging
/// each message. Reaching the stop time returns the paired reason.
async fn stream_until(
    subscription: &Subscription,
    client: &HttpClient,
    collector_url: &str,
    since: Option<&str>,
    last_id: &mut Option<String>,
    acks: &mut JoinSet<()>,
    (stop_at, stop_reason): (Instant, StreamEnd),
) -> StreamEnd {
    let mut url = format!("{}/json", subscription.topic_url);
    if let Some(since) = since {
        url.push_str(&format!("?since={since}"));
    }
    let connect = http::request(
        client,
        Method::GET,
        &url,
        subscription.token.as_deref(),
        String::new(),
    );
    let response = match tokio::time::timeout_at(stop_at, connect).await {
        Err(_) => return stop_reason,
        Ok(Err(e)) => {
            eprintln!(
                "event=subscribe-failed phone={} server={} error={e}",
                subscription.phone, subscription.server
            );
            return StreamEnd::Closed;
        }
        Ok(Ok(response)) if response.status() != StatusCode::OK => {
            eprintln!(
                "event=subscribe-refused phone={} server={} status={}",
                subscription.phone,
                subscription.server,
                response.status()
            );
            return StreamEnd::Closed;
        }
        Ok(Ok(response)) => response,
    };
    println!(
        "event=subscribed phone={} server={} since={}",
        subscription.phone,
        subscription.server,
        if since.is_some_and(|s| s != "all") {
            "last-id"
        } else {
            since.unwrap_or("none")
        }
    );
    let mut body = response.into_body();
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let frame = match tokio::time::timeout_at(stop_at, body.frame()).await {
            Err(_) => return stop_reason,
            Ok(None | Some(Err(_))) => return StreamEnd::Closed,
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buffer.extend_from_slice(&data);
        while let Some(newline) = buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=newline).collect();
            let Ok(event) = serde_json::from_slice::<serde_json::Value>(&line) else {
                continue;
            };
            if event["event"] != "message" {
                continue;
            }
            let (Some(id), Some(message)) = (event["id"].as_str(), event["message"].as_str())
            else {
                continue;
            };
            *last_id = Some(id.to_owned());
            acks.spawn(acknowledge(
                client.clone(),
                format!("{collector_url}/ack"),
                message.to_owned(),
                subscription.delay,
            ));
        }
    }
}

async fn acknowledge(client: HttpClient, url: String, message: String, delay: Delay) {
    tokio::time::sleep(delay.draw()).await;
    let url = format!("{url}?t={}", now_ms());
    for _ in 0..10 {
        let sent = http::request_to_end(&client, Method::POST, &url, None, message.clone()).await;
        if matches!(sent, Ok((status, _)) if status.is_success()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!("event=ack-failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outages_parse() {
        assert_eq!(
            Outage::parse("10000+6000:resume"),
            Ok(Outage {
                start_after_ms: 10_000,
                duration_ms: 6_000,
                lossy: false
            })
        );
        assert!(Outage::parse("10000+6000:lossy").unwrap().lossy);
        for bad in ["10000+6000", "10000:resume", "a+1:resume", "1+1:drop"] {
            assert!(Outage::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ranges_parse() {
        assert_eq!(parse_range("10-150"), Ok((10, 150)));
        assert!(parse_range("150-10").is_err());
        assert!(parse_range("150").is_err());
    }
}
