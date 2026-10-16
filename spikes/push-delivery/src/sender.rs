//! The measurement run and the setup probe.
//!
//! The run sends alerts to every configured phone and server at random times (a Poisson process
//! per target, so nights get alerts like days), records each send and each acknowledgement in
//! the results file, and stops after the requested duration, then waits one deadline for late
//! acknowledgements. The probe sends one alert per target and waits for its acknowledgement,
//! the shape of the D105 test notification, without touching the results file.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::collector::{self, AckSink};
use crate::config::{Config, Target};
use crate::http::{self, HttpClient};
use crate::now_ms;
use crate::records::{AckRecord, PhoneLabel, Record, ResultsLog, SendRecord};
use crate::token::{exponential_gap_ms, new_alert_id};

async fn bind(config: &Config) -> Result<TcpListener, String> {
    TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", config.listen))
}

/// Runs the measurement for `duration`, or until Ctrl-C when `duration` is `None`.
pub async fn run(config: &Config, duration: Option<Duration>) -> Result<(), String> {
    let log = Arc::new(ResultsLog::open(&config.results)?);
    let listener = bind(config).await?;
    let ack_log = Arc::clone(&log);
    let sink: AckSink = Arc::new(move |ack| {
        if let Err(e) = ack_log.append(&Record::Ack(ack)) {
            eprintln!("event=record-failed error={e}");
        }
    });
    let collector = tokio::spawn(collector::serve(listener, sink));
    let client = http::client(config.ca_file.as_deref())?;
    let (stop, stopped) = watch::channel(false);
    let mut senders = JoinSet::new();
    for target in &config.targets {
        senders.spawn(send_loop(
            target.clone(),
            client.clone(),
            Arc::clone(&log),
            config.mean_interval_ms,
            stopped.clone(),
        ));
    }
    println!(
        "event=ready targets={} listen={}",
        config.targets.len(),
        config.listen
    );
    match duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => tokio::signal::ctrl_c()
            .await
            .map_err(|e| format!("cannot wait for Ctrl-C: {e}"))?,
    }
    // Ignored error: every receiver may already be gone if all senders ended.
    let _ = stop.send(true);
    while senders.join_next().await.is_some() {}
    println!(
        "event=sending-stopped waiting_ms={}",
        config.criterion.deadline_ms
    );
    tokio::time::sleep(Duration::from_millis(config.criterion.deadline_ms)).await;
    collector.abort();
    println!("event=done");
    Ok(())
}

async fn send_loop(
    target: Target,
    client: HttpClient,
    log: Arc<ResultsLog>,
    mean_interval_ms: u64,
    mut stopped: watch::Receiver<bool>,
) {
    let target = Arc::new(target);
    let mut in_flight = JoinSet::new();
    loop {
        let gap = Duration::from_millis(exponential_gap_ms(mean_interval_ms));
        tokio::select! {
            () = tokio::time::sleep(gap) => {}
            _ = stopped.changed() => break,
        }
        let id = new_alert_id();
        let sent_ms = now_ms();
        let (target, client, log) = (Arc::clone(&target), client.clone(), Arc::clone(&log));
        // Publishes run concurrently so that a slow server does not shift the schedule.
        in_flight.spawn(async move {
            let published = http::publish(&client, &target, &id).await;
            if let Err(e) = &published {
                eprintln!(
                    "event=publish-failed phone={} server={} error={e}",
                    target.phone, target.server
                );
            }
            let record = Record::Send(SendRecord {
                id,
                phone: target.phone.clone(),
                server: target.server,
                sent_ms,
                published: published.is_ok(),
            });
            if let Err(e) = log.append(&record) {
                eprintln!("event=record-failed error={e}");
            }
        });
    }
    while in_flight.join_next().await.is_some() {}
}

/// Sends one alert to each target of `phone` (every target when `None`) and waits up to `wait`
/// for the acknowledgements. Prints one line per target; returns whether all were acknowledged.
pub async fn probe(
    config: &Config,
    phone: Option<&PhoneLabel>,
    wait: Duration,
) -> Result<bool, String> {
    let targets: Vec<&Target> = config
        .targets
        .iter()
        .filter(|t| phone.is_none_or(|p| &t.phone == p))
        .collect();
    if targets.is_empty() {
        return Err("no configured target matches".to_owned());
    }
    let listener = bind(config).await?;
    let (acks, mut received) = mpsc::unbounded_channel::<AckRecord>();
    let sink: AckSink = Arc::new(move |ack| {
        // Ignored error: the probe has stopped listening once its wait is over.
        let _ = acks.send(ack);
    });
    let collector = tokio::spawn(collector::serve(listener, sink));
    let client = http::client(config.ca_file.as_deref())?;

    let mut waiting: HashMap<String, (&Target, u64)> = HashMap::new();
    let mut all_ok = true;
    for target in targets {
        let id = new_alert_id();
        let sent_ms = now_ms();
        match http::publish(&client, target, &id).await {
            Ok(()) => {
                waiting.insert(id, (target, sent_ms));
            }
            Err(e) => {
                all_ok = false;
                println!(
                    "probe phone={} server={} published=no acknowledged=no error={e}",
                    target.phone, target.server
                );
            }
        }
    }
    let deadline = tokio::time::Instant::now() + wait;
    while !waiting.is_empty() {
        match tokio::time::timeout_at(deadline, received.recv()).await {
            Ok(Some(ack)) => {
                if let Some((target, sent_ms)) = waiting.remove(&ack.id) {
                    println!(
                        "probe phone={} server={} published=yes acknowledged=yes latency_ms={}",
                        target.phone,
                        target.server,
                        ack.arrival_ms.saturating_sub(sent_ms)
                    );
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    for (target, _) in waiting.values() {
        all_ok = false;
        println!(
            "probe phone={} server={} published=yes acknowledged=no",
            target.phone, target.server
        );
    }
    collector.abort();
    Ok(all_ok)
}
