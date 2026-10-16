//! `push-delivery`: the E13 measurement tool. See `RUNBOOK.md` for the real run and `run.sh`
//! for the simulated one.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use hyper::{Method, StatusCode};
use push_delivery::config::Config;
use push_delivery::payload::audit_ntfy_message;
use push_delivery::phone_sim::{self, Delay, Outage, Subscription, parse_range};
use push_delivery::records::{PhoneLabel, read_records};
use push_delivery::{http, now_ms, report, sender, token};

const USAGE: &str = "\
usage:
  push-delivery run --config <file> [--duration-ms <n>]
  push-delivery probe --config <file> [--phone <phone-n>] [--wait-ms <n>]
  push-delivery report --config <file> [--at-ms <n>] [--explain]
  push-delivery new-topic
  push-delivery new-ntfy-token
  push-delivery audit-cache --url <topic url> [--token <value|env:NAME>] [--expect <n>]
  push-delivery phone-sim --phone <phone-n> --collector <url> --duration-ms <n>
      --subscribe <server>,<base url>,<topic>,<token|->,<delay low-high>,<slow per mille>,<slow low-high>[,<start+duration:resume|lossy>...]
";

struct Args(Vec<String>);

impl Args {
    /// Removes `--name <value>` and returns the value; `--name` given twice keeps the first.
    fn value(&mut self, name: &str) -> Result<Option<String>, String> {
        match self.0.iter().position(|a| a == name) {
            None => Ok(None),
            Some(i) if i + 1 < self.0.len() => {
                let value = self.0.remove(i + 1);
                self.0.remove(i);
                Ok(Some(value))
            }
            Some(_) => Err(format!("{name} needs a value")),
        }
    }

    fn values(&mut self, name: &str) -> Result<Vec<String>, String> {
        let mut values = Vec::new();
        while let Some(value) = self.value(name)? {
            values.push(value);
        }
        Ok(values)
    }

    fn required(&mut self, name: &str) -> Result<String, String> {
        self.value(name)?
            .ok_or_else(|| format!("{name} is required"))
    }

    fn flag(&mut self, name: &str) -> bool {
        match self.0.iter().position(|a| a == name) {
            Some(i) => {
                self.0.remove(i);
                true
            }
            None => false,
        }
    }

    fn number(&mut self, name: &str) -> Result<Option<u64>, String> {
        self.value(name)?
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("{name}: `{v}` is not a number"))
            })
            .transpose()
    }

    fn done(self) -> Result<(), String> {
        match self.0.first() {
            None => Ok(()),
            Some(extra) => Err(format!("unexpected argument `{extra}`")),
        }
    }
}

fn resolve(value: &str) -> Result<String, String> {
    match value.strip_prefix("env:") {
        Some(name) => {
            std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))
        }
        None => Ok(value.to_owned()),
    }
}

fn load_config(args: &mut Args) -> Result<Config, String> {
    Config::load(&PathBuf::from(args.required("--config")?))
}

fn parse_subscription(phone: &PhoneLabel, text: &str) -> Result<Subscription, String> {
    let fields: Vec<&str> = text.split(',').collect();
    let [
        server,
        base_url,
        topic,
        token,
        delay,
        slow_per_mille,
        slow,
        outages @ ..,
    ] = fields.as_slice()
    else {
        return Err(format!("subscription `{text}` has too few fields"));
    };
    Ok(Subscription {
        phone: phone.clone(),
        server: server.parse()?,
        topic_url: format!("{}/{}", base_url.trim_end_matches('/'), resolve(topic)?),
        token: match *token {
            "-" => None,
            value => Some(resolve(value)?),
        },
        delay: Delay {
            normal_ms: parse_range(delay)?,
            slow_per_mille: slow_per_mille
                .parse()
                .map_err(|_| format!("`{slow_per_mille}` is not a per mille"))?,
            slow_ms: parse_range(slow)?,
        },
        outages: outages
            .iter()
            .map(|o| Outage::parse(o))
            .collect::<Result<_, _>>()?,
    })
}

async fn audit_cache(url: &str, token: Option<&str>, expect: Option<u64>) -> Result<bool, String> {
    let client = http::client(None)?;
    let poll = format!("{url}/json?poll=1&since=all");
    let (status, body) =
        http::request_to_end(&client, Method::GET, &poll, token, String::new()).await?;
    if status != StatusCode::OK {
        return Err(format!("poll answered {status}"));
    }
    let text = String::from_utf8_lossy(&body);
    let mut messages = 0u64;
    let mut content_free = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let message: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("poll line is not JSON: {e}"))?;
        messages += 1;
        match audit_ntfy_message(&message) {
            Ok(()) => content_free += 1,
            Err(reason) => println!("audit refused={reason}"),
        }
    }
    println!("audit messages={messages} content_free={content_free}");
    Ok(messages == content_free && messages > 0 && expect.is_none_or(|n| n == messages))
}

async fn dispatch(mut args: Args) -> Result<bool, String> {
    if args.0.is_empty() {
        return Err("no command".to_owned());
    }
    let command = args.0.remove(0);
    match command.as_str() {
        "run" => {
            let config = load_config(&mut args)?;
            let duration = args.number("--duration-ms")?.map(Duration::from_millis);
            args.done()?;
            sender::run(&config, duration).await?;
            Ok(true)
        }
        "probe" => {
            let config = load_config(&mut args)?;
            let phone: Option<PhoneLabel> =
                args.value("--phone")?.map(|p| p.parse()).transpose()?;
            let wait = Duration::from_millis(args.number("--wait-ms")?.unwrap_or(60_000));
            args.done()?;
            sender::probe(&config, phone.as_ref(), wait).await
        }
        "report" => {
            let config = load_config(&mut args)?;
            let at_ms = args.number("--at-ms")?.unwrap_or_else(now_ms);
            let explain = args.flag("--explain");
            args.done()?;
            let records = read_records(&config.results)?;
            let targets: Vec<_> = config
                .targets
                .iter()
                .map(|t| (t.phone.clone(), t.server))
                .collect();
            let report = report::compute(&targets, &records, config.criterion, config.night, at_ms);
            if explain {
                for target in &report.targets {
                    print!("{}", report::explain(target));
                }
            }
            println!("{report}");
            Ok(true)
        }
        "new-topic" => {
            args.done()?;
            println!("{}", token::new_topic());
            Ok(true)
        }
        "new-ntfy-token" => {
            args.done()?;
            println!("{}", token::new_ntfy_token());
            Ok(true)
        }
        "audit-cache" => {
            let url = args.required("--url")?;
            let token = args.value("--token")?.map(|t| resolve(&t)).transpose()?;
            let expect = args.number("--expect")?;
            args.done()?;
            audit_cache(&url, token.as_deref(), expect).await
        }
        "phone-sim" => {
            let phone: PhoneLabel = args.required("--phone")?.parse()?;
            let collector = args.required("--collector")?;
            let duration = Duration::from_millis(
                args.number("--duration-ms")?
                    .ok_or("--duration-ms is required")?,
            );
            let subscriptions = args
                .values("--subscribe")?
                .iter()
                .map(|s| parse_subscription(&phone, s))
                .collect::<Result<Vec<_>, _>>()?;
            args.done()?;
            if subscriptions.is_empty() {
                return Err("phone-sim needs at least one --subscribe".to_owned());
            }
            phone_sim::run(
                subscriptions,
                collector.trim_end_matches('/').to_owned(),
                duration,
            )
            .await;
            Ok(true)
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args(std::env::args().skip(1).collect());
    match dispatch(args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
