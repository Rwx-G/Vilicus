---
title: 'E13: push delivery reliability'
epic: 1
story: 13
status: 'in-progress'
author: Rwx-G
created: 2026-10-16
implements: [E13, FR-56, D105, D118, AD-32]
---

# Story 1.13: E13: push delivery reliability

As the owner,
I want content-free push alerts measured on each household phone for a week,
So that the veto window and the recovery alerts rest on a channel that actually delivers.

**Acceptance Criteria:**

**AC1 (E13, FR-56, AD-32, D118)**
**Given** a sender under `spikes/e13-push/` posting content-free alerts (one generic text, no title, sender or detail) through the push webhook to two UnifiedPush servers of the ntfy type: the default self-hosted server, reached through a named private destination (D105), and a public server, each with a topic protected by an access token or a random name of at least 128 bits
**When** it sends alerts at random times, idle nights included, to each household phone for 7 days on each server, and each phone records the reception time
**Then** the delivery delay of every alert is recorded per phone and per server, labelled only as self-hosted or public, without any phone model or server name in the record

**AC2 (E13, D105)**
**Given** the recorded delays
**When** they are evaluated per phone
**Then** a server passes only if 99 % of alerts were delivered within 10 minutes over the 7 days on every phone, and the result is recorded for each server; E13 as a whole passes when the default self-hosted server passes, and a public server below the threshold is documented as not recommended without failing E13

**AC3 (E13, D105)**
**Given** a phone falls below the threshold
**When** the result is recorded
**Then** the fallback is recorded in `doc/decisions.md`: a second push distributor within the same webhook transport, plus the maximum waits of FR-56; polling is never the only path

**Spike plan:**
- Question: is a persistent connection or UnifiedPush reliable enough for content-free notifications on Android (E13)?
- Method: content-free alerts through the push webhook to each household phone for 7 days, idle nights included, on the default self-hosted UnifiedPush server and on a public server (D118).
- Pass criterion: 99 % of alerts delivered within 10 minutes over 7 days per phone (D105).
- Timebox: 2 working days of setup plus 7 days of observation.
- Fallback on failure: a second push distributor within the same webhook transport, plus the maximum waits of FR-56; never polling as the only path.
- Result record: E13 status in `doc/research-notes.md` with per-phone delivery rates under anonymous labels.
- Push server: settled by D118 (PRD open question 8, resolved): a self-hosted server by default, a public one when the household chooses it; a public server sees only delivery timing metadata. No phone model or server name is written in the results.

**Dependencies:**
- None.

**References:**
- `doc/research-notes.md` section 3 (E13)
- `doc/prd.md` FR-56, section 9, section 11 (open question 8, resolved)
- `doc/decisions.md` D105, D118
- `doc/architecture-spine.md` AD-32

## Implementation Notes

**What was built.** Everything the real run needs except the phones and the 7 days, plus a simulated end-to-end check of the whole pipeline.

- Location: the story names `spikes/e13-push/`; the spike lives in `spikes/push-delivery/`, as the epic's spike instructions asked. It is a standalone crate (its own empty `[workspace]`, edition 2024, Apache-2.0, `publish = false`).
- `push-delivery run`: one sender per phone and server kind posts content-free alerts at random times (a Poisson process with a configurable mean interval, 30 minutes for the real run, so nights get as many alerts as days), and an acknowledgement collector receives the ids back. Both append to a results file. The run stops after the given duration and waits one deadline for late acknowledgements.
- `push-delivery probe`: one alert per target and a wait for its acknowledgement, the shape of the D105 test notification, used to check each phone before the run; it writes nothing to the results.
- `push-delivery report [--explain]`: per phone and server, the alerts evaluated, in time, late, missing and unpublished, the in-time rate, latency percentiles (p50, p90, p99, max) and a cumulative distribution, night coverage, time coverage and largest gap, duplicate acknowledgements and the phone-reported median delay; then a verdict per phone, per server, and for E13.
- `push-delivery phone-sim`: a simulated phone that subscribes like the ntfy app in instant-delivery mode (a long-lived JSON stream, `since=<last id>` on reconnect) and acknowledges each alert, with injected processing delays, a share of slow (doze-like) acknowledgements, resumed outages and lossy outages.
- `push-delivery audit-cache`: reads back every message a server stored for a topic and refuses any that is not exactly the generic text and one id, or that carries any field beyond id, times, event, topic and body.
- `compose/`: the test network, with two ntfy 2.31.0 servers pinned by digest (the self-hosted default and a stand-in for a public one), the sender and collector, and two simulated phones. `run.sh` drives it; `RUNBOOK.md` gives the steps of the real run.

**Payload and acknowledgement.**

- The body is `Vilicus security alert. ref <id>`, the id being 128 random bits in hex. The publish request sets no title, tags, priority, click URL, icon, actions or attachment; the pipeline test checks the headers sent, and `audit-cache` checks what each server stored.
- On a real phone, the ntfy app broadcasts `io.heckel.ntfy.MESSAGE_RECEIVED` with the message text for every message (ntfy documentation, "Automation apps"); a MacroDroid macro posts the text to the collector, which extracts the id. A page opened from the notification was rejected: it needs a tap, so it would measure the person, not the channel, and a click URL would also show the collector's address to a public server.
- The delay that counts runs from the send to the acknowledgement's arrival at the collector, an upper bound of reception, so a pass is never overstated. The phone's own time (`?t=`) is recorded for information only, because phone clocks are not trusted for the verdict.

**Anonymity (AC1).** A record holds an alert id, a label that must be `phone-<1..99>`, a server kind that must be `self-hosted` or `public`, times and the publish outcome. The record types cannot hold a URL, a topic, a token, a model or a server name, and the configuration refuses any other label.

**Topic protection (AD-32, D118).** On the simulated self-hosted server, `auth-default-access` is `deny-all` and the accounts are declared at start: the sender may only write the phone topics, and each phone may only read its own. The public stand-in has no accounts; its topics are 128-bit random names. The configuration refuses a topic without a token unless it has the 128-bit random shape.

**Verdict rules.**

- An alert is evaluated once its deadline has passed at the report time; before that it is pending. In time means acknowledged within the deadline, the deadline included. Late, missing and unpublished alerts count as not delivered. The first acknowledgement of an id counts; later ones are counted as duplicates.
- A phone and server pass when at least 99.00 % of evaluated alerts were in time (integer arithmetic, no rounding up), provided the result is complete: at least 100 evaluated alerts (a spike choice: below that, one miss cannot be told from a pass), evaluated alerts spanning the whole window, and at least one night alert per full day of the window. Otherwise the verdict is `INCOMPLETE`, never a pass.
- A server passes when every phone on it passes, fails when any fails, and is otherwise incomplete. E13 follows the self-hosted server (D118); a public server that fails is reported `status=not-recommended`.
- A report computed with any criterion other than D105's labels every verdict line `criterion=simulation` and adds "this is not an E13 result".

**Simulation parameters.** Deadline 3 s, window 40 s, mean interval 300 ms, run 45 s, minimum 100 alerts per target. Phone 1: delays of 10 to 150 ms and one 1.5 s outage per connection, resumed from its last id. Phone 2: on the self-hosted server, 5 % of acknowledgements delayed 1 to 2 s; on the public stand-in, a 6 s outage resumed from its last id (alerts later than the deadline) and a 4 s outage reconnected without it (lost alerts).

**Dependencies.** None reaches the product; all are spike-only. The spine pins tokio, hyper and rustls; the others are new.

| Crate | Version | Why |
|---|---|---|
| tokio | 1.53.2 | Runtime; the spine's pin |
| hyper | 1.12.0 | HTTP server (collector) and client (push webhook, phone stream); the spine's HTTP layer, used without axum because the collector has two routes |
| hyper-util, http-body-util, bytes | 0.1.21, 0.1, 1 | hyper's tokio glue, pooled client and bodies |
| hyper-rustls, rustls (aws-lc-rs), rustls-pki-types, webpki-roots | 0.27.10, 0.23.45, 1.12, 1 | HTTPS to a public server or to a self-hosted one behind TLS, with an optional household CA file; rustls with aws-lc-rs is the spine's TLS stack |
| serde_json | 1.0.154 | The ntfy JSON stream and poll answers, read untyped so that the audit refuses unknown fields |
| getrandom | 0.3.4 | 128-bit ids and topics, and the random schedule, from the OS source |

No database crate: the results are an append-only tab-separated file, synced after each line, which the owner can read with any tool. That is the smallest choice that survives a restart. `Cargo.lock` also carries getrandom 0.2.17 and 0.4.3, pulled by dependencies.

**Not in scope here.** The egress proxy and the named private destination (D105) were tested by E14 (Story 1.12); the sender here posts directly. UnifiedPush delivery to a Vilicus Android app (after V0.1) and payload encryption (RFC 8291) are not measured: in V0.1 the alert is shown by the distributor app itself, which is what the run measures.

## Result

Command, from the repository root on any host with Docker (Git Bash on Windows works): `bash spikes/push-delivery/run.sh`. It takes about 80 seconds after the first image build.

Run on 2026-10-16: exit code 0, `RESULT PASS`, 78 `PASS` lines and no `FAIL` line:

- 4 cargo gates: `fmt`, `clippy` (`--all-targets -- -D warnings`), `build_tests`, and `test_count` (37 passed, 0 ignored, 37 expected);
- 37 test functions (unit tests, the verdict rules on synthetic weeks of records, and the sender, collector, probe and results file against a mock push server);
- 37 network checks: `network_ready`, 7 `access.*`, 3 `run.*`, 11 `ac1.*`, 10 `ac2.*` and 5 `faults.*`.

Versions: rustc 1.99.1, ntfy 2.31.0, tokio 1.53.2, hyper 1.12.0, rustls 0.23.45, Docker 29.8.2. `shellcheck` is clean on `run.sh`.

The simulated report of that run (criterion `simulation`, not an E13 result):

| Phone | Server | Evaluated | In time | Late | Missing | Rate | p50 / p99 / max (ms) | Verdict |
|---|---|---|---|---|---|---|---|---|
| phone-1 | self-hosted | 144 | 144 | 0 | 0 | 100.00 % | 74 / 1119 / 1551 | PASS |
| phone-1 | public | 151 | 151 | 0 | 0 | 100.00 % | 85 / 1346 / 1388 | PASS |
| phone-2 | self-hosted | 167 | 167 | 0 | 0 | 100.00 % | 80 / 1716 / 1795 | PASS |
| phone-2 | public | 158 | 137 | 12 | 9 | 86.70 % | 89 / 5794 / 5803 | FAIL |

Server lines: self-hosted `PASS`, public `FAIL status=not-recommended`; `e13 verdict=PASS self_hosted=PASS public=FAIL criterion=simulation`. No unknown acknowledgement.

A fault was injected once and reverted: giving phone 1 a 5 s lossy outage on the self-hosted server made `run.sh` print `FAIL ac2.phone-1.self-hosted.all_in_time`, `FAIL ac2.server.self-hosted.pass`, `FAIL ac2.e13_follows_the_self_hosted_server` and `FAIL faults.only_phone-2_public_has_alerts_not_in_time`, report `e13 verdict=FAIL self_hosted=FAIL`, print `RESULT FAIL` and exit 1.

**Findings.**

1. **The pipeline and the statistics hold end to end.** Every late or missing alert of the run was sent during an injected outage of that connection (late ones in a resumed outage, missing ones in a lossy one, with a 1 s margin for alerts in flight), and no other connection had any (`faults.*`). Every message both servers stored was the generic text and one id, and their counts matched the published alerts (`ac1.*.every_stored_message_content_free`). The results file held only ids, labels, kinds and times, and none of the topics, tokens, URLs or server names (`ac1.results_*`).
2. **Whether an outage costs late alerts or lost ones depends on the distributor.** Reconnecting with the last message id made the server replay what the phone missed: a 1.5 s outage cost nothing, and a 6 s outage only made the alerts sent in its first seconds late. Reconnecting without it lost every alert of the outage. The real run shows which way the ntfy app behaves after a long loss of signal; `--explain` tells late from missing.
3. **Duplicate acknowledgements happen.** Each run counted a few per connection (0 to 6), on connections with and without outages. Their cause was not isolated: a replay on reconnect or a retried acknowledgement. The first arrival counts and the verdict is unaffected; for the product it confirms that the D75 token must be single use, as AD-32 already states.
4. **ntfy's access control gives what AD-32 asks.** With `deny-all` and declared accounts, an anonymous read or publish, a phone publishing, a phone reading another phone's topic, the sender reading, and an unknown token were all refused, and the phone read its own topic (`access.*`).
5. **A push server stores the alert text, so a public one would see a token sent in clear.** The audit read every message back from the public stand-in's cache. If the product's push payload carried the D75 one-time token the way this spike carries its id, a public server's operator could read and redeem it, which AD-32's "sees only delivery timing metadata" does not allow. Proposed as update 2.
6. **Phones must reach the self-hosted server away from home.** The design states how the Core reaches the self-hosted server (a named private destination) but not how a phone does once it leaves the household network. A run made only at home would overstate E13; `RUNBOOK.md` requires reaching the server and the collector over mobile data before the run starts. Proposed as update 2.
7. **The acknowledgement path is part of the measurement.** On a real phone the delay includes the automation app's HTTP request, so a phone can fail on its acknowledgement path rather than on the push. The report gives an upper bound; `RUNBOOK.md` step 9 says how to tell the two apart.
8. **Sample size.** At a 30-minute mean, a phone gets about 336 alerts per server over 7 days, so 99 % allows 3 misses. The spike adds completeness conditions (at least 100 alerts, the whole window, one night alert per full day) so that a short or sparse run is reported `INCOMPLETE`, never `PASS`. Proposed as update 1.

**Not run here.** The measurement itself needs the household's Android phones for 7 days; it was not run, and no E13 result exists yet. Procedure: `spikes/push-delivery/RUNBOOK.md`. Every verdict in this section was computed with simulation parameters and is labelled so.

| Criterion | Result | Evidence |
|---|---|---|
| AC1 (E13, FR-56, AD-32, D118): alerts at random times, idle nights included, to each phone for 7 days on both servers; delay recorded per phone and per server under anonymous labels | **Not run here: needs the household phones for 7 days** | Tooling proven on the simulated network: random sends on both server kinds, delays recorded per phone and server (`ac1.four_targets_reported`, `ac1.*.at_least_100_alerts_evaluated_none_pending`), results limited to ids, anonymous labels, kinds and times (`ac1.results_lines_hold_only_ids_labels_kinds_and_times`, `ac1.results_hold_no_topic_token_url_or_server_name`), content-free payloads as stored by each server (`ac1.*.every_stored_message_content_free`), topic protection (`access.*`). Night coverage is computed and required by the verdict (`test.a_short_or_sparse_or_nightless_run_is_incomplete_not_passed`); the 45 s simulation has no night. |
| AC2 (E13, D105): a server passes only at 99 % within 10 minutes over 7 days on every phone; E13 passes when the self-hosted server passes; a public server below the threshold is not recommended | **Not run here: needs the household phones for 7 days** | Verdict rules proven: at 400 alerts, 4 misses pass and 5 fail (`test.exactly_99_percent_passes_and_one_less_fails`); late and unpublished alerts are not delivered (`test.late_and_unpublished_alerts_are_not_delivered`); one failing phone fails its server, and E13 follows the self-hosted server either way (`test.a_failing_phone_fails_its_server_and_e13_follows_the_self_hosted_server`); end to end with simulation parameters, `ac2.server.self-hosted.pass`, `ac2.server.public.fail_not_recommended` and `ac2.e13_follows_the_self_hosted_server`, plus the injected fault above for the failing case. |
| AC3 (E13, D105): a phone below the threshold records the fallback in `doc/decisions.md` | **Not run here: needs the household phones for 7 days** | No phone was measured, so no fallback is due. `RUNBOOK.md` step 10 states when and what to record. |

## Proposed design document updates

Not applied: this spike does not edit shared design documents. Where a decision is needed it is written as "new decision record"; the number is assigned when it is added.

1. `doc/research-notes.md` section 3, E13 row, Method column: append "The sender posts each alert with a 128-bit one-time id at random times (a Poisson process, mean 30 minutes); on each phone the distributor app's message broadcast is posted back by an automation app, and the delay is measured to that acknowledgement's arrival at the collector, an upper bound of reception. A phone's result is complete only with at least 100 alerts spanning the 7 days and at least one night alert per day; otherwise it is reported incomplete, not passed. Tooling and procedure: `spikes/push-delivery/` and its `RUNBOOK.md` (Story 1.13)."
2. `doc/decisions.md`: add a new decision record, amending D75 and D118, and its row in the table. It needs the owner's decision; the recommended text: "Amends D75 and D118. Context: the E13 tooling (Story 1.13) showed that an ntfy-type server stores and serves the alert body, so a one-time acknowledgement token sent in the push payload is readable by the server's operator; and the design says how the Core reaches a self-hosted push server but not how a member's phone reaches it away from the household network. Decision: the push payload carries no redeemable token in clear on any server: the one-time token is shown and redeemed when the member opens the alert in a Vilicus client on a device they control, and the push carries only the generic text and an opaque reference that redeems nothing. A self-hosted push server must be reachable from members' phones off the household network, the way the household reaches Vilicus remotely, and the enrollment test notification is redeemed once over mobile data. Consequences: acknowledging an alert needs a signed-in Vilicus client; a self-hosted push server adds a remotely reachable service." The alternative to the first half, encrypting the payload to the member's device (RFC 8291), keeps a one-step acknowledgement but needs a Vilicus app as the UnifiedPush receiver, which V0.1 does not have.
3. `doc/architecture-spine.md` AD-32 rule: after "single use and rate limited;", add "the push payload never carries the token in clear, which is shown when the member opens the alert in a Vilicus client [new decision record];". After "reached through a named private destination (AD-16);", add "members' phones reach it off the household network the way they reach Vilicus remotely [new decision record];".
4. `doc/prd.md` FR-56, first consequence: after "On a public server, the topic uses an access token or a random name of at least 128 bits.", add "On any server, the push payload carries no redeemable acknowledgement token in clear, and a self-hosted server is reachable from members' phones off the household network [new decision record]."
5. `doc/architecture.md`, out-of-browser notification channel paragraph: after "On any push server, the payload carries one generic text per severity (spine AD-32).", add "It carries no redeemable acknowledgement token in clear; the token is shown when the member opens the alert in a Vilicus client [new decision record]."
