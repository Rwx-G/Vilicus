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

### Android emulator run (2026-10-17)

An emulator simulation, `criterion=simulation`: **not an E13 result**, and the story stays `in-progress`. It replaces the simulated phone with the real ntfy Android app on an Android 15 emulator and forces power and connectivity states while the unchanged sender posts alerts. Tooling and procedure: `spikes/push-delivery/android/` (README there).

**Commands**, from the repository root on the Windows development host (Git Bash, Docker Desktop): `bash spikes/push-delivery/android/run.sh --smoke` and `bash spikes/push-delivery/android/run.sh` (180 minutes of alerts). Not an `e2e/run.sh` phase: it needs KVM and runs for hours.

**Images and versions**, each pinned in `android/android.lock`:

| Piece | Version | Pin |
|---|---|---|
| Android emulator | 37.2.12 (build 16428233, stable channel) | SHA-256 `b08fc43d...` |
| platform-tools (adb) | 37.0.1 | SHA-256 `d230f138...` |
| System image | `system-images;android-35;google_apis;x86_64` r9, Android 15, `AE3A.240806.043`, userdebug | SHA-256 `c67b9ba0...` |
| ntfy Android app | 1.25.2 (version code 63), F-Droid build | SHA-256 `b4baa6f6...`, matching F-Droid's index; F-Droid signer `76e94d8e...` |
| ntfy server | 2.31.0 | the digest of `../compose` |
| Base image | `debian:trixie-slim` | the digest the other spikes use |

The SDK packages are under the Android Software Development Kit License Agreement (`android-sdk-license`, referenced by all three); building the image accepts it, and the lock records the SHA-1 of the accepted text. Emulator: headless, `-gpu swiftshader_indirect`, KVM, 4 cores, 4 GiB, fresh AVD per run, no Play Store, no Google account. The test network is internal: neither the emulator nor the servers reach the internet. Docker 29.8.2; on this host the `kvm_intel` module of Docker Desktop's VM had to be loaded once (`modprobe` through `nsenter`), it was not loaded after a restart.

**Setup**, checked by `run.sh`: APK checksum equal to the lock, ntfy 1.25.2 installed, `POST_NOTIFICATIONS` granted, the phone's read-only account stored in the app, one subscription with instant delivery and not muted (through an `ntfy://` link), the instant delivery foreground service running, battery optimisation exemption set (RUNBOOK step 6.4).

**Acknowledgement without MacroDroid.** A host-side observer polls `dumpsys notification --noredact` every second, takes the id from each ntfy notification, posts it to the collector's `/ack` with the notification's post time as `t=`, then snoozes it (Android caps active notifications per app). The collector's arrival time, which the report uses, therefore includes the observer's delay; the post time is the phone-reported column.

**Scenario** (default, scaled to 180 minutes; each disruptive segment followed by a baseline one): baseline (screen on, charging, exempt) 10 min; screen off and battery unplugged 12; deep Doze forced (`dumpsys deviceidle force-idle`) with the exemption 22, then without it 22, each with one maintenance window stepped halfway; standby buckets `working_set` 8, `frequent` 8, `rare` 10, `restricted` 14 (screen off, unplugged, not exempt); Wi-Fi and mobile data off 13 (longer than the deadline) and 4; ntfy force-stopped 8, then reopened; reboot 12. Mean interval 20 s, a Poisson schedule. The smoke mode runs every state once in 6 minutes at a 5 s mean. The scenario samples the device's actual state every minute; `pipeline.forced_states_observed_on_the_device` checks that the forced states took effect.

**Smoke run**: `RESULT PASS`, 24 `PASS`, 0 `FAIL`, about 20 minutes; 70 alerts, all delivered in time (p50 0.9 s, max 35.1 s, the latter in the network-off segment). The first smoke run and the first compressed run exposed emulator and tooling faults, fixed before the runs recorded here: the emulator's virtual Wi-Fi does not rejoin after a reboot (the first run then lost every alert after the reboot, none of them reaching the app), and a forced maintenance window could be stepped twice.

**Compressed run** (default mode, 15:45 to 18:56 UTC, 3 h 11 min): `RESULT PASS`, 24 `PASS`, 0 `FAIL`. 479 alerts, 471 in time, 8 late, 0 lost, 0 unpublished, no unknown or duplicate acknowledgement, every stored message content-free. Per state (latency to the collector's arrival, nearest rank; phone-reported is the median from send to the notification's post time):

| State | Alerts | In time (10 min) | Late | Lost | Rate | p50 / p90 / p99 / max (s) | Phone-reported p50 (s) |
|---|---|---|---|---|---|---|---|
| baseline | 124 | 124 | 0 | 0 | 100.00 % | 0.7 / 1.2 / 19.9 / 21.1 | 0.0 |
| screen-off-unplugged | 33 | 33 | 0 | 0 | 100.00 % | 0.7 / 1.1 / 1.2 / 1.2 | 0.0 |
| doze-exempt | 59 | 59 | 0 | 0 | 100.00 % | 0.7 / 1.1 / 1.2 / 1.2 | 0.0 |
| doze-not-exempt | 60 | 60 | 0 | 0 | 100.00 % | 0.8 / 1.1 / 1.2 / 1.2 | 0.0 |
| bucket-working_set | 25 | 25 | 0 | 0 | 100.00 % | 0.6 / 1.1 / 1.2 / 1.2 | 0.0 |
| bucket-frequent | 13 | 13 | 0 | 0 | 100.00 % | 0.9 / 1.1 / 1.1 / 1.1 | 0.0 |
| bucket-rare | 28 | 28 | 0 | 0 | 100.00 % | 0.8 / 1.2 / 1.2 / 1.2 | 0.0 |
| bucket-restricted | 30 | 30 | 0 | 0 | 100.00 % | 0.7 / 1.1 / 1.2 / 1.2 | 0.0 |
| network-off-long (13 min) | 35 | 27 | 8 | 0 | 77.14 % | 325.7 / 703.4 / 779.9 / 779.9 | 324.5 |
| network-off-short (4 min) | 18 | 18 | 0 | 0 | 100.00 % | 161.5 / 222.0 / 244.8 / 244.8 | 161.0 |
| app-force-stopped (8 min) | 18 | 18 | 0 | 0 | 100.00 % | 192.5 / 400.9 / 418.5 / 418.5 | 191.7 |
| reboot | 36 | 36 | 0 | 0 | 100.00 % | 0.7 / 2.0 / 11.8 / 11.8 | 0.0 |

The baseline tail (p99 19.9 s) is the alerts sent in the first seconds of a recovery segment, shown with the replay. Observer delay: notification post to observation p50 0.76 s, p99 10.4 s, max 21.1 s (the maxima at the bursts after a network restore or a reopen); observation to accepted acknowledgement p50 6 ms, p99 142 ms; app reception (logcat) to notification post p50 4 ms. An earlier 3 h run, made before the observer batched its snoozes, gave the same picture (517 alerts, 506 in time, 11 late, 0 lost) but serialised a burst's acknowledgements by about 1.2 s each, up to 39 s, which turned 5 alerts late that the notification's post time showed in time; it is not the recorded run.

**Findings.**

1. **Doze did not delay the ntfy app at all, exempt or not.** Every alert sent during forced deep Doze outside a maintenance window was shown while the device was still idle, 7 ms after its send at the median and 15 ms at most, by the notification's post time (57 of 57 exempt, 59 of 59 not exempt), so none waited for a maintenance window or for the exit. The app's instant delivery is a foreground service (`specialUse` type), and Android lets a process with a foreground service keep its network in Doze; the battery optimisation exemption made no difference on this image. The forced maintenance windows ended by themselves in less than 60 seconds.
2. **App standby buckets do not hold on the app.** A forced bucket (`working_set` to `restricted`) was in place at the first one-minute sample and gone at the next ones (1 of 8 to 14 samples per state): the system put the app back in `active`, consistent with its running foreground service. Delivery was unaffected in every bucket, including the first minute of `restricted`.
3. **A network loss costs late alerts, never lost ones.** After each outage the app reconnected with the last message id and the server replayed everything: 0 lost over both outages. Alerts sent in the first 3 minutes of the 13-minute outage were shown more than 10 minutes after their send (8 late, 602 to 779 s by the post time too); a 4-minute outage cost nothing. This is the run's only state below 99 %, and it is the deadline, not the channel, that it measures.
4. **A force-stopped app receives nothing until it is opened again**; then the replay delivered every alert of the stop (up to 418 s, bounded by the stop's 8 minutes). On a phone whose vendor force-stops background apps, this is how alerts would be delayed, and only reopening the app ends it; RUNBOOK step 6.4 (the exemption) is the defence the real run must record. One smoke run caught a narrower case: an alert read by the app in the same milliseconds as the force-stop was stored but never shown, and the app did not show it after the restart either.
5. **A reboot costs the boot time.** The app's boot receiver restarted the service and the replay delivered the alerts sent during the reboot (max 11.8 s, the boot took about 21 s), once the network was back.
6. **The distributor app keeps the alert text in three more places.** Besides the server's cache (finding 5 above), the ntfy app writes every message's body to logcat at debug level in its release build (`NtfySubscriberService: Received notification: ... message=...`), stores it in its database, and shows it in the notification. A token in the payload would be readable there too. Proposed as update 6.
7. **What the emulator cannot say.** No carrier network, no radio power states, no vendor battery management (the force-stops and restrictions real phones add on top of Doze), forced states reached by `dumpsys` rather than by hours of idleness, Wi-Fi rejoined by the scenario after it is turned back on or after a reboot, and 3 hours instead of 7 days. The household run remains the only E13 measurement.

## Proposed design document updates

Not applied: this spike does not edit shared design documents. Where a decision is needed it is written as "new decision record"; the number is assigned when it is added.

1. `doc/research-notes.md` section 3, E13 row, Method column: append "The sender posts each alert with a 128-bit one-time id at random times (a Poisson process, mean 30 minutes); on each phone the distributor app's message broadcast is posted back by an automation app, and the delay is measured to that acknowledgement's arrival at the collector, an upper bound of reception. A phone's result is complete only with at least 100 alerts spanning the 7 days and at least one night alert per day; otherwise it is reported incomplete, not passed. Tooling and procedure: `spikes/push-delivery/` and its `RUNBOOK.md` (Story 1.13)."
2. `doc/decisions.md`: add a new decision record, amending D75 and D118, and its row in the table. It needs the owner's decision; the recommended text: "Amends D75 and D118. Context: the E13 tooling (Story 1.13) showed that an ntfy-type server stores and serves the alert body, so a one-time acknowledgement token sent in the push payload is readable by the server's operator; and the design says how the Core reaches a self-hosted push server but not how a member's phone reaches it away from the household network. Decision: the push payload carries no redeemable token in clear on any server: the one-time token is shown and redeemed when the member opens the alert in a Vilicus client on a device they control, and the push carries only the generic text and an opaque reference that redeems nothing. A self-hosted push server must be reachable from members' phones off the household network, the way the household reaches Vilicus remotely, and the enrollment test notification is redeemed once over mobile data. Consequences: acknowledging an alert needs a signed-in Vilicus client; a self-hosted push server adds a remotely reachable service." The alternative to the first half, encrypting the payload to the member's device (RFC 8291), keeps a one-step acknowledgement but needs a Vilicus app as the UnifiedPush receiver, which V0.1 does not have.
3. `doc/architecture-spine.md` AD-32 rule: after "single use and rate limited;", add "the push payload never carries the token in clear, which is shown when the member opens the alert in a Vilicus client [new decision record];". After "reached through a named private destination (AD-16);", add "members' phones reach it off the household network the way they reach Vilicus remotely [new decision record];".
4. `doc/prd.md` FR-56, first consequence: after "On a public server, the topic uses an access token or a random name of at least 128 bits.", add "On any server, the push payload carries no redeemable acknowledgement token in clear, and a self-hosted server is reachable from members' phones off the household network [new decision record]."
5. `doc/architecture.md`, out-of-browser notification channel paragraph: after "On any push server, the payload carries one generic text per severity (spine AD-32).", add "It carries no redeemable acknowledgement token in clear; the token is shown when the member opens the alert in a Vilicus client [new decision record]."
6. `doc/decisions.md`, D135 (Proposed), Context: after "is readable by the server's operator,", add "and the Android emulator run (story 1.13) showed that the ntfy app, the V0.1 distributor, also writes every message body to logcat in its release build, stores it in its database and shows it in the notification, so a token in the payload is readable on the device by anything that can read those,". This strengthens the first half of D135 and changes neither its decision nor D118: on the emulator, Doze, standby buckets and reboots did not delay the self-hosted server's delivery through the ntfy app, so nothing in this run argues for revisiting D118's default. The owner decides D135 as before.
7. `doc/research-notes.md` section 3, E13 row, Result column: after "the 7-day run on the household's phones has not started.", add "An Android 15 emulator run with the ntfy app 1.25.2 (story 1.13, `spikes/push-delivery/android/`, 3 hours, forced states, `criterion=simulation`, not an E13 result) delivered every alert sent under Doze, standby buckets, screen off and reboot within seconds and lost none; outages delayed alerts by the outage's length, so only an outage longer than 10 minutes made alerts late, and a force-stopped app received nothing until reopened."
