---
title: 'E13 emulator run: the ntfy Android app under forced power states'
author: Rwx-G
story: doc/stories/story-1.13-e13-push-delivery-reliability.md
---

# E13 emulator run

The real ntfy Android app on an Android 15 emulator, driven through Docker, receiving the
content-free alerts of the existing sender (`../src/sender.rs`) from the self-hosted ntfy server
while a scenario forces power and connectivity states. It sits between the simulated run
(`../run.sh`, simulated phones) and the real run (`../RUNBOOK.md`, the household phones for 7
days). Every figure it produces is labelled `criterion=simulation`; it never yields an E13
result.

## Commands

From the repository root, on a host with Docker and `/dev/kvm` passable to a container (Git Bash
on Windows works):

```sh
bash spikes/push-delivery/android/run.sh --smoke                 # every state once, about 20 minutes
bash spikes/push-delivery/android/run.sh                         # compressed run, 180 minutes of alerts, about 3 h 10
bash spikes/push-delivery/android/run.sh --duration-min 60       # the same profile scaled to 60 minutes
bash spikes/push-delivery/android/run.sh --save-dir /tmp/e13-run # also keep the results, timeline, observer log and reports
```

Both modes wait one deadline (10 minutes) after the last alert for late acknowledgements. The
script prints `PASS`/`FAIL` lines, the report of the whole run, the per-state table, and
`RESULT PASS|FAIL`; it exits non-zero only when the pipeline fails. A forced state delivering
below 99 % is a recorded result, not a failure. It is not an `e2e/run.sh` phase: it needs KVM and
runs for hours.

On Docker Desktop with the WSL2 backend, KVM is a module of the Docker VM's kernel that may not be
loaded after a restart of Docker Desktop; `android.kvm_available` fails and prints the command
that loads it. The first build downloads about 2.1 GB and produces an image of about 7.3 GB.

## What it builds

- `Dockerfile`: Debian 13 (pinned by digest) with the Android emulator, platform-tools, the
  `system-images;android-35;google_apis;x86_64` image and the ntfy app APK, each pinned by SHA-256
  in `android.lock`. Headless (`-no-window -no-audio -no-boot-anim`), `-gpu swiftshader_indirect`,
  KVM, 4 cores, 4 GiB, a fresh AVD (`avd/`) and no snapshot on every start.
- `compose.yaml`: an internal network (no route to the internet) with the self-hosted ntfy server
  (`deny-all`, write-only sender, read-only phone account), the sender and collector, and the
  emulator.
- `scenario.py setup`: installs the APK, grants `POST_NOTIFICATIONS`, stores the phone's account
  in the app's database (as the app's own user), subscribes with an `ntfy://` link (instant
  delivery; the F-Droid build has no other mode), and exempts the app from battery optimisation as
  RUNBOOK step 6 asks.
- `observer.py`: stands in for MacroDroid. Polls `dumpsys notification --noredact` every second,
  takes the alert id from each ntfy notification, posts it to the collector's `/ack` with the
  notification's post time as `t=`, then snoozes the notification so the app never reaches
  Android's limit on active notifications. It also follows logcat for the app's `Received
  notification` line, and logs its own delay (post to observation, observation to accepted
  acknowledgement, poll cycle times).
- `scenario.py run`: the profile of segments (screen off and unplugged, forced deep Doze with and
  without the exemption and one maintenance window each, standby buckets `working_set`,
  `frequent`, `rare` and `restricted`, Wi-Fi and mobile data off for 13 and 4 minutes, app
  force-stopped then reopened, reboot), each followed by a baseline segment; it samples the
  device's actual state every minute into the timeline.
- `analyse.py`: assigns each alert to the state it was sent in, writes one results file per state
  for the unchanged `push-delivery report`, then prints the per-state table, the outcome of each
  alert not in time (lost or late, received by the app or not, shown or not), when alerts sent
  during Doze were shown, and the observer's delay.

## Licences

Using the emulator and the system image implies the Android Software Development Kit License
Agreement (`android-sdk-license`, the licence all three SDK packages reference); `android.lock`
records the SHA-1 of the accepted text, written to `licenses/android-sdk-license` in the image as
sdkmanager would. The ntfy app is Apache-2.0. No Google account is used; the image has no Play
Store.

## Limits

An emulator: no carrier network, no radio power states, no OEM battery management (the vendor
killers that real phones add on top of Doze), Doze and buckets forced by `dumpsys` rather than
reached by idleness, and hours instead of 7 days. The emulator's virtual Wi-Fi does not rejoin by
itself after it is turned back on or after a reboot; the scenario asks it to, so the network
segments measure the app's recovery once the network is back, not the phone's. The latency counts
the observer's polling (reported separately) and the acknowledgement's HTTP request.
