"""Acknowledgement observer of the E13 emulator run: stands in for MacroDroid.

It polls the emulator over adb for the notifications the ntfy app posts, finds the alert id in
each notification's text, and posts it to the collector's /ack, with the notification's post
time (converted to this container's clock) as the phone time `t=`. The collector records its own
arrival time, which the verdict uses, so the observer's polling delay is part of the measured
latency; this script measures that delay so the report can bound or subtract it.

It also follows logcat for the ntfy app's "Received notification" line, the moment the app read
the message from its connection, to tell a message that reached the app from one that was shown.

Every line of the observer log is tab separated, all times Unix milliseconds on this
container's clock:

    seen       <id> <posted_ms> <observed_ms> <ack_ms> <http status>
    received   <id> <received_ms>
    offset     <host_ms> <device_minus_host_ms> <round_trip_ms>
    adb-error  <host_ms> <what>
    cycles     <count> <p50_ms> <p99_ms> <max_ms>

A notification is snoozed for a day once acknowledged, so the app never reaches Android's limit
on active notifications per app.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TextIO

PACKAGE = "io.heckel.ntfy"
ALERT_ID = re.compile(r"\bref ([0-9a-f]{32})\b")
RECEIVED = re.compile(
    r"^\s*(\d+)\.(\d{3})\s.*Received notification: .*message=Vilicus security alert\. ref ([0-9a-f]{32})\b"
)
OFFSET_EVERY_S = 30
ADB_TIMEOUT_S = 20
SNOOZE_MS = 86_400_000


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def adb(*args: str, timeout: float = ADB_TIMEOUT_S) -> str | None:
    """Runs one adb command; returns its standard output, or None on failure or timeout."""
    try:
        done = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None
    return done.stdout if done.returncode == 0 else None


class Log:
    """The append-only observer log, synced after each line like the results file."""

    def __init__(self, file: TextIO) -> None:
        self.lock = threading.Lock()
        self.file = file

    def write(self, *fields: object) -> None:
        with self.lock:
            self.file.write("\t".join(str(f) for f in fields) + "\n")
            self.file.flush()
            os.fsync(self.file.fileno())


def measure_offset() -> tuple[int, int] | None:
    """(round trip, device clock minus this container's clock) of the fastest of three probes."""
    best: tuple[int, int] | None = None
    for _ in range(3):
        before = now_ms()
        out = adb("shell", "date", "+%s%3N", timeout=10)
        after = now_ms()
        if out is None or not out.strip().isdigit():
            continue
        sample = (after - before, int(out.strip()) - (before + after) // 2)
        if best is None or sample[0] < best[0]:
            best = sample
    return best


def ntfy_notifications(dump: str) -> list[tuple[str, str, int]]:
    """(key, alert id, creation time on the device clock) of each active ntfy alert notification."""
    section = dump.split("Notification List:", 1)[-1].split("Notification attention state:", 1)[0]
    found = []
    for block in re.split(r"\n(?=\s*NotificationRecord\()", section):
        if f"pkg={PACKAGE} " not in block:
            continue
        key = re.search(r"\n\s*key=(\S+)", block)
        text = re.search(r"android\.text=String \((.*)\)", block)
        created = re.search(r"mCreationTimeMs=(\d+)", block)
        alert = ALERT_ID.search(text.group(1)) if text else None
        if key and alert and created:
            found.append((key.group(1), alert.group(1), int(created.group(1))))
    return found


def post_ack(collector: str, alert_id: str, phone_ms: int) -> int | None:
    """Posts the notification text to the collector; returns the HTTP status, None if unreachable."""
    request = urllib.request.Request(
        f"{collector}/ack?t={phone_ms}",
        data=f"Vilicus security alert. ref {alert_id}".encode(),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)
    except (urllib.error.URLError, OSError):
        return None


def follow_logcat(log: Log, offset: list[int], stop: threading.Event) -> None:
    """Logs the first 'Received notification' line of each alert id, across reboots."""
    seen: set[str] = set()
    while not stop.is_set():
        adb("wait-for-device", timeout=600)
        with subprocess.Popen(
            ["adb", "logcat", "-v", "epoch", "-s", "NtfySubscriberService:D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ) as process:
            assert process.stdout is not None
            for line in process.stdout:
                if stop.is_set():
                    break
                match = RECEIVED.match(line)
                if match and match.group(3) not in seen:
                    seen.add(match.group(3))
                    device_ms = int(match.group(1)) * 1000 + int(match.group(2))
                    log.write("received", match.group(3), device_ms - offset[0])
            process.kill()
        time.sleep(1)


def percentile(sorted_values: list[int], percent: int) -> int | str:
    """Nearest-rank percentile, the report's definition."""
    if not sorted_values:
        return "-"
    rank = max(1, -(-percent * len(sorted_values) // 100))
    return sorted_values[rank - 1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collector", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--poll-ms", type=int, default=1000)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args()

    with args.log.open("a", encoding="utf-8") as log_file:
        log = Log(log_file)
        # offset[0] is the latest device-minus-host offset, shared with the logcat thread.
        offset = [0]
        measured = measure_offset()
        if measured:
            offset[0] = measured[1]
            log.write("offset", now_ms(), measured[1], measured[0])
        stop = threading.Event()
        threading.Thread(target=follow_logcat, args=(log, offset, stop), daemon=True).start()

        acknowledged: set[str] = set()
        # Seen but not yet accepted by the collector: id -> (key, posted_ms, observed_ms).
        pending: dict[str, tuple[str, int, int]] = {}
        cycles: list[int] = []
        last_offset = time.monotonic()
        print("observer ready", flush=True)
        while not args.stop_file.exists():
            started = now_ms()
            if time.monotonic() - last_offset >= OFFSET_EVERY_S:
                last_offset = time.monotonic()
                measured = measure_offset()
                if measured:
                    offset[0] = measured[1]
                    log.write("offset", now_ms(), measured[1], measured[0])
            dump = adb("shell", "dumpsys", "notification", "--noredact")
            observed = now_ms()
            if dump is None:
                log.write("adb-error", observed, "dumpsys")
            else:
                for key, alert_id, created_device_ms in ntfy_notifications(dump):
                    if alert_id not in acknowledged and alert_id not in pending:
                        pending[alert_id] = (key, created_device_ms - offset[0], observed)
            # Every acknowledgement first, then one adb call snoozes them all: a snooze per
            # alert would delay the rest of a burst (a replay after an outage) by about a second
            # each.
            to_snooze = []
            for alert_id, (key, posted_ms, observed_ms) in list(pending.items()):
                status = post_ack(args.collector, alert_id, posted_ms)
                if status == 204:
                    del pending[alert_id]
                    acknowledged.add(alert_id)
                    log.write("seen", alert_id, posted_ms, observed_ms, now_ms(), status)
                    to_snooze.append(f"cmd notification snooze --for {SNOOZE_MS} '{key}'")
            if to_snooze:
                adb("shell", "; ".join(to_snooze), timeout=60)
            cycles.append(now_ms() - started)
            time.sleep(max(0, args.poll_ms - (now_ms() - started)) / 1000)
        stop.set()
        cycles.sort()
        log.write("cycles", len(cycles), percentile(cycles, 50), percentile(cycles, 99), cycles[-1] if cycles else "-")
    print(f"observer stopped acknowledged={len(acknowledged)} pending={len(pending)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
