"""Phone setup and power-state scenario of the E13 emulator run.

`setup` installs the pinned ntfy APK, grants the notification permission, stores the phone's
account for the self-hosted server in the app, subscribes to the phone's topic with an
ntfy:// link (instant delivery), and exempts the app from battery optimisation, as RUNBOOK.md
step 6 asks of a real phone.

`run` walks a profile of segments while the sender posts alerts at random times, forcing a
power or connectivity state in each: screen off and battery unplugged, deep Doze forced with and
without the battery optimisation exemption (with one maintenance window each), app standby
buckets, Wi-Fi and mobile data off, the app force-stopped, and a reboot. It writes a timeline so
that the analysis can assign each alert to the state it was sent in:

    state   <host_ms> <name>
    event   <host_ms> <what>
    check   <host_ms> <observed device state>

All times are Unix milliseconds on this container's clock.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TextIO

PACKAGE = "io.heckel.ntfy"
MAIN_ACTIVITY = f"{PACKAGE}/.ui.MainActivity"
DATABASE = f"/data/data/{PACKAGE}/databases/AppDatabase"
HEX = re.compile(r"^[0-9a-f]{32}$")
CHECK_EVERY_S = 60


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def adb(*args: str, timeout: float = 60, check: bool = False) -> str:
    """Runs one adb command and returns its standard output ('' on a timeout)."""
    try:
        done = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        if check:
            raise
        return ""
    if check and done.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


def shell(command: str, timeout: float = 60, check: bool = False) -> str:
    return adb("shell", command, timeout=timeout, check=check)


def wait_for_boot(limit_s: float = 600) -> None:
    deadline = time.monotonic() + limit_s
    adb("wait-for-device", timeout=limit_s)
    while time.monotonic() < deadline:
        if shell("getprop sys.boot_completed", timeout=10).strip() == "1":
            return
        time.sleep(2)
    raise RuntimeError("the emulator did not finish booting")


def wake_and_unlock() -> None:
    shell("input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard")


def wait_for_network(limit_s: float = 120) -> bool:
    """Waits for a default network, asking Wi-Fi to rejoin: the emulator does not rejoin by itself."""
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        if "Active default network: none" not in shell("dumpsys connectivity | grep 'Active default network'"):
            return True
        shell("cmd wifi connect-network AndroidWifi open")
        time.sleep(3)
    return False


def wait_for_no_network(limit_s: float = 30) -> bool:
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        if "Active default network: none" in shell("dumpsys connectivity | grep 'Active default network'"):
            return True
        time.sleep(1)
    return False


# ------------------------------------------------------------------------------------------------
# Setup


def setup(ntfy_url: str, topic: str, user: str, password: str) -> None:
    if not HEX.match(topic) or not HEX.match(password) or not re.match(r"^[a-z0-9]+$", user):
        raise ValueError("topic and password must be 128-bit hex, the user lowercase alphanumeric")
    wait_for_boot()
    adb("root", check=True)
    time.sleep(2)
    wait_for_boot()
    # No lock screen to dismiss; the scenario turns the screen off and on itself.
    shell("locksettings set-disabled true; svc power stayon false")
    apk_sha256 = hashlib.sha256(Path("/opt/e13/ntfy.apk").read_bytes()).hexdigest()
    print(f"apk_sha256={apk_sha256}")
    adb("install", "-r", "/opt/e13/ntfy.apk", check=True)
    shell(f"pm grant {PACKAGE} android.permission.POST_NOTIFICATIONS", check=True)
    wake_and_unlock()
    # A first start creates the app's database; then the account is stored the way the app's
    # user settings store it (base URL, user, password), as the app's own user.
    shell(f"am start -W -n {MAIN_ACTIVITY}", check=True)
    time.sleep(3)
    shell(f"am force-stop {PACKAGE}")
    sql = f"INSERT OR REPLACE INTO User(baseUrl, username, password) VALUES ('{ntfy_url}', '{user}', '{password}');"
    shell(f"su $(stat -c %u /data/data/{PACKAGE}) sqlite3 {DATABASE} \"{sql}\"", check=True)
    host = ntfy_url.removeprefix("http://")
    secure = "false" if ntfy_url.startswith("http://") else "true"
    shell(f"am start -W -a android.intent.action.VIEW -d 'ntfy://{host}/{topic}?secure={secure}' {PACKAGE}", check=True)
    time.sleep(3)
    # Leave the topic's view: the app does not notify for the topic shown on screen.
    shell("input keyevent KEYCODE_HOME")
    shell(f"dumpsys deviceidle whitelist +{PACKAGE}", check=True)
    print_state()


def print_state() -> None:
    package = shell(f"dumpsys package {PACKAGE}")
    version = re.search(r"versionName=(\S+)", package)
    granted = re.search(r"android.permission.POST_NOTIFICATIONS: granted=(\w+)", package)
    rows = shell(f"su $(stat -c %u /data/data/{PACKAGE}) sqlite3 {DATABASE} 'SELECT instant, mutedUntil FROM Subscription;'")
    services = shell(f"dumpsys activity services {PACKAGE}")
    print(f"ntfy_version={version.group(1) if version else '-'}")
    print(f"post_notifications_granted={granted.group(1) if granted else '-'}")
    print(f"subscriptions={rows.strip().replace(chr(10), ',') or '-'} (instant|muted_until)")
    print(f"foreground_service={'yes' if 'isForeground=true' in services else 'no'}")
    print(f"battery_optimisation_exempt={'yes' if PACKAGE in shell('dumpsys deviceidle whitelist') else 'no'}")
    print(f"android={shell('getprop ro.build.version.release').strip()} sdk={shell('getprop ro.build.version.sdk').strip()}")
    print(f"build={shell('getprop ro.build.fingerprint').strip()}")


# ------------------------------------------------------------------------------------------------
# Scenario


@dataclass(frozen=True)
class Conditions:
    screen_on: bool = True
    plugged: bool = True
    exempt: bool = True
    bucket: str | None = None
    doze: bool = False
    network: bool = True
    app_running: bool = True


BASELINE = Conditions()
SCREEN_OFF = replace(BASELINE, screen_on=False, plugged=False)
NOT_EXEMPT = replace(SCREEN_OFF, exempt=False)


@dataclass(frozen=True)
class Segment:
    name: str
    seconds: float
    conditions: Conditions
    # A maintenance window halfway through a forced Doze, of this many seconds.
    maintenance_s: float = 0
    reboot: bool = False


def bucket(name: str) -> Conditions:
    return replace(NOT_EXEMPT, bucket=name)


# The full profile, in minutes; --duration-min scales it. Every disruptive segment is followed
# by a baseline one, so that recovery is measured and the next state starts clean.
FULL = [
    ("baseline", 10, BASELINE, 0, False),
    ("screen-off-unplugged", 12, SCREEN_OFF, 0, False),
    ("doze-exempt", 22, replace(SCREEN_OFF, doze=True), 60, False),
    ("baseline", 4, BASELINE, 0, False),
    ("doze-not-exempt", 22, replace(NOT_EXEMPT, doze=True), 60, False),
    ("baseline", 4, BASELINE, 0, False),
    ("bucket-working_set", 8, bucket("working_set"), 0, False),
    ("bucket-frequent", 8, bucket("frequent"), 0, False),
    ("bucket-rare", 10, bucket("rare"), 0, False),
    ("bucket-restricted", 14, bucket("restricted"), 0, False),
    ("baseline", 4, BASELINE, 0, False),
    ("network-off-long", 13, replace(BASELINE, network=False), 0, False),
    ("baseline", 6, BASELINE, 0, False),
    ("network-off-short", 4, replace(BASELINE, network=False), 0, False),
    ("baseline", 4, BASELINE, 0, False),
    ("app-force-stopped", 8, replace(BASELINE, app_running=False), 0, False),
    ("baseline", 5, BASELINE, 0, False),
    ("reboot", 12, BASELINE, 0, True),
    ("baseline", 10, BASELINE, 0, False),
]

# The smoke profile, in seconds: every state once, briefly.
SMOKE = [
    ("baseline", 45, BASELINE, 0, False),
    ("screen-off-unplugged", 30, SCREEN_OFF, 0, False),
    ("doze-exempt", 45, replace(SCREEN_OFF, doze=True), 10, False),
    ("doze-not-exempt", 45, replace(NOT_EXEMPT, doze=True), 10, False),
    ("bucket-restricted", 30, bucket("restricted"), 0, False),
    ("network-off-short", 30, replace(BASELINE, network=False), 0, False),
    ("baseline", 15, BASELINE, 0, False),
    ("app-force-stopped", 30, replace(BASELINE, app_running=False), 0, False),
    ("baseline", 15, BASELINE, 0, False),
    ("reboot", 60, BASELINE, 0, True),
    ("baseline", 15, BASELINE, 0, False),
]


def profile(smoke: bool, duration_min: float) -> list[Segment]:
    if smoke:
        return [Segment(n, s, c, m, r) for n, s, c, m, r in SMOKE]
    total = sum(entry[1] for entry in FULL)
    scale = duration_min / total
    return [Segment(n, max(10.0, minutes * 60 * scale), c, m, r) for n, minutes, c, m, r in FULL]


class Timeline:
    def __init__(self, file: TextIO) -> None:
        self.file = file

    def write(self, kind: str, what: str) -> None:
        self.file.write(f"{kind}\t{now_ms()}\t{what}\n")
        self.file.flush()
        os.fsync(self.file.fileno())


def observed_state() -> str:
    """One line of what the device reports, for the timeline's evidence."""
    out = shell(
        "echo deep=$(dumpsys deviceidle get deep) light=$(dumpsys deviceidle get light)"
        f" bucket=$(am get-standby-bucket {PACKAGE})"
        " $(dumpsys power | grep -m1 -o 'mWakefulness=[A-Za-z]*')"
        " $(dumpsys battery | grep -m1 -o 'AC powered: [a-z]*' | tr -d ' ')"
        " net=$(dumpsys connectivity | grep -m1 'Active default network' | sed 's/.*: //')"
        f" fgs=$(dumpsys activity services {PACKAGE} | grep -c 'isForeground=true')",
        timeout=30,
    )
    return " ".join(out.split()) or "unreachable"


class Device:
    """Moves the emulator from its current conditions to the ones a segment asks for."""

    def __init__(self, timeline: Timeline) -> None:
        self.timeline = timeline
        self.current = BASELINE

    def apply(self, target: Conditions) -> None:
        current = self.current
        if current.doze and not target.doze:
            # Leaving Doze the way a phone does: the forced mode ends and the screen comes on.
            shell("dumpsys deviceidle unforce")
            wake_and_unlock()
            self.timeline.write("event", "doze-exit")
            current = replace(current, doze=False, screen_on=True)
        if target.network and not current.network:
            shell("svc wifi enable; svc data enable")
            restored = wait_for_network()
            self.timeline.write("event", f"network-restored ok={'yes' if restored else 'no'}")
        if target.app_running and not current.app_running:
            # The member opens the app again.
            wake_and_unlock()
            shell(f"am start -W -n {MAIN_ACTIVITY}")
            time.sleep(2)
            shell("input keyevent KEYCODE_HOME")
            self.timeline.write("event", "app-started")
            current = replace(current, screen_on=True)
        if target.exempt != current.exempt:
            shell(f"dumpsys deviceidle whitelist {'+' if target.exempt else '-'}{PACKAGE}")
        if target.plugged != current.plugged:
            shell("dumpsys battery reset" if target.plugged else "dumpsys battery unplug")
        if target.screen_on != current.screen_on or target.screen_on:
            if target.screen_on:
                wake_and_unlock()
            else:
                shell("input keyevent KEYCODE_SLEEP")
        if target.bucket is not None:
            shell(f"am set-standby-bucket {PACKAGE} {target.bucket}")
        elif current.bucket is not None:
            shell(f"am set-standby-bucket {PACKAGE} active")
        if target.doze:
            shell("dumpsys deviceidle force-idle")
        if not target.network and current.network:
            shell("svc wifi disable; svc data disable")
            dropped = wait_for_no_network()
            self.timeline.write("event", f"network-dropped ok={'yes' if dropped else 'no'}")
        if not target.app_running and current.app_running:
            shell(f"am force-stop {PACKAGE}")
        self.current = target

    def reboot(self) -> None:
        self.timeline.write("event", "reboot-requested")
        adb("reboot", timeout=60)
        wait_for_boot()
        self.timeline.write("event", "boot-completed")
        wake_and_unlock()
        shell("input keyevent KEYCODE_HOME")
        # The emulator's virtual Wi-Fi does not rejoin after a reboot on its own (a phone does);
        # without this the rest of the run would measure an emulator with no network.
        restored = wait_for_network()
        self.timeline.write("event", f"network-restored ok={'yes' if restored else 'no'}")
        # A reboot resets the battery override and the bucket; the exemption persists.
        self.current = BASELINE


def hold(seconds: float, timeline: Timeline, segment: Segment) -> None:
    """Waits out a segment, recording the device state every minute and running its maintenance window."""
    started = time.monotonic()
    maintenance_at = seconds / 2 if segment.maintenance_s else None
    next_check = 0.0
    while (elapsed := time.monotonic() - started) < seconds:
        if maintenance_at is not None and elapsed >= maintenance_at:
            maintenance_at = None
            # Stepping a forced deep Doze once enters IDLE_MAINTENANCE; stepping again returns.
            timeline.write("event", f"maintenance-start {shell('dumpsys deviceidle step').strip()}")
            time.sleep(segment.maintenance_s)
            # The system may have closed the window itself; stepping then would open another.
            if shell("dumpsys deviceidle get deep").strip() == "IDLE_MAINTENANCE":
                timeline.write("event", f"maintenance-end {shell('dumpsys deviceidle step').strip()}")
            else:
                timeline.write("event", "maintenance-end closed by the system before the step")
            continue
        if elapsed >= next_check:
            next_check = elapsed + CHECK_EVERY_S
            timeline.write("check", observed_state())
        time.sleep(1)


def run(segments: list[Segment], timeline_path: Path) -> None:
    with timeline_path.open("a", encoding="utf-8") as file:
        timeline = Timeline(file)
        device = Device(timeline)
        for segment in segments:
            started = time.monotonic()
            timeline.write("state", segment.name)
            print(f"segment {segment.name} seconds={segment.seconds:.0f}", flush=True)
            if segment.reboot:
                device.apply(BASELINE)
                device.reboot()
            else:
                device.apply(segment.conditions)
            hold(segment.seconds - (time.monotonic() - started), timeline, segment)
        # The sender may still post for a few seconds after the last segment, in baseline.
        timeline.write("state", "baseline")
        device.apply(BASELINE)
        timeline.write("event", "scenario-done")
        timeline.write("check", observed_state())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    set_up = commands.add_parser("setup")
    set_up.add_argument("--ntfy-url", required=True)
    set_up.add_argument("--user", required=True)
    scenario = commands.add_parser("run")
    scenario.add_argument("--timeline", type=Path, required=True)
    scenario.add_argument("--smoke", action="store_true")
    scenario.add_argument("--duration-min", type=float, default=180)
    plan = commands.add_parser("plan", help="print the profile's total duration in ms")
    plan.add_argument("--smoke", action="store_true")
    plan.add_argument("--duration-min", type=float, default=180)
    args = parser.parse_args()
    if args.command == "setup":
        # The topic and the password come from the environment, never from the command line.
        setup(args.ntfy_url, os.environ["TOPIC_PHONE"], args.user, os.environ["PHONE_PASSWORD"])
    elif args.command == "run":
        run(profile(args.smoke, args.duration_min), args.timeline)
    else:
        print(round(sum(s.seconds for s in profile(args.smoke, args.duration_min)) * 1000))
    return 0


if __name__ == "__main__":
    sys.exit(main())
