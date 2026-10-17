"""Per-state analysis of the E13 emulator run.

`split` assigns every alert of the results file to the scenario state it was sent in and writes,
per state, a results file holding that state's sends and every acknowledgement, plus a copy of
the run configuration pointing at it. Running the unchanged `push-delivery report` on each copy
gives the per-state delivery rate, late and missing counts and latency percentiles.

`table` reads those reports back with the timeline and the observer log and prints the
per-state table, how alerts sent during Doze arrived (while idle, in the maintenance window or
after leaving Doze), what the observer's own delay was, and `CHECK <name> ok|fail` lines for
run.sh. Every figure it prints is labelled as an emulator simulation.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

DOZE_STATES = ("doze-exempt", "doze-not-exempt")
DEADLINE_MS = 600_000
NAME = re.compile(r"^[a-z0-9_-]+$")
# The screen is off when the power manager is not Awake: Asleep, or Dozing (ambient display).
SCREEN_OFF = "screen-off"
# What the device must report (scenario.py observed_state) for a forced state to count as
# taken effect; `a|b` accepts either. Deep Doze includes its maintenance windows. App standby
# bucket values are Android's UsageStatsManager constants.
DEEP_DOZE = "deep=IDLE|deep=IDLE_MAINTENANCE"
EXPECTED = {
    "screen-off-unplugged": (SCREEN_OFF, "ACpowered:false"),
    "doze-exempt": (DEEP_DOZE, "bucket=5"),
    "doze-not-exempt": (DEEP_DOZE,),
    "bucket-working_set": (SCREEN_OFF,),
    "bucket-frequent": (SCREEN_OFF,),
    "bucket-rare": (SCREEN_OFF,),
    "bucket-restricted": (SCREEN_OFF,),
    "network-off-long": ("net=none",),
    "network-off-short": ("net=none",),
    "app-force-stopped": ("fgs=0",),
}
# A forced standby bucket is checked on the segment's first sample only: the system may move the
# app back (it does while the app runs a foreground service), which the table reports as held or
# not, rather than as a pipeline failure.
FORCED_BUCKET = {
    "bucket-working_set": "bucket=20",
    "bucket-frequent": "bucket=30",
    "bucket-rare": "bucket=40",
    "bucket-restricted": "bucket=45",
}


@dataclass
class Send:
    id: str
    sent_ms: int
    line: str


def read_results(path: Path) -> tuple[list[Send], list[str], dict[str, int]]:
    """Sends, raw acknowledgement lines and the first arrival time of each acknowledged id."""
    sends, acks, first_ack = [], [], {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "send":
            sends.append(Send(fields[1], int(fields[4]), line))
        elif fields[0] == "ack":
            acks.append(line)
            arrival = int(fields[2])
            first_ack[fields[1]] = min(arrival, first_ack.get(fields[1], arrival))
    return sends, acks, first_ack


def read_timeline(path: Path, kinds: tuple[str, ...] = ("event",)) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """The state changes, and the lines of the other `kinds` (events by default)."""
    states, others = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        kind, at, what = line.split("\t", 2)
        if kind == "state":
            if not NAME.match(what):
                raise ValueError(f"state name `{what}`")
            states.append((int(at), what))
        elif kind in kinds:
            others.append((int(at), what))
    return states, others


def forced_states_took_effect(
    states: list[tuple[int, str]], checks: list[tuple[int, str]]
) -> tuple[bool, str, dict[str, tuple[int, int]]]:
    """Whether every sample inside a forced state shows it, and per bucket state (held, samples)."""
    failures, samples = [], 0
    bucket_held: dict[str, tuple[int, int]] = {}
    previous = None
    for at, observed in checks:
        name = state_at(states, at)
        first_of_segment = (name, max(start for start, _ in states if start <= at)) != previous
        previous = (name, max(start for start, _ in states if start <= at))
        expected = list(EXPECTED.get(name, ()))
        if name in FORCED_BUCKET:
            held, total = bucket_held.get(name, (0, 0))
            bucket_held[name] = (held + (FORCED_BUCKET[name] in observed.split()), total + 1)
            if first_of_segment:
                expected.append(FORCED_BUCKET[name])
        if not expected:
            continue
        samples += 1
        facts = observed.split()
        if "mWakefulness=Awake" not in facts:
            facts.append(SCREEN_OFF)
        missing = [e for e in expected if not any(alt in facts for alt in e.split("|"))]
        if missing:
            failures.append(f"{name}:{'+'.join(missing)}")
    detail = f"samples={samples} mismatches={','.join(failures) or 'none'}"
    return not failures and samples > 0, detail, bucket_held


def state_at(states: list[tuple[int, str]], at_ms: int) -> str:
    """The state active at `at_ms`; alerts sent before the first state count as that state."""
    current = states[0][1]
    for start, name in states:
        if start > at_ms:
            break
        current = name
    return current


def ordered_states(states: list[tuple[int, str]]) -> list[str]:
    seen: list[str] = []
    for _, name in states:
        if name not in seen:
            seen.append(name)
    return seen


def split(results: Path, timeline: Path, conf: Path, out: Path) -> None:
    sends, acks, _ = read_results(results)
    states, _ = read_timeline(timeline)
    by_state: dict[str, list[str]] = defaultdict(list)
    for send in sends:
        by_state[state_at(states, send.sent_ms)].append(send.line)
    conf_lines = conf.read_text(encoding="utf-8").splitlines()
    for name in ordered_states(states):
        state_results = out / f"state-{name}.tsv"
        state_results.write_text("\n".join(by_state[name] + acks) + "\n", encoding="utf-8")
        lines = [f"results {state_results}" if line.startswith("results ") else line for line in conf_lines]
        (out / f"state-{name}.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(name)


def fields_of(line: str) -> dict[str, str]:
    return dict(pair.split("=", 1) for pair in line.split()[1:] if "=" in pair)


def read_observer(path: Path) -> tuple[dict[str, tuple[int, int, int]], dict[str, int], list[str]]:
    """Seen alerts (posted, observed, acknowledged), app receptions, and the cycles line."""
    seen, received, cycles = {}, {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "seen":
            seen[fields[1]] = (int(fields[2]), int(fields[3]), int(fields[4]))
        elif fields[0] == "received":
            received[fields[1]] = int(fields[2])
        elif fields[0] == "cycles":
            cycles = fields[1:]
    return seen, received, cycles


def percentile(values: list[int], percent: int) -> str:
    """Nearest-rank percentile, the report's definition."""
    if not values:
        return "-"
    ordered = sorted(values)
    rank = max(1, -(-percent * len(ordered) // 100))
    return str(ordered[rank - 1])


def seconds(ms: str) -> str:
    return "-" if ms in ("-", "") else f"{int(ms) / 1000:.1f}"


def doze_windows(states: list[tuple[int, str]], events: list[tuple[int, str]]) -> list[dict[str, object]]:
    """Each forced Doze segment with its maintenance windows and the time the device left Doze."""
    windows = []
    bounds = states[1:] + [(sys.maxsize, "")]
    for (start, name), (end, _) in zip(states, bounds):
        if name not in DOZE_STATES:
            continue
        inside = [(at, what) for at, what in events if start <= at]
        starts = [at for at, what in inside if what.startswith("maintenance-start") and at < end]
        ends = [at for at, what in inside if what.startswith("maintenance-end") and at < end]
        exits = [at for at, what in inside if what == "doze-exit"]
        windows.append(
            {
                "name": name,
                "start": start,
                "end": end,
                "maintenance": list(zip(starts, ends)),
                # A Doze followed by another Doze segment is left only by the later one.
                "exit": exits[0] if exits else end,
            }
        )
    return windows


def table(results: Path, timeline: Path, observer: Path, reports: Path) -> int:
    sends, _, first_ack = read_results(results)
    states, events = read_timeline(timeline)
    seen, received, cycles = read_observer(observer)
    names = ordered_states(states)
    checks: list[tuple[str, bool, str]] = []

    print("emulator run, criterion=simulation: this is not an E13 result")
    print("| State | Alerts | In time (10 min) | Late | Lost | Unpublished | Rate | p50 / p90 / p99 / max (s) | Phone-reported p50 (s) |")
    print("|---|---|---|---|---|---|---|---|---|")
    evaluated_total = 0
    rows_ok = True
    report_lines = {}
    for name in names:
        report = (reports / f"report-{name}.txt").read_text(encoding="utf-8")
        target = next((line for line in report.splitlines() if line.startswith("target ")), None)
        if target is None or "criterion=simulation" not in target or "not an E13 result" not in report:
            rows_ok = False
            continue
        f = fields_of(target)
        report_lines[name] = f
        evaluated = int(f["evaluated"])
        evaluated_total += evaluated
        parts = sum(int(f[k]) for k in ("in_time", "late", "missing", "unpublished"))
        rows_ok &= parts == evaluated and f["pending"] == "0"
        latency = " / ".join(seconds(f[k]) for k in ("p50_ms", "p90_ms", "p99_ms", "max_ms"))
        print(
            f"| {name} | {evaluated} | {f['in_time']} | {f['late']} | {f['missing']} | {f['unpublished']}"
            f" | {f['rate_percent']} % | {latency} | {seconds(f['phone_reported_p50_ms'])} |"
        )
    checks.append(("per_state_table_produced", rows_ok and len(report_lines) == len(names), f"states={len(names)}"))
    checks.append(
        ("every_alert_accounted_as_delivered_late_or_lost", rows_ok and evaluated_total == len(sends),
         f"sends={len(sends)} evaluated={evaluated_total}")
    )

    # Lost alerts: did the app receive them (logcat), show them (notification), or neither?
    print()
    print("Alerts not in time, by state:")
    any_listed = False
    for send in sends:
        name = state_at(states, send.sent_ms)
        arrival = first_ack.get(send.id)
        latency = None if arrival is None else arrival - send.sent_ms
        if latency is not None and latency <= DEADLINE_MS:
            continue
        any_listed = True
        outcome = "lost" if latency is None else f"late latency_s={latency / 1000:.0f}"
        app = "received-by-app" if send.id in received else "never-received-by-app"
        shown = "shown" if send.id in seen else "not-shown"
        offset_s = (send.sent_ms - states[0][0]) / 1000
        print(f"  state={name} sent_at_s={offset_s:.0f} outcome={outcome} {app} {shown}")
    if not any_listed:
        print("  none")

    print()
    print("Alerts sent during forced Doze, by when they were shown (device post time):")
    for window in doze_windows(states, events):
        tally: dict[str, int] = defaultdict(int)
        idle_latency: list[int] = []
        maintenance = window["maintenance"]
        for send in sends:
            if not window["start"] <= send.sent_ms < window["end"]:
                continue
            if any(ms <= send.sent_ms <= me for ms, me in maintenance):
                tally["sent in the maintenance window"] += 1
                continue
            # Sent while idle: shown before the next maintenance window or the exit, or held to one.
            boundary = min([ms for ms, _ in maintenance if ms > send.sent_ms] + [window["exit"]])
            shown_at = seen.get(send.id, (None,))[0]
            if shown_at is None:
                tally["sent while idle, not shown"] += 1
                continue
            idle_latency.append(shown_at - send.sent_ms)
            if shown_at < boundary:
                tally["sent while idle, shown while idle"] += 1
            elif shown_at >= window["exit"]:
                tally["sent while idle, held to the Doze exit"] += 1
            else:
                tally["sent while idle, held to a maintenance window"] += 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "no alert"
        latency = f"; sent-while-idle latency p50 {percentile(idle_latency, 50)} ms max {max(idle_latency, default='-')} ms"
        print(f"  {window['name']}: {summary}{latency}")

    # The observer's own delay: notification posted -> observed by the poll -> accepted by the collector.
    poll_delay = [observed - posted for posted, observed, _ in seen.values()]
    ack_delay = [acked - observed for _, observed, acked in seen.values()]
    shown_after_received = [seen[i][0] - received[i] for i in seen if i in received]
    print()
    print("Observer delay (ms, nearest rank):")
    print(f"  notification posted -> observed: p50 {percentile(poll_delay, 50)} p99 {percentile(poll_delay, 99)} max {max(poll_delay, default='-')}")
    print(f"  observed -> acknowledgement accepted: p50 {percentile(ack_delay, 50)} p99 {percentile(ack_delay, 99)} max {max(ack_delay, default='-')}")
    print(f"  app received -> notification posted: p50 {percentile(shown_after_received, 50)} max {max(shown_after_received, default='-')}")
    if cycles:
        print(f"  poll cycles: count {cycles[0]} p50 {cycles[1]} p99 {cycles[2]} max {cycles[3]}")
    checks.append(("observer_delay_measured", bool(poll_delay) and bool(cycles), f"seen={len(seen)}"))

    _, samples = read_timeline(timeline, ("check",))
    took_effect, detail, bucket_held = forced_states_took_effect(states, samples)
    checks.append(("forced_states_observed_on_the_device", took_effect, detail))
    print()
    print("Forced standby bucket still in place at each one-minute sample:")
    for name, (held, total) in bucket_held.items():
        print(f"  {name}: {held} of {total} samples")

    first_state_end = states[1][0] if len(states) > 1 else sys.maxsize
    first_baseline = [s for s in sends if s.sent_ms < first_state_end]
    in_time = [s for s in first_baseline if s.id in first_ack and first_ack[s.id] - s.sent_ms <= DEADLINE_MS]
    checks.append(
        ("pipeline_end_to_end_in_the_first_baseline", bool(first_baseline) and len(in_time) == len(first_baseline),
         f"alerts={len(first_baseline)} in_time={len(in_time)}")
    )
    print()
    for name, ok, detail in checks:
        print(f"CHECK {name} {'ok' if ok else 'fail'} {detail}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("split", "table"):
        sub = commands.add_parser(command)
        sub.add_argument("--results", type=Path, required=True)
        sub.add_argument("--timeline", type=Path, required=True)
        if command == "split":
            sub.add_argument("--conf", type=Path, required=True)
            sub.add_argument("--out", type=Path, required=True)
        else:
            sub.add_argument("--observer", type=Path, required=True)
            sub.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "split":
        split(args.results, args.timeline, args.conf, args.out)
        return 0
    return table(args.results, args.timeline, args.observer, args.reports)


if __name__ == "__main__":
    sys.exit(main())
