#!/usr/bin/env bash
# E13 emulator run: the real ntfy Android app on an Android 15 emulator, driven through Docker,
# receiving the content-free alerts of the existing sender from the self-hosted ntfy server while
# a scenario forces power and connectivity states (screen off, battery unplugged, deep Doze with
# and without the battery optimisation exemption, app standby buckets, network off, app
# force-stopped, reboot). A host-side observer stands in for MacroDroid: it reads the app's
# notifications over adb and acknowledges them to the collector.
#
# Usage: bash run.sh [--smoke] [--duration-min <n>] [--save-dir <dir>]
#   default      the compressed run, 180 minutes of alerts (--duration-min scales it)
#   --smoke      every state once, about 6 minutes of alerts
#   --save-dir   copy the results, timeline, observer log and reports there before cleaning up
# Both modes then wait one deadline (10 minutes) for late acknowledgements.
#
# Prints `PASS <name>` / `FAIL <name>` lines, the per-state table, and `RESULT PASS|FAIL`;
# exits non-zero when the pipeline itself fails. A forced state delivering below 99 % is a
# recorded result, not a failure. Every figure is labelled criterion=simulation: this run never
# yields an E13 result. Needs Docker with /dev/kvm passable to a container.
set -euo pipefail

android_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
spike_dir="$(cd "$android_dir/.." && pwd)"
host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
export MSYS_NO_PATHCONV=1

mode=full
duration_min=180
save_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --smoke) mode=smoke ;;
    --duration-min) duration_min="$2"; shift ;;
    --save-dir) save_dir="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

ntfy_image="binwiederhier/ntfy@sha256:803b2aaeb94df76c8b32ecd91039dc80b0fddb7041dcaf082b33bcdfd4ba39ad"
runtime_image="vilicus-spike-push-delivery-runtime"
android_image="vilicus-spike-push-delivery-android"
compose=(docker compose -f "$(host_path "$android_dir/compose.yaml")" -p vilicus-e13-android)
data=/var/lib/push-delivery
log="$(mktemp)"
failed=0

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  : >"$log"
}
trap cleanup EXIT

record() {
  local status="$1" name="$2"
  echo "$status $name"
  if [ "$status" = FAIL ]; then
    sed 's/^/  | /' "$log"
    failed=1
  fi
}

# expect_ok NAME PATTERN CMD...: the command succeeds and its output matches PATTERN (grep -E).
expect_ok() {
  local name="$1" pattern="$2"
  shift 2
  if "$@" >"$log" 2>&1 && grep -Eq -- "$pattern" "$log"; then record PASS "$name"; else record FAIL "$name"; fi
}

abort() {
  echo "RESULT FAIL"
  exit 1
}

on_emulator() { "${compose[@]}" exec -T "$@"; }
adb_shell() { on_emulator emulator adb shell "$@" | tr -d '\r'; }
in_core() { "${compose[@]}" run --rm --no-deps -T -e TOKEN_PHONE core "$@" 2>/dev/null; }

# ---------------------------------------------------------------------------------------------
# Images and KVM.
docker build --quiet --file "$(host_path "$spike_dir/compose/Dockerfile")" --tag "$runtime_image" "$(host_path "$spike_dir")" >/dev/null
docker build --quiet --tag "$android_image" "$(host_path "$android_dir")" >/dev/null
docker pull --quiet "$ntfy_image" >/dev/null
expect_ok android.kvm_available '^kvm$' \
  docker run --rm --device /dev/kvm --entrypoint sh "$android_image" -c 'test -c /dev/kvm && echo kvm'
if [ "$failed" -ne 0 ]; then
  echo "  | On Docker Desktop with the WSL2 backend, load the module in its VM first:"
  echo "  | docker run --rm --privileged --pid=host <debian image> nsenter -t 1 -m -- modprobe kvm_intel"
  abort
fi

# ---------------------------------------------------------------------------------------------
# Test network: fresh topic, tokens and password for every run; nothing is written to the host.
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
tool() { docker run --rm "$runtime_image" push-delivery "$@"; }
export TOPIC_PHONE TOKEN_SENDER TOKEN_PHONE PHONE_PASSWORD E13_AUTH_USERS E13_AUTH_ACCESS E13_AUTH_TOKENS
TOPIC_PHONE="$(tool new-topic)"
TOKEN_SENDER="$(tool new-ntfy-token)"
TOKEN_PHONE="$(tool new-ntfy-token)"
PHONE_PASSWORD="$(tool new-topic)"
# shellcheck disable=SC2016 # a regular expression for the bcrypt hash, not an expansion
hash="$(printf '%s\n%s\n' "$PHONE_PASSWORD" "$PHONE_PASSWORD" | docker run --rm -i "$ntfy_image" user hash 2>/dev/null | grep -Eo '\$2[aby]\$[0-9]+\$[./A-Za-z0-9]{53}')"
E13_AUTH_USERS="sender:$hash:user,phone1:$hash:user"
E13_AUTH_ACCESS="sender:$TOPIC_PHONE:wo,phone1:$TOPIC_PHONE:ro"
E13_AUTH_TOKENS="sender:$TOKEN_SENDER,phone1:$TOKEN_PHONE"

smoke_flag=()
if [ "$mode" = smoke ]; then smoke_flag=(--smoke); fi
# The mean interval gives about 70 alerts in the smoke run and 540 in the default one.
if [ "$mode" = smoke ]; then mean_interval_ms=5000; else mean_interval_ms=20000; fi
export E13_DURATION_MS=0 E13_CONF=""
"${compose[@]}" up --detach --quiet-pull ntfy-self emulator >/dev/null 2>&1
E13_DURATION_MS="$(on_emulator emulator python3 /opt/e13/scenario.py plan "${smoke_flag[@]}" --duration-min "$duration_min" | tr -d '\r')"
# Deadline: D105's 10 minutes. The window is the run's length, so the report is never D105's
# and every line says criterion=simulation.
E13_CONF="results $data/results.tsv
listen 0.0.0.0:8080
mean_interval_ms $mean_interval_ms
deadline_ms 600000
window_ms $E13_DURATION_MS
threshold_percent 99
min_alerts 100
night 0 0 6
target phone-1 self-hosted http://ntfy-self env:TOPIC_PHONE env:TOKEN_SENDER"
echo "INFO mode=$mode alerts_ms=$E13_DURATION_MS mean_interval_ms=$mean_interval_ms"

booted=0
for _ in $(seq 1 120); do
  if [ "$(adb_shell getprop sys.boot_completed 2>/dev/null)" = 1 ]; then booted=1; break; fi
  sleep 3
done
if [ "$booted" -ne 1 ]; then
  "${compose[@]}" logs --tail 40 emulator >"$log" 2>&1 || true
  record FAIL android.boot_completed
  abort
fi
record PASS android.boot_completed
echo "INFO $(on_emulator emulator emulator -version 2>/dev/null | head -n 1 | tr -d '\r')"
echo "INFO $(on_emulator emulator adb version | head -n 2 | tr '\n' ' ' | tr -d '\r')"
echo "INFO $("${compose[@]}" exec -T ntfy-self ntfy --version 2>&1 | head -n 1)"
echo "INFO docker $(docker version --format '{{.Server.Version}}')"

# ---------------------------------------------------------------------------------------------
# The phone: install, permission, account, instant subscription, battery exemption.
setup_out="$(mktemp)"
if ! on_emulator -e TOPIC_PHONE -e PHONE_PASSWORD emulator \
    python3 /opt/e13/scenario.py setup --ntfy-url http://10.113.14.10 --user phone1 >"$setup_out" 2>&1; then
  cp "$setup_out" "$log"
  record FAIL android.ntfy_setup
  : >"$setup_out"
  abort
fi
sed 's/^/INFO /' "$setup_out" | tr -d '\r'
lock_sha="$(sed -n 's/^NTFY_APP_SHA256=//p' "$android_dir/android.lock")"
expect_ok android.apk_matches_lock "^apk_sha256=$lock_sha" grep '^apk_sha256=' "$setup_out"
expect_ok android.ntfy_app_1.25.2_installed '^ntfy_version=1\.25\.2' grep '^ntfy_version=' "$setup_out"
expect_ok android.post_notifications_granted '=true' grep '^post_notifications_granted=' "$setup_out"
expect_ok android.subscribed_with_instant_delivery_not_muted '^subscriptions=1\|0 ' grep '^subscriptions=' "$setup_out"
expect_ok android.instant_delivery_service_running '=yes' grep '^foreground_service=' "$setup_out"
expect_ok android.battery_optimisation_exempt '=yes' grep '^battery_optimisation_exempt=' "$setup_out"
: >"$setup_out"
if [ "$failed" -ne 0 ]; then abort; fi

# ---------------------------------------------------------------------------------------------
# The run: observer, scenario, then the sender for the scenario's duration.
on_emulator -d emulator sh -c "python3 /opt/e13/observer.py --collector http://10.113.14.20:8080 \
  --log $data/observer.tsv --stop-file $data/observer.stop >$data/observer.out 2>&1"
on_emulator -d emulator sh -c "python3 /opt/e13/scenario.py run ${smoke_flag[*]} --duration-min $duration_min \
  --timeline $data/timeline.tsv >$data/scenario.out 2>&1"
started=0
for _ in $(seq 1 60); do
  if on_emulator emulator grep -q '^state' "$data/timeline.tsv" 2>/dev/null; then started=1; break; fi
  sleep 1
done
if [ "$started" -ne 1 ]; then
  on_emulator emulator cat "$data/scenario.out" >"$log" 2>&1 || true
  record FAIL run.scenario_started
  abort
fi
"${compose[@]}" up --detach core >/dev/null 2>&1
record PASS run.scenario_started

# Fail fast when nothing comes back: the first acknowledgement within 3 minutes.
acked=0
for _ in $(seq 1 90); do
  if on_emulator emulator grep -q '^ack' "$data/results.tsv" 2>/dev/null; then acked=1; break; fi
  sleep 2
done
if [ "$acked" -ne 1 ]; then
  { on_emulator emulator cat "$data/observer.out"; "${compose[@]}" logs --tail 20 core; } >"$log" 2>&1 || true
  record FAIL run.first_acknowledgement_within_3_minutes
  abort
fi
record PASS run.first_acknowledgement_within_3_minutes

core_status="$(docker wait "$("${compose[@]}" ps -q -a core)")"
"${compose[@]}" logs --no-log-prefix core >"$log" 2>&1 || true
if [ "$core_status" = 0 ] && grep -q 'event=done' "$log"; then record PASS run.sender_completed; else record FAIL run.sender_completed; fi
expect_ok run.no_publish_failure '^0$' sh -c "grep -c 'event=publish-failed' '$log' || true"
expect_ok run.scenario_completed 'scenario-done' on_emulator emulator grep 'scenario-done' "$data/timeline.tsv"
on_emulator emulator touch "$data/observer.stop"
for _ in $(seq 1 30); do
  if on_emulator emulator grep -q '^cycles' "$data/observer.tsv" 2>/dev/null; then break; fi
  sleep 1
done
expect_ok run.observer_stopped_cleanly '^observer stopped' on_emulator emulator tail -n 1 "$data/observer.out"

# ---------------------------------------------------------------------------------------------
# Reports: the whole run, then one per state with the unchanged report command.
report="$(mktemp)"
in_core push-delivery report --config "$data/android.conf" --explain >"$report" || true
echo "INFO report of the whole run:"
sed 's/^/  | /' "$report"
expect_ok report.labelled_simulation_not_e13 'this is not an E13 result' cat "$report"
expect_ok report.every_target_line_simulation '^target phone=phone-1 server=self-hosted .*pending=0 .*criterion=simulation$' grep '^target ' "$report"
expect_ok report.no_unknown_acknowledgement '^unknown_acks count=0$' grep '^unknown_acks' "$report"
evaluated="$(grep '^target ' "$report" | tr ' ' '\n' | sed -n 's/^evaluated=//p')"
unpublished="$(grep '^target ' "$report" | tr ' ' '\n' | sed -n 's/^unpublished=//p')"
expect_ok ac1.every_stored_message_content_free "content_free=$((evaluated - unpublished))\$" \
  in_core push-delivery audit-cache --url "http://ntfy-self/$TOPIC_PHONE" --token env:TOKEN_PHONE --expect "$((evaluated - unpublished))"

on_emulator emulator mkdir -p "$data/states"
mapfile -t states < <(on_emulator emulator python3 /opt/e13/analyse.py split --results "$data/results.tsv" \
  --timeline "$data/timeline.tsv" --conf "$data/android.conf" --out "$data/states" | tr -d '\r')
for state in "${states[@]}"; do
  in_core sh -c "push-delivery report --config $data/states/state-$state.conf --explain >$data/states/report-$state.txt" || true
done
table="$(mktemp)"
on_emulator emulator python3 /opt/e13/analyse.py table --results "$data/results.tsv" --timeline "$data/timeline.tsv" \
  --observer "$data/observer.tsv" --reports "$data/states" | tr -d '\r' >"$table" || true
echo "INFO per-state results (criterion=simulation, not an E13 result):"
grep -v '^CHECK ' "$table" | sed 's/^/  | /'
while read -r _ name outcome detail; do
  echo "$detail" >"$log"
  if [ "$outcome" = ok ]; then record PASS "pipeline.$name"; else record FAIL "pipeline.$name"; fi
done < <(grep '^CHECK ' "$table")
expect_ok pipeline.table_has_one_row_per_state "^${#states[@]}\$" grep -c '^| [a-z]' "$table"

if [ -n "$save_dir" ]; then
  mkdir -p "$save_dir"
  "${compose[@]}" cp "emulator:$data/." "$(host_path "$save_dir")" >/dev/null
  cp "$report" "$save_dir/report.txt"
  cp "$table" "$save_dir/table.txt"
  echo "INFO saved to $save_dir"
fi
: >"$report"
: >"$table"

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
