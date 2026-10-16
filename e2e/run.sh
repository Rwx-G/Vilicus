#!/usr/bin/env bash
# Replayable end-to-end campaign for the Epic 1 spikes. Runs one phase per spike, strictly one
# after the other (never in parallel, so the CPU-sensitive spikes measure on an idle engine),
# captures each phase's full output, and writes a per-run summary under e2e/results/.
#
# Usage: bash e2e/run.sh [--list] [--only <phase>[,<phase>...]] [--skip-<phase>]... [--keep-going]
# See e2e/README.md for the phases, the replay procedure and the runtime expectations.
#
# Environment:
#   E2E_IDLE_WAIT      seconds to wait for other containers to stop before a CPU-sensitive
#                      phase (default 300); the phase fails if the engine is still busy.
#   E2E_TIMEOUT_SCALE  integer multiplier applied to every phase timeout (default 1).
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$E2E_DIR/.." && pwd)"
SPIKES_DIR="$REPO_DIR/spikes"
IDLE_WAIT="${E2E_IDLE_WAIT:-300}"
TIMEOUT_SCALE="${E2E_TIMEOUT_SCALE:-1}"
# rust:1-trixie (Debian 13, rustc 1.99.1), the digest the spikes pin.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"

# phase|story|spike directory|cpu-sensitive (yes/no)|timeout seconds
PHASES=(
  "ad36|1.1|ad36-key-prototype|no|1800"
  "hpke|1.2|hpke-review|no|1800"
  "device-key|1.3|browser-device-key|no|2400"
  "naming|1.4|naming-options|no|2400"
  "passkey|1.5|passkey-stepup|no|2400"
  "sandbox|1.6|sandbox-profile|no|1800"
  "authorizer|1.7|sqlite-authorizer|no|1800"
  "argon2id|1.8|argon2id-params|yes|2700"
  "cbor|1.9|canonical-cbor|no|1800"
  "locked-memory|1.10|locked-memory|no|1800"
  "secure-delete|1.11|secure-delete-wal|no|1800"
  "egress|1.12|egress-filter|no|2400"
  "push|1.13|push-delivery|no|1800"
  "separate-origin|1.14|separate-origin|no|3600"
  "core-execution|1.15|core-execution|yes|3600"
  "hybrid-kex|1.16|hybrid-kex|no|2400"
  "prf-probe|1.17|prf-probe|no|2400"
)

usage() {
  sed -n '6,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  echo "Phases: $(phase_names | tr '\n' ' ')"
}

phase_names() {
  local entry
  for entry in "${PHASES[@]}"; do echo "${entry%%|*}"; done
}

is_phase() {
  phase_names | grep -qx -- "$1"
}

# The runner of a phase: the spike's run.sh, or the built-in cargo gates for story 1.1, which
# has no run.sh of its own.
runner_of() {
  local phase="$1" dir="$2"
  if [ "$phase" = "ad36" ]; then
    echo "builtin"
  else
    echo "spikes/$dir/run.sh"
  fi
}

list_phases() {
  local entry phase story dir cpu timeout runner present
  printf '%-16s %-6s %-34s %-5s %-8s %s\n' PHASE STORY RUNNER CPU TIMEOUT PRESENT
  for entry in "${PHASES[@]}"; do
    IFS='|' read -r phase story dir cpu timeout <<<"$entry"
    runner="$(runner_of "$phase" "$dir")"
    present=yes
    if [ "$runner" != "builtin" ] && [ ! -f "$REPO_DIR/$runner" ]; then present=no; fi
    printf '%-16s %-6s %-34s %-5s %-8s %s\n' "$phase" "$story" "$runner" "$cpu" \
      "$((timeout * TIMEOUT_SCALE))s" "$present"
  done
}

# --- Arguments -----------------------------------------------------------------------------
ORIGINAL_ARGS=("$@")
ONLY=()
declare -A SKIP_FLAG=()
KEEP_GOING=0
while [ $# -gt 0 ]; do
  case "$1" in
    --list) list_phases; exit 0 ;;
    --keep-going) KEEP_GOING=1 ;;
    --only)
      [ $# -ge 2 ] || { echo "--only needs a phase name" >&2; exit 2; }
      IFS=',' read -r -a requested <<<"$2"
      ONLY+=("${requested[@]}")
      shift ;;
    --only=*) IFS=',' read -r -a requested <<<"${1#--only=}"; ONLY+=("${requested[@]}") ;;
    --skip-*) SKIP_FLAG["${1#--skip-}"]=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
for name in "${ONLY[@]}" "${!SKIP_FLAG[@]}"; do
  is_phase "$name" || { echo "unknown phase: $name (see --list)" >&2; exit 2; }
done

selected() {
  local name
  [ ${#ONLY[@]} -eq 0 ] && return 0
  for name in "${ONLY[@]}"; do [ "$name" = "$1" ] && return 0; done
  return 1
}

# --- Run context ---------------------------------------------------------------------------
GIT_HEAD="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_SHORT="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(git -C "$REPO_DIR" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$GIT_SHORT"
RESULTS_DIR="$E2E_DIR/results/$RUN_ID"
mkdir -p "$RESULTS_DIR"

if ! DOCKER_SERVER="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"; then
  echo "Docker engine unreachable: start Docker and retry." >&2
  exit 2
fi
DOCKER_RESOURCES="$(docker info --format '{{.NCPU}} CPUs, {{.MemTotal}} bytes' 2>/dev/null || echo unknown)"
HOST_CPUS="$(nproc 2>/dev/null || echo unknown)"
HOST_MEM_KB="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || true)"
HOST_MEM="${HOST_MEM_KB:+$((HOST_MEM_KB / 1024)) MiB}"
COMMAND_LINE="bash e2e/run.sh"
for arg in "${ORIGINAL_ARGS[@]}"; do COMMAND_LINE+=" $(printf '%q' "$arg")"; done

{
  echo "date_utc:        $STARTED_UTC"
  echo "git_head:        $GIT_HEAD ($GIT_BRANCH)"
  echo "git_dirty_paths: $GIT_DIRTY"
  echo "docker_server:   $DOCKER_SERVER"
  echo "docker_engine:   $DOCKER_RESOURCES"
  echo "host:            $HOST_CPUS CPUs, ${HOST_MEM:-unknown memory}, $(uname -s)"
  echo "command:         $COMMAND_LINE"
  echo "results:         e2e/results/$RUN_ID"
} | tee "$RESULTS_DIR/run-info.txt"
echo

# --- Phase runners -------------------------------------------------------------------------
# Both functions run in a child bash through `export -f` (so timeout can bound them).
# shellcheck disable=SC2317
host_path() {
  # Git Bash on Windows: Docker needs a Windows path.
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi
}

# Story 1.1 has no run.sh: the same cargo gates as the other spikes, in the pinned container.
# shellcheck disable=SC2317
run_ad36() {
  local spike_host
  spike_host="$(host_path "$SPIKES_DIR/ad36-key-prototype")"
  MSYS_NO_PATHCONV=1 docker run --rm --interactive \
    -v "$spike_host:/spike:ro" \
    -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
    -v vilicus-ad36-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_TERM_COLOR=never \
    -w /spike \
    "$RUST_IMAGE" bash -s <<'IN_CONTAINER'
set -uo pipefail
status=0
step() {
  local name="$1"; shift
  if "$@" > /tmp/step.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  /' /tmp/step.log
    status=1
  fi
}
echo "INFO image $(. /etc/os-release && echo "$PRETTY_NAME"), $(rustc --version)"
step toolchain_components rustup component add rustfmt clippy
step fmt cargo fmt --check
step clippy cargo clippy --locked --all-targets -- -D warnings
cargo test --locked > /tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' \
        -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -gt 0 ]; then
  echo "PASS tests ($passed passed)"
else
  echo "FAIL tests (exit $tests_status, $passed passed)"
  tail -n 60 /tmp/tests.log | sed 's/^/  | /'
  status=1
fi
exit $status
IN_CONTAINER
}

running_containers() {
  docker ps --quiet 2>/dev/null | wc -l | tr -d ' '
}

# A CPU-sensitive phase must measure on an idle engine: wait for other containers to stop.
wait_for_idle_engine() {
  local waited=0 count
  count="$(running_containers)"
  while [ "$count" -ne 0 ]; do
    if [ "$waited" -ge "$IDLE_WAIT" ]; then
      echo "Engine still busy after ${IDLE_WAIT}s: $count container(s) running:"
      docker ps --format '  {{.Names}} ({{.Image}}, {{.Status}})'
      echo "Stop them (or raise E2E_IDLE_WAIT) and rerun this phase with --only."
      return 1
    fi
    echo "Waiting for an idle engine: $count container(s) running (${waited}s of ${IDLE_WAIT}s)"
    sleep 10
    waited=$((waited + 10))
    count="$(running_containers)"
  done
}

count_lines() {
  local pattern="$1" file="$2" n
  n="$(grep -cE "$pattern" "$file" 2>/dev/null)" || true
  echo "${n:-0}"
}

# --- Campaign ------------------------------------------------------------------------------
SUMMARY_TSV="$RESULTS_DIR/summary.tsv"
printf 'phase\tstory\tstatus\texit_code\tpass\tfail\tinfo\tduration_s\tskip_reason\n' > "$SUMMARY_TSV"
EXIT_CODE=0
FAILED_PHASES=()

record() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$SUMMARY_TSV"
}

for entry in "${PHASES[@]}"; do
  IFS='|' read -r phase story dir cpu timeout <<<"$entry"
  runner="$(runner_of "$phase" "$dir")"
  log="$RESULTS_DIR/$phase.log"

  skip_reason=""
  if ! selected "$phase"; then
    skip_reason="not selected by --only"
  elif [ -n "${SKIP_FLAG[$phase]:-}" ]; then
    skip_reason="--skip-$phase"
  elif [ "$runner" != "builtin" ] && [ ! -f "$REPO_DIR/$runner" ]; then
    skip_reason="$runner does not exist"
  elif [ "$EXIT_CODE" -ne 0 ] && [ "$KEEP_GOING" -eq 0 ]; then
    skip_reason="earlier phase failed (use --keep-going)"
  fi
  if [ -n "$skip_reason" ]; then
    record "$phase" "$story" SKIP - 0 0 0 0 "$skip_reason"
    if selected "$phase"; then echo "=== SKIP $phase (story $story): $skip_reason ==="; fi
    continue
  fi

  echo "=== PHASE $phase (story $story, $runner, timeout $((timeout * TIMEOUT_SCALE))s) ==="
  started=$(date +%s)
  : > "$log"

  phase_exit=0
  engine_busy=0
  if [ "$cpu" = "yes" ] && ! wait_for_idle_engine 2>&1 | tee -a "$log"; then
    engine_busy=1
    phase_exit=125
  fi
  if [ "$engine_busy" -eq 0 ]; then
    set +e
    if [ "$runner" = "builtin" ]; then
      export -f run_ad36 host_path
      export SPIKES_DIR RUST_IMAGE
      timeout --kill-after=60 "$((timeout * TIMEOUT_SCALE))" bash -c run_ad36 2>&1 | tee -a "$log"
    else
      timeout --kill-after=60 "$((timeout * TIMEOUT_SCALE))" bash "$REPO_DIR/$runner" 2>&1 | tee -a "$log"
    fi
    phase_exit=${PIPESTATUS[0]}
    set -e
  fi
  duration=$(( $(date +%s) - started ))

  pass=$(count_lines '^PASS ' "$log")
  fail=$(count_lines '^FAIL ' "$log")
  info=$(count_lines '^[[:space:]]*INFO ' "$log")
  # A phase passes only when its runner exits zero, prints at least one PASS and no FAIL.
  status=PASS
  note=""
  if [ "$phase_exit" -eq 124 ] || [ "$phase_exit" -eq 137 ]; then
    status=TIMEOUT
    note="timed out after $((timeout * TIMEOUT_SCALE))s"
  elif [ "$engine_busy" -eq 1 ]; then
    status=FAIL
    note="engine not idle"
  elif [ "$phase_exit" -ne 0 ] || [ "$fail" -ne 0 ] || [ "$pass" -eq 0 ]; then
    status=FAIL
  fi
  record "$phase" "$story" "$status" "$phase_exit" "$pass" "$fail" "$info" "$duration" "$note"

  if [ "$status" != "PASS" ]; then
    EXIT_CODE=1
    FAILED_PHASES+=("$phase")
    echo
    echo "--- $phase $status (exit $phase_exit${note:+, $note}); last 40 lines of e2e/results/$RUN_ID/$phase.log ---"
    tail -n 40 "$log"
    if [ "$status" = "TIMEOUT" ]; then
      echo "--- containers still running after the timeout (not stopped by this harness) ---"
      docker ps --format '  {{.Names}} ({{.Image}}, {{.Status}})'
    fi
  fi
  echo "=== END $phase: $status in ${duration}s (pass $pass, fail $fail, info $info) ==="
  echo
done

# --- Summary -------------------------------------------------------------------------------
FINISHED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "# E2E run $RUN_ID"
  echo
  echo '```'
  cat "$RESULTS_DIR/run-info.txt"
  echo "finished_utc:    $FINISHED_UTC"
  echo '```'
  echo
  echo "| Phase | Story | Status | Exit | PASS | FAIL | INFO | Duration (s) | Skip reason or note |"
  echo "|---|---|---|---|---|---|---|---|---|"
  tail -n +2 "$SUMMARY_TSV" | while IFS=$'\t' read -r p s st ec pa fa in du re; do
    echo "| $p | $s | $st | $ec | $pa | $fa | $in | $du | $re |"
  done
  echo
  if [ "$EXIT_CODE" -eq 0 ]; then
    echo "Result: all selected phases passed."
  else
    echo "Result: failed phases: ${FAILED_PHASES[*]}."
  fi
} > "$RESULTS_DIR/summary.md"

echo "=== SUMMARY (e2e/results/$RUN_ID) ==="
column -t -s $'\t' "$SUMMARY_TSV" 2>/dev/null || cat "$SUMMARY_TSV"
echo

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "=== ALL E2E TESTS PASSED ==="
else
  echo "=== E2E FAILED: ${FAILED_PHASES[*]} ==="
fi
exit "$EXIT_CODE"
