#!/usr/bin/env bash
# E26 spike (story 1.14): runs the cargo gates and the release build in a Debian 13 Rust
# container, starts the test network (own DNS server, test PKI, Gateway stand-in, attacker sink,
# Caddy and nginx), checks the API's side-effect rules, then drives Chromium and Firefox of two
# Playwright releases through every instance name and mode. Prints one `PASS <name>` or
# `FAIL <name>` line per check (plus `INFO` lines), ends with `RESULT PASS` or `RESULT FAIL`,
# removes its compose project, and exits non-zero on any failure. Needs only Docker; runs from
# Linux or from Git Bash on Windows.
set -uo pipefail

# rust:1-trixie (Debian 13), the same digest as docker/compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
TARGET_VOLUME="vilicus-separate-origin-target"
PROJECT="vilicus-e26"
# Update when a test function is added or removed: a run that silently lost tests must not pass.
EXPECTED_TESTS=43
# PASS plus FAIL lines each browser harness must print; a harness that skipped checks must not
# pass. Update when a check is added to or removed from harness/harness.mjs or the layout.
EXPECTED_BROWSER_CHECKS=1110
EXPECTED_BRANDED_CHECKS=558

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Git Bash on Windows: give Docker a Windows path and stop MSYS rewriting container paths.
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi
# Checks expected to FAIL, each with the story finding it records (one check name per line).
KNOWN="$SPIKE_DIR/known-findings.txt"
COMPOSE=(docker compose --project-name "$PROJECT" --file "$HOST_DIR/docker/compose.yaml")
WORK="$(mktemp -d)"

failed=0
record() {
  echo "$1 $2"
  [ "$1" = PASS ] || failed=1
}
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1
  for f in "$WORK"/*; do [ -f "$f" ] && : >"$f"; done
}
trap cleanup EXIT

# --- 1. Crate checks and release build ------------------------------------------------------
docker volume create "$TARGET_VOLUME" >/dev/null
docker run --rm --interactive \
  -v "$HOST_DIR:/spike:ro" \
  -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
  -v "$TARGET_VOLUME:/target" \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e EXPECTED_TESTS="$EXPECTED_TESTS" \
  -w /spike \
  "$RUST_IMAGE" bash -s <<'IN_CONTAINER' || failed=1
set -uo pipefail
status=0
step() {
  local name="$1"; shift
  if "$@" >/tmp/step.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  | /' /tmp/step.log
    status=1
  fi
}
echo "INFO $(rustc --version)"
step toolchain_components rustup component add rustfmt clippy
step fmt cargo fmt --check
step clippy cargo clippy --locked --all-targets -- -D warnings
step build_release cargo build --locked --release
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$EXPECTED_TESTS" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
  grep -h -A20 '^failures:' /tmp/tests.log | sed 's/^/  | /'
  status=1
fi
exit "$status"
IN_CONTAINER

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi

# --- 2. Test network ------------------------------------------------------------------------
"${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1
if ! "${COMPOSE[@]}" build --quiet >"$WORK/build.log" 2>&1 || ! "${COMPOSE[@]}" up --detach --quiet-pull >"$WORK/up.log" 2>&1; then
  record FAIL network_up
  sed 's/^/  | /' "$WORK/build.log" "$WORK/up.log"
  echo "RESULT FAIL"
  exit 1
fi
ready=0
for _ in $(seq 1 90); do
  logs="$("${COMPOSE[@]}" logs 2>/dev/null)"
  if [ "$(grep -c 'event=ready role=' <<<"$logs")" -ge 6 ]; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  record FAIL network_ready
  "${COMPOSE[@]}" logs 2>&1 | tail -40 | sed 's/^/  | /'
  echo "RESULT FAIL"
  exit 1
fi
record PASS network_ready
echo "INFO docker $(docker version --format '{{.Server.Version}}')"
echo "INFO $("${COMPOSE[@]}" exec -T caddy caddy version 2>&1 | head -n 1 | sed 's/^/caddy /')"
echo "INFO $("${COMPOSE[@]}" exec -T nginx nginx -v 2>&1)"

# --- 3. The API's side-effect rules, seen from the network ------------------------------------
# A signed POST with a session changes state; nothing else does. The browser checks then require
# that the counter never moves during their runs.
# shellcheck disable=SC2016 # expanded by the shell inside the browser container
api_out="$("${COMPOSE[@]}" exec -T browser-current sh -c '
  set -u
  name="$(awk '"'"'$1 == "instance" && $3 == "direct" { print $4; exit }'"'"' /layout/instances.txt)"
  cat /pki/ca-*.crt > /tmp/all-cas.crt
  c="curl -sS --max-time 10 --cacert /tmp/all-cas.crt -c /tmp/jar -b /tmp/jar"
  state() { curl -sS --max-time 10 http://10.89.0.10:9000/state; echo; }
  echo "start $(state)"
  echo "login $($c -o /dev/null -w "%{http_code}" -X POST "https://$name/api/login")"
  echo "get_action $($c -o /dev/null -w "%{http_code}" "https://$name/api/action") $(state)"
  echo "unsigned $($c -o /dev/null -w "%{http_code}" -X POST "https://$name/api/action") $(state)"
  echo "no_session $(curl -sS --max-time 10 --cacert /tmp/all-cas.crt -o /dev/null -w "%{http_code}" -H "x-vilicus-signature: s" -X POST "https://$name/api/action") $(state)"
  echo "signed $($c -o /dev/null -w "%{http_code}" -H "x-vilicus-signature: s" -X POST "https://$name/api/action") $(state)"
' 2>&1)"
expect_line() {
  if grep -Eq -- "$2" <<<"$api_out"; then record PASS "$1"; else record FAIL "$1"; fi
}
expect_line api.login_sets_session '^login 204$'
expect_line api.counter_starts_at_zero '^start [{]"mutations":0[}]$'
expect_line api.get_on_action_has_no_side_effect '^get_action 405 [{]"mutations":0[}]$'
expect_line api.post_without_signature_refused '^unsigned 403 [{]"mutations":0[}]$'
expect_line api.post_without_session_refused '^no_session 403 [{]"mutations":0[}]$'
expect_line api.signed_post_with_session_changes_state '^signed 200 [{]"mutations":1[}]$'
if [ "$failed" -ne 0 ]; then
  while IFS= read -r line; do echo "  | $line"; done <<<"$api_out"
fi

# --- 4. Browsers ------------------------------------------------------------------------------
# label, compose service, engine, run id prefix; the four harnesses run in parallel.
# label, compose service, expected PASS plus FAIL lines, then the command. The Playwright
# harnesses run every mode; the branded Firefox builds rerun the passive fixtures only.
browsers=(
  "chromium-current browser-current $EXPECTED_BROWSER_CHECKS harness.mjs chromium chromium-current cc"
  "firefox-current browser-current $EXPECTED_BROWSER_CHECKS harness.mjs firefox firefox-current fc"
  "chromium-previous browser-previous $EXPECTED_BROWSER_CHECKS harness.mjs chromium chromium-previous cp"
  "firefox-previous browser-previous $EXPECTED_BROWSER_CHECKS harness.mjs firefox firefox-previous fp"
  "branded-firefox-158 browser-branded $EXPECTED_BRANDED_CHECKS branded.mjs branded-firefox-158 /opt/firefox-158/firefox/firefox 4444 ba"
  "branded-firefox-157 browser-branded $EXPECTED_BRANDED_CHECKS branded.mjs branded-firefox-157 /opt/firefox-157/firefox/firefox 4445 bb"
)
pids=()
: >"$WORK/seen-known"
for entry in "${browsers[@]}"; do
  read -r label service _ script args <<<"$entry"
  # shellcheck disable=SC2086 # the argument list is split on purpose
  "${COMPOSE[@]}" exec -T "$service" node "/app/harness/$script" $args >"$WORK/$label.log" 2>&1 &
  pids+=("$!")
done
for i in "${!browsers[@]}"; do
  read -r label _ expected _ <<<"${browsers[$i]}"
  wait "${pids[$i]}"
  # The harness exits 1 whenever it printed a FAIL line; which FAILs are acceptable is decided
  # below against the known findings, and a crash shows up as unclean output or a short count.
  # A known finding prints KNOWN-FAIL; a known finding that passes, and any other FAIL, fail.
  grep -E '^INFO ' "$WORK/$label.log"
  # shellcheck disable=SC2016 # awk program
  if ! awk -v known="$KNOWN" -v seenfile="$WORK/seen-known" '
    BEGIN {
      while ((getline line < known) > 0) {
        if (line ~ /^#/ || line == "") continue
        name = line; sub(/ .*/, "", name)
        finding = line; sub(/^[^ ]+ /, "", finding)
        K[name] = finding
      }
    }
    /^(PASS|FAIL) / {
      if ($2 in K) {
        print $2 >> seenfile
        if ($1 == "FAIL") print "KNOWN-FAIL " $2 " " K[$2]
        else { print "FAIL " $2 " (known finding no longer reproduces: " K[$2] ")"; bad = 1 }
      } else {
        print
        if ($1 == "FAIL") bad = 1
      }
    }
    END { exit bad }' "$WORK/$label.log"; then
    failed=1
  fi
  if grep -Evq '^(PASS|FAIL|INFO) ' "$WORK/$label.log"; then
    record FAIL "$label.harness_output_clean"
    grep -Ev '^(PASS|FAIL|INFO) ' "$WORK/$label.log" | head -20 | sed 's/^/  | /'
  fi
  count="$(grep -Ec '^(PASS|FAIL) ' "$WORK/$label.log")"
  if [ "$count" -eq "$expected" ]; then
    record PASS "$label.check_count ($count checks, $expected expected)"
  else
    record FAIL "$label.check_count ($count checks, $expected expected)"
  fi
done

# Every known finding must have been checked in this run.
while read -r name _; do
  case "$name" in ''|'#'*) continue ;; esac
  if ! grep -qxF -- "$name" "$WORK/seen-known"; then
    record FAIL "$name (known finding not checked in this run)"
  fi
done <"$KNOWN"

if [ "$failed" -eq 0 ]; then
  echo "RESULT PASS"
else
  echo "RESULT FAIL"
fi
exit "$failed"
