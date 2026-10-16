#!/usr/bin/env bash
# E13 spike, simulated end to end: runs the cargo gates in a Debian 13 container, then the whole
# pipeline on a Docker Compose test network (two ntfy servers, the sender and collector, two
# simulated phones with injected delays and outages). Prints one `PASS <name>` or `FAIL <name>`
# line per check, ends with `RESULT PASS` or `RESULT FAIL`, removes its compose project, and
# exits non-zero on any failure. The simulation uses a shortened criterion and never yields an
# E13 result; the real run is in RUNBOOK.md. Runs from Linux or from Git Bash on Windows; needs
# Docker only.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
fi
export MSYS_NO_PATHCONV=1
image="vilicus-spike-push-delivery"
ntfy_image="binwiederhier/ntfy@sha256:803b2aaeb94df76c8b32ecd91039dc80b0fddb7041dcaf082b33bcdfd4ba39ad"
runtime_image="vilicus-spike-push-delivery-runtime"
compose=(docker compose -f "$mount_dir/compose/compose.yaml" -p vilicus-e13)
log="$(mktemp)"
report="$(mktemp)"
failed=0

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  : >"$log"
  : >"$report"
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

# ---------------------------------------------------------------------------------------------
# Cargo gates, in the same image family as the other spikes.
docker build --quiet --tag "$image" "$mount_dir" >/dev/null
docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume vilicus-push-delivery-target:/target \
  --volume vilicus-cargo-registry:/usr/local/cargo/registry \
  --env CARGO_TARGET_DIR=/target \
  --workdir /src \
  "$image" bash -s <<'IN_CONTAINER' || failed=1
set -uo pipefail
failed=0
check() {
  local name="$1"; shift
  if "$@" >/tmp/check.log 2>&1; then echo "PASS $name"; else echo "FAIL $name"; sed 's/^/  | /' /tmp/check.log; failed=1; fi
}
echo "INFO $(rustc --version)"
for crate in tokio hyper hyper-util hyper-rustls rustls serde_json getrandom; do
  echo "INFO $crate $(grep -A1 "^name = \"$crate\"$" Cargo.lock | sed -n 's/version = "\(.*\)"/\1/p' | tr '\n' ' ')"
done
check fmt cargo fmt --check
check clippy cargo clippy --locked --all-targets -- -D warnings
check build_tests cargo test --locked --no-run
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
# A run that silently lost or skipped tests must not pass. Update EXPECTED_TESTS when a test
# function or a doc test is added or removed.
EXPECTED_TESTS=37
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$EXPECTED_TESTS" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $EXPECTED_TESTS expected)"
  grep -h -A20 '^failures:' /tmp/tests.log | sed 's/^/  | /' || true
  failed=1
fi
exit "$failed"
IN_CONTAINER

# ---------------------------------------------------------------------------------------------
# Test network. Fresh topics, tokens and password hash for every run; nothing is written to disk.
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
export E13_DURATION_MS=45000
export E13_PHONE_DURATION_MS=50000
export TOPIC_P1_SELF="" TOPIC_P2_SELF="" TOPIC_P1_PUBLIC="" TOPIC_P2_PUBLIC=""
export TOKEN_SENDER="" TOKEN_P1="" TOKEN_P2="" E13_AUTH_USERS="" E13_AUTH_ACCESS="" E13_AUTH_TOKENS=""
"${compose[@]}" build --quiet core >/dev/null 2>&1
docker pull --quiet "$ntfy_image" >/dev/null
tool() { docker run --rm "$runtime_image" push-delivery "$@"; }
TOPIC_P1_SELF="$(tool new-topic)"
TOPIC_P2_SELF="$(tool new-topic)"
TOPIC_P1_PUBLIC="$(tool new-topic)"
TOPIC_P2_PUBLIC="$(tool new-topic)"
TOKEN_SENDER="$(tool new-ntfy-token)"
TOKEN_P1="$(tool new-ntfy-token)"
TOKEN_P2="$(tool new-ntfy-token)"
# Users authenticate with tokens only; the password behind the hash is random and discarded.
password="$(tool new-topic)"
# shellcheck disable=SC2016 # a regular expression for the bcrypt hash, not an expansion
hash="$(printf '%s\n%s\n' "$password" "$password" | docker run --rm -i "$ntfy_image" user hash 2>/dev/null | grep -Eo '\$2[aby]\$[0-9]+\$[./A-Za-z0-9]{53}')"
E13_AUTH_USERS="sender:$hash:user,phone1:$hash:user,phone2:$hash:user"
E13_AUTH_ACCESS="sender:$TOPIC_P1_SELF:wo,sender:$TOPIC_P2_SELF:wo,phone1:$TOPIC_P1_SELF:ro,phone2:$TOPIC_P2_SELF:ro"
E13_AUTH_TOKENS="sender:$TOKEN_SENDER,phone1:$TOKEN_P1,phone2:$TOKEN_P2"
"${compose[@]}" up --detach --quiet-pull >/dev/null 2>&1

ready=0
for _ in $(seq 1 60); do
  if grep -q 'event=ready' < <("${compose[@]}" logs --no-log-prefix core 2>/dev/null); then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  "${compose[@]}" logs >"$log" 2>&1 || true
  record FAIL network_ready
  echo "RESULT FAIL"
  exit 1
fi
record PASS network_ready
echo "INFO $("${compose[@]}" exec -T ntfy-self ntfy --version 2>&1 | head -n 1)"
echo "INFO $("${compose[@]}" exec -T phone-1 curl --version | head -n 1)"
echo "INFO docker $(docker version --format '{{.Server.Version}}')"

# ---------------------------------------------------------------------------------------------
# Topic protection on the self-hosted server (D118, AD-32), checked while the run is going.
on_phone() { "${compose[@]}" exec -T phone-1 "$@"; }
code() { on_phone curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 "$@"; }
self_url="http://ntfy-self"
expect_ok access.anonymous_read_refused '^(401|403)$' code "$self_url/$TOPIC_P1_SELF/json?poll=1"
expect_ok access.anonymous_publish_refused '^(401|403)$' code -d probe "$self_url/$TOPIC_P1_SELF"
expect_ok access.phone_cannot_publish '^(401|403)$' code -H "Authorization: Bearer $TOKEN_P1" -d probe "$self_url/$TOPIC_P1_SELF"
expect_ok access.phone_cannot_read_another_phone '^(401|403)$' code -H "Authorization: Bearer $TOKEN_P1" "$self_url/$TOPIC_P2_SELF/json?poll=1"
expect_ok access.sender_cannot_read '^(401|403)$' code -H "Authorization: Bearer $TOKEN_SENDER" "$self_url/$TOPIC_P1_SELF/json?poll=1"
expect_ok access.phone_reads_its_own_topic '^200$' code -H "Authorization: Bearer $TOKEN_P1" "$self_url/$TOPIC_P1_SELF/json?poll=1"
expect_ok access.wrong_token_refused '^(401|403)$' code -H "Authorization: Bearer $(tool new-ntfy-token)" "$self_url/$TOPIC_P1_SELF/json?poll=1"

# ---------------------------------------------------------------------------------------------
# The run: wait for the sender to stop and drain, then for the phones.
core_status="$(docker wait "$("${compose[@]}" ps -q core)")"
for phone in phone-1 phone-2; do docker wait "$("${compose[@]}" ps -q -a "$phone")" >/dev/null; done
"${compose[@]}" logs --no-log-prefix core >"$log" 2>&1 || true
if [ "$core_status" = 0 ] && grep -q 'event=done' "$log"; then record PASS run.completed; else record FAIL run.completed; fi
expect_ok run.no_publish_failure '^0$' sh -c "\"\$@\" | grep -c 'event=publish-failed' || true" _ "${compose[@]}" logs --no-log-prefix core
expect_ok run.no_ack_failure '^0$' sh -c "\"\$@\" | grep -c 'event=ack-failed' || true" _ "${compose[@]}" logs --no-log-prefix phone-1 phone-2

in_core() { "${compose[@]}" run --rm --no-deps -T core "$@" 2>/dev/null; }
in_core push-delivery report --config /etc/push-delivery/sim.conf --explain >"$report" || true
echo "INFO report:"
sed 's/^/  | /' "$report"
report_line() { grep -E "^target phone=$1 server=$2 " "$report"; }
field() { report_line "$1" "$2" | tr ' ' '\n' | sed -n "s/^$3=//p"; }

# AC1: delays recorded per phone and per server under anonymous labels.
expect_ok ac1.four_targets_reported '^4$' sh -c "grep -c '^target ' '$report'"
for target in phone-1:self-hosted phone-1:public phone-2:self-hosted phone-2:public; do
  phone="${target%%:*}" server="${target#*:}"
  expect_ok "ac1.$phone.$server.at_least_100_alerts_evaluated_none_pending" '^ok$' \
    sh -c "[ \"$(field "$phone" "$server" evaluated)\" -ge 100 ] && [ \"$(field "$phone" "$server" pending)\" -eq 0 ] && echo ok"
done
results_copy="$(in_core cat /var/lib/push-delivery/results.tsv)"
record_shape='
  /^send\t[0-9a-f]{32}\tphone-[12]\t(self-hosted|public)\t[0-9]+\t(ok|failed)$/ { n++; next }
  /^ack\t[0-9a-f]{32}\t[0-9]+\t([0-9]+|-)$/ { n++; next }
  { bad++ }
  END { if (n > 0 && bad == 0) print "ok"; else print "bad=" bad " good=" n }'
# shellcheck disable=SC2016 # expanded by the inner shell
expect_ok ac1.results_lines_hold_only_ids_labels_kinds_and_times '^ok$' \
  sh -c 'printf "%s\n" "$1" | awk "$2"' _ "$results_copy" "$record_shape"
leaks=0
for secret in "$TOPIC_P1_SELF" "$TOPIC_P2_SELF" "$TOPIC_P1_PUBLIC" "$TOPIC_P2_PUBLIC" "$TOKEN_SENDER" "$TOKEN_P1" "$TOKEN_P2" ntfy http 10.113.13.; do
  if grep -qF -- "$secret" <<<"$results_copy"; then leaks=$((leaks + 1)); fi
done
results_copy=""
expect_ok ac1.results_hold_no_topic_token_url_or_server_name '^0$' echo "$leaks"

# Content-free payloads: every message each server stored is the generic text and one id.
audit() {
  local phone="$1" server="$2" url="$3" token="$4"
  local published=$(( $(field "$phone" "$server" evaluated) - $(field "$phone" "$server" unpublished) ))
  expect_ok "ac1.$phone.$server.every_stored_message_content_free" "content_free=$published\$" \
    on_phone_run push-delivery audit-cache --url "$url" --token "$token" --expect "$published"
}
on_phone_run() { "${compose[@]}" run --rm --no-deps -T phone-1 "$@"; }
audit phone-1 self-hosted "$self_url/$TOPIC_P1_SELF" "$TOKEN_P1"
audit phone-2 self-hosted "$self_url/$TOPIC_P2_SELF" "$TOKEN_P2"
audit_public() {
  local phone="$1" topic="$2"
  local published=$(( $(field "$phone" public evaluated) - $(field "$phone" public unpublished) ))
  expect_ok "ac1.$phone.public.every_stored_message_content_free" "content_free=$published\$" \
    on_phone_run push-delivery audit-cache --url "http://ntfy-public/$topic" --expect "$published"
}
audit_public phone-1 "$TOPIC_P1_PUBLIC"
audit_public phone-2 "$TOPIC_P2_PUBLIC"

# AC2: per-phone verdicts, per-server verdicts and the D118 E13 rule, on simulation parameters.
expect_ok ac2.phone-1.self-hosted.all_in_time 'late=0 missing=0 unpublished=0 .*rate_percent=100.00 .*verdict=PASS' report_line phone-1 self-hosted
expect_ok ac2.phone-1.public.all_in_time_after_resumed_outage 'late=0 missing=0 unpublished=0 .*rate_percent=100.00 .*verdict=PASS' report_line phone-1 public
expect_ok ac2.phone-2.self-hosted.all_in_time_with_slow_acknowledgements 'late=0 missing=0 unpublished=0 .*rate_percent=100.00 .*verdict=PASS' report_line phone-2 self-hosted
expect_ok ac2.phone-2.self-hosted.slow_acknowledgements_seen '^ok$' sh -c "[ \"$(field phone-2 self-hosted max_ms)\" -ge 1000 ] && echo ok"
expect_ok ac2.phone-2.public.late_and_missing_alerts_fail_it '^ok$' sh -c "
  [ \"$(field phone-2 public late)\" -gt 0 ] && [ \"$(field phone-2 public missing)\" -gt 0 ] \
  && [ \"$(field phone-2 public verdict)\" = FAIL ] && echo ok"
expect_ok ac2.server.self-hosted.pass '^server server=self-hosted verdict=PASS criterion=simulation$' grep '^server server=self-hosted' "$report"
expect_ok ac2.server.public.fail_not_recommended '^server server=public verdict=FAIL status=not-recommended criterion=simulation$' grep '^server server=public' "$report"
expect_ok ac2.e13_follows_the_self_hosted_server '^e13 verdict=PASS self_hosted=PASS public=FAIL criterion=simulation$' grep '^e13 ' "$report"
expect_ok ac2.labelled_not_an_e13_result 'this is not an E13 result' cat "$report"
expect_ok ac2.no_unknown_acknowledgement '^unknown_acks count=0$' grep '^unknown_acks' "$report"

# Every alert that was not in time is explained by an injected outage of that connection: late
# ones by a resumed outage, missing ones by a lossy one (1 s margin for alerts in flight).
"${compose[@]}" logs --no-log-prefix phone-1 phone-2 2>/dev/null | grep '^outage ' >"$log.outages" || true
expect_ok faults.four_outages_logged '^4$' sh -c "wc -l <'$log.outages' | tr -d ' '"
expect_ok faults.only_phone-2_public_has_alerts_not_in_time '^0$' sh -c "grep '^alert ' '$report' | grep -vc 'phone=phone-2 server=public' || true"
expect_ok faults.every_late_or_missing_alert_falls_in_an_outage '^ok [1-9][0-9]*$' sh -c "
  awk '
    FNR == NR && /phone=phone-2 server=public/ {
      for (i = 1; i <= NF; i++) { split(\$i, kv, \"=\"); f[kv[1]] = kv[2] }
      n++; start[n] = f[\"start_ms\"]; end[n] = f[\"end_ms\"]; mode[n] = f[\"mode\"]; next
    }
    FNR != NR && /^alert phone=phone-2 server=public/ {
      for (i = 1; i <= NF; i++) { split(\$i, kv, \"=\"); g[kv[1]] = kv[2] }
      want = (g[\"outcome\"] == \"late\") ? \"resume\" : \"lossy\"; hit = 0
      for (j = 1; j <= n; j++)
        if (mode[j] == want && g[\"sent_ms\"] >= start[j] - 1000 && g[\"sent_ms\"] <= end[j] + 1000) hit = 1
      if (!hit) { print \"unexplained \" \$0; bad++ }
      total++
    }
    END { if (bad == 0) print \"ok \" total }' '$log.outages' '$report'"
expect_ok faults.resumed_with_last_id '^[1-9]' sh -c "\"\$@\" | grep -c 'event=subscribed phone=phone-2 server=public since=last-id'" _ "${compose[@]}" logs --no-log-prefix phone-2
expect_ok faults.lossy_reconnect_without_last_id '^[1-9]' sh -c "\"\$@\" | grep -c 'event=subscribed phone=phone-2 server=public since=none'" _ "${compose[@]}" logs --no-log-prefix phone-2
: >"$log.outages"

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
