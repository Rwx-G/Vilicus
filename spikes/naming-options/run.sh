#!/usr/bin/env bash
# Spike E24 (story 1.4): passkeys and an installable web app under each naming option.
#
# 1. Builds and checks the crate in a Debian 13 Rust container (build, fmt, clippy, tests; no
#    test may be ignored or missing).
# 2. Starts the compose test bed (DNS servers, test certificate authorities, one test instance
#    per naming option, the self-signed instance of AC2) on internal networks only.
# 3. Runs the DNS checks, then the browser driver in each browser (current and previous Chrome
#    and Firefox, desktop builds on Linux).
# 4. Prints one `PASS <name>` or `FAIL <name>` line per check, the matrix, `RESULT PASS` or
#    `RESULT FAIL`, removes the compose project, and exits non-zero on any failure.
#
# Runs from Linux or from Git Bash on Windows; needs Docker with compose, and network access
# the first time to build the images.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
fi
export MSYS_NO_PATHCONV=1
build_image="vilicus-spike-e24-build"
target_volume="vilicus-e24-target"
compose=(docker compose -f "$mount_dir/compose/compose.yaml" -p vilicus-e24
  --profile setup --profile probe --profile browsers)
browsers=(chrome-155 chrome-154 firefox-158 firefox-157)
work="$(mktemp -d)"
failed=0

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 || true
}
trap cleanup EXIT

record() {
  local status="$1" name="$2" log="${3:-}"
  echo "$status $name"
  if [ "$status" = FAIL ]; then
    failed=1
    if [ -n "$log" ]; then sed 's/^/  | /' "$log"; fi
  fi
}

# ---------------------------------------------------------------------------------------------
# 1. Cargo gates.
docker build --quiet --tag "$build_image" - <"$spike_dir/Dockerfile.build" >/dev/null
docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume "$target_volume:/target" \
  --volume vilicus-cargo-registry:/usr/local/cargo/registry \
  --env CARGO_TARGET_DIR=/target \
  --env CARGO_TERM_COLOR=never \
  --workdir /src \
  "$build_image" bash -s <<'IN_BUILD' || failed=1
set -uo pipefail
failed=0
step() {
  local name="$1"; shift
  if "$@" >/tmp/step.log 2>&1; then
    echo "PASS $name"
  else
    echo "FAIL $name"
    sed 's/^/  | /' /tmp/step.log
    failed=1
  fi
}
echo "INFO $(rustc --version)"
echo "INFO $(grep -A1 '^name = "webauthn-rs"$' Cargo.lock | tr '\n' ' ')"
step build cargo build --locked --all-targets
step fmt cargo fmt --check
step clippy cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' \
        -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
# Every test in the tree must have run and passed; none may be ignored.
expected=$(grep -rhE '#\[(tokio::)?test\]' src | wc -l)
passed=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) passed.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
ignored=$(grep -h '^test result:' /tmp/tests.log | sed 's/.* \([0-9]*\) ignored.*/\1/' | awk '{ s += $1 } END { print s + 0 }')
if [ "$tests_status" -eq 0 ] && [ "$passed" -eq "$expected" ] && [ "$ignored" -eq 0 ]; then
  echo "PASS test_count ($passed passed, $ignored ignored, $expected expected)"
else
  echo "FAIL test_count ($passed passed, $ignored ignored, $expected expected)"
  grep -h -A20 '^failures:' /tmp/tests.log | sed 's/^/  | /' || true
  failed=1
fi
exit $failed
IN_BUILD

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL (cargo gates)"
  exit 1
fi

# ---------------------------------------------------------------------------------------------
# 2. Test bed.
"${compose[@]}" build --quiet certs browsers >/dev/null
"${compose[@]}" down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 || true
"${compose[@]}" run --rm certs | grep '^INFO' || true
"${compose[@]}" up --detach --quiet-pull public-dns overlay-dns router router-strict probe lan-client \
  srv-dyndns srv-overlay srv-localca srv-ip srv-selfsigned srv-mdns srv-same >/dev/null 2>&1
probe() { "${compose[@]}" exec -T probe "$@"; }
for endpoint in 10.88.0.21/443 100.64.88.22/443 10.88.0.23/443 10.88.0.24/443 10.88.0.25/443 \
  10.88.0.26/443 10.88.0.27/443 10.88.0.27/8443; do
  for _ in $(seq 1 50); do
    if probe timeout 1 bash -c "</dev/tcp/$endpoint" 2>/dev/null; then break; fi
    sleep 0.2
  done
done

# ---------------------------------------------------------------------------------------------
# 3. DNS checks: what each naming option needs from name resolution.
dig_short() { probe dig +short +time=2 +tries=1 "@$1" "$2" A 2>&1 | tr -d '\r' | tr '\n' ' ' | sed 's/ $//'; }
dns_expect() {
  local name="$1" server="$2" host="$3" expected="$4" answer
  answer="$(dig_short "$server" "$host")"
  echo "$answer" >"$work/dns.log"
  if [ "$answer" = "$expected" ]; then
    record PASS "dns.$name ($host -> ${answer:-no address})"
  else
    record FAIL "dns.$name ($host -> ${answer:-no address}, expected ${expected:-no address})" "$work/dns.log"
  fi
}
dns_expect dyndns_private_answer_with_rebind_exception 10.88.0.53 household.dyn.example 10.88.0.21
dns_expect dyndns_private_answer_dropped_by_rebind_protection 10.88.0.54 household.dyn.example ""
"${compose[@]}" logs router-strict >"$work/router-strict.log" 2>&1
if grep -q 'possible DNS-rebind attack detected: household.dyn.example' "$work/router-strict.log"; then
  record PASS "dns.rebind_protection_logged_the_dyndns_answer"
else
  record FAIL "dns.rebind_protection_logged_the_dyndns_answer" "$work/router-strict.log"
fi
# The private-network name: only a device that joined the overlay resolves and reaches it.
dns_expect overlay_name_by_overlay_resolver 100.64.88.53 household.tailnet.example 100.64.88.22
dns_expect overlay_resolver_forwards_lan_names 100.64.88.53 vilicus.home.arpa 10.88.0.23
dns_expect overlay_name_unknown_to_home_router 10.88.0.53 household.tailnet.example ""
if "${compose[@]}" exec -T lan-client getent hosts household.tailnet.example >"$work/lan-client.log" 2>&1; then
  record FAIL "dns.lan_only_client_cannot_resolve_overlay_name" "$work/lan-client.log"
else
  record PASS "dns.lan_only_client_cannot_resolve_overlay_name"
fi
if "${compose[@]}" exec -T lan-client timeout 3 bash -c '</dev/tcp/100.64.88.22/443' >"$work/lan-client.log" 2>&1; then
  record FAIL "net.lan_only_client_cannot_reach_overlay_instance" "$work/lan-client.log"
else
  record PASS "net.lan_only_client_cannot_reach_overlay_instance"
fi
# dnsmasq's rebinding protection does not cover 100.64.0.0/10: the overlay answer passes it.
dns_expect overlay_answer_passes_rebind_protection 10.88.0.54 household.tailnet.example 100.64.88.22
dns_expect local_ca_name 10.88.0.53 vilicus.home.arpa 10.88.0.23
dns_expect dot_local_name 10.88.0.53 vilicus.local 10.88.0.26
dns_expect temporary_host_name 10.88.0.53 host01.home.arpa 10.88.0.25
dns_expect same_name 10.88.0.53 same.home.arpa 10.88.0.27

# ---------------------------------------------------------------------------------------------
# 4. Browsers. Each driver run prints PLAN <n>; exactly n PASS or FAIL lines must follow.
for browser in "${browsers[@]}"; do
  log="$work/$browser.log"
  status=0
  timeout 600 "${compose[@]}" run --rm -T browsers node /app/driver.mjs "$browser" >"$log" 2>&1 || status=$?
  grep -E '^(PASS|FAIL|INFO|ROW) ' "$log"
  plan="$(sed -n 's/^PLAN \([0-9]*\)$/\1/p' "$log")"
  reported="$(grep -cE '^(PASS|FAIL) ' "$log" || true)"
  if [ -n "$plan" ] && [ "$plan" -eq "$reported" ] && [ "$status" -eq 0 ] && ! grep -q '^FAIL ' "$log"; then
    record PASS "$browser.check_count ($reported of $plan, driver exit $status)"
  else
    record FAIL "$browser.check_count (${reported} of ${plan:-no plan}, driver exit $status)" "$log"
  fi
done

# Evidence on the server side: the browsers' refusals of the self-signed certificate.
"${compose[@]}" logs --no-log-prefix srv-selfsigned >"$work/srv-selfsigned.txt" 2>&1 || true
echo "INFO srv-selfsigned TLS handshakes refused by a browser: $(grep -c 'tls handshake .* failed' "$work/srv-selfsigned.txt" || true)"
"${compose[@]}" logs --no-log-prefix srv-ip >"$work/srv-ip.txt" 2>&1 || true
sed -n 's/^E24 serving/INFO srv-ip serving/p' "$work/srv-ip.txt"

# ---------------------------------------------------------------------------------------------
# 5. Matrix: one row per option, one column per browser.
echo
header="MATRIX | option |"
for browser in "${browsers[@]}"; do header="$header $browser |"; done
echo "$header"
cat "$work"/*.log | awk -v order="${browsers[*]}" '
  /^ROW / { cell[$2 SUBSEP $3] = $4; if (!($2 in seen)) { seen[$2] = 1; rows[++n] = $2 } }
  END {
    split(order, cols, " ")
    for (i = 1; i <= n; i++) {
      line = "MATRIX | " rows[i] " |"
      for (j = 1; j in cols; j++) line = line " " ((rows[i] SUBSEP cols[j]) in cell ? cell[rows[i], cols[j]] : "missing") " |"
      print line
    }
  }'
echo

if [ "$failed" -eq 0 ]; then
  echo "RESULT PASS"
else
  echo "RESULT FAIL"
fi
exit "$failed"
