#!/usr/bin/env bash
# E14 spike: runs the cargo gates in a Debian 13 container, then the CONNECT proxy against real
# client traffic on a Docker Compose test network. Prints one `PASS <name>` or `FAIL <name>` line
# per check, ends with `RESULT PASS` or `RESULT FAIL`, removes its compose project, and exits
# non-zero on any failure. Runs from Linux or from Git Bash on Windows; needs Docker only.
set -euo pipefail

spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mount_dir="$spike_dir"
if command -v cygpath >/dev/null 2>&1; then
  mount_dir="$(cygpath -w "$spike_dir")"
fi
export MSYS_NO_PATHCONV=1
image="vilicus-spike-egress-filter"
compose=(docker compose -f "$mount_dir/compose/compose.yaml" -p vilicus-e14)
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

# expect_fail NAME PATTERN CMD...: the command fails and its output matches PATTERN.
expect_fail() {
  local name="$1" pattern="$2"
  shift 2
  if ! "$@" >"$log" 2>&1 && grep -Eq -- "$pattern" "$log"; then record PASS "$name"; else record FAIL "$name"; fi
}

# ---------------------------------------------------------------------------------------------
# Cargo gates, in the same image family as the other spikes.
docker build --quiet --tag "$image" "$mount_dir" >/dev/null
docker run --rm --interactive \
  --volume "$mount_dir:/src:ro" \
  --volume vilicus-egress-filter-target:/target \
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
echo "INFO tokio $(grep -A1 '^name = "tokio"' Cargo.lock | sed -n 's/version = "\(.*\)"/\1/p')"
check fmt cargo fmt --check
check clippy_release_features cargo clippy --locked --all-targets -- -D warnings
check clippy_test_network cargo clippy --locked --all-targets --all-features -- -D warnings
# A build without the test-network feature refuses documentation-ranges-public at load.
check release_build_refuses_documentation_ranges cargo test --locked --lib config::tests::documentation_ranges_need_the_test_network_feature
check build_tests cargo test --locked --all-features --no-run
cargo test --locked --all-features --no-fail-fast >/tmp/tests.log 2>&1
tests_status=$?
grep -h '^test .* \.\.\. \(ok\|FAILED\|ignored\)$' /tmp/tests.log \
  | sed -e 's/^test \(.*\) \.\.\. ok$/PASS test.\1/' -e 's/^test \(.*\) \.\.\. FAILED$/FAIL test.\1/' \
        -e 's/^test \(.*\) \.\.\. ignored$/FAIL test.\1 (ignored)/'
# A run that silently lost or skipped tests must not pass. Update EXPECTED_TESTS when a test
# function or a doc test is added or removed.
EXPECTED_TESTS=43
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
# Test network.
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
if ! "${compose[@]}" build --quiet >"$log" 2>&1; then
  record FAIL network_build
  echo "RESULT FAIL"
  exit 1
fi
"${compose[@]}" up --detach --quiet-pull >/dev/null 2>&1

client() { "${compose[@]}" exec -T client "$@"; }
as_uid() { local uid="$1"; shift; "${compose[@]}" exec -T --user "$uid" client "$@"; }
on_proxy() { "${compose[@]}" exec -T proxy "$@"; }
on_sandbox() { "${compose[@]}" exec -T sandbox "$@"; }
# unit PROPERTY... -- CMD...: runs CMD as uid 2001 in a transient systemd service.
unit() {
  local props=()
  while [ "$1" != "--" ]; do props+=("--property=$1"); shift; done
  shift
  on_sandbox systemd-run --wait --pipe --quiet --property=User=2001 "${props[@]}" "$@"
}
service_log() { "${compose[@]}" logs --no-log-prefix "$1" 2>/dev/null; }

ready=0
for _ in $(seq 1 60); do
  if service_log proxy | grep -q 'event=ready' \
    && service_log resolver | grep -q 'event=ready' \
    && "${compose[@]}" exec -T allowed test -s /srv/big.sha256 2>/dev/null \
    && { on_sandbox systemctl is-system-running 2>/dev/null || true; } | grep -Eq '^(running|degraded)$'; then
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
echo "INFO kernel $(on_sandbox uname -r)"
echo "INFO $(on_sandbox systemctl --version | head -n 1)"
echo "INFO $(client curl --version | head -n 1)"
echo "INFO $(on_sandbox nginx -v 2>&1)"
echo "INFO docker $(docker version --format '{{.Server.Version}}')"

curl_base=(curl -sS --max-time 30 --cacert /etc/egress-test/ca.crt)
via_a=("${curl_base[@]}" -x http://127.0.0.1:3128)
via_b=("${curl_base[@]}" -x http://127.0.0.1:3129)
sock() { echo "/run/egress/$1.sock"; }
tunnel() { local uid="$1" caller="$2"; shift 2; as_uid "$uid" egress-probe tunnel --socket "$(sock "$caller")" "$@"; }
raw() { local uid="$1" caller="$2"; shift 2; as_uid "$uid" egress-probe raw --socket "$(sock "$caller")" "$@"; }

# ---------------------------------------------------------------------------------------------
# AC1: real client traffic through the proxy (curl behind the loopback forwarder of plugin-a).
expect_ok ac1.http11_to_allowlisted_host 'upstream=allowed .*proto=HTTP/1.1' client "${via_a[@]}" --http1.1 https://allowed.test/
expect_ok ac1.http2_to_allowlisted_host 'upstream=allowed .*proto=HTTP/2.0' client "${via_a[@]}" --http2 https://allowed.test/
expect_ok ac1.ipv6_only_allowlisted_host 'upstream=allowed host=allowed6.test' client "${via_a[@]}" https://allowed6.test/
expect_ok ac1.websocket_to_allowlisted_host 'ws-hello upstream=allowed' client "${via_a[@]}" wss://allowed.test/ws
# shellcheck disable=SC2016 # expanded by the shell inside the client container
expect_ok ac1.long_download_64MiB_intact 'sha256 ok 67108864' client sh -c '
  got=$(curl -sS --max-time 120 --cacert /etc/egress-test/ca.crt -x http://127.0.0.1:3128 https://allowed.test/big.bin | tee /tmp/big.bin | sha256sum | cut -d " " -f 1)
  want=$(curl -sS --cacert /etc/egress-test/ca.crt -x http://127.0.0.1:3128 https://allowed.test/big.sha256)
  [ "$got" = "$want" ] && echo "sha256 ok $(wc -c </tmp/big.bin)"'
# shellcheck disable=SC2016 # expanded by the shell inside the client container
expect_ok ac1.fifty_concurrent_tunnels '^50$' client sh -c '
  for i in $(seq 1 50); do
    curl -sS --max-time 30 --http1.1 --cacert /etc/egress-test/ca.crt -x http://127.0.0.1:3128 \
      -o /dev/null -w "%{http_code}\n" "https://allowed.test/concurrent-$i" &
  done | grep -c "^200$"; wait'
expect_fail ac1.redirect_to_host_off_the_allowlist_refused 'response 403' client "${via_a[@]}" -L https://allowed.test/redirect-forbidden
expect_fail ac1.redirect_to_ip_literal_refused 'response 403' client "${via_a[@]}" -L https://allowed.test/redirect-ip
expect_fail ac1.quic_only_through_http_proxy_unsupported 'HTTP/3 is not supported over an HTTP proxy' client "${via_a[@]}" --http3-only https://allowed.test/
expect_ok ac1.quic_preferred_falls_back_to_the_tunnel 'upstream=allowed .*proto=HTTP/2.0' client "${via_a[@]}" --http3 https://allowed.test/
expect_fail ac1.quic_direct_from_client_namespace_fails 'curl: \(' client "${curl_base[@]}" --http3-only --resolve allowed.test:443:203.0.113.10 https://allowed.test/
quic=(curl -sS --max-time 10 --http3-only --cacert /etc/egress-test/ca.crt --resolve allowed.test:443:203.0.113.10 https://allowed.test/)
expect_ok ac1.control.quic_direct_works_in_unrestricted_unit 'proto=HTTP/3.0' unit -- "${quic[@]}"
expect_fail ac1.quic_direct_denied_by_ipaddressdeny 'curl: \(' unit IPAddressDeny=any -- "${quic[@]}"
expect_fail ac1.quic_direct_denied_by_af_unix_only 'curl: \(' unit RestrictAddressFamilies=AF_UNIX -- "${quic[@]}"

# Bypass attempts on the request itself.
expect_fail bypass.host_off_the_allowlist 'response 403' client "${via_a[@]}" https://forbidden.test/
expect_fail bypass.websocket_to_host_off_the_allowlist 'response 403' client "${via_a[@]}" wss://forbidden.test/ws
expect_ok bypass.ip_literal_v4 'status=403' tunnel 2001 plugin-a --target 203.0.113.11:443 --expect-status 403 --expect-reason 'IP literals'
expect_ok bypass.ip_literal_v6 'status=403' tunnel 2001 plugin-a --target '[2001:db8:113::11]:443' --expect-status 403 --expect-reason 'IP literals'
expect_ok bypass.ip_literal_v4_mapped 'status=403' tunnel 2001 plugin-a --target '[::ffff:203.0.113.11]:443' --expect-status 403 --expect-reason 'IP literals'
expect_ok bypass.ip_literal_of_allowlisted_host 'status=403' tunnel 2001 plugin-a --target 203.0.113.10:443 --expect-status 403 --expect-reason 'IP literals'
expect_ok bypass.ip_decimal_form 'status=400' tunnel 2001 plugin-a --target 3405803787:443 --expect-status 400 --expect-reason 'malformed hostname'
expect_ok bypass.ip_hex_form 'status=400' tunnel 2001 plugin-a --target 0xcb.0x71.0.11:443 --expect-status 400 --expect-reason 'malformed hostname'
for port in 80 22 8443 444; do
  expect_ok "bypass.alternate_port_$port" 'status=403' tunnel 2001 plugin-a --target "allowed.test:$port" --expect-status 403 --expect-reason 'not on the caller'
done
expect_ok bypass.port_with_leading_zero 'status=400' tunnel 2001 plugin-a --target allowed.test:0443 --expect-status 400 --expect-reason port
expect_ok bypass.trailing_dot 'status=400' tunnel 2001 plugin-a --target allowed.test.:443 --expect-status 400 --expect-reason 'malformed hostname'
expect_ok bypass.userinfo_in_target 'status=400' tunnel 2001 plugin-a --target allowed.test@forbidden.test:443 --expect-status 400 --expect-reason 'malformed hostname'
expect_ok bypass.uppercase_is_the_same_host 'upstream=allowed' tunnel 2001 plugin-a --target ALLOWED.TEST:443 --path /uppercase --expect-status 200 --expect-upstream allowed
expect_ok bypass.absolute_form_http_allowlisted '^405$' client curl -sS -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}\n' http://allowed.test/
expect_ok bypass.absolute_form_http_forbidden '^405$' client curl -sS -x http://127.0.0.1:3128 -o /dev/null -w '%{http_code}\n' http://forbidden.test/
expect_ok bypass.host_header_mismatch_reaches_only_the_allowlisted_address 'upstream=allowed host=forbidden.test' \
  client "${via_a[@]}" --http1.1 -H 'Host: forbidden.test' https://allowed.test/
expect_ok bypass.connect_host_header_ignored 'upstream=allowed' raw 2001 plugin-a \
  --data 'CONNECT allowed.test:443 HTTP/1.1\r\nHost: forbidden.test:443\r\n\r\nGET /connect-host-mismatch HTTP/1.1\r\nHost: forbidden.test\r\nConnection: close\r\n\r\n' \
  --expect-status 200 --expect-body upstream=allowed
expect_ok bypass.sni_mismatch_reaches_only_the_allowlisted_address 'upstream=allowed .*sni=forbidden.test' \
  client curl -sS --max-time 20 -k --resolve forbidden.test:4443:127.0.0.1 https://forbidden.test:4443/
expect_ok bypass.http2_prior_knowledge_to_proxy 'status=405' raw 2001 plugin-a --data 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' --expect-status 405
expect_ok bypass.h2c_upgrade_to_proxy 'status=405' raw 2001 plugin-a \
  --data 'GET http://forbidden.test/ HTTP/1.1\r\nHost: forbidden.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n' \
  --expect-status 405
expect_ok bypass.connect_udp_upgrade_to_proxy 'status=405' raw 2001 plugin-a \
  --data 'GET /.well-known/masque/udp/forbidden.test/443/ HTTP/1.1\r\nHost: proxy\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n' \
  --expect-status 405
expect_ok bypass.http2_connect_version 'status=400' raw 2001 plugin-a --data 'CONNECT forbidden.test:443 HTTP/2.0\r\n\r\n' --expect-status 400
expect_ok bypass.http10_connect_still_filtered 'status=403' raw 2001 plugin-a --data 'CONNECT forbidden.test:443 HTTP/1.0\r\n\r\n' --expect-status 403 --expect-reason 'not on the caller'
expect_ok bypass.control_byte_in_request_line 'status=400' raw 2001 plugin-a --data 'CONNECT allowed.test:443\x1b[2J HTTP/1.1\r\n\r\n' --expect-status 400 --expect-reason 'not visible ASCII'
expect_ok bypass.second_request_after_refusal_not_served 'status=403' raw 2001 plugin-a \
  --data 'CONNECT forbidden.test:443 HTTP/1.1\r\n\r\nCONNECT allowed.test:443 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n' \
  --expect-status 403 --expect-reason 'not on the caller'
pad="$(printf 'a%.0s' $(seq 1 9000))"
expect_ok bypass.oversized_header 'status=431' raw 2001 plugin-a --data "CONNECT allowed.test:443 HTTP/1.1\\r\\nX-Pad: $pad\\r\\n\\r\\n" --expect-status 431
expect_ok bypass.slow_header_times_out 'status=408' raw 2001 plugin-a --data 'CONNECT allowed.test:443 HTTP/1.1\r\n' --expect-status 408
expect_fail bypass.doh_by_name 'response 403' client "${via_a[@]}" -H 'accept: application/dns-message' \
  'https://dns.google/dns-query?dns=AAABAAABAAAAAAAACWZvcmJpZGRlbgR0ZXN0AAABAAE'
expect_ok bypass.doh_other_provider 'status=403' tunnel 2001 plugin-a --target cloudflare-dns.com:443 --expect-status 403 --expect-reason 'not on the caller'
expect_fail bypass.doh_by_ip_literal 'response 403' client "${via_a[@]}" -k 'https://1.1.1.1/dns-query?dns=AAABAAABAAAAAAAACWZvcmJpZGRlbgR0ZXN0AAABAAE'
expect_ok bypass.exfiltration_by_lookup_of_refused_name 'status=403' tunnel 2001 plugin-a --target exfil-secret-payload.test:443 --expect-status 403 --expect-reason 'not on the caller'

# Caller identification: one socket per caller, peer uid checked.
expect_fail caller.plugin_b_cannot_use_plugin_a_entries 'response 403' client "${via_b[@]}" https://allowed.test/
expect_ok caller.plugin_b_reaches_its_own_entry 'upstream=allowed host=other.test' client "${via_b[@]}" https://other.test/
expect_fail caller.plugin_a_cannot_use_plugin_b_entries 'response 403' client "${via_a[@]}" https://other.test/
expect_ok caller.wrong_uid_on_plugin_a_socket 'status=403' tunnel 2002 plugin-a --target allowed.test:443 --expect-status 403 --expect-reason 'caller identity mismatch'
expect_ok caller.root_on_plugin_a_socket 'status=403' tunnel 0 plugin-a --target allowed.test:443 --expect-status 403 --expect-reason 'caller identity mismatch'
expect_ok caller.plugin_a_on_core_socket 'status=403' tunnel 2001 core --target push.lan:8443 --expect-status 403 --expect-reason 'caller identity mismatch'

# SNI check (plugin-b): the first TLS record must be a ClientHello naming the CONNECT host.
expect_ok sni.matching_client_hello_passes 'upstream=allowed host=other.test sni=other.test' client "${via_b[@]}" https://other.test/
expect_fail sni.mismatching_sni_closes_the_tunnel 'curl: [(]35[)]' client curl -sS --max-time 20 -k --resolve forbidden.test:4444:127.0.0.1 https://forbidden.test:4444/
# What the SNI check cannot see: a Host header naming another service inside a TLS session whose
# SNI matches. A front end that routes on the Host header would serve that other service.
expect_ok sni.host_header_fronting_not_detected 'upstream=allowed host=forbidden.test sni=other.test' client "${via_b[@]}" --http1.1 -H 'Host: forbidden.test' https://other.test/
expect_fail sni.plain_http_closes_the_tunnel 'does not contain' tunnel 2002 plugin-b --target other.test:443 --expect-status 200 --expect-upstream allowed
expect_ok sni.closures_logged 'decision=close-tunnel reason="SNI does not match the CONNECT host"' service_log proxy

# Connection limit per caller (64 here): plugin-a holds 64 tunnels; its next connection is
# refused while plugin-b and the Core are still served, and plugin-a recovers when they close.
"${compose[@]}" exec -d -T --user 2001 client egress-probe hold --socket /run/egress/plugin-a.sock --target allowed.test:443 --count 64 --seconds 8
sleep 4
expect_ok limit.caller_over_its_limit_refused 'status=503' tunnel 2001 plugin-a --target allowed.test:443 --expect-status 503 --expect-reason 'connection limit'
expect_ok limit.other_caller_still_served 'upstream=allowed host=other.test' client "${via_b[@]}" https://other.test/
expect_ok limit.core_still_served 'upstream=allowed' tunnel 2000 core --target allowed.test:443 --path /core-under-load --expect-status 200 --expect-upstream allowed
recovered=0
for _ in $(seq 1 20); do
  if tunnel 2001 plugin-a --target allowed.test:443 --expect-status 200 >"$log" 2>&1; then recovered=1; break; fi
  sleep 1
done
if [ "$recovered" -eq 1 ]; then record PASS limit.caller_recovers_after_release; else record FAIL limit.caller_recovers_after_release; fi

# ---------------------------------------------------------------------------------------------
# Internal addresses after resolution: allowlisted names that resolve inside are still refused.
internal_cases=(
  "internal.test:443|10.77.0.10 is private"
  "mixed.test:443|10.77.0.10 is private"
  "loopback.test:8443|127.0.0.1 is loopback"
  "zero.test:8443|0.0.0.0 is unspecified"
  "metadata.test:80|169.254.169.254 is link-local"
  "cgnat.test:443|shared address space"
  "mcast.test:443|224.0.0.1 is multicast"
  "bench.test:443|benchmarking"
  "mapped.test:443|::ffff:10.77.0.10 is private"
  "mapped-loopback.test:8443|::ffff:127.0.0.1 is loopback"
  "nat64.test:443|embedding 10.77.0.10"
  "sixtofour.test:443|embedding 10.77.0.10"
  "teredo.test:443|Teredo"
  "ula.test:443|fd00:77::10 is unique local"
  "linklocal6.test:443|fe80::1 is link-local"
  "loopback6.test:8443|::1 is loopback"
  "mcast6.test:443|ff02::1 is multicast"
  "household.test:443|203.0.113.20 is blocked by deployment policy"
  "self.test:443|203.0.113.2 is blocked by deployment policy"
  "push.lan:8443|10.77.0.10 is private"
  "nsp64.test:443|embedding 10.77.0.10"
)
for case in "${internal_cases[@]}"; do
  target="${case%%|*}"
  expect_ok "internal.refused.${target%%:*}" 'status=403' tunnel 2004 misconfigured --target "$target" --expect-status 403 --expect-reason "${case#*|}"
done
# Controls, for the refused addresses that a host on the test network answers: each is reachable
# from the proxy's own namespace, so those refusals come from the address check, not from
# routing. The other refused addresses (link-local, CGNAT, multicast, benchmarking, NAT64, 6to4,
# Teredo) have no host here; their refusal reason shows the check, not reachability.
for addr in 10.77.0.10:443 '[fd00:77::10]:443' '[::ffff:10.77.0.10]:443' 127.0.0.1:8443 '[::1]:8443' 0.0.0.0:8443 203.0.113.20:443; do
  expect_ok "internal.control.reachable_from_proxy_namespace.$addr" 'outcome=ok' on_proxy egress-probe direct-tcp --addr "$addr" --expect ok
done

# Named private destinations (D105): the Core and the backup caller only, inside the named range.
expect_ok private.core_reaches_named_destination 'upstream=internal' tunnel 2000 core --target push.lan:8443 --path /core-named --expect-status 200 --expect-upstream internal
expect_ok private.backup_reaches_named_destination 'upstream=internal' tunnel 2003 backup --target push.lan:8443 --path /backup-named --expect-status 200 --expect-upstream internal
expect_ok private.core_other_port_refused 'status=403' tunnel 2000 core --target push.lan:443 --expect-status 403 --expect-reason 'not on the caller'
expect_ok private.plugin_without_entry_refused 'status=403' tunnel 2001 plugin-a --target push.lan:8443 --expect-status 403 --expect-reason 'not on the caller'

# Per-host budget shared by every caller: 6 tunnels per window for budget.test, 1 reserved for
# the Core and the backup caller.
budget_ok=1
for uid_caller in 2001:plugin-a 2002:plugin-b 2001:plugin-a 2002:plugin-b 2001:plugin-a; do
  tunnel "${uid_caller%%:*}" "${uid_caller#*:}" --target budget.test:443 --expect-status 200 >>"$log" 2>&1 || budget_ok=0
done
if [ "$budget_ok" -eq 1 ]; then record PASS budget.five_tunnels_across_two_callers; else record FAIL budget.five_tunnels_across_two_callers; fi
expect_ok budget.sixth_tunnel_refused_for_plugin_a 'status=429' tunnel 2001 plugin-a --target budget.test:443 --expect-status 429
expect_ok budget.sixth_tunnel_refused_for_plugin_b 'status=429' tunnel 2002 plugin-b --target budget.test:443 --expect-status 429
expect_ok budget.core_uses_its_reserve 'upstream=allowed' tunnel 2000 core --target budget.test:443 --expect-status 200 --expect-upstream allowed
expect_ok budget.reserve_exhausted_for_the_core_too 'status=429' tunnel 2000 core --target budget.test:443 --expect-status 429

# ---------------------------------------------------------------------------------------------
# AC2: a name that rebinds between two lookups.
expect_ok ac2.advisory_lookup_sees_a_public_address 'answer=203.0.113.10' on_sandbox egress-probe dns-query --server 203.0.113.53:53 --name rebind-a.test --expect-a 203.0.113.10
expect_ok ac2.proxy_lookup_gets_the_internal_address_and_refuses 'status=403' tunnel 2001 plugin-a --target rebind-a.test:443 --expect-status 403 --expect-reason '10.77.0.10 is private'
expect_ok ac2.proxy_dials_the_address_it_checked 'upstream=allowed' tunnel 2001 plugin-a --target rebind-b.test:443 --path /rebind-b --expect-status 200 --expect-upstream allowed
expect_ok ac2.name_has_rebound_since 'answer=10.77.0.10' on_sandbox egress-probe dns-query --server 203.0.113.53:53 --name rebind-b.test --expect-a 10.77.0.10
expect_ok ac2.proxy_resolved_the_name_once '^1$' sh -c "\"\$@\" | grep -c 'query name=rebind-b.test type=A .*from=\[::ffff:203.0.113.2\]'" _ "${compose[@]}" logs --no-log-prefix resolver
expect_ok ac2.proxy_logged_the_dialled_address 'target=rebind-b.test:443 decision=allow addr=203.0.113.10:443' service_log proxy

# ---------------------------------------------------------------------------------------------
# AC3: direct connections without the proxy.
expect_ok ac3.netns.direct_tcp_ipv4_fails 'outcome=fail' client egress-probe direct-tcp --addr 203.0.113.10:443 --expect fail
expect_ok ac3.netns.direct_tcp_ipv6_fails 'outcome=fail' client egress-probe direct-tcp --addr '[2001:db8:113::10]:443' --expect fail
expect_ok ac3.netns.direct_udp_dns_fails 'outcome=fail' client egress-probe dns-query --server 203.0.113.53:53 --name allowed.test --expect-fail
on_sandbox systemd-run --unit=e14-canary --quiet egress-probe canary --listen 127.0.0.1:9999 --name sandbox-loopback >/dev/null
direct_targets=(
  "public_ipv4|direct-tcp --addr 203.0.113.10:443"
  "public_ipv6|direct-tcp --addr [2001:db8:113::10]:443"
  "forbidden_host|direct-tcp --addr 203.0.113.11:443"
  "lan_ipv4|direct-tcp --addr 10.77.0.10:443"
  "lan_ipv6|direct-tcp --addr [fd00:77::10]:443"
  "loopback|direct-tcp --addr 127.0.0.1:9999"
)
for case in "${direct_targets[@]}"; do
  name="${case%%|*}"
  read -r -a args <<<"${case#*|}"
  expect_ok "ac3.control.unrestricted_unit.$name" 'outcome=ok' unit -- egress-probe "${args[@]}" --expect ok
  expect_ok "ac3.ipaddressdeny.$name" 'outcome=fail' unit IPAddressDeny=any -- egress-probe "${args[@]}" --expect fail
  expect_ok "ac3.full_profile.$name" 'outcome=fail' unit RestrictAddressFamilies=AF_UNIX IPAddressDeny=any -- egress-probe "${args[@]}" --expect fail
done
expect_ok ac3.control.unrestricted_unit.udp_dns 'answer=203.0.113.10' unit -- egress-probe dns-query --server 203.0.113.53:53 --name allowed.test --expect-a 203.0.113.10
expect_ok ac3.ipaddressdeny.udp_dns 'outcome=fail' unit IPAddressDeny=any -- egress-probe dns-query --server 203.0.113.53:53 --name allowed.test --expect-fail
expect_ok ac3.full_profile.udp_dns 'outcome=fail' unit RestrictAddressFamilies=AF_UNIX IPAddressDeny=any -- egress-probe dns-query --server 203.0.113.53:53 --name allowed.test --expect-fail
expect_ok ac3.full_profile.proxy_still_works 'upstream=allowed' unit RestrictAddressFamilies=AF_UNIX IPAddressDeny=any -- \
  egress-probe tunnel --socket /run/egress/plugin-a.sock --target allowed.test:443 --path /from-sandboxed-unit --expect-status 200 --expect-upstream allowed

# ---------------------------------------------------------------------------------------------
# What the servers saw over the whole run.
expect_ok logs.forbidden_upstream_never_reached_through_the_proxy '^0$' sh -c "\"\$@\" | grep -Ec '^(203\.0\.113\.2|2001:db8:113::2) ' || true" _ "${compose[@]}" logs --no-log-prefix forbidden
expect_ok logs.internal_target_reached_only_by_named_destinations '^/core-named /backup-named $' sh -c "\"\$@\" | grep -E '^(10\.77\.0\.2|203\.0\.113\.2|fd00:77::2|2001:db8:113::2):' | sed -E 's/.*\"GET ([^ ]*) .*/\1/' | tr '\n' ' '" _ "${compose[@]}" logs --no-log-prefix internal
expect_ok logs.proxy_host_loopback_reached_only_by_controls '^3$' sh -c "\"\$@\" | grep -c 'canary connection from'" _ "${compose[@]}" logs --no-log-prefix proxy
expect_ok logs.refused_names_never_resolved '^0$' sh -c "\"\$@\" | grep -Ec 'query name=(forbidden\.test|dns\.google|cloudflare-dns\.com|exfil-secret-payload\.test) ' || true" _ "${compose[@]}" logs --no-log-prefix resolver
expect_ok logs.search_list_never_applied '^0$' sh -c "\"\$@\" | grep -c 'corp\.test' || true" _ "${compose[@]}" logs --no-log-prefix resolver
expect_ok logs.refused_target_names_not_logged '^0$' sh -c "\"\$@\" | grep -Ec 'forbidden\.test|dns\.google|cloudflare-dns|exfil-secret-payload|203\.0\.113\.11' || true" _ "${compose[@]}" logs --no-log-prefix proxy
expect_ok logs.refused_targets_logged_as_length_and_hash 'target=redacted[(]len=[0-9]+,hash=[0-9a-f]{16}[)] decision=refuse' service_log proxy
expect_ok logs.ipv6_dialled_for_ipv6_only_host 'target=allowed6.test:443 decision=allow addr=\[2001:db8:113::10\]:443' service_log proxy

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
