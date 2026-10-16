#!/usr/bin/env bash
# E10 spike checks. Runs as root inside the systemd container that run.sh starts, with the
# spike directory at /spike and the build output at /target. Prints INFO lines and one
# `PASS <name>` or `FAIL <name>` line per check, and exits non-zero on any failure.
set -uo pipefail

BIN=/usr/local/bin/e10-spike
PEER_DIR=/run/vilicus/core/peer
REF=vilicus-plugin@ref.service
OTHER=vilicus-plugin@other.service
REUSE=vilicus-plugin@reuse.service
CORE=vilicus-core.service
failed=0

pass() { echo "PASS $1"; }
fail() {
  echo "FAIL $1"
  shift
  for line in "$@"; do echo "  | $line"; done
  failed=1
}
# check NAME COMMAND...: PASS when the command succeeds.
check() {
  local name="$1"
  shift
  if "$@" >/tmp/check.log 2>&1; then
    pass "$name"
  else
    fail "$name"
    sed 's/^/  | /' /tmp/check.log
  fi
}
info() { echo "INFO $*"; }
# wait_for TENTHS COMMAND...: retries the command every 0.1 s.
wait_for() {
  local tries="$1"
  shift
  for _ in $(seq "$tries"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}
core_log() { journalctl -u "$CORE" -o cat --no-pager; }
core_has() { core_log | grep -E -q -- "$1"; }
unit_log() { journalctl -u "$1" -o cat --no-pager; }
main_pid() { systemctl show -P MainPID "$1"; }
pid_uid() { stat -c %u "/proc/$1"; }
# The value of KEY=... in a line.
field() { sed -n "s/.*[[:space:]]$1=\([^[:space:]]*\).*/\1/p"; }

# ---------------------------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------------------------
info "kernel $(uname -r)"
info "$(systemctl --version | head -1)"
info "packages $(dpkg-query -W -f '${Package}=${Version} ' systemd dbus libc6)"
info "cgroup $(stat -fc %T /sys/fs/cgroup)"

install -m 0755 /target/debug/e10-spike "$BIN"
install -m 0644 /spike/units/vilicus-core.service /spike/units/vilicus-ipfilter-check.service \
  "/spike/units/vilicus-plugin@.service" /etc/systemd/system/
install -D -m 0644 /spike/units/vilicus-spike.sysusers.conf /etc/sysusers.d/vilicus-spike.conf
systemd-sysusers >/dev/null
install -d -m 0700 /etc/vilicus-spike/load
for instance in ref other reuse; do
  printf 'e10-test-value-%s\n' "$instance" >"/etc/vilicus-spike/load/$instance.value"
  chmod 0600 "/etc/vilicus-spike/load/$instance.value"
done
install -d -m 0755 /run/e10-gate
systemctl daemon-reload
systemd-run --quiet --unit=e10-abstract-listener -p Type=notify "$BIN" listen-abstract e10-abstract
systemd-run --quiet --unit=e10-tcp-listener -p Type=notify "$BIN" listen-tcp 0.0.0.0:47001
systemctl start dbus.socket
systemctl start "$CORE"
systemctl start "$REF" "$OTHER"

served() { core_has "SERVED unit=$1 pid=$(main_pid "$1") nonce_ok=true"; }
wait_for 100 served "$REF" || fail setup_ref_served "$(core_log | tail -20)"
wait_for 100 served "$OTHER" || fail setup_other_served "$(core_log | tail -20)"
REF_PID=$(main_pid "$REF")
REF_UID=$(pid_uid "$REF_PID")
info "ref plugin pid=$REF_PID uid=$REF_UID; core uid=$(pid_uid "$(main_pid "$CORE")")"

check units_verify systemd-analyze verify "$CORE" "$REF" vilicus-ipfilter-check.service
info "$("$BIN" late-pidfd)"

# The host check the Core requires (spine AD-16): it ran before the Core started, and it
# refuses a host where the probe unit's datagram is not filtered.
check startup_core_requires_ipfilter_check \
  bash -c "systemctl show -P Requires $CORE | grep -qw vilicus-ipfilter-check.service"
check startup_ipfilter_check_passed systemctl is-active --quiet vilicus-ipfilter-check.service
info "$(journalctl -u vilicus-ipfilter-check.service -o cat --no-pager | grep '^IPFILTER_CHECK' | tail -1)"
out=$("$BIN" ipfilter-check --without-filter)
status=$?
info "without the filter: $out"
check startup_ipfilter_check_refuses_unfiltered_host \
  test "$status" -ne 0 -a -n "$(grep 'IPFILTER_CHECK fail .*udp_send open.*datagram_received=true' <<<"$out")"
for unit in "$CORE" "$REF"; do
  check "cgroup_path_matches_systemd_$unit" \
    test "$("$BIN" expected-cgroup "$unit")" = "$(systemctl show -P ControlGroup "$unit")"
done

# ---------------------------------------------------------------------------------------------
# AC1: the reference plugin works under the fixed profile, and direct sockets fail
# ---------------------------------------------------------------------------------------------
check ac1_plugin_active systemctl is-active --quiet "$REF"
check ac1_plugin_runs_as_dynamic_user test "$REF_UID" -ge 61184 -a "$REF_UID" -le 65519
check ac1_plugin_served_one_request_with_its_credential \
  core_has "SERVED unit=$REF pid=$REF_PID nonce_ok=true credential=e10-test-value-ref$"
value=$(cat /etc/vilicus-spike/load/ref.value)
check ac1_plugin_read_its_credential   bash -c "journalctl -u $REF -o cat --no-pager | grep -q 'CREDENTIAL read len=${#value}$'"

# Exact outcome of each probe under the plugin's profile, and under a control unit that runs
# as `nobody` with no sandboxing at all (DynamicUser=yes is not used for the control because it
# implies ProtectSystem=strict and other options). Where both are equal, plain permissions
# already block the probe and the profile option is defence in depth the run cannot attribute.
declare -A PLUGIN_EXPECT=(
  [socket_inet_tcp]="blocked EAFNOSUPPORT" [socket_inet6_tcp]="blocked EAFNOSUPPORT"
  [socket_inet_udp]="blocked EAFNOSUPPORT" [socket_inet_raw]="blocked EAFNOSUPPORT"
  [socket_packet]="blocked EAFNOSUPPORT" [socket_netlink]="blocked EAFNOSUPPORT"
  [dbus_system_bus]="blocked ENOENT" [systemd_private]="blocked ENOENT"
  [journal_stdout]="blocked ENOENT" [other_peer]="blocked ENOENT"
  [abstract_host]="blocked ECONNREFUSED"
  [unshare_net]="blocked EPERM" [unshare_user_net]="blocked EPERM"
  [proc_other_pids]="blocked none-visible"
  [write_etc]="blocked EROFS" [write_var_lib]="blocked EROFS" [write_usr]="blocked EROFS"
  [read_root_home]="blocked EACCES"
)
declare -A CONTROL_EXPECT=(
  [socket_inet_tcp]="open" [socket_inet6_tcp]="open" [socket_inet_udp]="open"
  [socket_inet_raw]="blocked EPERM" [socket_packet]="blocked EPERM" [socket_netlink]="open"
  [dbus_system_bus]="open" [systemd_private]="blocked EACCES"
  [journal_stdout]="open" [other_peer]="blocked EACCES"
  [abstract_host]="open"
  [unshare_net]="blocked EPERM" [unshare_user_net]="open"
  [proc_other_pids]="open"
  [write_etc]="blocked EACCES" [write_var_lib]="blocked EACCES" [write_usr]="blocked EACCES"
  [read_root_home]="blocked EACCES"
)
sorted_keys() { printf '%s\n' "$@" | sort | tr '\n' ' '; }
outcome_of() {
  awk -v n="$2" '$1 == "PROBE" && $2 == n { $1 = ""; $2 = ""; sub(/^ +/, ""); print; exit }' "$1"
}
systemd-run --quiet --wait --pipe --unit=e10-control -p User=nobody "$BIN" probe >/tmp/control.probes 2>&1
unit_log "$REF" | grep '^PROBE ' >/tmp/plugin.probes
# The tables cover exactly the probes the binary runs, no more and no fewer.
probes_run=$(awk '$1 == "PROBE" {print $2}' /tmp/control.probes | sort | tr '\n' ' ')
check probe_tables_match_the_probes_run \
  test "$probes_run" = "$(sorted_keys "${!PLUGIN_EXPECT[@]}")" \
  -a "$probes_run" = "$(sorted_keys "${!CONTROL_EXPECT[@]}")"
check ac1_plugin_ran_every_probe \
  test "$(awk '{print $2}' /tmp/plugin.probes | sort -u | tr '\n' ' ')" = "$probes_run"
for name in $probes_run; do
  plugin=$(outcome_of /tmp/plugin.probes "$name")
  control=$(outcome_of /tmp/control.probes "$name")
  info "probe $name: plugin [$plugin] control [$control]"
  # proc_other_pids prints how many processes it sees when open; only "open" is compared.
  plugin=${plugin/#open */open}
  control=${control/#open */open}
  check "ac1_plugin_${name}_${PLUGIN_EXPECT[$name]// /_}" test "$plugin" = "${PLUGIN_EXPECT[$name]}"
  check "control_nobody_${name}_${CONTROL_EXPECT[$name]// /_}" test "$control" = "${CONTROL_EXPECT[$name]}"
  if [ "${PLUGIN_EXPECT[$name]}" = "${CONTROL_EXPECT[$name]}" ]; then
    info "probe $name: same outcome without the sandbox, not attributable to the profile"
  fi
done

# IP filter on its own: the address families are opened on purpose, so only IPAddressDeny=any
# stands between the unit and the addresses.
ip_probe() {
  local unit="$1" target="$2"
  shift 2
  systemd-run --quiet --wait --pipe --unit="$unit" -p DynamicUser=yes \
    -p "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" "$@" "$BIN" probe-ip "$target"
}
container_ip=$(getent ahostsv4 "$(cat /etc/hostname)" | awk 'NR==1 {print $1}')
info "container address $container_ip"
# TCP only to the two listeners, which have a positive control; TEST-NET-1 gets UDP only, with
# its own control, since a TCP timeout there could also mean an unreachable address.
n=0
for target in "127.0.0.1:47001" "$container_ip:47001" "192.0.2.10:9"; do
  n=$((n + 1))
  out=$(ip_probe "e10-ipdeny-$n" "$target" -p IPAddressDeny=any)
  info "ipdeny $target: $(echo "$out" | tr '\n' ';')"
  if [ "$target" != "192.0.2.10:9" ]; then
    # The dropped SYN shows as a connect timeout (the probe's 3 s limit), not as EPERM.
    check "ac1_ipdeny_tcp_${target}_blocked_TimedOut" grep -qx "PROBE tcp_connect blocked TimedOut" <<<"$out"
  fi
  check "ac1_ipdeny_udp_${target}_blocked_EPERM" grep -qx "PROBE udp_send blocked EPERM" <<<"$out"
  out=$(ip_probe "e10-ipopen-$n" "$target")
  info "no ipdeny $target: $(echo "$out" | tr '\n' ';')"
  if [ "$target" != "192.0.2.10:9" ]; then
    check "control_without_ipdeny_tcp_${target}_open" grep -qx "PROBE tcp_connect open" <<<"$out"
  fi
  check "control_without_ipdeny_udp_${target}_open" grep -qx "PROBE udp_send open" <<<"$out"
done

# Every line of the plugin template's fixed profile block, as systemd loaded it. The keys whose
# rendering differs from the file are mapped here; every other value must be identical.
profile_value() {
  case "$1=$2" in
    IPAddressDeny=any) echo "0.0.0.0/0 ::/0" ;;
    MemoryMax=64M) echo 67108864 ;;
    SystemCallErrorNumber=EPERM) echo 1 ;;
    BindPaths=*) echo "$2:rbind" ;;
    *) echo "$2" ;;
  esac
}
# IPAddressDeny is a set: systemd prints its prefixes in an order that differs from one boot to
# the next (observed: "0.0.0.0/0 ::/0" on some boots, "::/0 0.0.0.0/0" on others), so both sides
# are compared as sorted lists of prefixes. Every other key is compared as printed.
canonical_value() {
  case "$1" in
    IPAddressDeny) tr ' ' '\n' <<<"$2" | sort | tr '\n' ' ' ;;
    *) echo "$2" ;;
  esac
}
# profile_matches KEY EXPECTED: prints both values when they differ.
profile_matches() {
  local actual expected
  actual=$(systemctl show -P "$1" "$REF")
  expected=$2
  if [ "$(canonical_value "$1" "$actual")" = "$(canonical_value "$1" "$expected")" ]; then
    return 0
  fi
  echo "expected [$expected] actual [$actual]"
  return 1
}
sed -n '/^# Fixed profile/,$p' "/spike/units/vilicus-plugin@.service" | grep -E '^[A-Za-z]+=' >/tmp/profile.lines
check profile_block_present test "$(wc -l </tmp/profile.lines)" -gt 30
while IFS='=' read -r key value; do
  [ "$key" = SystemCallFilter ] && continue
  value=${value//%n/$REF}
  value=${value//%i/ref}
  check "profile_$key" profile_matches "$key" "$(profile_value "$key" "$value")"
done </tmp/profile.lines
info "IPAddressDeny as printed on this boot: [$(systemctl show -P IPAddressDeny "$REF")]"
systemctl show -P SystemCallFilter "$REF" | tr ' ' '\n' >/tmp/syscalls
check profile_SystemCallFilter_allows_pidfd_open grep -qx pidfd_open /tmp/syscalls
for call in io_uring_setup io_uring_enter io_uring_register mount setuid; do
  check "profile_SystemCallFilter_denies_$call" bash -c "! grep -qx $call /tmp/syscalls"
done

# The profile listed in doc/architecture.md section 4 alone, for comparison with the unit file.
baseline=$(systemd-run --quiet --wait --pipe --unit=e10-baseline -p DynamicUser=yes \
  -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p NoNewPrivileges=yes \
  -p SystemCallFilter=@system-service -p RestrictAddressFamilies=AF_UNIX -p IPAddressDeny=any \
  -p ProtectProc=invisible -p MemoryMax=64M -p TasksMax=16 "$BIN" probe)
while read -r _ name outcome reason; do
  info "baseline profile probe $name: $outcome ${reason:-}"
done <<<"$baseline"
check baseline_profile_reaches_system_bus grep -q "PROBE dbus_system_bus open" <<<"$baseline"
check baseline_profile_reaches_host_abstract_socket grep -q "PROBE abstract_host open" <<<"$baseline"
check baseline_profile_reaches_journal_stream grep -q "PROBE journal_stdout open" <<<"$baseline"
check baseline_profile_creates_user_and_network_namespaces grep -q "PROBE unshare_user_net open" <<<"$baseline"

# ---------------------------------------------------------------------------------------------
# AC2: the Core identifies the peer's unit and rejects every other process
# ---------------------------------------------------------------------------------------------
ref_line=$(core_log | grep "DECISION unit=$REF pid=$REF_PID " | tail -1)
info "ref decision: $ref_line"
check ac2_expected_unit_accepted \
  grep -q "uid=$REF_UID cgroup_member=yes pidfd_alive=true .* verdict=accept reason=unit-match" <<<"$ref_line"
other_pid=$(main_pid "$OTHER")
check ac2_second_unit_accepted_on_its_own_socket \
  core_has "DECISION unit=$OTHER pid=$other_pid .* verdict=accept reason=unit-match"
# Finding: ProtectProc=invisible on the Core hides /proc/<pid> of every other user, so the
# Core cannot read /proc/<pid>/cgroup; the check reads the unit's cgroup.procs instead.
check ac2_proc_cgroup_hidden_from_core_by_protectproc \
  grep -q "proc_cgroup=unreadable(ENOENT)" <<<"$ref_line"

# intruder UNIT PROPERTY...: a transient unit given the ref plugin's socket directory, as if
# the bind-mount layer had failed, connects and reports what the Core answered.
intruder() {
  local unit="$1"
  shift
  systemd-run --quiet --wait --pipe --unit="$unit" "$@" \
    -p "BindPaths=$PEER_DIR/$REF:/run/vilicus/peer" \
    "$BIN" connect --socket /run/vilicus/peer/core.sock
}
out=$(intruder e10-intruder-other-uid -p DynamicUser=yes)
info "other uid intruder: $(echo "$out" | tr '\n' ';')"
check ac2_other_unit_rejected grep -q "OUTCOME rejected other-unit" <<<"$out"
check ac2_other_unit_has_another_uid test "$(echo "$out" | field uid)" != "$REF_UID"

out=$(intruder e10-intruder-same-uid -p DynamicUser=yes -p User=vilicus-plugin-ref)
info "same uid intruder: $(echo "$out" | tr '\n' ';')"
check ac2_same_uid_other_unit_rejected grep -q "OUTCOME rejected other-unit" <<<"$out"
# What the AC3 fallback would see: the same uid, so SO_PEERCRED alone would accept it.
check ac3_peercred_uid_cannot_tell_same_uid_unit test "$(echo "$out" | field uid)" = "$REF_UID"

out=$("$BIN" connect --socket "$PEER_DIR/$REF/core.sock")
info "root outside any unit: $(echo "$out" | tr '\n' ';')"
check ac2_process_outside_any_unit_rejected grep -q "OUTCOME rejected other-unit" <<<"$out"

# systemd refuses because the name has a unit file ("already loaded or has a fragment file").
check ac2_unit_name_with_a_unit_file_cannot_be_taken_by_a_transient_unit \
  bash -c "! systemd-run --quiet --unit=$REF /bin/true 2>/dev/null"

# A cgroup whose last component is the expected unit's name, outside systemd's tree for it, as
# a user manager or a unit with Delegate=yes may be able to create (here root creates it).
spoof=/sys/fs/cgroup/e10-spoof.slice/$REF
mkdir -p "$spoof"
out=$(sh -c "echo \$\$ >'$spoof/cgroup.procs' && cat /proc/self/cgroup && exec '$BIN' connect --socket '$PEER_DIR/$REF/core.sock'")
info "spoofed cgroup name: $(echo "$out" | tr '\n' ';')"
check ac2_spoof_leaf_name_equals_expected_unit grep -q "^0::/e10-spoof.slice/$REF$" <<<"$out"
check ac2_spoofed_unit_name_rejected grep -q "OUTCOME rejected other-unit" <<<"$out"

# Pid reuse: a process of another unit connects to the reuse plugin's socket and exits while the
# Core holds the connection before verifying it; its pid is then given to the reuse plugin.
out=$(systemd-run --quiet --wait --pipe --unit=e10-reuse-attacker -p DynamicUser=yes \
  -p "BindPaths=$PEER_DIR/$REUSE:/run/vilicus/peer" \
  "$BIN" connect --socket /run/vilicus/peer/core.sock --leave-after-hello)
attacker_pid=$(echo "$out" | field pid)
info "reuse attacker: $(echo "$out" | tr '\n' ';')"
forced=no
for attempt in $(seq 1 400); do
  offset=$((attempt % 6 + 1))
  echo $((attacker_pid - offset)) >/proc/sys/kernel/ns_last_pid
  systemctl start "$REUSE"
  if [ "$(main_pid "$REUSE")" = "$attacker_pid" ]; then
    forced=yes
    info "pid $attacker_pid reused by $REUSE after $attempt attempts"
    break
  fi
  systemctl stop "$REUSE"
done
check ac2_pid_reuse_forced test "$forced" = yes
touch /run/e10-gate/open
reuse_lines() { core_log | grep "DECISION unit=$REUSE pid=$attacker_pid "; }
wait_for 100 bash -c "[ \$(journalctl -u $CORE -o cat --no-pager | grep -c 'DECISION unit=$REUSE pid=$attacker_pid ') -ge 2 ]"
info "reuse decisions: $(reuse_lines | tr '\n' ';')"
check ac2_reused_pid_passes_a_pid_only_check \
  bash -c "journalctl -u $CORE -o cat --no-pager | grep 'DECISION unit=$REUSE pid=$attacker_pid ' | grep -q 'cgroup_member=yes pidfd_alive=false pid_only_check=accept'"
check ac2_reused_pid_rejected_by_pidfd \
  bash -c "journalctl -u $CORE -o cat --no-pager | grep 'DECISION unit=$REUSE pid=$attacker_pid ' | grep -q 'pidfd_alive=false .* verdict=reject reason=peer-exited'"
check ac2_reuse_unit_own_connection_accepted \
  bash -c "journalctl -u $CORE -o cat --no-pager | grep 'DECISION unit=$REUSE pid=$attacker_pid ' | grep -q 'pidfd_alive=true .* verdict=accept'"

# A peer that forks after being served and exits: the child keeps the connection, as a
# descriptor passed with SCM_RIGHTS would. KillMode=process keeps the child alive past the main
# process, which the template does not allow (KillMode=control-group); the Core must still end
# the connection when the process it verified exits.
systemd-run --quiet --unit=e10-forker -p DynamicUser=yes -p KillMode=process \
  -p "BindPaths=$PEER_DIR/e10-forker.service:/run/vilicus/peer" \
  "$BIN" connect --socket /run/vilicus/peer/core.sock --fork-hold
wait_for 100 core_has "PEER_EXITED unit=e10-forker.service "
info "forker: $(core_log | grep -E '(DECISION|SERVED|PEER_EXITED|CLOSED) unit=e10-forker' | tr '\n' ';')"
check token_connection_closed_when_verified_process_exits \
  core_has "PEER_EXITED unit=e10-forker.service "
holder_closed() { journalctl -u e10-forker -o cat --no-pager | grep -q HELD_CLOSED; }
wait_for 100 holder_closed
check token_holding_child_sees_the_close holder_closed

# ---------------------------------------------------------------------------------------------
# Restarts
# ---------------------------------------------------------------------------------------------
old_invocation=$(systemctl show -P InvocationID "$REF")
systemctl restart "$REF"
new_pid=$(main_pid "$REF")
wait_for 100 served "$REF"
check restart_plugin_gets_a_new_pid test "$new_pid" != "$REF_PID"
check restart_new_process_accepted core_has "DECISION unit=$REF pid=$new_pid .* verdict=accept reason=unit-match"
check restart_old_connection_closed core_has "(CLOSED|PEER_EXITED) unit=$REF pid=$REF_PID( |$)"
check restart_invocation_id_changes test "$(systemctl show -P InvocationID "$REF")" != "$old_invocation"

# The Core alone, without the restart propagating to the plugin through Requires=: the plugin
# keeps its pid and its bind mount of the preserved runtime directory, and is served again by
# the new Core on the socket the new Core created there.
kept_pid=$(main_pid "$REF")
served_count() { core_log | grep -c "SERVED unit=$REF pid=$1 "; }
served_more() { [ "$(served_count "$1")" -gt "$2" ]; }
before=$(served_count "$kept_pid")
systemctl restart --job-mode=ignore-dependencies "$CORE"
wait_for 100 served_more "$kept_pid" "$before"
check restart_core_alone_plugin_keeps_its_pid test "$(main_pid "$REF")" = "$kept_pid"
check restart_core_alone_same_plugin_served_again served_more "$kept_pid" "$before"

before=$(core_log | grep -c "SERVED unit=$REF ")
systemctl restart "$CORE"
wait_for 100 bash -c "[ \$(journalctl -u $CORE -o cat --no-pager | grep -c 'SERVED unit=$REF ') -gt $before ]"
check restart_core_plugin_served_again \
  test "$(core_log | grep -c "SERVED unit=$REF ")" -gt "$before"
check restart_core_restarts_plugin test "$(main_pid "$REF")" != "$new_pid"

# ---------------------------------------------------------------------------------------------
# systemd-analyze security
# ---------------------------------------------------------------------------------------------
declare -A EXPECTED_EXPOSURE=([$CORE]=0.4 [$REF]=0.2)
for unit in "$CORE" "$REF"; do
  systemd-analyze security --no-pager "$unit" >/tmp/security.txt 2>&1
  score=$(grep -o 'Overall exposure level for [^:]*: [0-9.]*' /tmp/security.txt | awk '{print $NF}')
  info "systemd-analyze security $unit: exposure $score"
  grep -E '^\s*✗' /tmp/security.txt | sed 's/✗//' | tr -cd '[:print:]\n' | awk '{$1=$1; print}' |
    while read -r line; do info "  open item $unit: $line"; done
  check "security_exposure_${EXPECTED_EXPOSURE[$unit]}_$unit" test "$score" = "${EXPECTED_EXPOSURE[$unit]}"
done

if [ "$failed" -ne 0 ]; then
  echo "RESULT FAIL"
  exit 1
fi
echo "RESULT PASS"
