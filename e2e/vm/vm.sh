#!/usr/bin/env bash
# Debian 13 e2e VM, driven through Docker: a QEMU/KVM guest booted from the pinned Debian cloud
# image (IMAGE.lock) on a fresh overlay, with systemd as PID 1 and Docker Engine from the Debian
# archive. See e2e/vm/README.md.
#
# Usage: bash e2e/vm/vm.sh <command> [args]
#   up                build the host image, boot the VM, wait for cloud-init and Docker
#   ssh <command...>  run a command in the VM as the test user
#   sync              copy the repository at HEAD (committed content only, as a git bundle)
#                     into the VM
#   e2e <phase...>    run e2e/run.sh --only <phases> --keep-going in the VM and copy the
#                     results back to e2e/results/vm-<timestamp>-<sha>/
#   info              kernel, OS, CPUs, memory, systemd, Docker and disk facts of the VM
#   console           print the guest console (the VM container's log) so far
#   down              stop and remove the VM container and its overlay
#
# Environment:
#   VM_SSH_PORT  host port forwarded to the guest's SSH, bound to 127.0.0.1 (default 2222)
#   VM_CPUS, VM_MEMORY_MIB, VM_DISK_SIZE  guest size, passed to entrypoint.sh when set
#                (its defaults: 4, 8192, 60G)
#   VM_IMAGES_DIR  host directory holding the verified base image instead of the
#                vilicus-vm-images volume, so that CI can cache it (ci/vm/README.md)
#   E2E_*, E[0-9]*_*  forwarded to e2e/run.sh in the VM (for example E2E_TIMEOUT_SCALE=2,
#                     or a spike's image override)
set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$VM_DIR/../.." && pwd)"
STATE_DIR="$VM_DIR/state"
CONTAINER=vilicus-vm
HOST_IMAGE=vilicus-vm-host
IMAGES_VOLUME=vilicus-vm-images
RUN_VOLUME=vilicus-vm-run
VM_SSH_PORT="${VM_SSH_PORT:-2222}"
VM_USER=vilicus
# The repository lives at ~/vilicus in the guest, a link to the directory of the synced SHA.
GUEST_REPO='$HOME/vilicus'

# Git Bash on Windows: Docker needs Windows paths for bind mounts and build contexts, and MSYS
# must not rewrite the Linux paths passed to the container (/dev/kvm, /state). With path
# conversion off, the native Git for Windows needs a Windows path too.
export MSYS_NO_PATHCONV=1
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi
}
repo_git() {
  if command -v cygpath >/dev/null 2>&1; then
    git -C "$(cygpath -m "$REPO_DIR")" "$@"
  else
    git -C "$REPO_DIR" "$@"
  fi
}

log() { echo "[vm] $*" >&2; }
die() { log "error: $*"; exit 1; }

usage() {
  sed -n '6,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

container_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = true ]
}

# vm_ssh COMMAND: runs COMMAND (one shell string) in the guest; stdin and stdout pass through.
vm_ssh() {
  container_running || die "the VM is not running: run 'vm.sh up' first"
  docker exec -i "$CONTAINER" ssh -q -p 2222 -i /root/.ssh/id_ed25519 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=10 \
    -o BatchMode=yes "$VM_USER@127.0.0.1" "$1"
}

render_seed() {
  local public_key instance_id
  public_key="$(cat "$STATE_DIR/id_ed25519.pub")"
  instance_id="vilicus-vm-$(date -u +%Y%m%dT%H%M%SZ)"
  cat >"$STATE_DIR/meta-data" <<EOF
instance-id: $instance_id
local-hostname: vilicus-vm
EOF
  cat >"$STATE_DIR/user-data" <<EOF
#cloud-config
hostname: vilicus-vm
ssh_pwauth: false
disable_root: true
users:
  - name: $VM_USER
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - $public_key
package_update: true
packages:
  - ca-certificates
  - curl
  - docker-buildx
  - docker-compose
  - docker.io
  - git
  - rsync
  - systemd-coredump
runcmd:
  - [swapoff, --all]
  - [sed, -i, '/[[:space:]]swap[[:space:]]/d', /etc/fstab]
  - [systemctl, mask, --now, swap.target]
  - [usermod, --append, --groups, docker, $VM_USER]
  - [systemctl, enable, --now, docker.service]
EOF
}

cmd_up() {
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    die "container $CONTAINER already exists: run 'vm.sh down' first, so each run starts clean"
  fi
  mkdir -p "$STATE_DIR"
  log "building $HOST_IMAGE"
  docker build --quiet --tag "$HOST_IMAGE" "$(host_path "$VM_DIR")" >/dev/null
  # A new key pair for every run; the answer overwrites the previous run's key.
  ssh-keygen -q -t ed25519 -N '' -C "vilicus-vm-run" -f "$STATE_DIR/id_ed25519" <<<y >/dev/null
  render_seed
  local images="$IMAGES_VOLUME"
  if [ -n "${VM_IMAGES_DIR:-}" ]; then
    mkdir -p "$VM_IMAGES_DIR"
    images="$(host_path "$(cd "$VM_IMAGES_DIR" && pwd)")"
  fi
  log "booting the VM (container $CONTAINER, SSH on 127.0.0.1:$VM_SSH_PORT, base image in $images)"
  # `--env NAME` without a value passes NAME only when it is set here; entrypoint.sh defaults it.
  docker run --detach --name "$CONTAINER" \
    --device /dev/kvm \
    --env VM_CPUS --env VM_MEMORY_MIB --env VM_DISK_SIZE \
    --publish "127.0.0.1:$VM_SSH_PORT:2222" \
    --volume "$images:/images" \
    --volume "$RUN_VOLUME:/vm-run" \
    --volume "$(host_path "$STATE_DIR"):/state:ro" \
    "$HOST_IMAGE" >/dev/null

  local waited=0 limit=1800
  log "waiting for SSH"
  # container_running first: vm_ssh exits the script when the container is gone, and with its
  # stderr silenced here the reason in the container log would never be printed.
  until container_running && vm_ssh true 2>/dev/null; do
    container_running || { docker logs --tail 40 "$CONTAINER" >&2; die "the VM container stopped"; }
    [ "$waited" -lt "$limit" ] || die "no SSH after ${limit}s; see 'docker logs $CONTAINER'"
    sleep 5
    waited=$((waited + 5))
  done
  log "waiting for cloud-init (package installation)"
  local status
  status="$(vm_ssh 'cloud-init status --wait >/dev/null 2>&1; cloud-init status --long' || true)"
  echo "$status" | sed 's/^/  /' >&2
  grep -q '^status: done' <<<"$status" || die "cloud-init did not finish cleanly"
  log "waiting for Docker"
  waited=0
  until vm_ssh 'docker version --format "{{.Server.Version}}"' >/dev/null 2>&1; do
    [ "$waited" -lt 300 ] || die "Docker does not answer in the VM"
    sleep 5
    waited=$((waited + 5))
  done
  docker logs "$CONTAINER" 2>&1 | grep '^\[vm-host\]' >&2 || true
  log "VM ready: docker $(vm_ssh 'docker version --format "{{.Server.Version}}"'), kernel $(vm_ssh 'uname -r')"
}

cmd_ssh() {
  [ $# -gt 0 ] || die "usage: vm.sh ssh <command...>"
  vm_ssh "$*"
}

cmd_sync() {
  local sha
  sha="$(repo_git rev-parse HEAD)"
  local dirty
  dirty="$(repo_git status --porcelain | wc -l | tr -d ' ')"
  [ "$dirty" -eq 0 ] || log "note: $dirty uncommitted path(s) in the working tree are not copied"
  # A bundle of HEAD rather than `git archive`: the guest gets exactly the committed tree, and a
  # checkout whose `git rev-parse HEAD` is the real SHA, which e2e/run.sh and the spikes record
  # (run.sh also stops under `set -e -o pipefail` on a tree without git metadata).
  log "copying $sha (git bundle of HEAD) into the VM"
  repo_git bundle create --quiet - HEAD \
    | vm_ssh "set -e; dir=\$HOME/checkout-$sha; cat >\"\$dir.bundle\"; [ -d \"\$dir/.git\" ] || git -c init.defaultBranch=main clone --quiet --no-checkout \"\$dir.bundle\" \"\$dir\"; git -C \"\$dir\" -c advice.detachedHead=false checkout --quiet --detach $sha; echo $sha >\"\$dir/.git/vm-sha\"; ln -sfn \"\$dir\" $GUEST_REPO"
  log "synced: $(vm_ssh "git -C $GUEST_REPO rev-parse HEAD"), $(vm_ssh "git -C $GUEST_REPO status --porcelain | wc -l") uncommitted path(s) in the guest"
}

info_script() {
  cat <<'EOF'
echo "kernel:        $(uname -r) ($(uname -v))"
echo "os:            $(. /etc/os-release && echo "$PRETTY_NAME"), debian_version $(cat /etc/debian_version)"
echo "cpus:          $(nproc) ($(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'))"
echo "memory:        $(free -m | awk '/^Mem:/ { print $2 " MiB total, " $7 " MiB available" }')"
echo "swap:          $(tail -n +2 /proc/swaps | wc -l) active device(s); $(free -m | awk '/^Swap:/ { print $2 " MiB" }')"
echo "systemd:       $(systemctl --version | head -n 1); PID 1 is $(cat /proc/1/comm); state $(systemctl is-system-running || true)"
echo "cgroup:        $(stat -fc %T /sys/fs/cgroup)"
echo "apparmor:      $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "core_pattern:  $(cat /proc/sys/kernel/core_pattern)"
echo "suid_dumpable: $(cat /proc/sys/fs/suid_dumpable)"
echo "docker:        $(docker version --format 'client {{.Client.Version}}, server {{.Server.Version}}'), $(docker compose version 2>&1 | head -n 1), $(docker buildx version 2>&1 | head -n 1)"
echo "docker info:   $(docker info --format '{{.NCPU}} CPUs, {{.MemTotal}} bytes, storage {{.Driver}}, cgroup {{.CgroupDriver}} v{{.CgroupVersion}}')"
echo "packages:      $(dpkg-query -W -f '${Package}=${Version} ' linux-image-cloud-amd64 systemd systemd-coredump docker.io docker-compose docker-buildx 2>/dev/null)"
root_dev="$(findmnt -no SOURCE /)"
disk="$(lsblk -no PKNAME "$root_dev")"
echo "disk:          /dev/$disk $(lsblk -dno SIZE,ROTA,TRAN "/dev/$disk" | awk '{ print $1 ", rotational=" $2 }'), driver $(basename "$(readlink -f "/sys/block/$disk/device/driver")"), root $(findmnt -no SOURCE,FSTYPE /), scheduler $(cat "/sys/block/$disk/queue/scheduler")"
echo "root free:     $(df -h --output=avail / | tail -n 1 | tr -d ' ')"
EOF
}

cmd_info() {
  vm_ssh "$(info_script)"
  echo "qemu:          $(docker exec "$CONTAINER" qemu-system-x86_64 --version | head -n 1)"
  echo "vm host image: $(docker inspect --format '{{.Config.Image}} {{.Image}}' "$CONTAINER")"
  echo "base image:    $(sed -n 's/^DEBIAN_IMAGE_FILE=//p' "$VM_DIR/IMAGE.lock")"
}

cmd_e2e() {
  [ $# -gt 0 ] || die "usage: vm.sh e2e <phase...>"
  local phases sha short stamp forwarded="" name results local_dir
  phases="$(IFS=,; echo "$*")"
  sha="$(vm_ssh "cat $GUEST_REPO/.git/vm-sha" 2>/dev/null)" || die "nothing synced: run 'vm.sh sync' first"
  short="${sha:0:7}"
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  while IFS='=' read -r name _; do
    forwarded+=" $name=$(printf '%q' "${!name}")"
  done < <(env | grep -E '^(E2E|E[0-9]+)_[A-Z0-9_]*=' || true)
  log "running phases $phases at $sha in the VM${forwarded:+ with$forwarded}"
  set +e
  vm_ssh "cd $GUEST_REPO && env$forwarded bash e2e/run.sh --only $phases --keep-going"
  local status=$?
  set -e
  results="$(vm_ssh "ls -1t $GUEST_REPO/e2e/results | head -n 1")"
  [ -n "$results" ] || die "no results folder in the VM"
  local_dir="vm-$stamp-$short"
  mkdir -p "$REPO_DIR/e2e/results"
  vm_ssh "tar -c -C $GUEST_REPO/e2e/results $results" \
    | tar -x -C "$REPO_DIR/e2e/results" --transform "s,^$results,$local_dir,"
  {
    echo "vm_sha:        $sha"
    echo "vm_command:    bash e2e/vm/vm.sh e2e $*${forwarded:+ (environment:$forwarded)}"
    echo "vm_results:    $results"
    echo "vm_exit:       $status"
    cmd_info
  } >"$REPO_DIR/e2e/results/$local_dir/vm-info.txt"
  log "results copied to e2e/results/$local_dir (exit $status)"
  return "$status"
}

cmd_console() {
  docker inspect "$CONTAINER" >/dev/null 2>&1 || die "no VM container: run 'vm.sh up' first"
  docker logs "$CONTAINER" 2>&1
}

cmd_down() {
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    docker logs "$CONTAINER" >"$STATE_DIR/console.log" 2>&1 || true
    docker rm --force "$CONTAINER" >/dev/null
    log "container $CONTAINER removed (console log kept in e2e/vm/state/console.log)"
  fi
  if docker volume inspect "$RUN_VOLUME" >/dev/null 2>&1; then
    docker volume rm "$RUN_VOLUME" >/dev/null
    log "overlay volume $RUN_VOLUME removed; base image cache $IMAGES_VOLUME kept"
  fi
}

[ $# -gt 0 ] || { usage; exit 2; }
command="$1"
shift
case "$command" in
  up) cmd_up ;;
  ssh) cmd_ssh "$@" ;;
  sync) cmd_sync ;;
  e2e) cmd_e2e "$@" ;;
  info) cmd_info ;;
  console) cmd_console ;;
  down) cmd_down ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
