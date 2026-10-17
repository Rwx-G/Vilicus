#!/usr/bin/env bash
# Boots the Debian 13 e2e VM inside the vilicus-vm-host container. Started by `vm.sh up`.
#
#   /images  named volume: the verified Debian cloud image, downloaded once and kept.
#   /vm-run  named volume: this run's overlay and seed, recreated on every boot, removed by
#            `vm.sh down`.
#   /state   read-only bind mount of e2e/vm/state: the per-run SSH key and the cloud-init
#            user-data and meta-data rendered by vm.sh.
#
# The guest console goes to the container log (`docker logs vilicus-vm`).
set -euo pipefail

# shellcheck source=IMAGE.lock
. /vm/IMAGE.lock
VM_CPUS="${VM_CPUS:-4}"
VM_MEMORY_MIB="${VM_MEMORY_MIB:-8192}"
VM_DISK_SIZE="${VM_DISK_SIZE:-60G}"
base="/images/$DEBIAN_IMAGE_FILE"
overlay=/vm-run/overlay.qcow2
seed=/vm-run/seed.iso

log() { echo "[vm-host] $*"; }
die() { log "error: $*"; exit 1; }

[ -c /dev/kvm ] || die "/dev/kvm is missing: start the container with --device /dev/kvm on an engine with nested virtualisation"

verified() { echo "$DEBIAN_IMAGE_SHA512  $1" | sha512sum --check --status; }

# The published list must still carry the locked checksum for this file: a mismatch means the
# lock or the mirror changed, and the boot stops rather than guess which one is right.
curl -fsSL --retry 3 "$DEBIAN_IMAGE_SUMS_URL" -o /tmp/SHA512SUMS
published="$(awk -v f="$DEBIAN_IMAGE_FILE" '$2 == f { print $1 }' /tmp/SHA512SUMS)"
[ "$published" = "$DEBIAN_IMAGE_SHA512" ] \
  || die "published SHA512SUMS lists [${published:-nothing}] for $DEBIAN_IMAGE_FILE, IMAGE.lock says $DEBIAN_IMAGE_SHA512"

if [ ! -f "$base" ] || ! verified "$base"; then
  log "downloading $DEBIAN_IMAGE_URL"
  curl -fL --retry 3 --progress-bar "$DEBIAN_IMAGE_URL" -o "$base.part"
  verified "$base.part" || die "downloaded $DEBIAN_IMAGE_FILE does not match its SHA512"
  mv "$base.part" "$base"
fi
log "base image $DEBIAN_IMAGE_FILE, SHA512 verified against IMAGE.lock and $DEBIAN_IMAGE_SUMS_URL"

# A fresh overlay every boot: the guest never writes to the verified base image.
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay" "$VM_DISK_SIZE"
cloud-localds "$seed" /state/user-data /state/meta-data

install -d -m 0700 /root/.ssh
install -m 0600 /state/id_ed25519 /root/.ssh/id_ed25519

log "$(qemu-system-x86_64 --version | head -n 1); ${VM_CPUS} vCPUs, ${VM_MEMORY_MIB} MiB, ${VM_DISK_SIZE} virtio disk"
exec qemu-system-x86_64 \
  -enable-kvm -cpu host -machine q35 \
  -smp "$VM_CPUS" -m "$VM_MEMORY_MIB" \
  -drive "file=$overlay,if=virtio,format=qcow2,cache=none,discard=unmap" \
  -drive "file=$seed,if=virtio,format=raw,readonly=on" \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -display none -monitor none -serial stdio
