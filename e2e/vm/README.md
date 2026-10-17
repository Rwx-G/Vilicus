---
title: 'Debian 13 e2e VM'
author: Rwx-G
---

# Debian 13 e2e VM

`e2e/vm/vm.sh` boots a disposable Debian 13 (trixie) virtual machine and runs `e2e/run.sh`
phases inside it. It exists for the spikes whose result depends on the host rather than on the
userland: Docker containers share the engine's kernel, which on Docker Desktop is the WSL2
kernel (6.18), not Debian 13's 6.12, and they never run under a host systemd with AppArmor
and `systemd-coredump`. In the VM, the same spike scripts run their containers on Debian 13's
kernel, under Debian's Docker Engine, on a host whose PID 1 is systemd 257.

It is a local precursor of Story 2.3 (the CI harness), not that story's deliverable.

## Requirements

- Docker with nested virtualisation: `/dev/kvm` must be passable to a container. On Docker
  Desktop for Windows (WSL2 backend) check with
  `MSYS_NO_PATHCONV=1 docker run --rm --device /dev/kvm alpine:3.20 ls -l /dev/kvm`.
- About 8 GiB of free memory and 4 CPUs for the guest, plus disk for its Docker images and
  build caches (the guest disk is sparse, up to 60 GiB).
- Network access to `cloud.debian.org` and `deb.debian.org` (the guest installs its packages
  at first boot) and to Docker Hub (the spikes pull their pinned images).
- Bash (Linux, or Git Bash on Windows), `git`, `ssh-keygen`.

## How it is built

- `Dockerfile`: QEMU, `qemu-utils`, `cloud-image-utils` and the OpenSSH client on
  `debian:trixie-slim`, pinned by digest.
- `IMAGE.lock`: the Debian cloud image (genericcloud, amd64, a dated build), its URL and its
  SHA512. `entrypoint.sh` checks that the published `SHA512SUMS` still lists that checksum for
  that file, downloads the image once into the `vilicus-vm-images` volume, and verifies it on
  every boot.
- Each boot creates a new qcow2 overlay on top of the verified image in the `vilicus-vm-run`
  volume, so every run starts from the pristine image. The overlay and the base image live in
  Docker volumes, not in the working tree, so a synced or network folder never carries a
  multi-gigabyte disk image.
- Guest: KVM with `-cpu host`, 4 vCPUs, 8 GiB, a virtio disk of 60 GiB (`cache=none`, so a
  guest `fsync` reaches the host disk), user-mode networking with the guest's SSH forwarded to
  `127.0.0.1:2222` on the host.
- Cloud-init (NoCloud seed): a `vilicus` user with passwordless sudo and a key pair generated
  for each run into `e2e/vm/state/` (ignored by git), no password login, no root login;
  `docker.io`, `docker-compose` (v2), `docker-buildx`, `git`, `rsync`, `curl` and
  `systemd-coredump` from the Debian archive; swap disabled.

## Commands

```bash
bash e2e/vm/vm.sh up                     # build, boot, wait for cloud-init and Docker
bash e2e/vm/vm.sh info                   # kernel, systemd, CPUs, memory, disk, Docker
bash e2e/vm/vm.sh sync                   # check out git HEAD in the VM (committed content only)
bash e2e/vm/vm.sh e2e sandbox egress     # run phases, copy results back
bash e2e/vm/vm.sh ssh 'coredumpctl list' # any command in the guest
bash e2e/vm/vm.sh down                   # remove the VM container and its overlay
```

- `sync` sends a git bundle of HEAD and checks that commit out in the guest, so uncommitted
  changes are never tested; it warns when the working tree is dirty. A bundle rather than
  `git archive`: the guest checkout answers `git rev-parse HEAD` with the real SHA, which
  `e2e/run.sh` and the spikes record (and `e2e/run.sh` stops on a tree without git metadata).
  The checkout lands in `~/checkout-<sha>` in the guest and `~/vilicus` points to it.
- `e2e <phase...>` runs `bash e2e/run.sh --only <phases> --keep-going` in the guest and copies
  its results folder to `e2e/results/vm-<UTC timestamp>-<short sha>/`, with a `vm-info.txt`
  holding the SHA, the command and the `info` output. Variables named `E2E_*` or `E<n>_*` in the
  caller's environment are forwarded, for example `E2E_TIMEOUT_SCALE=2` for the first run on
  cold caches.
- `down` keeps the verified base image (`vilicus-vm-images`) for the next run and saves the guest
  console to `e2e/vm/state/console.log`.
- `VM_SSH_PORT` changes the host port if 2222 is taken.

## What this approximates, and what it does not

It is the right operating system: Debian 13's kernel (the `cloud` flavour of the 6.12 line,
which the genericcloud image ships; the reference host would run the generic flavour of the
same line), systemd 257 as PID 1, AppArmor enabled, `systemd-coredump` behind a pipe
`core_pattern`, Debian's Docker Engine 26 on cgroup v2.

It is not the reference host. It is a KVM guest given 4 vCPUs on a fast desktop CPU, with that
CPU's caches and memory bandwidth, and a virtual disk backed by a file on the desktop's SSD
inside Docker Desktop's own VM. Argon2id is bound by memory bandwidth and the Core pipeline by
`fsync`, so `argon2id` and `core-execution` numbers from the VM are closer to the reference
shape than a CPU quota (4 dedicated vCPUs, a real block device, nothing else running in the
guest), but still not a measurement of a small physical 4-core machine with its own SSD.

The spikes still run their checks in containers inside the guest (privileged ones for the
systemd checks), as on Docker Desktop. What changes is the kernel, the engine and the host
around them. A check that must run under the guest's own systemd (outside any container) is
run with `vm.sh ssh`, as the story's manual procedure describes.

## Known interactions

- A privileged container that boots systemd shares the host's `/proc/sys`. Unless its
  `systemd-sysctl.service` is masked, Debian's `10-coredump-debian.conf` sets the host's
  `kernel.core_pattern` to `core` and the guest loses its `systemd-coredump` pipe until the next
  boot. The spike images mask it; `bash e2e/vm/vm.sh ssh 'cat /proc/sys/kernel/core_pattern'`
  shows the value in effect, and `sudo systemctl restart systemd-sysctl` restores it.
- The guest has no swap, as the reference host is expected to run. A check that needs swap (the
  `swap` group of `locked-memory`) fails here unless a swap file is added for that run.
- Debian's Docker Compose 2.26 starts every `logs` line with an erase-line escape (`ESC [2K`),
  even when the output is not a terminal; a script that anchors patterns on `logs` output must
  strip it.
