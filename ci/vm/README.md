---
title: 'Debian 13 VM CI harness'
author: Rwx-G
---

# Debian 13 VM CI harness

Tests that need systemd as PID 1, its units, sockets and sandboxing run in a Debian 13 virtual
machine (`doc/architecture-spine.md` AD-33). `ci/vm_harness.py` drives that VM for CI. The VM
itself is the Epic 1 one, reused as it is: `e2e/vm/vm.sh` boots the Debian cloud image pinned in
`e2e/vm/IMAGE.lock` with QEMU and KVM inside a Docker container, on a fresh overlay, with
cloud-init installing Docker Engine and `systemd-coredump` from the Debian archive. See
`e2e/vm/README.md` for how the VM is built and what it does and does not approximate.

## Files

- `ci/vm_harness.py`: the driver; `python3 ci/vm_harness.py --help` lists its commands. Its
  tests are `ci/test_vm_harness.py`, run by the `workspace-policy` job with every other `ci/`
  test.
- `ci/vm/vilicus-ci-smoke.service`: the smoke unit. `smoke` installs it in the guest, starts it
  with `systemctl`, asserts that it is active and collects its journal.
- `ci/vm/systemd-container/Dockerfile`: a privileged container that boots systemd as PID 1
  inside the guest, the way the E10 and E14 spikes do. `smoke` boots it and asserts that its
  PID 1 is systemd and that `systemd-sysctl.service` is masked.
- `ci/release_gates.py` and `ci/release_gates.toml`: the release gates of FR-109 and their
  declarations (Story 2.6), run in this VM; see "Release gates" below.

## In CI

The `vm-smoke` job of `.github/workflows/ci.yml` runs on every pull request on a GitHub-hosted
`ubuntu-24.04` runner. It is not a required check yet. Its steps, in order:

1. `sudo python3 ci/vm_harness.py check-kvm`, right after the checkout. It opens `/dev/kvm`,
   asks for the KVM API version and creates a VM, and on failure names what is missing: the
   device (with what the CPU flags say about hardware virtualisation), access to it, or a working
   KVM API. It runs as root because QEMU opens the device as root in the `e2e/vm` container; the
   runner user's access does not matter.
2. The verified base image is restored from the Actions cache, keyed by `IMAGE.lock`.
   `e2e/vm/entrypoint.sh` checks it against the SHA512 of `IMAGE.lock` on every boot, and checks
   that Debian's published `SHA512SUMS` still lists that value, so a stale or altered cache entry
   fails the boot instead of being used.
3. `ci/release_gates.py build` (one cargo build for the shipped `vilicus`, then one for the
   testbed artefact), then `up` (boot, wait for cloud-init, assert that the guest is Debian 13
   on x86_64 with systemd as PID 1), `copy` of the binary into `~/artefacts/`, and `run` of the
   binary in the guest: `run` streams the command's output into the log, then exits with its
   status. A second step runs `run -- 'exit 3'` and fails unless it returns 3.
4. `smoke`: the smoke unit, then the privileged systemd container. It runs whenever `up`
   succeeded, even after a failed `run` step, so its journals are still collected.
5. `ci/release_gates.py run`, on any booted VM like the smoke (see Release gates below).
6. `collect` (guest facts from `vm.sh info`, and the guest console), the upload of everything
   under `vm-results/` as the `vm-smoke-results` artefact, and `down`, each under `always()`.

### kernel.core_pattern guard

`run` and `smoke` read `/proc/sys/kernel/core_pattern` in the guest before and after their test
and fail when it changed. They also fail, without running the test, when the pattern is not the
guest's `systemd-coredump` pipe beforehand. A privileged container that boots systemd shares the
guest's `/proc/sys`: unless its `systemd-sysctl.service` is masked, Debian's
`10-coredump-debian.conf` replaces the guest's `systemd-coredump` pipe with `core` until the next
boot, and every later test runs on the file case (Story 1.6, "Debian 13 VM run"; gates E10-4 and
E16-4). Every Dockerfile under `ci/vm/` whose container boots an init (its last `ENTRYPOINT` or
`CMD` runs `/sbin/init` or `/lib/systemd/systemd`, or it declares neither and inherits its base
image's) must mask `systemd-sysctl.service`; `ci/test_vm_harness.py` fails otherwise. After a
failure, `bash e2e/vm/vm.sh ssh 'sudo systemctl restart systemd-sysctl'` restores the pattern
(not through `run`, whose check would refuse the wrong pattern).

### Results artefact

`vm-smoke-results` holds `vilicus-run.log`, `smoke-unit-journal.txt`, `smoke-unit-status.txt`,
`systemd-container-journal.txt`, `vm-info.txt`, `console.log` and one log per release gate under
`release-gates/`. The job log holds the `PASS` and `FAIL` lines.

## Release gates

Each gate of `ci/release_gates.toml` carries a target tag (FR-109, D102): `testbed` for a gate
that needs a module or a test double, `package` for every other gate. The file's header says how
a gate is declared. `ci/release_gates.py check`, in the `workspace-policy` job, fails on a gate
without a tag, with another tag or with an unknown key, and `run` refuses the same declarations
before it touches the guest.

`run` empties `~/release-gates/` in the guest, then for each target, package first: it copies the
target's artefact into `~/release-gates/<target>/` and runs each of its gates from there,
under GNU `timeout` (the gate's `timeout`, a default otherwise; a timed-out gate fails and the
next gates still run), between two reads of `kernel.core_pattern`, writing `<gate>.log` under
its `--out` directory. The
package artefact is the executables of `ci/release_artefacts.toml`; the testbed artefact is every
executable of a never-packaged crate (`vilicus-testbed` and the test doubles). The testbed
artefact reaches the guest only after the last package gate. Until the Debian package exists
(Story 5.7), the package artefact is the cargo-built executable, not the `.deb`.

Locally, after `up`: `python3 ci/release_gates.py build` (or a build in the pinned Rust image,
then `--artefact-dir` pointing at its output) and
`python3 ci/release_gates.py run --out vm-results/release-gates`.

## Locally

The same commands run from Git Bash on Windows or from Linux, with Docker able to pass
`/dev/kvm` to a container:

```bash
python3 ci/vm_harness.py check-kvm                  # in a container with --device /dev/kvm,
                                                    # or as root on Linux
python3 ci/vm_harness.py up
python3 ci/vm_harness.py copy path/to/artefact
python3 ci/vm_harness.py run --log run.log -- '~/artefacts/artefact --version'
python3 ci/vm_harness.py smoke --out vm-results
python3 ci/vm_harness.py collect --out vm-results
python3 ci/vm_harness.py down
```

- The VM is the `e2e/vm` one: one at a time per Docker engine, container `vilicus-vm`.
- `VM_CPUS`, `VM_MEMORY_MIB` and `VM_DISK_SIZE` size the guest, and `VM_IMAGES_DIR` puts the base
  image in a host directory instead of the `vilicus-vm-images` volume (`e2e/vm/vm.sh` header).
- On Docker Desktop, `/dev/kvm` can be missing from the engine after a restart, and `check-kvm`
  then reports that the device does not exist although the CPU shows VT-x. Loading the module in
  the engine's VM brings it back:
  `MSYS_NO_PATHCONV=1 docker run --rm --privileged --pid=host alpine:3.20 nsenter -t 1 -m -- modprobe kvm_intel`
  (`kvm_amd` on AMD).
- A file copied from a Windows checkout has no executable bit in the guest; `chmod +x` it there,
  or build it in a Linux container.

## Self-hosted runner fallback

Use it if GitHub-hosted runners stop offering KVM (the first step then fails with
`nested virtualisation: /dev/kvm does not exist`), or if the VM needs more than they give.

### Required host capabilities

- x86_64 Linux (Debian 13 or Ubuntu 24.04), with hardware virtualisation: the CPU flags show
  `vmx` (Intel) or `svm` (AMD), the `kvm_intel` or `kvm_amd` module is loaded, and `/dev/kvm`
  exists. A runner that is itself a VM needs nested virtualisation enabled by its hypervisor.
  `sudo python3 ci/vm_harness.py check-kvm` on the host must print `PASS`.
- Docker Engine, with the runner user in the `docker` group (the harness starts the QEMU
  container with `--device /dev/kvm`), and passwordless `sudo` for the runner user, which the
  first step uses.
- `bash`, `git`, `python3` 3.11 or newer, `ssh-keygen` and `tar`; `rustup`, which installs the
  toolchain of `rust-toolchain.toml`.
- Beyond what the runner itself needs: 4 CPUs, 8 GiB of memory and 30 GiB of disk free for the
  guest (the CI job gives it 2 vCPUs, 4 GiB and a 20 GiB sparse disk), its Docker images and the
  base image cache.
- Outbound HTTPS to `github.com` and the Actions service, `cloud.debian.org` (image and
  `SHA512SUMS`), `deb.debian.org` (the guest's packages), Docker Hub (the systemd container's
  base image) and `static.rust-lang.org` (the toolchain).

### Registering it

1. On a disposable host used for nothing else: this repository is public, and a job runs the
   code of the pull request that triggered it. In the repository settings, under Actions,
   General, keep "Require approval for all external contributors" so that no fork pull request
   runs on it without a maintainer's approval.
2. In Settings, Actions, Runners, "New self-hosted runner", Linux x64: GitHub shows the download
   URL of the current runner release and its SHA-256, and a registration token valid for one
   hour. On the host, as an unprivileged user, download the archive, check its SHA-256 against
   the one GitHub shows, and unpack it.
3. Register it as ephemeral, so that it takes one job and must be registered again:
   `./config.sh --url https://github.com/Rwx-G/Vilicus --token <TOKEN> --labels vilicus-kvm --ephemeral --unattended`.
4. Install and start the service: `sudo ./svc.sh install` and `sudo ./svc.sh start`. For an
   ephemeral runner, the host's provisioning registers a new one after each job.
5. In `.github/workflows/ci.yml`, change the `vm-smoke` job's `runs-on` to
   `[self-hosted, linux, x64, vilicus-kvm]`. Nothing else in the job changes.
6. Run the workflow with `workflow_dispatch` on a branch and check that the first step prints
   `PASS nested_virtualisation`.
