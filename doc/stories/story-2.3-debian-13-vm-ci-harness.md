---
title: 'Debian 13 VM CI harness'
epic: 2
story: 3
status: done
author: Rwx-G
created: 2026-10-16
implements: [AD-33, FR-109, E10, E16]
---

# Story 2.3: Debian 13 VM CI harness

As a project maintainer,
I want CI to boot a Debian 13 virtual machine with systemd as PID 1,
So that tests needing systemd units, sockets and sandboxing run in the real production shape.

**Acceptance Criteria:**

**AC1 (AD-33)**
**Given** a CI runner
**When** the VM job starts
**Then** its first step checks that the runner supports nested virtualisation
**And** fails with a clear message naming the missing capability when it does not.

**AC2 (AD-33, FR-109)**
**Given** a runner with nested virtualisation
**When** the job boots a Debian 13 amd64 image
**Then** systemd runs as PID 1 in the guest
**And** the job copies the built artefacts into the guest and runs a test command there, returning its exit status and logs to CI.

**AC3 (AD-33)**
**Given** a smoke test unit file shipped with the harness
**When** the harness starts it with `systemctl` in the guest
**Then** the test asserts the unit reaches the active state and its journal output is collected as a CI artefact.

**AC4 (AD-33)**
**Given** a project that cannot use a hosted runner with nested virtualisation
**When** a maintainer reads `ci/`
**Then** the self-hosted runner fallback is documented with its required host capabilities and the steps to register it.

**AC5 (E10, E16, AD-33)**
**Given** a test in the guest that boots systemd as PID 1 in a privileged container (as the E10 and E14 spikes do)
**When** the job runs it
**Then** the container image masks `systemd-sysctl.service`, because a privileged container that boots systemd shares the guest's `/proc/sys` and Debian's `10-coredump-debian.conf` replaced the guest's `systemd-coredump` pipe with `core` (Story 1.6, "Debian 13 VM run"; gates E10-4 and E16-4)
**And** the job reads `kernel.core_pattern` before and after the test and fails when it changed, so a later phase never tests the file case on a pipe host (gate E16-4: the locked-memory phase prints `core_pattern` and the report checks it against the host value).

**Dependencies:**
- Story 2.1 (workspace builds the artefacts)

**References:**
- `doc/architecture-spine.md` AD-33 (including the CI on GitHub Actions spine assumption)
- `doc/prd.md` FR-109
- `e2e/vm/` and its README (the Epic 1 Debian 13 KVM harness, a working example of AC2: QEMU with KVM, image pinned in `e2e/vm/IMAGE.lock`); `doc/qa/epic-1-report.md` section 15
- `doc/qa/gates/1.6-e10-sandbox-profile-and-peer-identity.yml` (E10-4), `doc/qa/gates/1.10-e16-locked-memory-and-zeroization.yml` (E16-4)

## Implementation Notes

**What was built**
- `ci/vm_harness.py` (Python standard library), the CI driver of the Debian 13 VM, with commands `check-kvm`, `up`, `copy`, `run`, `smoke`, `collect` and `down` (its docstring and `ci/vm/README.md` describe them). Tests: `ci/test_vm_harness.py`, picked up by `python3 -m unittest discover -s ci` in the `workspace-policy` job.
- `ci/vm/vilicus-ci-smoke.service`, the smoke unit (AC3): a `Type=exec` service under `DynamicUser=yes` with a few sandbox lines, whose shell prints one marker line and then sleeps.
- `ci/vm/systemd-container/Dockerfile`, the privileged systemd container the smoke boots in the guest (AC5): `debian:trixie-slim` at the digest `e2e/vm` and `spikes/sandbox-profile` use, `systemd` and `systemd-sysv`, `systemd-sysctl.service` masked.
- `ci/vm/README.md`: what the harness is, the CI job step by step, the `core_pattern` guard, the results artefact, local use, and the self-hosted runner fallback with its host capabilities and registration steps (AC4).
- `.github/workflows/ci.yml`: a new job `vm-smoke`, "Debian 13 VM smoke test (AD-33)", on `ubuntu-24.04`, on every trigger of the workflow, pull requests included. It is not a required check. Steps: checkout, `sudo python3 ci/vm_harness.py check-kvm`, the image cache, the toolchain, `cargo build --package vilicus --frozen --config ci/cargo-vendored.toml`, `up`, `copy` of `target/debug/vilicus`, `run` of it in the guest, `smoke`, then `collect`, the upload of `vm-results/` as artefact `vm-smoke-results`, and `down` under `always()`. New actions: `actions/upload-artifact` v7.0.2 by commit SHA; `actions/cache` v6.1.0 is the SHA Story 2.2 already uses. The workflow keeps its single `permissions: contents: read`.
- `ci/test_check_supply_chain.py`, `WorkflowAgreementTest`: five new tests. The `vm-smoke` job exists with its check name and command lines and runs `check-kvm` as the first step after the checkout; only the collection, upload and teardown steps carry an `if:`, and that `if:` is `always()`; the image cache is keyed by `hashFiles('e2e/vm/IMAGE.lock')`; every `uses:` in the workflow and in `.github/actions/` is local or pinned by a 40-hex commit SHA with a `# v<version>` comment; no job widens `permissions`. The existing vendored-sources test now also covers the `cargo build --package vilicus` line.
- `e2e/vm/vm.sh`, backward compatible:
  - `VM_CPUS`, `VM_MEMORY_MIB` and `VM_DISK_SIZE` are passed to the container with `--env NAME`, which passes a variable only when it is set, so `entrypoint.sh` keeps its defaults otherwise.
  - `VM_IMAGES_DIR`, when set, bind-mounts a host directory as `/images` instead of the `vilicus-vm-images` volume, which is what CI caches.
  - A `console` command prints the VM container's log.
  - The SSH wait loop checks that the container runs before calling `vm_ssh`. Before, a container that stopped during the wait made `vm_ssh` exit the script from inside the `until` condition with its stderr silenced, so `vm.sh up` exited 1 with no reason (seen in this story, see below).
- `e2e/vm/README.md`: points at the CI harness, documents the new variables and command, and the `modprobe kvm_intel` step needed after a Docker Desktop restart.
- `.gitattributes`: `e2e/vm/IMAGE.lock text eol=lf`. The lock is sourced by bash in the `e2e/vm` container, and a Windows checkout with `core.autocrlf=true` gave it CRLF, so every value ended in `\r` and curl refused the URL (`curl: (3) URL rejected: Malformed input to a URL function`). The working copy here was converted to LF; `git diff` shows no change to the file, since the index already holds LF.

**Decisions and why**
- *Reuse `e2e/vm` as the VM engine rather than a second VM under `ci/`.* The spine's source tree puts the harness in `ci/`, and the driver, unit, container and documentation are there; the image pin, the host container and the boot remain those of `e2e/vm`, which already boots the pinned image with systemd 257 as PID 1 and Docker in the guest. What it gives up: `ci/` depends on `e2e/vm/`, so a change there changes what CI boots, and one VM per Docker engine at a time (container `vilicus-vm`). `e2e/vm/README.md` now says so. Moving the engine under `ci/vm/` later is a mechanical change.
- *Python for the driver, not shell.* The AC1 check needs two ioctls, and the guard and the checks need tests; `ci/` already holds standard-library Python with unittest. The driver shells out to `e2e/vm/vm.sh` for everything that touches Docker. `bash` is resolved with `shutil.which`, because on Windows a bare `bash` would start the WSL launcher in `System32` before Git Bash.
- *AC1: what "usable" means.* `check-kvm` opens `/dev/kvm` read-write, requires `KVM_GET_API_VERSION` to return 12, and creates a VM with `KVM_CREATE_VM`. On failure it names the missing capability: the device (with the CPU's `vmx` or `svm` flag read from `/proc/cpuinfo`, to tell nested virtualisation off from a module not loaded or a device not passed into a container), access for the current uid, the KVM API, or VM creation. It runs with `sudo` in CI because QEMU opens the device as root inside the `e2e/vm` container; the runner user's access does not matter, so the usual udev rule for runner-user access is not needed.
- *AC1: "first step".* The check is the first step after `actions/checkout`, which it needs for the script. The test pins that order.
- *AC2: artefacts and the test command.* `copy` streams a tar archive over `vm.sh ssh` into `~/artefacts/`; `run` streams the command's output, stdout and stderr merged, to the job log and to `--log`, and exits with the guest command's status. The CI job copies the `vilicus` binary built in the job (a debug build of the current empty `main`) and runs it. `up` asserts that PID 1 of the guest is systemd. The guest command is passed through a step `env` variable so that the runner's shell does not expand it (actionlint flagged a quoted `~`).
- *AC3: what is asserted.* The unit is installed in `/etc/systemd/system/`, started with `systemctl start`, and its `ActiveState` must be `active`. Its journal must hold the marker line printed by this start's main process (`sh[<MainPID>]`); the journal and `systemctl status` are written to the results directory and uploaded. Tying the line to the `MainPID` came from a local run: a second smoke in the same boot first passed on the previous start's line.
- *AC5: mask plus guard.* The container image masks `systemd-sysctl.service`; `smoke` asserts that `systemctl is-enabled systemd-sysctl.service` reports `masked` inside the running container, and `ci/test_vm_harness.py` fails any Dockerfile under `ci/vm/` whose container boots an init without the mask (review fix 1 below). Independently, `run` and `smoke` read `kernel.core_pattern` before and after their test and fail on any change, with a status of 1 when the test itself passed and the test's own status otherwise. The guard does not restore the pattern: it prints the restore command, and the job stops.
- *Image verification: SHA512, not SHA-256.* The task asked for SHA-256. Debian publishes `SHA512SUMS` for its cloud images, and `e2e/vm/IMAGE.lock` pins the SHA512; `entrypoint.sh` verifies the file against it on every boot and checks that the published list still carries it. A second, SHA-256 pin would add a value to maintain and no protection.
- *Caching.* The verified image (about 330 MiB) is cached by `actions/cache` under `VM_IMAGES_DIR`, keyed by the hash of `IMAGE.lock`. A cache entry cannot replace the image unnoticed, because the SHA512 check runs on every boot. `VM_IMAGES_DIR` and `VM_RESULTS` are job-level variables under `github.workspace`, because job-level `env` cannot read `runner.temp`, and the `always()` steps need the paths even when the first step fails.
- *Guest size in CI.* 2 vCPUs, 4 GiB and a 20 GiB sparse disk, on a runner of 4 vCPUs and 16 GiB, leaving room for QEMU, Docker and the runner. The `e2e/vm` defaults (4, 8 GiB, 60 GiB) are unchanged for local runs.
- *Container rules.* The systemd container runs as root because systemd is its PID 1, and it is a disposable fixture inside a disposable VM; its Dockerfile says so. Hadolint 2.12.0 reports DL3008 (unpinned apt versions): ignored with a reason in the file, because the trixie archive keeps only the current version of a package and a pinned version stops installing at the next point release. The base is pinned by digest. `e2e/vm/Dockerfile` has the same DL3008 finding and was left as is.

**Review fixes (2026-10-18, after `f882c2f`)**
1. *Static mask check keyed on the init, not on how systemd was installed.* The first check matched `apt-get install ... systemd` only, and missed `apt-get --yes install systemd`, `apt install -y systemd-sysv` and a base image that already ships systemd. A Dockerfile under `ci/vm/` now needs the `systemctl mask systemd-sysctl.service` line when its last `ENTRYPOINT` or `CMD` runs `/sbin/init` or `/lib/systemd/systemd` (including `/usr/lib/systemd/systemd`, behind a shell or behind `tini`), or when it declares neither and inherits its base image's, as `FROM jrei/systemd-debian:13` does. Comment lines do not count as a mask. `HarnessFilesTest` replays those variants, and three that do not boot an init: a plain binary, a later `CMD` replacing the init, and `systemd-journald`.
2. *Guard pre-check.* `guarded` fails with `FAIL core_pattern_expected`, without running the test, when the pattern read before the test does not start with `|/usr/lib/systemd/systemd-coredump`, the pipe of the pinned Debian 13 guest (`GUEST_CORE_PATTERN_PREFIX`). A guest already on `core` used to pass, since before and after were equal, which is the E16-4 risk. The restore hint now uses `bash e2e/vm/vm.sh ssh 'sudo systemctl restart systemd-sysctl'`, because `run` would refuse it.
3. *Exit status propagation is now tested.* A CI step runs `python3 ci/vm_harness.py run -- 'exit 3'` and fails unless it returns 3. `WorkflowAgreementTest` pins that step. `GuestCommandTest` replaces the command behind `vm.sh ssh` with a local `sh -c`: `stream` returns 7 and logs both streams, and `copy` returns 7 whether the other side reads the archive (`cat >/dev/null; exit 7`) or not (`exit 7`). The second case showed that `copy` raised `BrokenPipeError` instead of returning the status, and `OSError: [Errno 22] Invalid argument` on Windows, where tarfile's cleanup writes to the broken pipe again. `copy` now opens the pipe unbuffered, returns the guest status on any `OSError` while writing, and re-raises when that status is 0, so a local error such as an unreadable artefact is not hidden.
4. *EPERM.* `check-kvm` reports `EPERM` from opening `/dev/kvm` as access denied by policy (a device cgroup or container rule; pass `--device /dev/kvm`), and no longer as a uid problem. `EACCES` keeps the uid message.
5. *Status 255.* `run` prints a hint that ssh returns 255 when it fails itself, so a 255 may mean the command never ran.
6. *No inherited stdin.* `Guest.run` passes `stdin=subprocess.DEVNULL` when it has no input, and `Guest.stream` always does. The test gives its own process a stdin holding one line and checks that a control child inheriting stdin does read it; without that control, the test passed under a runner whose stdin was already empty.
7. *Step timeouts.* `timeout-minutes` on the boot (20), on both `run` steps (10 and 5) and on the smoke (15), below the job's 45. `WorkflowAgreementTest` requires them.
8. *Smoke after a failed run step.* The boot step has `id: up`, and the smoke runs under `if: ${{ !cancelled() && steps.up.outcome == 'success' }}`, so a failed `run` step still produces the AC3 journals, and a failed boot skips the smoke. The agreement test allows exactly that condition on the smoke step, `always()` on the collection, upload and teardown, and nothing on the other steps.
9. *Smoke inside the guard.* `SmokeGuardTest` runs `cmd_smoke` on a fake guest whose pattern is `core` and whose `run` raises. Removing `guarded` from `cmd_smoke` turns it red.
10. *Guest identity.* `up` (through `check_guest`) also fails unless the guest's `VERSION_ID` is `13` (`guest_is_debian_13`) and `uname -m` is `x86_64` (`guest_is_amd64`). `CheckGuestTest` covers release 12, an empty release, `aarch64` and a non-systemd PID 1.
11. *`vm.sh down` message.* It names the directory when `VM_IMAGES_DIR` is set, and the volume otherwise.

`ci/vm/README.md` and the comment of `ci/vm/systemd-container/Dockerfile` state the new rules.

**Files**
- `ci/vm_harness.py`, `ci/test_vm_harness.py`
- `ci/vm/README.md`, `ci/vm/vilicus-ci-smoke.service`, `ci/vm/systemd-container/Dockerfile`
- `.github/workflows/ci.yml`, `ci/test_check_supply_chain.py`
- `e2e/vm/vm.sh`, `e2e/vm/README.md`, `.gitattributes`

**Open points**
- *GitHub run:* the first run of `vm-smoke` on GitHub, on commit `f882c2f`, passed, as reported to me (KVM present, VT-x, guest systemd 257, smoke unit active). I have not read that run's log or artefact myself, so its `core_pattern` lines and the upload are not checked here. The review fixes below have not run on GitHub yet.
- *Required check:* `vm-smoke` is not required, and branch protection was not changed. It has run green once (above); the check name to require is "Debian 13 VM smoke test (AD-33)".
- *Engine location:* `ci/` drives `e2e/vm/`. If the owner prefers the engine under `ci/vm/`, it moves with `e2e/vm/vm.sh` kept as a wrapper.
- *Unpinned guest packages:* cloud-init installs Docker and `systemd-coredump` from the trixie archive on the day of the run, as in Epic 1; `vm-info.txt` records their versions in each artefact.
- *`e2e/vm/state/console.log`:* the local runs of this story overwrote the Epic 1 console log there (ignored by git, rewritten by every `vm.sh down`). The Epic 1 results under `e2e/results/` are untouched.
- *Consumers:* Story 5.3 (E10-3 on the VM harness), Story 12.6 (restore drill) and the FR-109 test doubles are expected to add their tests as `run` steps or as smoke-like commands of this harness.

## Result

All commands ran on 2026-10-18 on the Windows development host. Python checks ran in `rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a` (Python 3.13.5) on a copy of the repository without the root `.cargo/` directory. VM runs were driven from Git Bash with the host's Python 3.14.2, against Docker Desktop 29.8.2 whose engine VM exposes KVM (after `modprobe kvm_intel`, see AC1). The `vilicus` binary for the VM runs was built in the same Rust image with `cargo build --package vilicus --frozen --config ci/cargo-vendored.toml`. The workflow has not run on GitHub.

Baseline:

- `python3 -m unittest discover -s ci`: `Ran 112 tests`, `OK` (90 before this story; 17 in `test_vm_harness.py`, 5 new in `WorkflowAgreementTest`). On the Windows host, `test_vm_harness.py` alone: 17 run, 3 skipped (the Linux character-device cases).
- `python3 ci/check_workspace.py`: `workspace checks passed: 12 crates`. `python3 ci/check_supply_chain.py`: `supply-chain checks passed: 12 packages`. `cargo fmt --all --check`: exit 0.
- `actionlint` 1.7.7 on the repository: no finding, exit 0. `hadolint` 2.12.0 on `ci/vm/systemd-container/Dockerfile`: no finding, exit 0.
- Workflow mutations, each on a fresh copy of `ci.yml`, each failing `WorkflowAgreementTest`: `check-kvm` step removed (`test_vm_job_checks_nested_virtualisation_first_and_runs_the_harness`); `if: always()` added to the smoke step, and removed from the upload step (`test_vm_job_runs_only_its_collection_and_teardown_under_always`); `actions/upload-artifact@v7` instead of the SHA (`test_every_action_is_local_or_pinned_by_commit_with_its_version`); the cache key on `e2e/vm/Dockerfile` (`test_vm_job_caches_the_image_by_its_lock`); `--config ci/cargo-vendored.toml` dropped from the VM build (`test_every_workspace_cargo_build_reads_the_vendored_sources`); `permissions: contents: write` on the job (`test_workflow_reads_the_repository_only`). The unmodified copy passes.

| Criterion | Result | Command and observed outcome |
|---|---|---|
| AC1 (AD-33) | **Pass locally, GitHub run pending** | `python3 ci/vm_harness.py check-kvm` as root in the Rust image. Without `--device /dev/kvm`: `FAIL nested_virtualisation: nested virtualisation: /dev/kvm does not exist; the CPU shows Intel VT-x; the kvm module is not loaded, or the device was not passed in (a container needs --device /dev/kvm)`, exit 1. With `--device /dev/kvm`: `PASS nested_virtualisation: /dev/kvm is a KVM device (API 12) that can create a VM; the CPU shows Intel VT-x`, exit 0. With the device and `--user 1000`: `FAIL ... KVM access: /dev/kvm exists but uid 1000 cannot open it read-write (Permission denied)`, exit 1. With `/dev/null` passed as `/dev/kvm`: `FAIL ... KVM API: /dev/kvm does not answer KVM_GET_API_VERSION (Inappropriate ioctl for device); it is not a KVM device`, exit 1. Before this run the engine itself had no `/dev/kvm` (`docker run --device /dev/kvm` failed with `error gathering device information`); `nsenter -t 1 -m -- modprobe kvm_intel` in the engine's VM brought it back. Unit tests: `CpuVirtualisationTest`, `CheckKvmTest` (missing device with and without CPU flags, regular file, non-KVM device, permission denied, wrong API version, failed VM creation, success). |
| AC2 (AD-33, FR-109) | **Pass locally, GitHub run pending** | `VM_CPUS=2 VM_MEMORY_MIB=4096 VM_DISK_SIZE=20G VM_IMAGES_DIR=<scratch>/vm-images python ci/vm_harness.py up`, first boot with an empty image directory: image downloaded, `SHA512 verified against IMAGE.lock and .../SHA512SUMS`, QEMU 10.0.13, `PASS guest_pid1_is_systemd: PID 1 is systemd, system state running`, `Debian GNU/Linux 13 (trixie), 6.12.111+deb13-cloud-amd64, systemd 257 (257.13-1~deb13u1)`, exit 0, 97 s. Second boot on the populated directory (the cache-hit path): no download, SHA512 verified, same PASS. `copy <scratch>/artefact/vilicus`: exit 0, the file listed in `~/artefacts/`. `run --log .../vilicus-run.log -- 'chmod +x ~/artefacts/vilicus; ~/artefacts/vilicus; status=$?; echo "vilicus exited $status on ..."; exit $status'` (the CI command plus `chmod`, because a file copied from Windows has no executable bit): `vilicus exited 0 on Debian GNU/Linux 13 (trixie)`, exit 0, same line in the log. `run -- 'echo to-stdout; echo to-stderr >&2; exit 3'`: both lines in the job output and the log, `INFO guest command exited 3`, harness exit 3. `e2e/vm` local use, unchanged commands without the new variables: see the paragraph below the table. |
| AC3 (AD-33) | **Pass locally, GitHub run pending** | `python ci/vm_harness.py smoke --out <scratch>/vm-results-2`, twice in the same boot: `PASS smoke_unit_started`, `PASS smoke_unit_active: ActiveState=active, MainPID=2617, Result=success, SubState=running`, `PASS smoke_unit_journal_collected: ... sh[2617]: vilicus-ci-smoke: running as uid 64692 under PID 1 systemd`, then on the second run `MainPID=3390` and the line of `sh[3390]`; `RESULT PASS`, exit 0 each. `smoke-unit-journal.txt`, `smoke-unit-status.txt` and `systemd-container-journal.txt` written; `collect` added `vm-info.txt` and `console.log`, exit 0. Negative, the same smoke with a copy of the unit whose `ExecStart` names a missing file: `FAIL smoke_unit_started: ... exited 1`, `FAIL smoke_unit_active: ActiveState=failed, ... Result=exit-code`, `FAIL smoke_unit_journal_collected`, `RESULT FAIL`, exit 1. The upload of the artefact itself runs only on GitHub. |
| AC4 (AD-33) | **Pass** | `ci/vm/README.md`, section "Self-hosted runner fallback": required host capabilities (x86_64 Linux with `vmx` or `svm`, the KVM module and `/dev/kvm`, nested virtualisation when the runner is a VM, `check-kvm` passing; Docker Engine and the docker group; passwordless sudo; tools; CPU, memory and disk; outbound hosts) and registration steps (repository approval setting for external contributors, download and SHA-256 check, `config.sh --ephemeral` with a label, the service, the `runs-on` change, a `workflow_dispatch` check of the first step). Not exercised: no self-hosted runner was registered. |
| AC5 (E10, E16, AD-33) | **Pass locally, GitHub run pending** | In each smoke run above: `PASS systemd_container_pid1_is_systemd: PID 1 is systemd, system state degraded`, `PASS systemd_container_masks_systemd_sysctl: systemd-sysctl.service is masked`, `INFO core_pattern before` and `after` both `\|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F`, `PASS core_pattern_unchanged`. Negative, written directly: `run -- 'sudo sysctl -w kernel.core_pattern=core'`: the command exits 0, `INFO core_pattern after: core`, `FAIL core_pattern_unchanged: the test changed kernel.core_pattern from '\|/usr/lib/systemd/systemd-coredump ...' to 'core'`, harness exit 1. Negative, the real mechanism: a copy of the systemd container without the `systemctl mask` line, built and booted privileged in the guest under `run`: `systemd-sysctl.service` reported `static`, the pattern went from the pipe to `core`, `FAIL core_pattern_unchanged`, exit 1. Each time `sudo systemctl restart systemd-sysctl` restored the pipe (that `run` itself failed the guard, as any change does). Unit tests: `CorePatternGuardTest` (unchanged pattern keeps the status, a change fails a passing command with 1 and keeps a failing command's status, the first read precedes the test), and `HarnessFilesTest` (every Dockerfile under `ci/vm/` that installs systemd masks `systemd-sysctl.service`, the check refuses the same Dockerfile with the mask removed, the smoke unit prints the line the harness looks for). |

`e2e/vm` local use after the changes, with none of the new variables set: `bash e2e/vm/vm.sh up` booted on the `vilicus-vm-images` volume with the old defaults (`4 vCPUs, 8192 MiB, 60G virtio disk`), SHA512 verified, `VM ready: docker 26.1.5+dfsg1, kernel 6.12.111+deb13-cloud-amd64`, exit 0; `info` printed the guest facts (its exit 1 in that run came from the `| head -4` of the check closing the pipe); `console` printed 1 095 lines; `ssh 'cat /proc/sys/kernel/core_pattern'` printed the `systemd-coredump` pipe; `down` removed the container and the overlay, exit 0. `bash e2e/vm/vm.sh help` lists the new `console` command. `vm.sh sync` and `vm.sh e2e` were not rerun; their code is unchanged.

### Review fixes (2026-10-18)

Run on the working tree after `f882c2f`, on the same hosts as above, limited to the tests that cover the edited files and one CI-sized VM boot.

- `python3 -m unittest test_vm_harness test_check_supply_chain.WorkflowAgreementTest` in the Rust image (from `ci/`): `Ran 41 tests`, `OK` (27 in `test_vm_harness.py`, none skipped; 14 in `WorkflowAgreementTest`), three times in a row, and also with stdin from `/dev/null`. On the Windows host, `test_vm_harness.py`: `OK (skipped=5)` (the four Linux character-device cases and the stdin case), three times in a row.
- `actionlint` 1.7.7: exit 0. `hadolint` 2.12.0 on `ci/vm/systemd-container/Dockerfile`: exit 0. `bash -n e2e/vm/vm.sh`: exit 0.
- Mutations, each on a fresh copy, each turning the named test red:

| Mutation | Red test |
|---|---|
| `cmd_smoke` calls the test without `guarded` | `test_smoke_runs_inside_the_core_pattern_guard` |
| pipe pre-check removed | `test_a_guest_not_on_the_coredump_pipe_fails_before_the_test_runs`, `test_smoke_runs_inside_the_core_pattern_guard` |
| `VERSION_ID` check always true | `test_another_release_machine_or_init_fails` |
| `uname -m` check always true | `test_another_release_machine_or_init_fails` |
| `EPERM` branch removed | `test_operation_not_permitted_is_reported_as_a_policy_denial` |
| 255 hint removed | `test_status_255_carries_the_ssh_hint_and_no_other_does` |
| `stream` without `stdin=subprocess.DEVNULL` | `test_stream_gives_the_command_no_stdin` |
| `run -- 'exit 3'` line removed from the workflow | `test_vm_job_checks_nested_virtualisation_first_and_runs_the_harness` |
| smoke condition replaced by `always()` | `test_vm_job_runs_only_its_collection_and_teardown_under_always` |
| `id: up` removed | `test_vm_job_smoke_condition_names_the_boot_step_and_guest_steps_time_out` |
| smoke `timeout-minutes` removed | `test_vm_job_smoke_condition_names_the_boot_step_and_guest_steps_time_out` |

- VM run, the job's step sequence with `VM_CPUS=2 VM_MEMORY_MIB=4096 VM_DISK_SIZE=20G` and the populated `VM_IMAGES_DIR`, 1 min 43 s from boot to `down`:
  - `up`: SHA512 verified, `PASS guest_pid1_is_systemd`, `PASS guest_is_debian_13: VERSION_ID=13`, `PASS guest_is_amd64: uname -m is x86_64`, exit 0.
  - `copy` exit 0. `run` of the binary: `vilicus exited 0 on Debian GNU/Linux 13 (trixie)`, exit 0.
  - The workflow's exit-status step, run as written: `INFO guest command exited 3: exit 3`, `PASS core_pattern_unchanged`, returned 3, `test "$status" -eq 3` exit 0.
  - `smoke`: every check `PASS` as before, journal line from `sh[2671]`, the `MainPID`, `RESULT PASS`, exit 0.
  - After `bash e2e/vm/vm.sh ssh 'sudo sysctl -w kernel.core_pattern=core'`: `smoke` printed `INFO core_pattern before: core` and `FAIL core_pattern_expected: kernel.core_pattern is 'core' before the test, not the |/usr/lib/systemd/systemd-coredump pipe of the Debian 13 guest; ... so this one is not run`, then `RESULT FAIL`, exit 1, with no smoke check run. `run -- 'echo this-must-not-run'` gave the same `FAIL`, exit 1, and its command's output never appeared. `bash e2e/vm/vm.sh ssh 'sudo systemctl restart systemd-sysctl; ...'` restored the pipe.
  - `collect` exit 0. `down`: `overlay volume vilicus-vm-run removed; base image kept in <scratch>/vm-images`, exit 0.
- Not rerun: `e2e/vm/vm.sh` without the new variables, since only its `down` message changed; the GitHub run of these fixes.
