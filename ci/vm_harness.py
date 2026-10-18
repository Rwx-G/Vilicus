#!/usr/bin/env python3
"""Debian 13 VM harness for CI (doc/architecture-spine.md AD-33; Story 2.3; ci/vm/README.md).

The VM itself is the Epic 1 one: `e2e/vm/vm.sh` boots the cloud image pinned in
`e2e/vm/IMAGE.lock` with QEMU and KVM inside a Docker container, systemd as PID 1. This driver
adds what CI needs on top of it:

  check-kvm            AD-33's first step: /dev/kvm present and usable, or a message naming the
                       missing capability. Run it as the user that starts QEMU: root through
                       Docker, so `sudo` on a GitHub-hosted runner.
  up                   boot the VM and assert that PID 1 of the guest is systemd
  copy PATH...         copy files or directories into ~/artefacts/ in the guest
  run -- COMMAND...    run COMMAND in the guest (one shell string, as ssh joins it), stream its
                       output, also into --log, and exit with its status
  smoke                start ci/vm/vilicus-ci-smoke.service with systemctl and assert that it is
                       active, boot the privileged systemd container of ci/vm/systemd-container,
                       and write both journals to --out
  collect              write the guest facts (`vm.sh info`) and the guest console to --out
  down                 stop the VM

`run` and `smoke` read kernel.core_pattern in the guest before and after their test and fail when
it changed (gates E10-4 and E16-4): a privileged container that boots systemd shares the guest's
/proc/sys.

Standard library only. Needs bash, Docker and ssh-keygen, as e2e/vm/vm.sh does.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VM_SH = REPO_ROOT / "e2e" / "vm" / "vm.sh"
HARNESS_DIR = REPO_ROOT / "ci" / "vm"
SMOKE_UNIT = HARNESS_DIR / "vilicus-ci-smoke.service"
SYSTEMD_CONTAINER = HARNESS_DIR / "systemd-container"
# The line the smoke unit's shell prints; ci/test_vm_harness.py checks that the unit prints it.
SMOKE_MARKER = "vilicus-ci-smoke: running as"

# Guest directories, relative to the test user's home (where ssh starts).
GUEST_ARTEFACTS = "artefacts"
GUEST_HARNESS = "ci-vm"
SYSTEMD_CONTAINER_NAME = "vilicus-ci-systemd"

KVM_DEVICE = Path("/dev/kvm")
CPUINFO = Path("/proc/cpuinfo")
# linux/kvm.h: _IO(KVMIO, 0x00) and _IO(KVMIO, 0x01) with KVMIO = 0xAE; the API version has been
# 12 since Linux 2.6.22 and KVM_GET_API_VERSION must return exactly that.
KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01
KVM_API_VERSION = 12
VIRTUALISATION_FLAGS = {"vmx": "Intel VT-x", "svm": "AMD-V"}


class MissingCapability(Exception):
    """The runner lacks what the VM needs; the message names the capability."""


class HarnessError(Exception):
    """The harness could not talk to the guest or got an answer it cannot read."""


# --- AC1: nested virtualisation -----------------------------------------------------------------


def cpu_virtualisation(cpuinfo: Path) -> list[str]:
    """Names of the hardware virtualisation extensions the CPU flags show, empty when none."""
    try:
        text = cpuinfo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    flags: set[str] = set()
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "flags":
            flags.update(value.split())
    return [name for flag, name in VIRTUALISATION_FLAGS.items() if flag in flags]


def _ioctl(fd: int, request: int, arg: int = 0) -> int:
    import fcntl  # Linux only; imported here so the module loads on any platform.

    return fcntl.ioctl(fd, request, arg)


def check_kvm(device: Path = KVM_DEVICE, cpuinfo: Path = CPUINFO, ioctl: Callable[[int, int, int], int] = _ioctl) -> str:
    """Raises MissingCapability unless `device` is a KVM device that can create a VM."""
    extensions = cpu_virtualisation(cpuinfo)
    cpu = (
        f"the CPU shows {' and '.join(extensions)}"
        if extensions
        else "the CPU shows no vmx or svm flag, so the runner (or the VM it runs in) exposes no hardware virtualisation"
    )
    if not device.exists():
        hint = (
            "the kvm module is not loaded, or the device was not passed in (a container needs --device /dev/kvm)"
            if extensions
            else "nested virtualisation is off for this runner"
        )
        raise MissingCapability(f"nested virtualisation: {device} does not exist; {cpu}; {hint}")
    if not stat.S_ISCHR(device.stat().st_mode):
        raise MissingCapability(f"nested virtualisation: {device} exists but is not a character device")
    try:
        fd = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    except PermissionError as error:
        raise MissingCapability(
            f"KVM access: {device} exists but uid {os.geteuid()} cannot open it read-write ({error.strerror}); "
            "run the check as the user that starts QEMU (root, through Docker)"
        ) from error
    except OSError as error:
        raise MissingCapability(f"KVM access: opening {device} read-write failed ({error.strerror})") from error
    try:
        try:
            version = ioctl(fd, KVM_GET_API_VERSION, 0)
        except OSError as error:
            raise MissingCapability(
                f"KVM API: {device} does not answer KVM_GET_API_VERSION ({error.strerror}); it is not a KVM device"
            ) from error
        if version != KVM_API_VERSION:
            raise MissingCapability(f"KVM API: {device} reports API version {version}, QEMU needs {KVM_API_VERSION}")
        try:
            vm_fd = ioctl(fd, KVM_CREATE_VM, 0)
        except OSError as error:
            raise MissingCapability(f"KVM VM creation: KVM_CREATE_VM on {device} failed ({error.strerror})") from error
        os.close(vm_fd)
    finally:
        os.close(fd)
    return f"{device} is a KVM device (API {version}) that can create a VM; {cpu}"


# --- AC5: kernel.core_pattern guard --------------------------------------------------------------


def guarded(read_core_pattern: Callable[[], str], test: Callable[[], int], report: Callable[[str], None] = print) -> int:
    """Runs `test` between two reads of kernel.core_pattern; a change fails the result."""
    before = read_core_pattern()
    report(f"INFO core_pattern before: {before}")
    status = test()
    after = read_core_pattern()
    report(f"INFO core_pattern after:  {after}")
    if after != before:
        report(
            f"FAIL core_pattern_unchanged: the test changed kernel.core_pattern from {before!r} to {after!r}. "
            "A privileged container that boots systemd without systemd-sysctl.service masked applies its "
            "sysctl.d to the guest (gates E10-4, E16-4); any later test would run on the wrong pattern. "
            "Restore with: sudo systemctl restart systemd-sysctl"
        )
        return status or 1
    report("PASS core_pattern_unchanged")
    return status


# --- The guest, through e2e/vm/vm.sh -------------------------------------------------------------


def _bash() -> str:
    # shutil.which follows PATH; a bare "bash" on Windows would start the WSL launcher in
    # System32 before Git Bash.
    found = shutil.which("bash")
    if found is None:
        raise HarnessError("bash is not on the PATH")
    return found


def vm_command(*args: str) -> list[str]:
    return [_bash(), VM_SH.as_posix(), *args]


class Guest:
    """The running VM, reached through `vm.sh ssh` as the test user."""

    def run(self, command: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            vm_command("ssh", command), input=stdin, capture_output=True, check=False
        )
        return subprocess.CompletedProcess(
            result.args,
            result.returncode,
            result.stdout.decode("utf-8", errors="replace"),
            result.stderr.decode("utf-8", errors="replace"),
        )

    def output(self, command: str) -> str:
        result = self.run(command)
        if result.returncode != 0:
            raise HarnessError(f"`{command}` exited {result.returncode} in the guest: {result.stderr.strip()}")
        return result.stdout.strip()

    def stream(self, command: str, log: Path | None) -> int:
        sink = log.open("w", encoding="utf-8", newline="\n") if log else contextlib.nullcontext()
        with sink as file, subprocess.Popen(
            vm_command("ssh", command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as process:
            assert process.stdout is not None
            for raw in process.stdout:
                line = raw.decode("utf-8", errors="replace")
                sys.stdout.write(line)
                sys.stdout.flush()
                if file:
                    file.write(line)
            return process.wait()

    def copy(self, paths: list[Path], destination: str) -> int:
        """Streams `paths` as a tar archive into ~/<destination>/ in the guest."""
        for path in paths:
            if not path.exists():
                raise HarnessError(f"{path} does not exist")
        target = shlex.quote(destination)
        with subprocess.Popen(
            vm_command("ssh", f"mkdir -p {target} && tar -x --no-same-owner -C {target}"), stdin=subprocess.PIPE
        ) as process:
            assert process.stdin is not None
            with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
                for path in paths:
                    archive.add(path, arcname=path.name, filter=_anonymous)
            process.stdin.close()
            return process.wait()

    def core_pattern(self) -> str:
        return self.output("cat /proc/sys/kernel/core_pattern")


def _anonymous(member: tarfile.TarInfo) -> tarfile.TarInfo:
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    return member


# --- Commands ------------------------------------------------------------------------------------


class Checks:
    """PASS and FAIL lines in the spikes' format; `failed` is set by any FAIL."""

    def __init__(self, report: Callable[[str], None] = print) -> None:
        self.failed = False
        self.report = report

    def check(self, name: str, ok: bool, detail: str) -> bool:
        self.report(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
        self.failed |= not ok
        return ok

    @property
    def status(self) -> int:
        return 1 if self.failed else 0


def cmd_up(guest: Guest) -> int:
    status = subprocess.run(vm_command("up"), check=False).returncode
    if status != 0:
        return status
    checks = Checks()
    pid1 = guest.output("cat /proc/1/comm")
    state = guest.run("systemctl is-system-running").stdout.strip()
    checks.check("guest_pid1_is_systemd", pid1 == "systemd", f"PID 1 is {pid1}, system state {state}")
    facts = guest.output('. /etc/os-release && echo "$PRETTY_NAME"; uname -r; systemctl --version | head -n 1')
    print(f"INFO guest: {', '.join(facts.splitlines())}")
    return checks.status


def _properties(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def smoke_unit(guest: Guest, out: Path, checks: Checks) -> None:
    unit = SMOKE_UNIT.name
    started = guest.run(
        f"sudo install -m 0644 {GUEST_HARNESS}/{unit} /etc/systemd/system/{unit}"
        f" && sudo systemctl daemon-reload && sudo systemctl start {unit}"
    )
    checks.check("smoke_unit_started", started.returncode == 0, f"systemctl start {unit} exited {started.returncode} {started.stderr.strip()}")
    properties = _properties(guest.run(f"systemctl show --property=ActiveState,SubState,MainPID,Result {unit}").stdout)
    checks.check(
        "smoke_unit_active",
        properties.get("ActiveState") == "active",
        ", ".join(f"{key}={value}" for key, value in sorted(properties.items())),
    )
    # The journal covers the boot, so an earlier start of the unit is in it too; only a line from
    # this start's main process counts.
    this_start = f"[{properties.get('MainPID', '')}]: {SMOKE_MARKER}"
    journal = ""
    for _ in range(15):
        journal = guest.run(f"sudo journalctl --unit={unit} --boot --no-pager --output=short-iso").stdout
        if this_start in journal:
            break
        time.sleep(1)
    (out / "smoke-unit-journal.txt").write_text(journal, encoding="utf-8", newline="\n")
    (out / "smoke-unit-status.txt").write_text(
        guest.run(f"systemctl status --no-pager --full {unit}").stdout, encoding="utf-8", newline="\n"
    )
    marker = next((line for line in journal.splitlines() if this_start in line), "")
    checks.check("smoke_unit_journal_collected", bool(marker), marker or f"no line with {this_start!r} in the unit's journal")
    guest.run(f"sudo systemctl stop {unit}")


def systemd_container(guest: Guest, out: Path, checks: Checks) -> None:
    name = SYSTEMD_CONTAINER_NAME
    built = guest.run(f"docker build --quiet --tag {name} {GUEST_HARNESS}/{SYSTEMD_CONTAINER.name}")
    if not checks.check("systemd_container_built", built.returncode == 0, built.stdout.strip() or built.stderr.strip()):
        return
    try:
        # As spikes/sandbox-profile/run.sh: systemd as PID 1 needs a writable cgroup tree and
        # mount namespaces, so --privileged and a private cgroup namespace.
        started = guest.run(f"docker run --detach --name {name} --privileged --cgroupns=private {name}")
        if not checks.check("systemd_container_started", started.returncode == 0, started.stderr.strip() or started.stdout.strip()):
            return
        state = guest.run(f"timeout 180 docker exec {name} systemctl is-system-running --wait").stdout.strip()
        pid1 = guest.run(f"docker exec {name} cat /proc/1/comm").stdout.strip()
        checks.check("systemd_container_pid1_is_systemd", pid1 == "systemd", f"PID 1 is {pid1 or 'unknown'}, system state {state}")
        sysctl = guest.run(f"docker exec {name} systemctl is-enabled systemd-sysctl.service").stdout.strip()
        checks.check("systemd_container_masks_systemd_sysctl", sysctl == "masked", f"systemd-sysctl.service is {sysctl or 'unknown'}")
        (out / "systemd-container-journal.txt").write_text(
            guest.run(f"docker exec {name} journalctl --boot --no-pager --output=short-iso").stdout,
            encoding="utf-8",
            newline="\n",
        )
    finally:
        guest.run(f"docker rm --force {name}")


def cmd_smoke(guest: Guest, out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    if guest.copy([SMOKE_UNIT, SYSTEMD_CONTAINER], GUEST_HARNESS) != 0:
        raise HarnessError("copying ci/vm/ into the guest failed")
    checks = Checks()

    def test() -> int:
        smoke_unit(guest, out, checks)
        systemd_container(guest, out, checks)
        return checks.status

    status = guarded(guest.core_pattern, test)
    print(f"RESULT {'PASS' if status == 0 else 'FAIL'}")
    return status


def cmd_run(guest: Guest, command: list[str], log: Path | None) -> int:
    if not command:
        raise HarnessError("usage: vm_harness.py run [--log FILE] -- COMMAND...")
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
    line = " ".join(command)

    def test() -> int:
        status = guest.stream(line, log)
        print(f"INFO guest command exited {status}: {line}")
        return status

    return guarded(guest.core_pattern, test)


def cmd_collect(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    status = 0
    for name, args in (("vm-info.txt", ("info",)), ("console.log", ("console",))):
        result = subprocess.run(vm_command(*args), capture_output=True, check=False)
        (out / name).write_bytes(result.stdout + result.stderr)
        print(f"INFO {name}: vm.sh {' '.join(args)} exited {result.returncode}")
        status = status or result.returncode
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-kvm")
    commands.add_parser("up")
    copy = commands.add_parser("copy")
    copy.add_argument("paths", nargs="+", type=Path)
    run = commands.add_parser("run")
    run.add_argument("--log", type=Path)
    run.add_argument("guest_command", nargs=argparse.REMAINDER)
    for name in ("smoke", "collect"):
        commands.add_parser(name).add_argument("--out", type=Path, required=True)
    commands.add_parser("down")
    args = parser.parse_args(argv)

    guest = Guest()
    try:
        if args.command == "check-kvm":
            print(f"PASS nested_virtualisation: {check_kvm()}")
            return 0
        if args.command == "up":
            return cmd_up(guest)
        if args.command == "copy":
            status = guest.copy(args.paths, GUEST_ARTEFACTS)
            if status == 0:
                print(guest.output(f"ls -l {GUEST_ARTEFACTS}"))
            return status
        if args.command == "run":
            command = args.guest_command[1:] if args.guest_command[:1] == ["--"] else args.guest_command
            return cmd_run(guest, command, args.log)
        if args.command == "smoke":
            return cmd_smoke(guest, args.out)
        if args.command == "collect":
            return cmd_collect(args.out)
        return subprocess.run(vm_command("down"), check=False).returncode
    except MissingCapability as error:
        print(f"FAIL nested_virtualisation: {error}", file=sys.stderr)
        return 1
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
