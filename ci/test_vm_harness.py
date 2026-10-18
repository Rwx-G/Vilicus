"""Tests for ci/vm_harness.py: the nested virtualisation check (AC1), the guest checks and the
exit status of guest commands (AC2), the kernel.core_pattern guard (AC5) and the files the
harness ships under ci/vm/.

No VM is started here; the commands that reach the guest are replaced by fakes or by local
shell commands. The Result section of Story 2.3 records the VM runs.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import errno
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import vm_harness as vh

LINUX = sys.platform.startswith("linux")
SH = shutil.which("sh")
# What a container runs as PID 1 is its last ENTRYPOINT and CMD, whatever installed it; a
# Dockerfile that declares neither inherits its base image's, which may be an init
# (jrei/systemd-debian, for one), so it counts as booting one.
INSTRUCTION = re.compile(r"(?im)^\s*(ENTRYPOINT|CMD)\b(.*)$")
INIT = re.compile(r"(/sbin/init|/lib/systemd/systemd)(?![\w-])")
MASKS_SYSTEMD_SYSCTL = re.compile(r"systemctl mask\b[^\n]*\bsystemd-sysctl(\.service)?(?![\w-])")


def boots_an_init(dockerfile: str) -> bool:
    last = {kind.upper(): value for kind, value in INSTRUCTION.findall(dockerfile)}
    return not last or any(INIT.search(value) for value in last.values())


def masks_systemd_sysctl_if_needed(dockerfile: str) -> bool:
    """A Dockerfile whose container boots an init must mask systemd-sysctl.service (E10-4, E16-4)."""
    code = "\n".join(line for line in dockerfile.splitlines() if not line.lstrip().startswith("#"))
    return not boots_an_init(code) or bool(MASKS_SYSTEMD_SYSCTL.search(code))


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def cpuinfo(self, flags: str) -> Path:
        path = self.dir / "cpuinfo"
        path.write_text(f"processor\t: 0\nflags\t\t: fpu {flags} sse2\n\nprocessor\t: 1\nflags\t\t: fpu {flags}\n")
        return path


class CpuVirtualisationTest(Scratch):
    def test_each_extension_flag_is_named(self) -> None:
        for flag, name in vh.VIRTUALISATION_FLAGS.items():
            with self.subTest(flag=flag):
                self.assertEqual(vh.cpu_virtualisation(self.cpuinfo(flag)), [name])

    def test_no_flag_and_no_file_give_nothing(self) -> None:
        self.assertEqual(vh.cpu_virtualisation(self.cpuinfo("pae")), [])
        self.assertEqual(vh.cpu_virtualisation(self.dir / "absent"), [])

    def test_a_flag_that_only_contains_the_name_does_not_count(self) -> None:
        self.assertEqual(vh.cpu_virtualisation(self.cpuinfo("vmx_ept svm_lock")), [])


class CheckKvmTest(Scratch):
    def failure(self, device: Path, flags: str = "vmx", **kwargs) -> str:
        with self.assertRaises(vh.MissingCapability) as caught:
            vh.check_kvm(device, self.cpuinfo(flags), **kwargs)
        return str(caught.exception)

    def test_missing_device_names_nested_virtualisation_and_the_cpu_flags(self) -> None:
        message = self.failure(self.dir / "kvm", "vmx")
        self.assertIn("nested virtualisation", message)
        self.assertIn("does not exist", message)
        self.assertIn("Intel VT-x", message)
        self.assertIn("--device /dev/kvm", message)
        message = self.failure(self.dir / "kvm", "pae")
        self.assertIn("no vmx or svm flag", message)
        self.assertIn("nested virtualisation is off", message)

    def test_a_regular_file_is_not_a_kvm_device(self) -> None:
        path = self.dir / "kvm"
        path.write_text("")
        self.assertIn("not a character device", self.failure(path))

    @unittest.skipUnless(LINUX and Path("/dev/null").exists(), "needs a Linux character device")
    def test_a_character_device_that_is_not_kvm_fails_on_the_api_ioctl(self) -> None:
        message = self.failure(Path("/dev/null"))
        self.assertIn("KVM_GET_API_VERSION", message)
        self.assertIn("not a KVM device", message)

    @unittest.skipUnless(LINUX and Path("/dev/null").exists(), "needs a Linux character device")
    def test_permission_denied_names_the_user(self) -> None:
        with mock.patch.object(os, "open", side_effect=PermissionError(errno.EACCES, "Permission denied")):
            message = self.failure(Path("/dev/null"))
        self.assertIn("KVM access", message)
        self.assertIn(f"uid {os.geteuid()}", message)

    @unittest.skipUnless(LINUX and Path("/dev/null").exists(), "needs a Linux character device")
    def test_operation_not_permitted_is_reported_as_a_policy_denial(self) -> None:
        with mock.patch.object(os, "open", side_effect=PermissionError(errno.EPERM, "Operation not permitted")):
            message = self.failure(Path("/dev/null"))
        self.assertIn("denied by policy", message)
        self.assertIn("--device /dev/kvm", message)
        self.assertNotIn("uid", message)

    @unittest.skipUnless(LINUX and Path("/dev/null").exists(), "needs a Linux character device")
    def test_api_version_and_vm_creation_are_both_required(self) -> None:
        def wrong_version(fd: int, request: int, arg: int) -> int:
            return 11

        self.assertIn("API version 11", self.failure(Path("/dev/null"), ioctl=wrong_version))

        def no_vm(fd: int, request: int, arg: int) -> int:
            if request == vh.KVM_GET_API_VERSION:
                return vh.KVM_API_VERSION
            raise OSError(errno.ENOMEM, "Cannot allocate memory")

        self.assertIn("KVM_CREATE_VM", self.failure(Path("/dev/null"), ioctl=no_vm))

        requests: list[int] = []

        def kvm(fd: int, request: int, arg: int) -> int:
            requests.append(request)
            return vh.KVM_API_VERSION if request == vh.KVM_GET_API_VERSION else os.open(os.devnull, os.O_RDONLY)

        summary = vh.check_kvm(Path("/dev/null"), self.cpuinfo("svm"), ioctl=kvm)
        self.assertEqual(requests, [vh.KVM_GET_API_VERSION, vh.KVM_CREATE_VM])
        self.assertIn("can create a VM", summary)
        self.assertIn("AMD-V", summary)


class FakeGuest:
    """A guest whose core_pattern a test command can change."""

    def __init__(self, pattern: str, status: int, new_pattern: str | None = None) -> None:
        self.pattern, self.status, self.new_pattern = pattern, status, new_pattern
        self.commands: list[str] = []

    def core_pattern(self) -> str:
        return self.pattern

    def stream(self, command: str, log: Path | None) -> int:
        self.commands.append(command)
        if self.new_pattern is not None:
            self.pattern = self.new_pattern
        if log:
            log.write_text(f"ran {command}\n")
        return self.status


PIPE = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %d %F"


class CorePatternGuardTest(Scratch):
    def run_guarded(self, guest: FakeGuest, command: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = vh.cmd_run(guest, command, self.dir / "logs" / "run.log")
        return status, output.getvalue()

    def test_unchanged_pattern_returns_the_command_status(self) -> None:
        for status in (0, 3):
            with self.subTest(status=status):
                result, output = self.run_guarded(FakeGuest(PIPE, status), ["exit", str(status)])
                self.assertEqual(result, status)
                self.assertIn("PASS core_pattern_unchanged", output)

    def test_changed_pattern_fails_a_passing_command(self) -> None:
        guest = FakeGuest(PIPE, 0, new_pattern="core")
        status, output = self.run_guarded(guest, ["docker", "run", "--privileged", "systemd-image"])
        self.assertEqual(status, 1)
        self.assertIn("FAIL core_pattern_unchanged", output)
        self.assertIn(repr(PIPE), output)
        self.assertIn("'core'", output)
        self.assertEqual(guest.commands, ["docker run --privileged systemd-image"])
        self.assertEqual((self.dir / "logs" / "run.log").read_text(), "ran docker run --privileged systemd-image\n")

    def test_changed_pattern_keeps_a_failing_command_status(self) -> None:
        status, output = self.run_guarded(FakeGuest(PIPE, 7, new_pattern="core"), ["false"])
        self.assertEqual(status, 7)
        self.assertIn("FAIL core_pattern_unchanged", output)

    def test_the_first_read_happens_before_the_test(self) -> None:
        reads: list[str] = []
        state = {"pattern": PIPE}

        def read() -> str:
            reads.append(state["pattern"])
            return state["pattern"]

        def test() -> int:
            state["pattern"] = "core"
            return 0

        self.assertEqual(vh.guarded(read, test, report=lambda line: None), 1)
        self.assertEqual(reads, [PIPE, "core"])

    def test_a_guest_not_on_the_coredump_pipe_fails_before_the_test_runs(self) -> None:
        for pattern in ("core", "|/bin/false %p", ""):
            with self.subTest(pattern=pattern):
                guest = FakeGuest(pattern, 0)
                status, output = self.run_guarded(guest, ["true"])
                self.assertEqual(status, 1)
                self.assertIn("FAIL core_pattern_expected", output)
                self.assertIn(vh.GUEST_CORE_PATTERN_PREFIX, output)
                self.assertEqual(guest.commands, [])

    def test_status_255_carries_the_ssh_hint_and_no_other_does(self) -> None:
        _, output = self.run_guarded(FakeGuest(PIPE, vh.SSH_FAILURE), ["true"])
        self.assertIn(f"status {vh.SSH_FAILURE} is also what ssh returns", output)
        _, output = self.run_guarded(FakeGuest(PIPE, 254), ["true"])
        self.assertNotIn("what ssh returns", output)

    def test_a_command_is_required(self) -> None:
        with self.assertRaises(vh.HarnessError):
            vh.cmd_run(FakeGuest(PIPE, 0), [], None)


class SmokeGuest:
    """A guest whose pattern is already wrong, so a guarded smoke must not touch the guest."""

    def copy(self, paths: list[Path], destination: str) -> int:
        return 0

    def core_pattern(self) -> str:
        return "core"

    def run(self, command: str) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"the smoke ran {command!r} on a guest that failed the guard")


class SmokeGuardTest(Scratch):
    def test_smoke_runs_inside_the_core_pattern_guard(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = vh.cmd_smoke(SmokeGuest(), self.dir / "out")
        self.assertEqual(status, 1)
        self.assertIn("FAIL core_pattern_expected", output.getvalue())
        self.assertIn("RESULT FAIL", output.getvalue())


class FactsGuest:
    """A guest that answers the checks of `check_guest` from a table of facts."""

    def __init__(self, **facts: str) -> None:
        self.facts = {"pid1": "systemd", "version": vh.GUEST_VERSION_ID, "machine": vh.GUEST_MACHINE, **facts}

    def output(self, command: str) -> str:
        if command == "cat /proc/1/comm":
            return self.facts["pid1"]
        if "VERSION_ID" in command:
            return self.facts["version"]
        if command == "uname -m":
            return self.facts["machine"]
        return "Debian GNU/Linux 13 (trixie)\n6.12.111+deb13-cloud-amd64\nsystemd 257"

    def run(self, command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "running\n", "")


class CheckGuestTest(unittest.TestCase):
    def check(self, guest: FactsGuest) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            status = vh.check_guest(guest)
        return status, output.getvalue()

    def test_the_pinned_guest_passes(self) -> None:
        status, output = self.check(FactsGuest())
        self.assertEqual(status, 0)
        for name in ("guest_pid1_is_systemd", "guest_is_debian_13", "guest_is_amd64"):
            self.assertIn(f"PASS {name}", output)

    def test_another_release_machine_or_init_fails(self) -> None:
        for fact, value, name in (
            ("version", "12", "guest_is_debian_13"),
            ("version", "", "guest_is_debian_13"),
            ("machine", "aarch64", "guest_is_amd64"),
            ("pid1", "init", "guest_pid1_is_systemd"),
        ):
            with self.subTest(fact=fact, value=value):
                status, output = self.check(FactsGuest(**{fact: value}))
                self.assertEqual(status, 1)
                self.assertIn(f"FAIL {name}", output)


@unittest.skipUnless(SH, "needs a POSIX sh")
class GuestCommandTest(Scratch):
    """`Guest.stream` and `Guest.copy` return the status of the command behind `vm.sh ssh`."""

    def test_stream_returns_the_status_and_logs_both_streams(self) -> None:
        log = self.dir / "run.log"
        command = [SH, "-c", "echo to-stdout; echo to-stderr >&2; exit 7"]
        with mock.patch.object(vh, "vm_command", return_value=command), redirect_stdout(io.StringIO()) as shown:
            status = vh.Guest().stream("ignored", log)
        self.assertEqual(status, 7)
        for line in ("to-stdout", "to-stderr"):
            self.assertIn(line, log.read_text())
            self.assertIn(line, shown.getvalue())

    @unittest.skipUnless(LINUX, "replaces file descriptor 0, which Windows children do not inherit the same way")
    def test_stream_gives_the_command_no_stdin(self) -> None:
        # This process's stdin holds a line for the duration of the test, so a command that
        # inherited it would read one.
        read_end, write_end = os.pipe()
        os.write(write_end, b"a line on the caller's stdin\n")
        os.close(write_end)
        saved = os.dup(0)
        os.dup2(read_end, 0)
        os.close(read_end)
        try:
            command = [SH, "-c", "if read -r line; then exit 1; fi; exit 7"]
            with mock.patch.object(vh, "vm_command", return_value=command), redirect_stdout(io.StringIO()):
                status = vh.Guest().stream("ignored", None)
            inherited = subprocess.run(command, check=False).returncode
        finally:
            os.dup2(saved, 0)
            os.close(saved)
        self.assertEqual(status, 7)
        self.assertEqual(inherited, 1, "the test's stdin did not reach a child that inherits it")

    def test_copy_returns_the_status_whether_or_not_the_archive_was_read(self) -> None:
        artefact = self.dir / "artefact"
        artefact.write_bytes(b"x" * 300_000)
        for script in ("exit 7", "cat >/dev/null; exit 7"):
            with self.subTest(script=script):
                with mock.patch.object(vh, "vm_command", return_value=[SH, "-c", script]):
                    self.assertEqual(vh.Guest().copy([artefact], "artefacts"), 7)


class HarnessFilesTest(unittest.TestCase):
    def test_the_smoke_unit_prints_the_line_the_harness_looks_for(self) -> None:
        unit = vh.SMOKE_UNIT.read_text(encoding="utf-8")
        exec_start = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        self.assertEqual(len(exec_start), 1)
        self.assertIn(vh.SMOKE_MARKER, exec_start[0])

    def test_every_harness_dockerfile_that_boots_an_init_masks_systemd_sysctl(self) -> None:
        dockerfiles = sorted(vh.HARNESS_DIR.rglob("Dockerfile*"))
        booting = [path for path in dockerfiles if boots_an_init(path.read_text(encoding="utf-8"))]
        self.assertIn(vh.SYSTEMD_CONTAINER / "Dockerfile", booting)
        for path in booting:
            with self.subTest(dockerfile=path.relative_to(vh.REPO_ROOT).as_posix()):
                self.assertTrue(masks_systemd_sysctl_if_needed(path.read_text(encoding="utf-8")))

    def test_the_mask_check_refuses_the_harness_dockerfile_without_the_mask(self) -> None:
        text = (vh.SYSTEMD_CONTAINER / "Dockerfile").read_text(encoding="utf-8")
        unmasked = MASKS_SYSTEMD_SYSCTL.sub("true", text)
        self.assertNotEqual(unmasked, text)
        self.assertFalse(masks_systemd_sysctl_if_needed(unmasked))

    def test_the_mask_check_follows_the_init_whatever_installed_it(self) -> None:
        mask = "RUN systemctl mask systemd-sysctl.service\n"
        booting = {
            "apt-get --yes install": 'FROM debian:trixie\nRUN apt-get --yes install systemd\nENTRYPOINT ["/sbin/init"]\n',
            "apt install -y": 'FROM debian:trixie\nRUN apt install -y systemd-sysv\nCMD ["/lib/systemd/systemd"]\n',
            "usr path, shell form": "FROM debian:trixie\nCMD /usr/lib/systemd/systemd --log-level=info\n",
            "init behind a shell": 'FROM debian:trixie\nCMD ["/bin/sh", "-c", "mount --make-rshared / && exec /sbin/init"]\n',
            "init behind tini": 'FROM debian:trixie\nENTRYPOINT ["/usr/bin/tini", "--"]\nCMD ["/sbin/init"]\n',
            "inherited from the base": "FROM jrei/systemd-debian:13\n",
            "mask only in a comment": 'FROM debian:trixie\n# RUN systemctl mask systemd-sysctl.service\nENTRYPOINT ["/sbin/init"]\n',
        }
        for case, dockerfile in booting.items():
            with self.subTest(case=case):
                self.assertFalse(masks_systemd_sysctl_if_needed(dockerfile))
                self.assertTrue(masks_systemd_sysctl_if_needed(dockerfile + mask))
        not_booting = {
            "a plain binary": 'FROM debian:trixie\nRUN apt-get install --yes curl systemd\nENTRYPOINT ["/usr/bin/curl"]\n',
            "a later CMD replaces the init": 'FROM debian:trixie\nCMD ["/sbin/init"]\nCMD ["/bin/true"]\n',
            "journald is not an init": 'FROM debian:trixie\nCMD ["/lib/systemd/systemd-journald"]\n',
        }
        for case, dockerfile in not_booting.items():
            with self.subTest(case=case):
                self.assertTrue(masks_systemd_sysctl_if_needed(dockerfile))

    def test_the_vm_script_the_harness_drives_exists(self) -> None:
        self.assertTrue(vh.VM_SH.is_file())


if __name__ == "__main__":
    unittest.main()
