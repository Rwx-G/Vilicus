"""Tests for ci/vm_harness.py: the nested virtualisation check (AC1), the kernel.core_pattern
guard (AC5) and the files the harness ships under ci/vm/.

The guest itself is not started here; the Result section of Story 2.3 records the VM runs.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import errno
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import vm_harness as vh

LINUX = sys.platform.startswith("linux")
INSTALLS_SYSTEMD = re.compile(r"apt-get install[^\n]*(\\\n[^\n]*)*\bsystemd\b")
MASKS_SYSTEMD_SYSCTL = re.compile(r"systemctl mask\b[^\n]*\bsystemd-sysctl\.service\b")


def masks_systemd_sysctl_if_needed(dockerfile: str) -> bool:
    """A Dockerfile that installs systemd must mask systemd-sysctl.service (gates E10-4, E16-4)."""
    return not INSTALLS_SYSTEMD.search(dockerfile) or bool(MASKS_SYSTEMD_SYSCTL.search(dockerfile))


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

    def test_a_command_is_required(self) -> None:
        with self.assertRaises(vh.HarnessError):
            vh.cmd_run(FakeGuest(PIPE, 0), [], None)


class HarnessFilesTest(unittest.TestCase):
    def test_the_smoke_unit_prints_the_line_the_harness_looks_for(self) -> None:
        unit = vh.SMOKE_UNIT.read_text(encoding="utf-8")
        exec_start = [line for line in unit.splitlines() if line.startswith("ExecStart=")]
        self.assertEqual(len(exec_start), 1)
        self.assertIn(vh.SMOKE_MARKER, exec_start[0])

    def test_every_harness_dockerfile_that_installs_systemd_masks_systemd_sysctl(self) -> None:
        dockerfiles = sorted(vh.HARNESS_DIR.rglob("Dockerfile*"))
        installing = [path for path in dockerfiles if INSTALLS_SYSTEMD.search(path.read_text(encoding="utf-8"))]
        self.assertIn(vh.SYSTEMD_CONTAINER / "Dockerfile", installing)
        for path in installing:
            with self.subTest(dockerfile=path.relative_to(vh.REPO_ROOT).as_posix()):
                self.assertTrue(masks_systemd_sysctl_if_needed(path.read_text(encoding="utf-8")))

    def test_the_mask_check_refuses_a_dockerfile_without_the_mask(self) -> None:
        text = (vh.SYSTEMD_CONTAINER / "Dockerfile").read_text(encoding="utf-8")
        unmasked = MASKS_SYSTEMD_SYSCTL.sub("true", text)
        self.assertNotEqual(unmasked, text)
        self.assertFalse(masks_systemd_sysctl_if_needed(unmasked))
        self.assertTrue(masks_systemd_sysctl_if_needed("FROM debian\nRUN apt-get install --yes curl\n"))

    def test_the_vm_script_the_harness_drives_exists(self) -> None:
        self.assertTrue(vh.VM_SH.is_file())


if __name__ == "__main__":
    unittest.main()
