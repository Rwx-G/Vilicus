"""Tests for ci/check_supply_chain.py, over synthetic `cargo metadata` documents, plus a run on
a real `cargo metadata` and the agreement of the workflow's tool versions with the spine.

Run from the repository root: python3 -m unittest discover -s ci
"""

from __future__ import annotations

import inspect
import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import check_supply_chain as sc
import check_workspace as cw
import fuzz as fz
import release_gates as rg

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
WORKFLOW = sc.REPO_ROOT / ".github" / "workflows" / "ci.yml"
SPINE = sc.REPO_ROOT / "doc" / "architecture-spine.md"


class Tree:
    """A synthetic `cargo metadata` document: packages, their targets and resolved edges."""

    def __init__(self) -> None:
        self.packages: dict[str, dict] = {}
        self.edges: dict[str, list[str]] = {}

    def add(self, name: str, version: str, *kinds: str) -> str:
        package_id = f"{REGISTRY}#{name}@{version}"
        targets = [{"kind": [kind], "name": name} for kind in (kinds or ("lib",))]
        self.packages[package_id] = {"id": package_id, "name": name, "version": version, "targets": targets}
        self.edges.setdefault(package_id, [])
        return package_id

    def depend(self, source: str, target: str) -> None:
        self.edges[source].append(target)

    def metadata(self) -> dict:
        nodes = [{"id": pid, "deps": [{"pkg": dep} for dep in deps]} for pid, deps in self.edges.items()]
        return {"packages": list(self.packages.values()), "resolve": {"nodes": nodes}}


class BuildTimeCodeTest(unittest.TestCase):
    def test_tree_without_build_time_code_passes_with_an_empty_allowlist(self) -> None:
        tree = Tree()
        tree.add("plain", "1.0.0")
        tree.add("tool", "1.0.0", "lib", "bin")
        self.assertEqual(sc.check_build_time_code(tree.metadata(), {}), [])

    def test_each_kind_of_build_time_code_off_the_allowlist_fails_naming_the_crate(self) -> None:
        for kind, description in sc.BUILD_TIME_KINDS.items():
            with self.subTest(kind=kind):
                tree = Tree()
                tree.add("plain", "1.0.0")
                tree.add("builder", "2.3.4", "lib", kind)
                violations = sc.check_build_time_code(tree.metadata(), {"other": "x"})
                self.assertIn(
                    f"build-time code: builder 2.3.4 has {description} ({kind} target) and is not on the allowlist",
                    violations[0],
                )
                self.assertEqual(len(violations), 2, violations)
                self.assertIn("allowlist entry other matches no package", violations[1])

    def test_both_kinds_in_one_package_are_named_once(self) -> None:
        tree = Tree()
        tree.add("both", "1.0.0", *sc.BUILD_TIME_KINDS)
        violations = sc.check_build_time_code(tree.metadata(), {})
        self.assertEqual(len(violations), 1, violations)
        for description in sc.BUILD_TIME_KINDS.values():
            self.assertIn(description, violations[0])

    def test_each_kind_on_the_allowlist_passes(self) -> None:
        for kind in sc.BUILD_TIME_KINDS:
            with self.subTest(kind=kind):
                tree = Tree()
                tree.add("builder", "1.0.0", "lib", kind)
                tree.add("builder", "2.0.0", "lib", kind)
                self.assertEqual(sc.check_build_time_code(tree.metadata(), {"builder": "reviewed"}), [])

    def test_allowlist_entry_without_a_reason_fails(self) -> None:
        tree = Tree()
        tree.add("builder", "1.0.0", "proc-macro")
        for reason in ("", "  "):
            with self.subTest(reason=reason):
                violations = sc.check_build_time_code(tree.metadata(), {"builder": reason})
                self.assertEqual(violations, ["build-time code: allowlist entry builder gives no reason"])

    def test_repository_allowlist_is_a_table_of_reasons(self) -> None:
        allowlist = tomllib.loads(sc.ALLOWLIST_FILE.read_text(encoding="utf-8"))["allowed"]
        self.assertIsInstance(allowlist, dict)
        for name, reason in allowlist.items():
            with self.subTest(name=name):
                self.assertIsInstance(reason, str)


class DuplicateExceptionTest(unittest.TestCase):
    """rand_chacha 0.2.2 forces rand_core 0.5.1 next to the workspace's rand_core 0.6.4."""

    def setUp(self) -> None:
        self.tree = Tree()
        member = self.tree.add("member", "0.0.0")
        new = self.tree.add("rand_core", "0.6.4")
        old = self.tree.add("rand_core", "0.5.1")
        chacha = self.tree.add("rand_chacha", "0.2.2")
        self.tree.depend(member, new)
        self.tree.depend(member, chacha)
        self.tree.depend(chacha, old)

    def check(self, skip: list, **bans: object) -> list[str]:
        return sc.check_duplicate_exceptions(self.tree.metadata(), {"bans": {"skip": skip, **bans}})

    def test_no_exception_passes(self) -> None:
        self.assertEqual(self.check([]), [])
        self.assertEqual(sc.check_duplicate_exceptions(self.tree.metadata(), {}), [])

    def test_exception_naming_the_forcing_dependency_passes(self) -> None:
        entry = {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: no release on rand_core 0.6"}
        self.assertEqual(self.check([entry]), [])

    def test_malformed_exceptions_fail(self) -> None:
        cases = {
            "bare string": ("rand_core@0.5.1", "must be a table"),
            "no reason": ({"crate": "rand_core@0.5.1"}, "must be a table"),
            "extra field": (
                {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: x", "depth": 1},
                "must be a table",
            ),
            "version range": ({"crate": "rand_core@<0.6", "reason": "forced by rand_chacha@0.2.2: x"}, "exact version"),
            "name only": ({"crate": "rand_core", "reason": "forced by rand_chacha@0.2.2: x"}, "exact version"),
            "reason without the forcing dependency": (
                {"crate": "rand_core@0.5.1", "reason": "old crate"},
                "forced by <name>@<version>: <why>",
            ),
            "reason without why": (
                {"crate": "rand_core@0.5.1", "reason": "forced by rand_chacha@0.2.2: "},
                "forced by <name>@<version>: <why>",
            ),
        }
        for label, (entry, fragment) in cases.items():
            with self.subTest(case=label):
                violations = self.check([entry])
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(fragment, violations[0])

    def test_exception_whose_forcing_dependency_does_not_force_it_fails(self) -> None:
        for forcing in ("member@0.0.0", "rand_chacha@0.2.1", "absent@1.0.0"):
            with self.subTest(forcing=forcing):
                violations = self.check([{"crate": "rand_core@0.5.1", "reason": f"forced by {forcing}: x"}])
                self.assertEqual(len(violations), 1, violations)
                self.assertIn(f"forced by {forcing}, which does not depend on rand_core@0.5.1", violations[0])

    def test_stale_exceptions_fail(self) -> None:
        violations = self.check([{"crate": "rand_core@0.4.0", "reason": "forced by rand_chacha@0.2.2: x"}])
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("matches no package of the tree", violations[0])
        violations = self.check([{"crate": "rand_chacha@0.2.2", "reason": "forced by member@0.0.0: x"}])
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("is the only version of rand_chacha", violations[0])

    def test_skip_tree_fails(self) -> None:
        violations = self.check([], **{"skip-tree": [{"crate": "rand_chacha@0.2.2"}]})
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("skip-tree", violations[0])


class VendorTest(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.committed = Path(temp.name) / "committed"
        self.fresh = Path(temp.name) / "fresh"

    def write(self, root: Path, relative: str, content: bytes) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_no_vendored_crate_on_either_side_passes(self) -> None:
        self.assertEqual(sc.vendor_differences(self.committed, self.fresh), [])

    def test_identical_trees_pass(self) -> None:
        for root in (self.committed, self.fresh):
            self.write(root, "itoa-1.0.15/src/lib.rs", b"code\n")
            self.write(root, "itoa-1.0.15/.cargo-checksum.json", b"{}")
        self.assertEqual(sc.vendor_differences(self.committed, self.fresh), [])

    def test_missing_extra_and_changed_files_fail(self) -> None:
        self.write(self.fresh, "a-1.0.0/src/lib.rs", b"code\n")
        self.write(self.fresh, "b-1.0.0/src/lib.rs", b"code\n")
        self.write(self.committed, "b-1.0.0/src/lib.rs", b"code\r\n")
        self.write(self.committed, "c-1.0.0/src/lib.rs", b"code\n")
        self.assertEqual(
            sc.vendor_differences(self.committed, self.fresh),
            [
                "vendor: a-1.0.0/src/lib.rs is missing from vendor/",
                "vendor: vendor/c-1.0.0/src/lib.rs is not written by cargo vendor from Cargo.lock",
                "vendor: vendor/b-1.0.0/src/lib.rs differs from what cargo vendor writes",
            ],
        )


@unittest.skipUnless(shutil.which("cargo"), "cargo is needed for the end-to-end test")
class EndToEndTest(unittest.TestCase):
    """The build-time code check on what a real `cargo metadata` reports, without the network."""

    def test_build_script_and_procedural_macro_are_named_on_real_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ["*"]\n', encoding="utf-8")
            for name, extra in (("with-build", ""), ("macro", "\n[lib]\nproc-macro = true\n"), ("plain", "")):
                (root / name / "src").mkdir(parents=True)
                (root / name / "src" / "lib.rs").write_text("", encoding="utf-8")
                (root / name / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n{extra}', encoding="utf-8"
                )
            (root / "with-build" / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
            output = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--offline", "--all-features"],
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
            metadata = json.loads(output)

        violations = sc.check_build_time_code(metadata, {})
        self.assertEqual(len(violations), 2, violations)
        self.assertIn("macro 0.1.0 has a procedural macro (proc-macro target)", violations[0])
        self.assertIn("with-build 0.1.0 has a build script (custom-build target)", violations[1])
        self.assertEqual(sc.check_build_time_code(metadata, {"macro": "test", "with-build": "test"}), [])


def stack_versions() -> dict[str, str]:
    """Name -> version for every row of the spine's Stack table, `a / b | 1 / 2` rows split."""
    section = SPINE.read_text(encoding="utf-8").split("\n## Stack\n", 1)[1].split("\n## ", 1)[0]
    versions = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2:
            continue
        names, values = cells[0].split(" / "), cells[1].split(" / ")
        if len(names) == len(values):
            versions.update(zip(names, values))
    return versions


# The merge gates of AD-33 this workflow carries, written out by hand on purpose: the job id, the
# check name branch protection requires, and the command lines that must appear whole in the job,
# so that dropping a job, renaming its check, or losing `-D warnings`, `--frozen`, `--locked` or
# the audit report check (`cargo audit --deny warnings` with reasoned exceptions) turns this test
# red.
GATE_JOBS = {
    "workspace-policy": (
        "Crate graph, manifests and unsafe code (AD-3, D29)",
        (
            "python3 -m unittest discover -s ci -v",
            "python3 ci/check_workspace.py",
            "python3 ci/check_supply_chain.py",
            "python3 ci/check_supply_chain.py --vendor",
            "python3 ci/check_sqlcipher_source.py",
            "python3 ci/check_packaging.py",
            "python3 ci/release_gates.py check",
        ),
    ),
    "lint": (
        "Format and lint",
        (
            "cargo fmt --all --check",
            "cargo clippy --workspace --all-targets --frozen --config ci/cargo-vendored.toml -- -D warnings",
        ),
    ),
    "build-and-test": (
        "Build and test",
        (
            "cargo build --workspace --frozen --config ci/cargo-vendored.toml",
            "cargo test --workspace --frozen --config ci/cargo-vendored.toml",
        ),
    ),
    "deny": ("Licences, duplicates, advisories and sources (cargo deny)", ("cargo deny --locked check",)),
    "vet": ("Audited dependencies (cargo vet)", ("cargo vet --locked",)),
    "audit": (
        "Security advisories (cargo audit)",
        (
            'cargo audit --json > "$RUNNER_TEMP/audit.json" || true',
            'python3 ci/check_audit_report.py ci/audit-exceptions.toml "$RUNNER_TEMP/audit.json"',
        ),
    ),
    "hpke-review": (
        "HPKE spike vectors and cross-test (D61, D120)",
        (
            'run="$(python3 ci/must_run.py --event "$EVENT" --base "$BASE" "${watched[@]}")"',
            "bash spikes/hpke-review/run.sh",
            'cargo audit --file spikes/hpke-review/Cargo.lock --json > "$RUNNER_TEMP/hpke-audit.json" || true',
            'python3 ci/check_audit_report.py spikes/hpke-review/audit-exceptions.toml "$RUNNER_TEMP/hpke-audit.json"',
        ),
    ),
}
# The Debian 13 VM job of Story 2.3, written out by hand like GATE_JOBS. It is not a merge gate
# yet, so it may run its result collection and its teardown under `if: always()`, and the smoke
# and the release gates of Story 2.6 on any booted VM, even after a failed run step, so that the
# AC3 journals and the gate logs are collected; nothing else is conditional. The check of nested
# virtualisation comes first, right after the checkout (AC1), and a guest `exit 3` must come back
# as 3 (AC2).
VM_JOB = (
    "vm-smoke",
    "Debian 13 VM smoke test (AD-33)",
    "sudo python3 ci/vm_harness.py check-kvm",
    (
        "python3 ci/release_gates.py build",
        "python3 ci/vm_harness.py up",
        "python3 ci/vm_harness.py copy target/debug/vilicus",
        "python3 ci/vm_harness.py run -- 'exit 3' || status=$?",
        'test "$status" -eq 3',
        "python3 ci/vm_harness.py smoke --out \"$VM_RESULTS\"",
        "python3 ci/release_gates.py run --out \"$VM_RESULTS/release-gates\"",
        "python3 ci/vm_harness.py collect --out \"$VM_RESULTS\"",
        "python3 ci/vm_harness.py down",
    ),
)
# The fuzz job of Story 2.7, written out by hand like GATE_JOBS: its check name, the dated nightly
# it alone installs, and its run of ci/fuzz.py. The upload of the failing inputs is the only step
# that runs once the job has failed, and nothing in the job is allowed to fail.
FUZZ_JOB = (
    "fuzz",
    "Coverage-guided fuzzing of vilicus-proto (D130)",
    (
        'rustup toolchain install "$FUZZ_TOOLCHAIN" --profile minimal',
        'python3 ci/check_fuzz_coverage.py --toolchain "$FUZZ_TOOLCHAIN"',
        'python3 ci/fuzz.py --toolchain "$FUZZ_TOOLCHAIN" --seconds "$FUZZ_SECONDS" --out "$FUZZ_OUT"',
    ),
)
FUZZ_UPLOAD_CONDITION = "failure() || cancelled()"
# What the fuzz job's timeout must hold besides fuzzing and minimization: the nightly install, the
# rustdoc and plan builds, and the build of every target with AddressSanitizer.
FUZZ_BUILD_MARGIN_MINUTES = 20
# Only the fuzz job may compile the fuzzing runtime: no other job enables every feature or the
# `libfuzzer` feature of vilicus-fuzz.
FUZZING_FEATURE = re.compile(r"--all-features|--features[ =]\S*libfuzzer|-F *\S*libfuzzer")
FUZZ_BUDGET = re.compile(r"FUZZ_SECONDS: \$\{\{ github\.event_name == 'schedule' && '(\d+)' \|\| '(\d+)' \}\}")
VM_ALWAYS_STEPS = ("ci/vm_harness.py collect", "actions/upload-artifact@", "ci/vm_harness.py down")
VM_BOOTED_STEPS = ("ci/vm_harness.py smoke", "ci/release_gates.py run ")
VM_BOOTED_CONDITION = "${{ !cancelled() && steps.up.outcome == 'success' }}"
# Steps that wait on the guest and so carry their own timeout, below the job's.
VM_TIMED_STEPS = ("ci/vm_harness.py up", "ci/vm_harness.py run ", *VM_BOOTED_STEPS)
PINNED_ACTION = re.compile(r"uses: (\./\S+|[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40} # v\d+(\.\d+)*)$")
# Workspace cargo subcommands that compile or fetch crates; each must read the vendored sources.
# `cargo fmt` reads no dependency, and the cargo-deny, cargo-vet and cargo-audit runs read
# metadata or the lockfile only.
VENDORED_SUBCOMMANDS = re.compile(r"\bcargo (build|test|clippy|check|run|doc|vendor|metadata)\b")
TRIGGERS = ("push", "pull_request", "merge_group", "workflow_dispatch", "schedule")


def workflow_jobs(text: str) -> dict[str, str]:
    """Job id -> the job's lines, split on the two-space keys under `jobs:`."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2]))


def command_lines(job: str) -> set[str]:
    """Every shell line of a job: one-line `run:` values and the lines of `run: |` blocks."""
    lines = set()
    for line in job.splitlines():
        stripped = line.strip()
        lines.add(stripped.removeprefix("run: ") if stripped.startswith("run: ") else stripped)
    return lines


class WorkflowAgreementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.jobs = workflow_jobs(self.text)

    def test_each_gate_job_has_its_check_name_and_its_commands(self) -> None:
        for job_id, (name, commands) in GATE_JOBS.items():
            with self.subTest(job=job_id):
                self.assertIn(job_id, self.jobs)
                job = self.jobs[job_id]
                self.assertIn(f"    name: {name}\n", job)
                lines = command_lines(job)
                for command in commands:
                    self.assertIn(command, lines)

    def test_no_gate_step_is_skipped_or_allowed_to_fail(self) -> None:
        self.assertNotIn("continue-on-error", self.text)
        for job_id in GATE_JOBS:
            job = self.jobs[job_id]
            with self.subTest(job=job_id):
                self.assertNotRegex(job, r"(?m)^    if:")
                if job_id != "hpke-review":
                    self.assertNotRegex(job, r"(?m)^\s+if:")

    def test_hpke_steps_after_the_detection_run_only_on_its_decision(self) -> None:
        steps = self.jobs["hpke-review"].split("\n      - ")
        detection = next(i for i, step in enumerate(steps) if "id: changes" in step)
        for step in steps[detection + 1 :]:
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn("if: steps.changes.outputs.run == 'true'", step)

    def test_every_workspace_cargo_build_reads_the_vendored_sources(self) -> None:
        flag = f"--config {sc.VENDORED_CONFIG_FILE}"
        commands = [
            line
            for job_id, job in self.jobs.items()
            if job_id != "hpke-review"
            for line in command_lines(job)
            if VENDORED_SUBCOMMANDS.search(line)
        ]
        self.assertTrue(commands)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(flag, command)

    def test_scripts_pass_the_vendored_configuration_to_cargo(self) -> None:
        for function in (
            sc.cargo_metadata,
            sc.check_vendor,
            cw.cargo_metadata,
            rg.cargo_build_commands,
            fz.plan_command,
            fz.build_command,
        ):
            with self.subTest(function=f"{function.__module__}.{function.__name__}"):
                source = inspect.getsource(function)
                self.assertIn('"--config"', source)
                self.assertRegex(source, r"VENDORED_CONFIG_FILE")
        self.assertEqual(sc.VENDORED_CONFIG_FILE, cw.VENDORED_CONFIG_FILE.as_posix())

    def test_fuzz_job_runs_every_target_on_a_nightly_pinned_by_date(self) -> None:
        job_id, name, commands = FUZZ_JOB
        self.assertIn(job_id, self.jobs)
        job = self.jobs[job_id]
        self.assertIn(f"    name: {name}\n", job)
        lines = command_lines(job)
        for command in commands:
            with self.subTest(command=command):
                self.assertIn(command, lines)
        toolchain = re.search(r"(?m)^      FUZZ_TOOLCHAIN: (\S+)$", job)
        self.assertIsNotNone(toolchain)
        self.assertRegex(toolchain.group(1), fz.DATED_NIGHTLY)
        # The nightly is the fuzz job's alone: rust-toolchain.toml stays on stable, and no other
        # job names the nightly.
        channel = tomllib.loads((sc.REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
        self.assertNotIn("nightly", channel)
        others = "".join(text for other, text in self.jobs.items() if other != job_id)
        self.assertNotRegex(others, r"nightly-\d|\+nightly|FUZZ_TOOLCHAIN")

    def test_fuzz_job_budget_is_short_on_changes_and_longer_on_the_schedule(self) -> None:
        budget = FUZZ_BUDGET.search(self.jobs[FUZZ_JOB[0]])
        self.assertIsNotNone(budget)
        scheduled, otherwise = (int(seconds) for seconds in budget.groups())
        self.assertGreater(otherwise, 0)
        self.assertGreater(scheduled, otherwise)

    def test_fuzz_job_runs_only_its_upload_after_a_failure(self) -> None:
        steps = self.jobs[FUZZ_JOB[0]].split("\n      - ")[1:]
        for step in steps:
            with self.subTest(step=step.splitlines()[0]):
                conditions = re.findall(r"(?m)^\s+if: (.*)$", step)
                if "actions/upload-artifact@" in step:
                    self.assertEqual(conditions, [FUZZ_UPLOAD_CONDITION])
                else:
                    self.assertEqual(conditions, [])

    def test_fuzz_job_timeout_holds_the_scheduled_budget_of_every_target(self) -> None:
        job = self.jobs[FUZZ_JOB[0]]
        timeout = re.search(r"(?m)^    timeout-minutes: (\d+)$", job)
        self.assertIsNotNone(timeout)
        scheduled = int(FUZZ_BUDGET.search(job).group(1))
        targets = [path.stem for path in (sc.REPO_ROOT / "fuzz" / "src" / "bin").glob("*.rs") if path.stem != fz.PLAN_BINARY]
        self.assertTrue(targets)
        needed = len(targets) * (scheduled + fz.MINIMIZE_SECONDS) / 60 + FUZZ_BUILD_MARGIN_MINUTES
        self.assertGreaterEqual(int(timeout.group(1)), needed)

    def test_no_job_but_the_fuzz_job_builds_the_fuzzing_runtime(self) -> None:
        for job_id, job in self.jobs.items():
            if job_id == FUZZ_JOB[0]:
                continue
            for line in command_lines(job):
                with self.subTest(job=job_id, line=line):
                    self.assertNotRegex(line, FUZZING_FEATURE)
        self.assertRegex("cargo build --all-features", FUZZING_FEATURE)
        self.assertRegex("cargo test -p vilicus-fuzz --features libfuzzer", FUZZING_FEATURE)
        self.assertRegex("cargo build -F vilicus-fuzz/libfuzzer", FUZZING_FEATURE)

    def test_triggers_include_the_merge_queue_and_the_weekly_run(self) -> None:
        triggers = self.text.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        for trigger in TRIGGERS:
            with self.subTest(trigger=trigger):
                self.assertRegex(triggers, rf"(?m)^  {trigger}:")
        self.assertRegex(triggers, r'(?m)^    - cron: "[^"]+"$')

    def test_every_cargo_tool_of_the_workflow_is_at_its_stack_version(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"uses: \./\.github/actions/cargo-tool\n\s+with:\n\s+tool: (\S+)\n\s+version: (\S+)\n", workflow)
        self.assertEqual(len(uses), workflow.count("uses: ./.github/actions/cargo-tool"))
        self.assertTrue(uses)
        stack = stack_versions()
        for tool, version in uses:
            with self.subTest(tool=tool):
                self.assertEqual(stack.get(tool), version)

    def test_vm_job_checks_nested_virtualisation_first_and_runs_the_harness(self) -> None:
        job_id, name, first, commands = VM_JOB
        self.assertIn(job_id, self.jobs)
        job = self.jobs[job_id]
        self.assertIn(f"    name: {name}\n", job)
        lines = command_lines(job)
        for command in (first, *commands):
            with self.subTest(command=command):
                self.assertIn(command, lines)
        self.assertTrue(any(line.startswith("python3 ci/vm_harness.py run ") for line in lines))
        steps = job.split("\n      - ")[1:]
        self.assertTrue(steps[0].startswith("uses: actions/checkout@"))
        self.assertIn(first, command_lines(steps[1]))

    def test_vm_job_runs_only_its_collection_and_teardown_under_always(self) -> None:
        steps = self.jobs[VM_JOB[0]].split("\n      - ")[1:]
        for step in steps:
            with self.subTest(step=step.splitlines()[0]):
                conditions = re.findall(r"(?m)^\s+if: (.*)$", step)
                if any(marker in step for marker in VM_ALWAYS_STEPS):
                    self.assertEqual(conditions, ["always()"])
                elif any(marker in step for marker in VM_BOOTED_STEPS):
                    self.assertEqual(conditions, [VM_BOOTED_CONDITION])
                else:
                    self.assertEqual(conditions, [])

    def test_vm_job_smoke_condition_names_the_boot_step_and_guest_steps_time_out(self) -> None:
        steps = self.jobs[VM_JOB[0]].split("\n      - ")[1:]
        boot = [step for step in steps if "run: python3 ci/vm_harness.py up\n" in step + "\n"]
        self.assertEqual(len(boot), 1)
        self.assertRegex(boot[0], r"(?m)^\s+id: up$")
        for marker in VM_TIMED_STEPS:
            matching = [step for step in steps if marker in step]
            self.assertTrue(matching, marker)
            for step in matching:
                with self.subTest(step=step.splitlines()[0]):
                    self.assertRegex(step, r"(?m)^\s+timeout-minutes: \d+$")

    def test_vm_job_caches_the_image_by_its_lock(self) -> None:
        job = self.jobs[VM_JOB[0]]
        self.assertIn("key: debian-cloud-image-${{ hashFiles('e2e/vm/IMAGE.lock') }}", job)
        self.assertIn("path: ${{ env.VM_IMAGES_DIR }}", job)
        self.assertRegex(job, r"(?m)^      VM_IMAGES_DIR: ")

    def test_every_action_is_local_or_pinned_by_commit_with_its_version(self) -> None:
        files = [WORKFLOW, *sorted((sc.REPO_ROOT / ".github" / "actions").rglob("action.yml"))]
        uses = [
            (path.name, line.strip().removeprefix("- "))
            for path in files
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().removeprefix("- ").startswith("uses:")
        ]
        self.assertTrue(uses)
        for path, line in uses:
            with self.subTest(file=path, line=line):
                self.assertRegex(line, PINNED_ACTION)

    def test_workflow_reads_the_repository_only(self) -> None:
        self.assertIn("\npermissions:\n  contents: read\n", self.text)
        for job_id, job in self.jobs.items():
            with self.subTest(job=job_id):
                self.assertNotIn("permissions:", job)

    def test_repository_deny_configuration_denies_every_duplicate_and_git_source(self) -> None:
        config = tomllib.loads(sc.DENY_FILE.read_text(encoding="utf-8"))
        self.assertEqual(config["bans"]["multiple-versions"], "deny")
        self.assertEqual(config["sources"]["unknown-git"], "deny")
        self.assertEqual(config["sources"].get("allow-git", []), [])


if __name__ == "__main__":
    unittest.main()
