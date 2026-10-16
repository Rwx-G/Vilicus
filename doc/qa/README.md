---
title: 'QA reports and gates'
author: Rwx-G
---

# QA reports and gates

This folder holds the evidence that a story's acceptance criteria were met: one hand-written
report per epic, written from a full end-to-end run, and one gate per story. Raw logs are not
committed (`e2e/results/` is ignored); the report carries the numbers that matter and the
command to reproduce them.

## Epic report

`doc/qa/epic-<n>-e2e-report.md`, written after a full `e2e/run.sh` campaign. It records:

- **Run context**: date (UTC), author, git commit SHA (full) and the count of uncommitted paths
  at run time, Docker server version, engine and host resources, copied from the run's
  `run-info.txt`.
- **Exact command**: as recorded by the harness, so the run can be replayed (see
  `e2e/README.md`).
- **Phase table**: one row per phase with story, status, PASS, FAIL and INFO counts, and
  duration, from `summary.tsv`.
- **Failures**: for each failed or timed-out phase, the failing assertions and their cause.
- **Anomalies**: anything unexpected that did not fail the run (a skipped phase, a measured
  value near its bound, a retry, a container left running), each one explained.
- **Not covered**: what the run cannot show (real devices, the real reference host), with a
  pointer to where that evidence is or will be recorded.

A report describes one run. A later run gets a new report section or a new file; a past
report is never edited to match a newer run.

## Story gates

`doc/qa/gates/<epic>.<story>-<slug>.yml`, with the slug of the story file under
`doc/stories/`. One gate per story, updated when the story is re-verified.

```yaml
schema: 1
story: '1.9'
story_title: 'E19: canonical CBOR in Rust and TypeScript'
gate: PASS            # PASS | CONCERNS | FAIL
status_reason: 'One sentence: why this gate.'
reviewer: Rwx-G
updated: '2026-10-16T00:00:00Z'
run:
  commit: '<full sha>'
  command: 'bash e2e/run.sh'
  report: 'doc/qa/epic-1-e2e-report.md'
top_issues: []        # each: { id, severity: low|medium|high, finding, suggested_action }
evidence:
  trace:
    ac_covered: [1, 2, 3]
    ac_gaps: []       # each gap names the AC and why it is not covered by the run
nfr_validation:
  security: { status: PASS, notes: '' }
  performance: { status: PASS, notes: '' }
  reliability: { status: PASS, notes: '' }
  maintainability: { status: PASS, notes: '' }
```

Gate values:

- **PASS**: every acceptance criterion is covered by a passing check of the recorded run.
- **CONCERNS**: the run passes, but an AC is covered only partly (emulated reference host,
  simulated service, device run still pending) or a top issue needs a decision. The gaps are
  listed, not hidden.
- **FAIL**: a check covering an AC fails, or an AC has no evidence at all.

A gate's verdict cites the run it rests on; a gate never claims more than the run showed.
