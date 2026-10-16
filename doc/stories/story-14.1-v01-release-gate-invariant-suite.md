---
title: 'V0.1 release-gate invariant suite'
epic: 14
story: 1
status: draft
author: Rwx-G
created: 2026-10-16
implements: [FR-61, NFR-1, I4, I5, I6, I8, I9, I10, I11, I12, I13, I15, I18, I21, I22, I24, I33, I35, I36, I40, I43, DC-37, DC-36, DC-54, DC-53, DC-46, DC-58, D102, AD-9]
---

# Story 14.1: V0.1 release-gate invariant suite

As the project maintainer,
I want one CI job that blocks a release unless every V0.1 release-gate invariant passes,
So that no V0.1 release ships with a broken safety property.

**Acceptance Criteria:**

**AC1 (FR-61, NFR-1)**
**Given** the decided V0.1 gate list of `doc/ai-safety.md` section 3.1 (I4, I5, I6, I8, I9, I10, I11, I12, I13 registry check, I15 against the channel double, I18, I21, I22 against the test double connector, I24, I33, I35, I36 registry declaration, I40, I43)
**When** the release job runs
**Then** each invariant maps to the named tests built by the stories that implement it, and the job fails if any mapped test fails, is skipped or is missing
**And** a test asserts the map lists exactly the invariants of section 3.1

**AC2 (FR-61, DC-37, DC-36, DC-54, DC-53, DC-46, DC-58, I43)**
**Given** the explicit requirements of FR-61
**When** the release job runs
**Then** it includes a gate test for the step-up bound to one action (DC-37), the stored-taint rule with its free-text exception (DC-36, DC-54), structured field validation (DC-53), the provider binding (DC-46) and the data type set of every record (DC-58, I43)
**And** I36 covers the registry declaration of data types only; the dietary filter part is listed for the meals milestone

**AC3 (AD-9)**
**Given** a member is unlocked in the testbed
**When** a reference module handler panics
**Then** the member stays unlocked, other files and partitions keep serving, and the gate passes only under those conditions

**AC4 (FR-61)**
**Given** the not-applicable invariants (I1, I2, I3, I16, I7, I14, I17, I19, I20, I23, I34, I39, I25 to I32, I37, I38, I41, I42)
**When** the release job runs
**Then** it prints each with the milestone where it becomes a gate, as listed in `doc/ai-safety.md` section 3.1

**AC5 (FR-61, D102)**
**Given** the gate list
**When** the job dispatches each gate
**Then** gates that need a module or a test double run against `vilicus-testbed`, and every other gate runs against the shipped `.deb` installed in the Debian 13 VM
**And** the job output names, per gate, the artefact it ran against

**AC6 (I11, I12)**
**Given** the caps of V0.1 (tool calls per task, system notifications per member per hour, consecutive refusals) and the kill switch
**When** the suite runs, the timing test on the reference host
**Then** each cap test and the 5-second kill switch timing test from both trigger paths run, and the timing result is recorded with the release

**Dependencies:**
- Story 13.6 (release procedure the job blocks)
- Story 10.13 (last pipeline story whose tests the suite maps)
- Story 11.10 (last operations story)

**References:**
- `doc/prd.md` FR-61, FR-109, section 7
- `doc/ai-safety.md` section 3 and section 3.1
- `doc/architecture-spine.md` AD-3, AD-9, AD-33
- `doc/decisions.md` D71, D98, D99, D102, D103, D113
