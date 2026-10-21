---
title: 'Capability matrix of the testbed'
author: Rwx-G
---

# Capability matrix of the testbed

The capability matrix fixture of `vilicus-testbed` (Story 3.10, AC2): the rows of the modules the testbed links and the shipped binary never does, in the format of `doc/capability-matrix.md`, whose Legend gives the meaning of every column. The testbed's registry is checked against this file by the capability matrix check of AD-9, as the shipped binary's registry is against `doc/capability-matrix.md`; no row of this file belongs in that one (D102).

## 2. Reference module

| Action | Actor | Tier | Confirmation | Exception class | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-----------------|-------|
| List reference items | any | 0 | none | none | allow-b | Exercises a tier 0 tool |
| Add a reference item | any | 1 | light | reversible_external_state | elevate | Exercises a tier 1 tool with an outbound effect, its effect intent and its undo handler |
