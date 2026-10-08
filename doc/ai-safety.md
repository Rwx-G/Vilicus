# AI safety principles

Status: design phase, no code yet. Revision 1. Structure and processes are in [architecture.md](architecture.md) (sections 9 to 11); every action and its tier is in [capability-matrix.md](capability-matrix.md); this document holds the rules and the tests that enforce them.

Prompt injection is not solved. These principles assume an injection will eventually succeed and aim to bound what it can do. The question is never "will the model be fooled", it is "what is the worst thing a fooled model can do here".

## 1. Principles

### P1. The model is an untrusted component; the Core decides

Treat model output like user input. The model proposes typed actions; deterministic code in the Core validates, authorizes and executes them. The model never holds keys, credentials, or ambient authority. The current date and time zone are injected by the Core; the model never infers them.

### P2. Never combine the lethal trio in one context

A context must not simultaneously have access to private data, exposure to untrusted content, and the ability to communicate or act externally. Roles:

- **Quarantined reader.** Reads untrusted content. No write, send or pay tool, no network access, no private data beyond the object it reads. It returns only **closed enums, bounded numbers and opaque identifiers that the Core resolves**. It never returns a free string that reaches the planner. Output is validated by the Core against a schema and marked `external`.
- **Planner.** Has the tools. Never sees raw untrusted text. Works on reader output and trusted data.
- **Drafter** (optional). Reads untrusted text in order to write a reply. Has no send tool. Its output is a free-text draft object marked `external`, stored locally and shown to the human, never forwarded as text to the planner. Sending is tier 2 with the whole text displayed.
- **System notifications** are static templates with parameters resolved by the Core, never model text, never URLs from a model.

An external MCP assistant is treated as a planner whose host Vilicus does not control. It gets reader output rather than raw untrusted bodies by default; a raw read is an explicit per-member opt-in and taints the session from that point.

### P3. Capability tokens per task

The Core issues tokens scoped to a task, a member, a module, a partition, a set of actions and a budget. Tokens are short-lived (minutes), revocable and logged. An assistant acting for member X can never exceed X's scope. Partition isolation is enforced by keys held in the Core, never by instructions in a prompt. Creating or revoking tokens is not a tool.

### P4. Three action tiers, and a precise meaning of "reversible"

| Tier | Examples | Rule |
|------|----------|------|
| 0 Read | List tasks, read an event, query the budget | Allowed within scope, logged |
| 1 Reversible write | Create a task, move a personal event, add a shopping item | Allowed within scope, journaled, undoable. Elevated when the session is tainted |
| 2 Irreversible, third-party or cross-partition | Pay, send, delete for good, share, order, answer an invitation, move an event that has guests, sync to an external account, write from a personal partition to the household or to another member | Signed confirmation from a paired native app, every time |
| H Human-only | Pairing, recovery, rights changes, plugin install, exposure, controller thresholds | Never exposed to the AI; step-up or signed confirmation |

**Reversible means reversible without effect on a third party.** Undo cannot recall an email, an RSVP or a synchronized change. Any outbound network effect is therefore tier 2. The single exception is the system notification (static template, the member's own channel, rate limited).

Rules for tier 2:

- The confirmation screen is generated on the device from the real parameters, not from the model's description, using a locally shipped template per action type.
- The channel is a **paired native app**. The device computes and displays the canonical hash and signs it with a hardware-bound key that requires biometrics or device credentials; the Core recomputes and verifies; the Gateway only relays. Details in `architecture.md`, section 10.
- A confirmation is bound to exactly the confirmed parameters, single use (nonce), and expires in under 2 minutes.
- The web client never confirms tier 2, because WebAuthn does not prove what was displayed and the Gateway is not trusted. No chat reply, no messaging plugin and no web click can confirm.
- Confirmations are bounded: one pending at a time by default, batching of homogeneous requests, a separate queue for requests from tainted sessions, repeated refusals suspend the task.

### P5. Provenance and taint

Taint is mandatory metadata on every record of every module, not only on memory. Each record carries a `source` and a `taint` (`trusted` or `external`); the Core adds `member` at read time when a member's assistant reads data authored by another member. The order is `trusted` < `member` < `external`.

- Derived data inherits the most restrictive label. A summary of external data is external.
- A session becomes tainted when it consumes any `external` or `member` datum, including a reader's typed output.
- Effects of taint: tier 0 allowed; tier 1 elevated; tier 2 goes to the separate tainted queue and the confirmation shows the origin; H denied; kill switch not available to the session.
- A record written by a tainted session inherits that session's taint, so tainted writes cannot launder into `trusted`. Pasting or importing external text into a trusted field is a promotion (tier 2, source shown).
- Free text written by another member passes through the reader before a planner uses it.
- Promoting tainted data to a lower label is a tier 2 action.
- Data written by another member is treated as untrusted for the assistant of a member: it may be read as data, never followed as instructions.
- Any write from a personal partition into the household partition, or into another member's partition, is tier 2.
- **Outbound content check.** Before a tier 2 send leaves the instance, the Core scans the outgoing body for fragments of private partitions that should not be there, and blocks a send to a non-member when such fragments appear in a confirmation derived from a tainted session. This is a heuristic backstop (exact and fuzzy match of stored values), not a proof.

### P6. Memory is an attack surface

- Facts derived from untrusted content are tagged, quarantined, and not used for planning until a human promotes them (tier 2).
- Facts carry source, taint, date and validity. They are invalidated, not silently overwritten, and can be rolled back (`MemoryStore` interface).
- The assistant cannot rewrite its own instructions or policy through memory.
- Memory is partitioned like the rest: one store per member and one for the household, each under its partition key.

### P7. Contain exfiltration

- No automatic fetching of URLs or images produced by the model.
- AI processes and plugins reach the network only through the egress proxy with an exact-hostname allowlist.
- Outbound messages go to allowlisted recipients or require tier 2 confirmation.
- Output rendered to humans is sanitized, with external content in a sandboxed iframe.
- Notifications are templates, rate limited, so they cannot carry freeform data.
- **Messaging plugins are outbound only, and only for notifications.** An inbound message is untrusted content that triggers no action. No tier 2 confirmation ever transits through a messaging plugin.

### P8. Plan for a wrong model, not only a hostile one

- Strict schemas on every tool call; invalid calls are rejected, not repaired.
- **Idempotency keys derived deterministically from the business parameters** (for example the cart contents and slot), so a retry or a duplicate proposal does nothing twice.
- Default caps (to tune): amounts, orders and messages per period, tool calls per task, token and cost budget per task and per member. Values in the capability matrix, section 11.
- Loop and repetition detection with automatic suspension.
- Dry-run mode that shows what would happen.
- A **kill switch** that revokes all tokens and suspends the assistant. It can be triggered by the human or by a Core detector, never by a tainted session; resuming requires a passkey.
- A **daily digest** of the assistant's writes, read by a human.
- Defined behaviour when the AI provider is unavailable (queue with a timeout, then fail with a notification, no silent switch of provider).
- Pinned model versions; a version switch runs the evaluation suite first (section 4).
- No free-form SQL, shell, file system or network access for the model.

### P9. Everything is audited

Each proposal, validation, confirmation and execution is written to the tamper-evident log with: actor (member and assistant), task, token id, action, tier, opaque identifiers and canonical parameter hash (not the parameters), taint, and outcome. The household can review what the assistant did through the digest and module journals.

### P10. Local by default for sensitive topics

Finance and similar questions go to a local model by default. Remote providers receive only what the task needs, under a per-provider, per-partition policy the household can inspect. Finance data to a remote provider is off unless explicitly enabled for a named task.

### P11. The alignment controller reduces friction, never replaces the human

A small local model (CPU, under 16 GB of RAM) answers a constrained question about a proposed elevated tier 1 action: accept or ask the human, with a probability and a confidence. It is the third layer: deterministic rules first (allowlists, caps, tiers), then the controller, then the human.

Rules:

1. **Structured input only.** It receives the user's original request as recorded by the Core on a trusted channel, the action type, enums, identifiers and diff metadata, and provenance flags. It never receives raw untrusted text or free-text fields, never decides on them, and is advisory only for tasks without a trusted original request.
2. **Closed output.** The answer comes from a closed set, enforced by grammar. Doubt, error, timeout, low confidence or unavailability mean "ask the human" (fail closed).
3. **Limited role.** It can lift only the elevation friction of tier 1. It never replaces confirmation of an irreversible, financial or third-party-affecting action, so tier 2 and H are out of its reach.
4. **Fixed thresholds.** It cannot modify its own thresholds, and neither can the assistant; a human sets them.
5. **Measured.** Metrics on a household evaluation set of legitimate and trapped cases: false accept rate (primary), false reject rate, expected calibration error. The false accept rate is a release gate.
6. **Realization (v1, planned).** A 3 to 4 billion parameter model in GGUF Q4 (Qwen or Gemma families), grammar-constrained output (GBNF), reading the log-probabilities of the options, recalibrated on the household set, with conservative thresholds. A fine-tuned encoder classifier is a v2 option. The commercial Jev model by TypeSafe AI (Choice, Score, Noul) is a conceptual reference, not a dependency: proprietary, API only, English first, not self-hostable; at most an optional connector for non-sensitive data.

### P12. The human is also a component with limits

A user who approves everything defeats tier 2. Confirmations must stay rare and legible, show taint origin without clutter, and be counted: a rising weekly tier 2 rate or a rising approval-without-delay rate is reported in the digest as a safety signal.

## 2. Process isolation

The AI runs in its own sandboxed processes (reader, planner, drafter as separate instances): separate dynamic user, no access to module databases or keys, no ambient network, a socket to the Core only, egress only through the proxy. Plugins run in separate sandboxed processes with the same fixed profile. The profile is imposed by the Core and tested in CI (`architecture.md`, section 4).

## 3. Testable invariants

These are automated tests. A failing invariant blocks a release. Each states the check, not an aspiration.

| ID | Invariant | How it is tested |
|----|-----------|------------------|
| I1 | A tainted session cannot execute any tier 2 action without a valid signed confirmation, and its request lands in the tainted queue | Integration test: inject tainted data, call every tier 2 tool, assert pending state and queue |
| I2 | A tier 2 action cannot execute without a signed confirmation bound to its exact canonical parameter hash, an unused nonce, and an unexpired timestamp | Property test: mutate each field of the signed payload; replay; wait past expiry; assert rejection |
| I3 | Web sessions, TOTP sessions, plugin messages and devices younger than 24 hours are all rejected as tier 2 confirmers | Table-driven test over every client type |
| I4 | An AI process or plugin cannot open a connection except to the egress proxy, and the proxy refuses hosts not on the allowlist | Sandbox test in CI: attempt direct sockets and non-allowlisted hosts |
| I5 | A token of member A cannot read member B's partition files or records | Test with two members: every tool, every module |
| I6 | A module cannot read another module's databases except through registered APIs | Static dependency lint (a module crate cannot depend on another module's storage types) plus a test that module handles are bound to one module and one partition |
| I7 | The reader's response is rejected if it contains any string field outside a closed enum or if an identifier does not resolve | Schema fuzzing against the Core validator |
| I8 | Every record written by any module has `source` and `taint`; a module without them fails registration | Registry test; storage layer property test |
| I9 | Taint inheritance: derived record taint equals the maximum of input taints | The storage API only accepts a derived record together with the list of its input record ids and computes the label itself; a test asserts that writes without inputs are rejected and that the computed label is the maximum |
| I10 | A tainted session cannot trigger the kill switch; a Core detector and a human can | Test per trigger source |
| I11 | Exceeding any cap suspends the task, raises an alert, and writes an audit entry | Parametrized test per cap |
| I12 | Revoking tokens (kill switch) makes all outstanding tokens fail within 5 seconds on the reference host (value to confirm by measurement) | Timing test |
| I13 | Any action producing outbound network effect is tier 2, except the system notification path | Tool registration requires a mandatory `network_effect` declaration (the build fails without it); every tool declaring one must be tier 2; the sandbox test I4 verifies that no module or plugin has another egress path |
| I14 | The controller never approves when its output is unparsable, late, or below threshold; it is never consulted for tier 2 or H | Fault injection on the controller; call-graph test |
| I15 | Messaging plugin inbound messages never create a proposal or a confirmation | Integration test with injected inbound messages |
| I16 | A send to a non-member from a tainted confirmation is blocked when the body contains fragments of a private partition | Seeded corpus: exact matches must be blocked in 100% of cases; near matches (edit distance up to 2 on tokens of at least 8 characters) in at least the agreed share, set before release |
| I17 | Facts with `external` taint are never returned to the planner without their tag, and never used for planning before promotion | MemoryStore contract tests |
| I18 | No tool allows the AI to create tokens, change thresholds, install plugins, pair devices, or start recovery | Static check: tool registry has no H action |

Plus a regression corpus of prompt-injection attempts (mail, web page, calendar invitation, file, tool output, plugin output, member-authored content) run against every release, and fuzzing of all parsers that touch external content (mail, imports, calendar feeds).

## 4. Evaluation

- An evaluation suite is versioned in the repository: injection corpus, controller cases (including French), tool-call correctness, idempotency under retry.
- A new model version, a new controller threshold or a new prompt template must pass the suite before it is used; results are stored with the version.
- Controller calibration is re-measured on the household's own labelled cases after enough real data exists.

## 5. What this does not solve

- A fooled model can still produce wrong tier 0 and tier 1 results within its scope (a bad summary, a wrong task, a misfiled transaction). The journal, undo and the daily digest are the answer, not prevention.
- A user who confirms without reading defeats tier 2 (P12).
- A compromised host defeats these controls (`threat-model.md`, T12).
- A compromised phone with malware controlling the screen defeats the displayed-parameters guarantee unless Android Protected Confirmation is in use on that device.
- Taint is label tracking: a wrong or missing label at the source defeats downstream decisions. Producers are therefore few and trusted (Core, reviewed modules), and plugins cannot lower a label.
- The controller can be wrong; its role is limited so that a wrong answer costs a bit of friction or an elevated write, not an irreversible action.

## 6. Open questions

- Granularity of reader output types without losing usefulness.
- How to present provenance in confirmations without fatigue.
- Whether some tier 1 actions in children's partitions should be tier 2.
- Controller quality in French and CPU latency (`research-notes.md`, E6).
- Exact bounded-output rule that lowers friction for low-risk record kinds.

## 7. Review log

| Date | Reviewer | Notes |
|------|----------|-------|
| 2026-10-08 | Author, draft v0 | Initial version |
| 2026-10-08 | Author, revision 1 | Added reader/planner/drafter roles, mandatory taint, redefinition of reversible, controller, kill switch rule, invariants with test methods, evaluation. Aligned with `architecture.md` |
