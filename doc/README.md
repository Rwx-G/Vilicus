# Vilicus design documents

Status: Revision 2, early development: the V0.1 spikes live in `spikes/`, their results in the records below; the Cargo workspace holds `vilicus-types` and `vilicus-proto`, the other crates are seeds. These documents are written before the code and are meant to be attacked. Each file has a review log or a status line; open questions are stated, not hidden. Update of 2026-10-16: glossary terms for assistant parity and activatable modules (PRD section 4.18) and ID ranges updated; then glossary terms changed or added by the revalidation decisions D69 to D86, by D87 to D96, by D97 to D100, and by the second revalidation, D101 to D115; then ID ranges updated for the owner decisions D116 to D118, and for D119 (AD-36 construction validated by the key prototype). Update of 2026-10-17: ID ranges updated for the V0.1 spike records D120 to D139, design changes DC-74 to DC-77, risks R54 and R55 and threats T67 and T68; glossary terms **Pairing code** and **Content origin** added. Update of 2026-10-18: ID ranges updated for design changes DC-78 to DC-81; the out-of-browser notification channel entry states where the acknowledgement token is shown (D135) and **Crypto-shredding** pointed to D132.

## Reading order

1. [`architecture.md`](architecture.md): components, trust levels, data and key structure, action pipeline, tier 2 confirmation, failure behaviour, remaining risks. Start here.
2. [`threat-model.md`](threat-model.md): assets, adversaries, trust boundaries, threats and mitigations.
3. [`key-management.md`](key-management.md): key hierarchy, enrollment, unlock, recovery, delegation, rotation, loss.
4. [`ai-safety.md`](ai-safety.md): rules for an assistant that acts, and the invariants that test them.
5. [`capability-matrix.md`](capability-matrix.md): every action by actor, tier, confirmation and behaviour in a tainted session.
6. [`decisions.md`](decisions.md): short records of why each choice was made, with status.
7. [`research-notes.md`](research-notes.md): what is reported, assumed, and still to test.
8. [`prd.md`](prd.md): product requirements from milestone V0.1 to V1: features, milestones, design changes, residual risks and spikes.
9. [`architecture-spine.md`](architecture-spine.md): the binding architecture decisions (AD-1 to AD-56) that keep separately built parts consistent, with the stack and the structural seed.

| Document | Purpose | Status |
|----------|---------|--------|
| [`architecture.md`](architecture.md) | Central design, diagrams, challenge log, remaining risks R1 to R55 | Revision 2 |
| [`threat-model.md`](threat-model.md) | Threats T1 to T68 against adversaries A1 to A20 | Revision 2 |
| [`key-management.md`](key-management.md) | Keys, unlock, recovery, rotation | Revision 2 |
| [`ai-safety.md`](ai-safety.md) | Principles P1 to P14, invariants I1 to I43 | Revision 2 |
| [`capability-matrix.md`](capability-matrix.md) | Action by tier by confirmation | Revision 2 |
| [`decisions.md`](decisions.md) | Decisions D1 to D146 | Revision 2 |
| [`research-notes.md`](research-notes.md) | Claims and experiments E1 to E32 (E21 unused) | Revision 2 |
| [`prd.md`](prd.md) | Product requirements FR-1 to FR-112, design changes DC-1 to DC-81 | Final |
| [`architecture-spine.md`](architecture-spine.md) | Architecture decisions AD-1 to AD-56 | Final |
| [`backlog.md`](backlog.md) | V0.1 epics and stories, in [`stories/`](stories/), status in [`sprint-status.yaml`](stories/sprint-status.yaml) | Epic 1 in review |
| [`qa/epic-1-report.md`](qa/epic-1-report.md) | Spike results, gates in [`qa/gates/`](qa/gates/) | Epic 1 |

Place architecture diagrams and images in [`assets/`](assets/).

## Glossary

Terms are used with one meaning across all documents.

| Term | Meaning |
|------|---------|
| **Instance** | One Vilicus installation, serving one household |
| **Household** | The people served by an instance: one person, a couple, a family |
| **Member** | A person with an account and a personal partition. Adults and children are both members |
| **Instance admin** | The role that manages the system (plugins, exposure, updates, backups); cannot add a member alone (see D34). Holds no data key. Regains control with the **admin recovery code**, printed only on the host console at bootstrap and redeemed only at the host CLI (`vilicus admin recover`, see D101) |
| **Partition** | A unit of key isolation, of one of three kinds: one **personal partition** per member, one **household partition** shared by the members, and one **home partition** per instance (see D53) |
| **Core** | The only component that holds keys. Identity, policy, bus, registry, migrations, and the internal MCP endpoint used by its own AI processes only (see D49) |
| **Gateway** | The exposed, low-trust process that serves the front end and relays traffic. Holds no keys |
| **Module** | A trusted crate compiled into the binary (tasks, calendar, budget...). Runs inside the Core process, has no keys, owns its databases |
| **Plugin** | First-party or third-party code in a separate sandboxed process; being first-party grants nothing (connectors, secondary channels, store connectors, device adapters). Untrusted. Until V1, first-party plugins ship inside the signed main package (see D102) |
| **AI process** | A sandboxed process running a model role: quarantined reader, planner, drafter or researcher |
| **Trusted fetcher** | The process that makes every researcher request after the Core checks its URL (GET only, a link found verbatim in a page already fetched for the task, no cookies, internal addresses blocked); it runs no model and no page code and returns bytes (see D73) |
| **Local model runtime** | The component that serves local models (quarantined reading, local-only data types, transcription and voice): its own unit, reached only over per-role Unix sockets, no network, no cache shared across members or roles, model files pinned by hash (see D83); the quarantined reader and the researcher never share a runtime process with the planner or the drafter (see D110) |
| **Quarantined reader** | The AI role that reads untrusted content and returns only closed enums, bounded numbers and opaque identifiers |
| **Planner** | The AI role that holds tools and never sees raw untrusted text |
| **Drafter** | The AI role that writes reply drafts from untrusted text; output stays local and human-only |
| **Researcher** | The AI role that reads the open web for a member's question and writes a report that only a human reads; it has no network of its own and its requests are made by the trusted fetcher (see D63, D73) |
| **Alignment controller** | A small local model that answers a constrained question on structured state, to reduce tier 1 friction. Never for tier 2 |
| **MemoryStore** | The interface to the assistant's memory (episodes, entities, dated facts) |
| **Capability token** | A short-lived Core-issued token scoped to a task, member, module, partition, actions and budget |
| **Tier** | Class of action: 0 read, 1 reversible write, 2 irreversible or third-party effect, H human-only |
| **Reversible** | Reversible without effect on a third party |
| **Elevated** | A tier 1 action in a tainted session, or a household write from a session that read personal free text (see D104): needs controller approval, a light confirmation or, in a voice conversation, a spoken confirmation (see D68). Once the member approves it, its structured fields are stored `trusted`, while free text drafted in a tainted session stays `external` (see D70, D99) |
| **Taint** | The trust label of a record: `trusted` or `external`, plus `member` for another member's data as seen by an assistant, a read-time view never stored. A write the member makes, or explicitly approves, is stored `trusted` with that member as author, except free text drafted in a tainted session, which keeps `external` whatever the approval and however edited; only text the member writes in full in an empty field of the approval screen is stored `trusted` (see D70, D99) |
| **Tainted session** | An AI session that has consumed `external` data or `member` free text; structured `member` fields do not taint it (see D70) |
| **Light confirmation** | One explicit tap in an authenticated paired session; the web client is allowed, and a paired browser signs it with its device key (see D35) |
| **Spoken confirmation** | A spoken "yes", transcribed locally only and recognized by the Core, never by an AI process, after a read-back from a fixed template filled only with the request's structured fields; it approves an elevated tier 1 request that carries no I13 exception class, and nothing else: never a cart, an own-account delivery or a restorable physical action, never a rule, a scheduled task, a playbook, an H action or tier 2 (see D68, D100) |
| **Signed confirmation** | Tier 2 approval from a paired native app that displays the canonical hash and signs it with a hardware-bound key |
| **Step-up** | A fresh passkey assertion required for human-only actions, bound to the hash of exactly one pending action and never replayable for another (see D71) |
| **Pairing code** | A short-lived code that pairs a further browser: a handle that names the pending pairing and a secret that is the OPAQUE password, so a party that observes or relays the pairing cannot use it (see D35, D122) |
| **Paired device** | A client with a registered public key: a native app, a browser holding a non-extractable device key (see D35), or a household display; new ones wait 24 hours before tier 2 |
| **DEK / KEK** | Data-encryption key / key-encryption key. A member DEK is wrapped by several KEKs |
| **Household key (HK)** | Versioned key of the household partition |
| **Delegation sub-key** | A key, sealed by the instance key, that lets a scheduled task open one module's file in one partition while its member is locked. Opt-in per task, revocable; not in V0.1 (see D36, D62). The task's run descriptor keeps its fire time in clear and its definition sealed under the sub-key; no sub-key runs a member-owned plugin (see D111) |
| **Instance key** | Key protecting Core metadata and the home partition (see D53); never opens a personal partition or the household partition, except, after V0.1, the module files of the delegation sub-keys it seals (see D62). Sealed to PCR 7 (see D96), so a live image signed under the same Secure Boot authorities can unseal it. Does not protect the secrets that let a device open the house, which are entered only at the host CLI and sealed to the TPM under a signed boot policy instead (see D78, D108). Each backup carries it wrapped to the backup public key (see D85) |
| **Backup public key** | The public key to which each backup's keys (instance key, audit key) are wrapped, so backups run unattended; its private key is derived from the backup secret, generated by the Core (at least 128 bits) and kept offline, so making a backup needs no secret; restoring or checking a backup's contents does (see D85, D106) |
| **Upgrade check** | `vilicus upgrade check`: reports the migrations an upgrade has pending and those that failed; each migration runs on a copy of its file, swapped in only on success (see D84) |
| **Crypto-shredding** | Deleting a record by destroying its key; on disk, that is a delete of the wrapped key under `secure_delete` followed by a TRUNCATE checkpoint (see D132) |
| **Outbox** | Pattern for cross-module consistency without cross-database transactions |
| **Content origin** | The separate origin, the instance name on port 8443, from which the Gateway serves sanitized external content in an empty sandbox; it never sets a cookie (see D139) |
| **Content-free notification** | A notification carrying no title, sender or amount |
| **Out-of-browser notification channel** | A channel, configured by each member, that delivers content-free security alerts without an open browser (see D47). An enrollment completes only after the member redeems the token of a test notification sent to it (see D105). A recovery alert carries a one-time acknowledgement token that the member redeems at the Core from a device they control (see D75), shown in a signed-in Vilicus client and never in the push payload (see D135) |
| **Milestone** | A numbered, installable release. **V0.1** is the Core; later milestones add modules and connectors; **V1** is the first community release |
| **Instance name** | The DNS name under which the instance is served to members' browsers, fixed before any passkey is enrolled, the instance admin's included (see D76). Passkeys are bound to it |
| **Web session** | An authenticated browser session, ended after 15 minutes without activity and after 12 hours at most; every request is signed by the browser's device key, and re-authentication is a passkey assertion (see D90) |
| **AI session** | One assistant task with one capability token. "Tainted session" always means a tainted AI session |
| **Primary channel** | The Vilicus app (web client and its installable PWA): the only place where a member converses with the assistant with full context, confirms, and manages their account |
| **Secondary channel** | An external messaging service connected through a plugin. Optional and lower assurance than the primary channel |
| **Channel binding** | The record that ties one sender identity on one secondary channel to one member. Created from the primary channel only |
| **Disclosure level** | What Vilicus may send on a given channel: full disclosure on the primary channel; on a secondary channel, only the data types on that channel's ceiling, applied as input gating when a token is issued (see D103), an allowlist that never includes budget, raw mail or health data and excludes presence, home state, alarm state, the calendar and children's data unless an adult adds them, from templates or within the ceiling, with a pointer to the app (see D42, D82) |
| **Household context** | Everything the household partition holds, shared by every member |
| **Member context** | Everything a member's personal partition holds (preferences, journal, conversations, assistant memory), private to that member |
| **Segmented answer** | An output built from the household context plus the requesting member's context, and from nothing in another member's personal partition |
| **Enrollment token** | A one-time secret printed by the CLI that lets a member complete an enrollment or re-enrollment in a browser; `vilicus member reenroll` issues one for a lost passkey, after a rename or after a restore, with that member's own passphrase (see D77) |
| **Member suspension** | `vilicus member suspend`: revokes a member's sessions, devices, channel bindings and unlock window and blocks login, keeping keys and data, with no household key rotation (see D77); a member may suspend their own account with their own passphrase (see D101); lifting it follows D87 |
| **Unlock window** | The period, chosen by a member at unlock, during which their partition stays unlocked: it starts at unlock and ends at the unlock time plus the chosen duration, whatever the web sessions do; extending it needs the passphrase (see D113) |
| **Model connector** | The component through which an AI process calls a model provider: remote (by API, or through the Claude subscription connector, see D97) or local through the local model runtime |
| **Claude subscription connector** | The model connector that runs the unmodified Claude Code binary headless for one member, as that member's model connector for the planner and drafter, under its own unit and user; untrusted like an AI process; its own sign-in credential lives in its state directory, outside the key hierarchy (see D97, D110) |
| **Data type** | One value of the closed set held in `vilicus-types` (`health`, `journal`, `budget`, `meals`, `meal_plan`, `stock`, `shopping_list`, `presence`, `home_state`, `alarm_state`, `calendar`, `child`, `mail_raw`, `household_other`, `personal_other`). Every record stores the set of data types it contains, a derived record's set being the union of its inputs' sets; the provider policy, the provider bound to a capability token and a secondary channel's ceiling all read it. The only term for this classification; "data class" is not used (see D48, D80, D103) |
| **Structured field** | A field whose value set is fixed at build time: a compiled enumeration, a bounded number, a date or an opaque UUIDv7, or a value of a reviewed vocabulary; validated on every write (see D37, D98, D104). Every other field is free text |
| **Reviewed vocabulary** | A run-time list of labels (tags, categories, room, scene, mode or ingredient names) whose every new label an adult confirms, at most 32 characters of Latin letters, digits, spaces, hyphens and apostrophes; only confirmed labels are structured values (see D104, D146) |
| **Reference module** | A module that exists to exercise the module contract in tests. Never packaged; linked only into the `vilicus-testbed` binary (see D102) |
| **Test double** | A non-shipped plugin, AI process or channel used in V0.1 tests to exercise an interface that has no shipped consumer yet; linked only into the `vilicus-testbed` binary (see D102) |
| **Testbed** | `vilicus-testbed`, a binary never packaged that links the reference module and the test doubles and accepts a CI test key; release gates that need them run against it, every other gate against the shipped package (see D102) |
| **Store connector** | A plugin that acts in a member's own store account to prepare a cart |
| **Home partition** | The partition holding the house's devices, rules and current state, encrypted by the instance key so that it is usable with every member locked. One per instance |
| **Device** | A physical or virtual thing in the house (sensor, light, shutter, valve, plug, vacuum, gateway) with typed capabilities and state, owned by the home automation module |
| **Device adapter** | A plugin that connects devices of one technology (a radio daemon, a local gateway, a vendor cloud) to the device model, through named grants that are never a loopback address (see D54, D115) |
| **Home rule** | A deterministic automation (trigger, conditions, actions) executed by the Core without a model, written or validated by an adult |
| **Mode** | A household-wide state used by home rules (for example home, away, night, alarm armed) |
| **Physical security device** | A device whose action can let someone in or hide an intrusion: lock, alarm, gate, garage door, camera |
| **Safety-relevant device** | A physical security device, or a device that powers the infrastructure (the server, a radio coordinator, a gateway). Locks, alarms, cameras, gates, garage doors, covers of unknown kind and `momentary` outputs are safety-relevant from discovery; an unclassified switch, plug or relay output accepts no command from a display, the assistant or a rule until an adult classifies it; an adapter cannot change a confirmed device's class (see D72, D109). Rules move it only toward the safe state; letting someone in or cutting its power is not offered before the native app (see D69) |
| **Scene** | A named set of device states applied together |
| **Sealed inbox** | A write-only store per personal or household partition, sealed to that partition's inbox public key and ingested at its next unlock and while it stays unlocked (see D53), in a SQLCipher file under a key derived from the instance key (see D114); not in V0.1 (see D107). It protects confidentiality, not integrity, against whoever holds the instance key, so ingested rows are `external` unless they carry a MAC under a key derived from the household key, which the Core adds only to rows it produces while an adult is unlocked (see D93) |
| **Researcher egress mode** | The egress proxy mode used only by the trusted fetcher for a researcher task: any public host, internal addresses blocked, per-host budgets (see D63, D73) |
| **Staleness limit** | How late a scheduled task may still run once after a restart or a missed time; past it the run is cancelled and recorded (see D62) |
| **Principal** | The closed set of actors a call runs as: member, CLI, AI task, plugin, event, rule, display, adapter, playbook (spine AD-8) |
| **Household sealed inbox** | A write-only store for household-partition data (sensitive history always, other data while every adult is locked), sealed to the household inbox public key and moved into the household partition at the next adult unlock |
| **Household presence** | Whether someone is home, without saying who |
| **Household display** | A paired device without a member (a wall tablet) that shows the house and drives devices that are not safety-relevant |
| **Scheduled task** | A structured assistant task run by the Core at a time or on an event, on behalf of one member (see D62) |
| **Quick check-in** | A scheduled question answered with one word or one number |
| **Disclosure grant** | A member's revocable permission for the Core to compute one derived value from their data and deliver it to another adult (see D64) |
| **Playbook** | A declarative, versioned chain of tool steps run by the Core without a model, triggered only by records written by a `Member`, `Rule`, `Adapter` or `Cli` principal (see D65, D109) |
| **Tool policy** | The subset of the capability matrix a member's tokens may contain (see D66) |
| **Activatable module** | A module that is off until a household or a member activates it (see D66) |
| **Own-account delivery** | A write to an account the member owns, such as mail to themself or a file in a dedicated folder (see D67); it follows the provider policy by data type, so local-only data types never go to a hosted account (see D81); its tool takes no destination argument |
| **Hosted account** | An account on a service the household does not operate; a destination is hosted unless its host resolves to the Vilicus host or to an address range the household declared private by an H action (see D81) |
| **Standing approval** | A member's revocable approval, listed in their settings, that lets a playbook deliver to one of that member's own destinations without a confirmation at each run (see D89) |
| **I13 exception class** | One of the closed set of named exceptions to the rule that an outbound effect is tier 2: `reversible_external_state`, `restorable_physical` and `own_account_delivery` (ai-safety I13; see D44, D56, D67) |
| **Safe direction** | The direction in which a rule or a tier 1 caller may move a safety-relevant device: locking, arming, closing, never the reverse (see D56, D69) |
| **Spoken provenance** | The label `spoken` carried by a transcribed turn: it does not taint the session, but a memory fact drawn from it is stored `external` until the member confirms it in the app (see D112) |
