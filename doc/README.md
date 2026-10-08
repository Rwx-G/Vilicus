# Vilicus design documents

Status: design phase, no code yet. These documents are written before the code and are meant to be attacked. Each file has a review log or a status line; open questions are stated, not hidden.

## Reading order

1. [`architecture.md`](architecture.md): components, trust levels, data and key structure, action pipeline, tier 2 confirmation, failure behaviour, remaining risks. Start here.
2. [`threat-model.md`](threat-model.md): assets, adversaries, trust boundaries, threats and mitigations.
3. [`key-management.md`](key-management.md): key hierarchy, enrollment, unlock, recovery, delegation, rotation, loss.
4. [`ai-safety.md`](ai-safety.md): rules for an assistant that acts, and the invariants that test them.
5. [`capability-matrix.md`](capability-matrix.md): every action by actor, tier, confirmation and behaviour in a tainted session.
6. [`decisions.md`](decisions.md): short records of why each choice was made, with status.
7. [`research-notes.md`](research-notes.md): what is reported, assumed, and still to test.

| Document | Purpose | Status |
|----------|---------|--------|
| [`architecture.md`](architecture.md) | Central design, diagrams, challenge log, remaining risks | Revision 1 |
| [`threat-model.md`](threat-model.md) | Threats T1 to T30 against adversaries A1 to A12 | Revision 1 |
| [`key-management.md`](key-management.md) | Keys, unlock, recovery, rotation | Revision 1 |
| [`ai-safety.md`](ai-safety.md) | Principles P1 to P12, invariants I1 to I18 | Revision 1 |
| [`capability-matrix.md`](capability-matrix.md) | Action by tier by confirmation | Revision 1 |
| [`decisions.md`](decisions.md) | Decisions D1 to D33 | Revision 1 |
| [`research-notes.md`](research-notes.md) | Claims and experiments E1 to E20 | Revision 1 |

Place architecture diagrams and images in [`assets/`](assets/).

## Glossary

Terms are used with one meaning across all documents.

| Term | Meaning |
|------|---------|
| **Instance** | One Vilicus installation, serving one household |
| **Household** | The people served by an instance: one person, a couple, a family |
| **Member** | A person with an account and a personal partition. Adults and children are both members |
| **Instance admin** | The role that manages the system (plugins, exposure, updates, adding members). Holds no data key |
| **Partition** | A unit of key isolation: one personal partition per member and one **household partition** shared by the members |
| **Core** | The only component that holds keys. Identity, policy, bus, registry, migrations, MCP endpoint |
| **Gateway** | The exposed, low-trust process that serves the front end and relays traffic. Holds no keys |
| **Module** | A trusted crate compiled into the binary (tasks, calendar, budget...). Runs inside the Core process, has no keys, owns its databases |
| **Plugin** | Third-party code in a separate sandboxed process (connectors, outbound messaging). Untrusted |
| **AI process** | A sandboxed process running a model role: quarantined reader, planner or drafter |
| **Quarantined reader** | The AI role that reads untrusted content and returns only closed enums, bounded numbers and opaque identifiers |
| **Planner** | The AI role that holds tools and never sees raw untrusted text |
| **Drafter** | The AI role that writes reply drafts from untrusted text; output stays local and human-only |
| **Alignment controller** | A small local model that answers a constrained question on structured state, to reduce tier 1 friction. Never for tier 2 |
| **MemoryStore** | The interface to the assistant's memory (episodes, entities, dated facts) |
| **Capability token** | A short-lived Core-issued token scoped to a task, member, module, partition, actions and budget |
| **Tier** | Class of action: 0 read, 1 reversible write, 2 irreversible or third-party effect, H human-only |
| **Reversible** | Reversible without effect on a third party |
| **Elevated** | A tier 1 action in a tainted session: needs controller approval or a light confirmation |
| **Taint** | The trust label of a record: `trusted` or `external`, plus `member` for another member's data as seen by an assistant |
| **Tainted session** | An AI session that has consumed `external` or `member` data |
| **Light confirmation** | One explicit tap in an authenticated paired session; the web client is allowed |
| **Signed confirmation** | Tier 2 approval from a paired native app that displays the canonical hash and signs it with a hardware-bound key |
| **Step-up** | A fresh passkey assertion required for human-only actions |
| **Paired device** | A client with a registered public key; new ones wait 24 hours before tier 2 |
| **DEK / KEK** | Data-encryption key / key-encryption key. A member DEK is wrapped by several KEKs |
| **Household key (HK)** | Versioned key of the household partition |
| **Delegation sub-key** | Explicit, scoped, revocable key letting a background task open one module's database while the member is locked |
| **Instance key** | Key protecting Core metadata only; never opens member data |
| **Crypto-shredding** | Deleting a record by destroying its key |
| **Outbox** | Pattern for cross-module consistency without cross-database transactions |
| **Content-free notification** | A notification carrying no title, sender or amount |
