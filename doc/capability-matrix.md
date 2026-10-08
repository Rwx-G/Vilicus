# Capability matrix

Status: design phase, no code yet. Revision 1. One row per action that the assistant, a plugin or a human could take. The matrix exists to expose gaps: any action not listed here does not exist; any irreversible or third-party-affecting action without a signed confirmation is a bug. Concepts are defined in [ai-safety.md](ai-safety.md) (P4, P5) and [architecture.md](architecture.md) (section 9).

## Legend

**Tier.** 0 read. 1 reversible write, where reversible means reversible **without effect on a third party**. 2 irreversible, third-party effect, outbound network effect, or crossing a partition boundary. H human-only administrative action, never exposed through MCP.

**Confirmation.** *none*. *light*: one explicit tap in an authenticated paired session, web allowed. *signed*: signed confirmation from a paired native app that is at least 24 hours old (architecture, section 10). *step-up*: fresh passkey assertion. *recovery*: recovery secret plus waiting period.

**Actor.** *any*: a human or an assistant through MCP. *human*: a human only. *Core*: the Core itself (detectors, system templates).

**Tainted session** (the session has consumed `external` or `member` data, see P5):
- *allow-b*: allowed when the taint came only from bounded reader outputs; otherwise treated as *elevate*.
- *elevate*: allowed after the alignment controller approves or a human gives a light confirmation.
- *queue*: tier 2 request goes to the separate tainted queue, with origin shown, signed confirmation required.
- *deny*: not available to a tainted session.

For tier 0 rows the value only says whether the read is permitted; reading `external` or `member` data taints the session. Rows with "external" in Notes produce data labelled `external`.

## 1. Core and administration

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read own profile and permissions | any | 0 | none | allow-b | |
| Read audit log, own scope | any | 0 | none | allow-b | |
| Unlock or lock own partition | human | H | passkey with PRF, or passphrase | deny | Keys never given to the AI |
| Create or revoke a capability token | Core | n/a | n/a | deny | Not a tool; invariant I18 |
| Create a member account | human | H | admin step-up | deny | Creates no keys; member enrolls own |
| Pair a device | human | H | step-up, QR, code typed on an already-paired device | deny | 24 hour delay for the new device |
| Remove a device | human | H | step-up | deny | Revokes key and sessions |
| Add an authenticator or change passphrase | human | H | step-up | deny | |
| Start or cancel recovery | human | H | recovery secret, waiting period, alert on all devices | deny | Key management, section 6 |
| Create or revoke a delegation sub-key | human | H | step-up | deny | One module, one partition |
| Add an adult to the household partition | human | H | signed, by every other adult, delay and notification | deny | Admin cannot do it |
| Remove a member | human | H | signed, by every other adult, delay and notification to the person | deny | Rotates the household key |
| Change listening address or exposure | human | H | admin step-up, blocking warning | deny | Internet exposure is explicit |
| Install or update a release | human | H | admin step-up, version diff shown | deny | Anti-rollback |
| Create, restore or delete a backup | human | H | admin step-up | deny | Restore requires acknowledgement of anchor mismatch |
| Configure an AI provider or its data policy | human | H | step-up, delay and adult veto | deny | Per provider and per partition |
| Change caps or controller thresholds | human | H | step-up | deny | Invariant I18 |
| Call a remote AI provider with household data | Core | 0 | provider policy | allow-b | Policy per partition; finance off unless enabled for a named task |
| Trigger the kill switch | human or Core detector | n/a | none | deny | Never from a tainted session |
| Resume after the kill switch | human | H | step-up | deny | |

## 2. Tasks

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| List and read tasks | any | 0 | none | allow-b | |
| Create or edit a task | any | 1 | none | allow-b | Journaled, undoable |
| Change status or check items | any | 1 | none | allow-b | |
| Delete a task | any | 1 | none | elevate | Soft delete first |
| Purge deleted tasks | any | 2 | signed | deny | |
| Move or share a task into the household partition or to another member | any | 2 | signed | deny | Crosses a partition boundary |
| Create or edit a task in the household partition by a member of it | any | 1 | none | elevate | Same partition; `member` taint for the others |

## 3. Calendar

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read events | any | 0 | none | allow-b | |
| Create, move or edit an event in a local calendar, no guests | any | 1 | none | elevate | Journaled, undoable |
| Create an event with guests | any | 2 | signed | queue | Sends invitations |
| Move or edit an event that has guests | any | 2 | signed | queue | Sends updates |
| Delete an event that has guests | any | 2 | signed | queue | Sends cancellations |
| Accept or decline an invitation (RSVP) | any | 2 | signed | deny | Outbound effect |
| Change an event in a calendar synchronized with an external account | any | 2 | signed | deny | Batched per sync run, items listed |
| Create a recipe reminder event from the meal plan | Core | 1 | none | n/a | Stored in the household calendar (same partition as the plan); members see it through a merged view, no cross-partition write |
| Create a birthday or reminder entry | any | 1 | none | allow-b | Local |
| Enable synchronization to an external calendar account | human | H | step-up | deny | |

## 4. Places and travel

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read places and travel times | any | 0 | none | allow-b | |
| Add or edit a place | any | 1 | none | elevate | Locations are sensitive |
| Compute travel time with an external routing provider | Core | 0 | provider policy | deny | Off by default; coordinates leave the instance; provider chosen by the household (H) |
| Local context lookup (web) | Core | 0 | none | allow-b | Separate Core stage, query from a Core template or enum (place, date), never from reader text; egress via the proxy; result `external` |
| Share a location with an external party | any | 2 | signed | deny | |

## 5. Budget

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read balances and transactions | any | 0 | none | deny | Sensitive; local model by default |
| Categorize a transaction | any | 1 | none | deny | Journaled, undoable. Imported rows are `external`, so assisted categorization of a fresh import runs as a separate untainted task that sees reader output (bounded categories), or uses deterministic rules and the UI |
| Import a statement | any | 1 | none | deny | File is untrusted, parser fuzzed; imported rows are `external` |
| Edit budget lines | any | 1 | none | deny | |
| Export data outside the instance | any | 2 | signed | deny | |
| Connect or change a bank connector | human | H | step-up | deny | |
| Initiate any payment or transfer | n/a | 2 | signed | deny | Not in scope for v1 |

## 6. Meals and groceries

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read recipes, plan, stock | any | 0 | none | allow-b | |
| Add a recipe or edit the plan | any | 1 | none | allow-b | |
| Import a recipe from external content | any | 1 | none | elevate | Stored with taint `external` |
| Update stock | any | 1 | none | allow-b | |
| Generate a shopping list | any | 1 | none | allow-b | Pure computation in the partition |
| Prepare a cart through a store plugin | any | 2 | signed | queue | Acts in the user's own store session; one confirmation for the item list. A household may relax this per plugin once cart operations prove reversible (open, D25) |
| Place an order | any | 2 | signed | queue | Real cart, total and slot shown; human validation always |
| Change store account or delivery details | human | H | step-up | deny | |

## 7. Documentation

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read pages and procedures | any | 0 | none | allow-b | |
| Create or edit a page | any | 1 | none | elevate | Versioned |
| Promote a task note to a page | any | 1 | none | elevate | Same partition, taint carried over |
| Write a page into the household partition from a personal partition | any | 2 | signed | deny | Crosses a boundary |
| Publish outside the household | any | 2 | signed | deny | |

## 8. Mail and messaging

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Read mail through the quarantined reader | any | 0 | none | allow-b | Output is typed fields only |
| Read a raw mail body in the web or app UI | human | 0 | none | n/a | Rendered in a sandboxed iframe |
| Raw read by an external assistant | any | 0 | none | n/a | Per-member opt-in; the session is tainted from that moment; per-record-kind allowlist and volume limits apply to all external assistant reads |
| Raise an alert about an important mail | any | 1 | none | allow-b | Static template to the owner only |
| Send a system notification | Core | n/a | none | n/a | Template, resolved parameters, own channel, rate limited |
| Draft a reply (drafter role) | any | 1 | none | allow-b | Draft stays local, labelled `external`, shown to the human only |
| Send a reply or a new mail | any | 2 | signed | queue | Full recipient list and body shown; outbound content check applies |
| Send a free-text message to a contact through a messaging plugin | n/a | n/a | n/a | n/a | Not supported in v1: messaging plugins are outbound only for notifications |
| Receive a message through a messaging plugin | Core | n/a | none | n/a | Untrusted content, creates no proposal or confirmation |
| Delete or move mail on the server | any | 2 | signed | deny | Write to an external account |
| Change a mail account connection | human | H | step-up | deny | |
| Grant write access on an OAuth account | human | H | step-up | deny | Read-only by default, per account and per action |

## 9. Assistant memory

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Search memory | any | 0 | none | allow-b | Tags and taint always returned |
| Record a fact from a trusted source | any | 1 | none | deny | |
| Record a fact from untrusted content | any | 1 | none | allow-b | Stored quarantined, tagged, not used for planning |
| Promote a quarantined fact | any | 2 | signed | deny | |
| Forget or invalidate a fact | any | 1 | none | elevate | Invalidated, not deleted; rollback available |
| Roll back memory to an earlier state | any | 1 | none | elevate | |
| Purge memory | any | 2 | signed | deny | |
| Enable the Graphiti annex backend | human | H | step-up | deny | Memory leaves the SQLCipher boundary |

## 10. Plugins and connectors

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| Install or enable a plugin | human | H | step-up, manifest diff shown by the Core, delay and adult veto | deny | |
| Grant a plugin network destinations | human | H | step-up, manifest diff shown, delay and adult veto | deny | Exact hostnames only |
| Change a plugin's rights | human | H | step-up, diff shown | deny | New confirmation on every change |
| Revoke or stop a plugin | human | H | none (safe direction, one action) | deny | Safe direction; also via signed revocation list |
| Call a plugin read operation | any | 0 | none | allow-b | Output is `external` |
| Call a plugin write operation | any | per manifest | per manifest | elevate | Any outbound network effect is tier 2 by rule (I13) |

## 11. Default caps (to tune)

| Cap | Initial value |
|-----|---------------|
| Orders per week | 2 |
| Mails sent per hour | 5 |
| System notifications per member per hour | 10 |
| Spend per order without extra confirmation | 0 (always confirm) |
| Tool calls per task | 50 |
| Tokens and cost per task | Configurable, conservative default |
| Tokens and cost per member per day | Configurable, conservative default |
| Capability token lifetime | Minutes, bound to one task |
| Pending signed confirmations | 1 in the normal queue, 1 in the tainted queue, with a lower hourly rate for the tainted queue (proposal: 3 per hour) |
| Signed confirmation expiry | Under 2 minutes |
| Consecutive refusals before the task is suspended | 3 |
| Wait for an unlock before a background task is canceled | 12 hours |
| Recovery waiting period | 48 hours |
| New device delay before tier 2 or pairing | 24 hours |

## 12. How to use this matrix

1. When adding a module or plugin, add its rows before writing code; the module registry loads tool definitions from the same table in code, and a build check compares them.
2. Reviewers look for: tier 2 actions without signed confirmation, anything that sends or deletes that a tainted session may call, and actions reachable by the AI that should be human-only.
3. Each row maps to an invariant test where possible (`ai-safety.md`, section 3). The check that every tool with a network effect is tier 2 (I13) and that no H action is a tool (I18) is automated over this table.

## 13. Review log

| Date | Reviewer | Notes |
|------|----------|-------|
| 2026-10-08 | Author, draft v0 | Initial version |
| 2026-10-08 | Author, revision 1 | Added Actor and Tainted session columns, tier H, outbound-effect rule, cross-partition rule, missing rows (notifications, routing, local lookup, administration, sync, recovery). Aligned with `architecture.md` |
