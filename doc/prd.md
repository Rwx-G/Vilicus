---
title: Vilicus PRD
author: Rwx-G
status: final
created: 2026-10-08
updated: 2026-10-16
---

# PRD: Vilicus

## 0. Document purpose

This PRD defines what Vilicus must do, from the first installable Core (milestone V0.1) to the first community release (V1). It is written for the owner, for the architecture and epic workflows that follow it, and for any contributor who needs to know why a capability exists.

It builds on the design documents in `doc/` (revision 2) and does not repeat them: the architecture, threat model, key management, AI safety principles, capability matrix and decision log stay authoritative for *how* things work. This PRD states *what* each milestone delivers, and section 8.1 lists the design changes the product needs that the design documents do not yet contain.

**At a glance.** V0.1 is the installable Core: packaging, members, keys, recovery, devices, partitions, the module platform, the action pipeline and the audit log. It has no user-facing module, and every interface without a shipped consumer is proven by a test double (section 6.1). Home automation is the first module after V0.1, followed by meals, the assistant conversation, the channels and the modules that bring the assistant to parity with the previous one, in the order of section 6.2. The design changes each milestone depends on are in section 8.1, the open questions in section 11.

Conventions:
- Features are in section 4. Functional requirements are numbered globally (FR-1 to FR-N); numbers are stable and are not in reading order.
- Each requirement or section carries one milestone tag: `[V0.1]`, `[after V0.1]`, or `[V0.1 partial]` when part of it ships in V0.1 and the body says which part.
- V0.1 requirements are written to be testable as they stand. A requirement without a Consequences block is tested by its statement, or by the design section it cites. Later milestones are coarser by intent.
- Terms follow the glossary in `doc/README.md` plus the additions in section 3.
- Inferences not yet confirmed by the owner carry `[ASSUMPTION]` and are indexed in section 12.

## 1. Vision

Vilicus is the steward of one household. One installation serves one family, and every part of its daily organization (meals, groceries, calendar, tasks, budget, family procedures) lives on one encrypted data foundation, entered once and known everywhere. On top of it sits an assistant that does not only answer but acts: it plans the week, builds the shopping list, prepares the cart, logs what you ate, reminds you of what matters. It also runs the house itself: heating, shutters, lights, presence and alarm keep working on their own, even when nobody is logged in.

What makes that safe is the same thing that makes it useful. The assistant works on structured data under rules the Core enforces, not under rules the model promises to follow. Each adult has a personal partition that the other adult and the other adult's assistant cannot read, unless that adult controls the host (section 8.2), and a shared household partition they both build on. The same question asked by two people gets two answers: same household facts, adapted to who is asking.

Vilicus replaces the owner's current general-purpose assistant and the household's current home automation software. The assistant's memory moves into Vilicus, and the app becomes the place where the household talks to its assistant. Messaging channels stay available as a convenience, never as the place where trust is decided. The assistant is Vilicus's own: no outside assistant is given a door into the household's data.

## 2. Target user

### 2.1 Jobs to be done

- **Feed the family without the double entry.** Pick meals once and have the list, the stock and the cart follow, instead of copying a recipe app into a list and the list into a store website by hand.
- **Know what is in the cupboard.** Stop buying duplicates and forgetting staples, without having to maintain a full inventory.
- **Track my own habits privately.** Log meals, estimate calories and macros, follow a personal goal, without the other adult seeing it.
- **Share one plan, get my own view of it.** Both adults see the same week; each sees what concerns them (who cooks tonight, my variant, my part of the list).
- **Delegate to an assistant I can trust with real actions.** Let it write, plan and prepare, knowing what it can and cannot do, and seeing afterwards what it did.
- **Let the house run itself.** Heating, shutters, lights and the alarm follow the household's rules, through a power cut and with nobody logged in; only a human opens the door.
- **Own the data.** Run it at home, encrypted, without a cloud account, without a container stack to maintain, without having to buy anything.

### 2.2 Non-users

- Companies and teams. Vilicus is not a collaboration suite.
- Anyone wanting a hosted service. One instance is one self-hosted household; there is no multi-tenant offering.
- Users who need a native iOS client before V1. `[ASSUMPTION]` iOS is not planned before V1.
- Children as users. Children are subjects of household data (meals, constraints, appointments); managed child accounts come after V1. `[ASSUMPTION]`
- People who want to drive their household data from an outside AI assistant. Vilicus exposes no MCP endpoint to outside assistants (DC-16).

### 2.3 Key user journeys

Personas are fictional. Thomas and Claire are the two adults of a household with two young children. V0.1 journeys use the full schema; later journeys are sketched and get the full schema when their milestone is planned.

- **UJ-1. Thomas installs Vilicus on the home server.** *(V0.1)*
  - **Persona and context:** Thomas runs a small Debian 13 server at home and wants Vilicus up without containers and without buying a domain.
  - **Entry state:** shell access to the server, no Vilicus installed.
  - **Path:** he installs the `.deb`; the service starts and prints a one-time bootstrap token and the fingerprint of a temporary self-signed certificate. He opens the wizard from his laptop on the LAN, compares the fingerprint and enters the token. The wizard first asks for the instance name and a certificate trusted by his devices; he follows the documented free option he prefers. The wizard then moves to that name, where he creates the instance admin account with its passkey, confirms the instance admin's push destination by opening a test notification on his phone, and writes down the backup secret the Core generates, then enrolls himself as the first member: passkey, passphrase, recovery secret printed and partially re-typed, and a test notification redeemed on his phone. No passkey is created before the instance name is in place.
  - **Climax:** he lands on his empty home screen, unlocked, in a paired browser, on the instance name.
  - **Resolution:** the wizard is permanently disabled; `vilicus status` on the server shows one member, all services healthy.
  - **Edge case:** his laptop crashed after the instance admin was created but before he enrolled; he runs `vilicus member enroll-first` on the host with the admin recovery code and finishes enrollment in the browser.

- **UJ-2. Thomas adds Claire from the command line.** *(V0.1)*
  - **Persona and context:** the household has two adults; Claire must have her own personal partition from day one.
  - **Entry state:** Thomas enrolled (UJ-1); Claire has her phone.
  - **Path:** Thomas runs `vilicus member add`; the CLI asks for his passphrase and prints a one-time enrollment token. Claire opens the enrollment page on her phone, enters the token, enrolls her passkey, chooses her passphrase, saves her recovery secret, and redeems a test notification sent to her phone. The Core generates her keys; her personal partition exists at once.
  - **Climax:** a day later, with no veto, the household key is wrapped for Claire at Thomas's next unlock, after the Core has checked her public key against the authentication created when Thomas ran the command; she now sees the household partition. Both were notified at each step; the audit log shows the operation.
  - **Resolution:** Claire has a personal partition Thomas cannot read, and both share the household partition.
  - **Edge case:** someone with shell access but without an adult's passphrase runs the command; it fails, and the failed attempt is audited.

- **UJ-3. Thomas starts his morning after a power cut.** *(V0.1)*
  - **Entry state:** the server restarted overnight; every member is locked.
  - **Path:** Thomas opens the app, logs in with his passkey, unlocks with his passphrase, and chooses how long his partition stays unlocked.
  - **Climax:** his data is back; the page shows the remaining unlock time, and the audit view shows the restart and his unlock.
  - **Resolution:** his partition stays unlocked for the chosen window, then locks itself even if he never comes back.

- **UJ-4. Claire plans the week with the assistant.** *(after V0.1)*
  - **Persona and context:** Claire wants the groceries off her mind; today she copies recipes into a list by hand.
  - **Path:** in the app she asks the assistant for next week's dinners. It uses the household context (shared recipes, including those Thomas added, stock, the children's constraints and portions, who cooks and who is away each evening) and her own context (her preferences). She swaps two meals and confirms.
  - **Climax:** the meal plan is written as Claire, and the shopping list is generated, minus what is in stock, grouped by aisle.
  - **Resolution:** Thomas opens the app and sees the same plan; the list shows what he picks up on his way home on the evening he cooks.
  - **Edge case:** Thomas's private journal shaped none of Claire's suggestions; her assistant cannot read it. Claire's own preferences shaped the proposals, but none of her private notes was copied into the shared plan.

- **UJ-5. Claire gets the cart prepared.** *(after V0.1)*
  - **Path:** from the shopping list, Claire starts cart preparation at the household's store (once the full conversation ships, she can also ask the assistant). A sandboxed store connector fills the cart in her own store account.
  - **Climax:** she reviews the cart on the store website, picks a slot and pays there herself.
  - **Resolution:** Vilicus never pays and never orders; the audit log shows which items were added.

- **UJ-6. Thomas logs his breakfast from a messaging app.** *(after V0.1)*
  - **Path:** Thomas has bound his messaging account to his member profile from the app. He sends "two pastries this morning".
  - **Climax:** the entry lands in his personal journal, processed by the local model; the reply says "logged" and nothing more specific; details and estimates are in the app.
  - **Edge case:** a message from an account that is not bound is ignored and counted in the audit log.

- **UJ-7. The house comes back on its own after a power cut.** *(after V0.1)*
  - **Path:** the power comes back at night; the server restarts with every member locked. The home rules resume at once: the heating schedule continues, the shutters open at the usual time, motion-activated lights work.
  - **Climax:** in the morning Thomas sees nothing unusual; the app shows the restart and the rules that ran.
  - **Edge case:** one radiator valve did not come back online; the household display and an out-of-browser notification flag it as offline.

- **UJ-8. The children use the household display.** *(after V0.1)*
  - **Path:** the household display, a wall tablet in the living room, shows the house: temperatures, open windows, the day type, the next train. A child closes the shutters of their room from it.
  - **Climax:** the shutters close; the tablet never shows anything from a member's partition or the household's meals, budget or calendar.
  - **Edge case:** the child tries to disarm the alarm from the tablet; the action is not offered there.

- **UJ-9. Claire arms the alarm and leaves.** *(after V0.1)*
  - **Path:** household presence turns to nobody home, and Vilicus proposes arming; Claire confirms from her phone.
  - **Climax:** a door opens while armed; both adults get a content-free alert and open the app for details, from outside the house, through the household's remote access (FR-86).
  - **Resolution:** in the evening Thomas comes home; his phone joins the network, and Vilicus tells the adults that someone is home while the alarm is armed. Until the native app exists, Thomas disarms with the alarm vendor's app or a physical gesture at the device; Vilicus proposes nothing it cannot do. Once the native app ships, disarming is a tier 2 action confirmed on it (FR-80). No rule, no web page and no assistant could have disarmed.

## 3. Glossary additions

The glossary in `doc/README.md` applies. This PRD adds:

- **Milestone**: a numbered, installable release. **V0.1** is the Core. Later milestones add modules and connectors in the order of section 6.2. **V1** is the first community release.
- **Instance name**: the DNS name under which the instance is served to members' browsers, fixed before any passkey is enrolled, the instance admin's included. Passkeys are bound to it.
- **Web session**: an authenticated browser session, ended after 15 minutes without activity and after 12 hours at most (D90, `doc/architecture.md` section 6).
- **AI session**: one assistant task with one capability token (`doc/architecture.md` section 9.3). "Tainted session" always means a tainted AI session.
- **Primary channel**: the Vilicus app (web client and its installable PWA). The only place where a member converses with the assistant with full context, confirms, and manages their account.
- **Secondary channel**: an external messaging service (for example Signal, Telegram, WhatsApp, Discord) connected through a plugin. Optional and lower assurance than the primary channel.
- **Channel binding**: the record that ties one sender identity on one secondary channel to one member. Created from the primary channel only.
- **Disclosure level**: what Vilicus may send on a given channel: full disclosure on the primary channel; on a secondary channel, only the data types of that channel's ceiling, an allowlist (never `budget`, `mail_raw` or `health`; `presence`, `home_state`, `alarm_state`, `calendar` and `child` only if an adult adds them), applied to what the session may read, from templates or within the ceiling, with a pointer to the app (FR-37).
- **Data type**: one value of the closed set held by `vilicus-types` (FR-68). Every record stores the set of data types it contains; the provider policy and the channel ceilings read that set (DC-58).
- **Household context**: everything the household partition holds, shared by every member.
- **Member context**: everything a member's personal partition holds (preferences, journal, conversations, assistant memory), private to that member.
- **Segmented answer**: an output built from the household context plus the requesting member's context, and from nothing in another member's personal partition.
- **Enrollment token**: a one-time secret printed by the CLI that lets a member complete an enrollment or re-enrollment in a browser.
- **Unlock window**: the period, chosen by a member at unlock, during which their partition stays unlocked; it starts at unlock and ends at the unlock time plus the chosen duration, whatever the web sessions do (FR-12).
- **Model connector**: the component through which an AI process calls a model provider, remote (by API, or through the Claude subscription connector) or local (FR-68).
- **Local model runtime**: the component that runs models on the host, in its own unit, reached only over Unix sockets, without network (FR-33).
- **Trusted fetcher**: the component without a model that performs every researcher request after the Core checks its URL, and returns the bytes (FR-90).
- **Member suspension**: the action that revokes a member's sessions, devices, bindings and unlock window and blocks their login, keeping keys and data; a member can also suspend their own account (FR-107).
- **Reference module**: a module that exists to exercise the module contract in tests. It is never packaged; it is linked only into the `vilicus-testbed` binary (FR-109).
- **Test double**: a non-shipped plugin, AI process, channel or model connector used in V0.1 tests to exercise an interface that has no shipped consumer yet; it runs only with the `vilicus-testbed` binary (FR-109).
- **Store connector**: a plugin that acts in a member's own store account to prepare a cart.
- **Home partition**: a partition holding the house's devices, rules and current state, encrypted by the instance key so that it is usable with every member locked. One per instance.
- **Device**: a physical or virtual thing in the house (sensor, light, shutter, valve, plug, vacuum, gateway) with typed capabilities and state, owned by the home automation module.
- **Device adapter**: a plugin that connects devices of one technology (a radio daemon, a local gateway, a vendor cloud) to the device model.
- **Home rule**: a deterministic automation (trigger, conditions, actions) executed by the Core without a model, written or validated by an adult.
- **Mode**: a household-wide state used by home rules (for example home, away, night, alarm armed).
- **Physical security device**: a device whose action can let someone in or hide an intrusion: lock, alarm, gate, garage door, camera.
- **Safety-relevant device**: a physical security device, or a device that powers the infrastructure (the server, a radio coordinator, a gateway). A device of a physical security kind is safety-relevant from discovery (FR-72). Rules move it only toward the safe state.
- **Scene**: a named set of device states applied together.
- **Household sealed inbox**: a write-only store for household-partition data (sensitive history always, other data while every adult is locked), sealed to the household inbox public key and moved into the household partition at the next adult unlock.
- **Scheduled task**: a structured assistant task run by the Core at a time or on an event, on behalf of one member (FR-87).
- **Delegation sub-key**: a key, sealed by the instance key, that lets a scheduled task open one module's file in one partition while its member is locked (FR-88).
- **Researcher**: the AI role that reads the open web for a member's question and writes a report that only a human reads (FR-90).
- **Disclosure grant**: a member's revocable permission for the Core to compute one derived value from their data and deliver it to another adult (FR-92).
- **Playbook**: a declarative, versioned chain of tool steps run by the Core without a model (FR-98).
- **Tool policy**: the subset of the capability matrix a member's tokens may contain (FR-99).
- **Activatable module**: a module that is off until a household or a member activates it (FR-100).
- **Quick check-in**: a scheduled question answered with one word or one number (FR-89).
- **Own-account delivery**: a write to an account the member owns, such as mail to themself or a file in a dedicated folder, under the provider policy by data type (DC-33, DC-47).
- **Household presence**: whether someone is home, without saying who.
- **Household display**: a paired device without a member (a wall tablet) that shows the house and drives devices that are not safety-relevant.

## 4. Features

### 4.1 Installation, packaging and CLI

**Description:** Vilicus installs as a Debian package on a Linux host with systemd, with no container runtime. The package provides one executable with subcommands, the systemd units of each process, and a CLI for every operation that must work without the web client. Realizes UJ-1, UJ-2.

#### FR-1: Debian package [V0.1]

The operator can install, upgrade and remove Vilicus with the system package manager.

**Consequences (testable):**
- `apt install ./vilicus_<version>.deb` on a clean Debian 13 system leaves the Core, Gateway, audit writer and egress proxy running as separate systemd services under unprivileged accounts. `[ASSUMPTION]` amd64 in V0.1, arm64 before V1; other distributions are decided for V1.
- Removing the package stops the services and leaves the data directory in place; purging is a separate explicit step.

#### FR-2: Process model and sandbox profile [V0.1]

Each process runs under the fixed sandbox profile defined in `doc/architecture.md` section 4.

**Consequences (testable):**
- CI checks every shipped unit against the profile and fails on a deviation.
- Every Unix socket created by the Core rejects a peer whose identity (its systemd unit, resolved from the peer process as in architecture spine AD-24) does not match the expected service.
- `systemd-analyze security` reports a score at or below an agreed threshold for each unit. `[ASSUMPTION]` threshold 2.0.
- On a host without a TPM, the documentation states that the instance key is protected by file permissions only (R14).

#### FR-3: Administration CLI [V0.1]

The operator can run these commands on the host, each defined by the requirement in parentheses:
- `vilicus status` (this requirement);
- `vilicus bootstrap token` (FR-4) and `vilicus admin recover` (FR-5);
- `vilicus member enroll-first` (FR-7), `vilicus member add` and `vilicus member veto` (FR-8), `vilicus member recover` (FR-14), `vilicus member reenroll` (FR-108), `vilicus member suspend` (FR-107);
- `vilicus device pair` (FR-16);
- `vilicus unlock` (FR-57);
- `vilicus instance listen` (FR-6) and `vilicus instance rename` (FR-66);
- `vilicus killswitch` (FR-30);
- `vilicus backup`, `vilicus backup verify`, `vilicus backup target set`, `vilicus restore` and `vilicus restore --replace` (FR-53, FR-54);
- `vilicus upgrade check` and `vilicus upgrade verify <package>` (FR-54);
- `vilicus host acknowledge-swap` (section 7);
- `vilicus events replay <dead-letter id>` (FR-24);
- `vilicus audit verify` (FR-31).

`vilicus ai connect claude <member>` ships with FR-33, after V0.1.

**Consequences (testable):**
- Every CLI command that grants access to member data requires a member passphrase, and none can be completed with the instance admin's credentials alone (DC-43): `member add` requires the passphrase of any existing adult; `device pair`, `unlock` and `member reenroll` require the target member's own passphrase, so one adult cannot pair a browser to the other adult's account; `member suspend` requires the passphrase of an adult other than the suspended member, or the member's own passphrase for their own account; `member veto` requires the vetoing adult's own passphrase. In each case the passphrase is that of the member who runs the command.
- `admin recover` and `member enroll-first` require the admin recovery code typed at the prompt, and grant no access to member data (DC-56).
- `status`, `bootstrap token`, `instance listen`, `killswitch`, `backup`, `backup verify`, `backup target set`, `restore`, `upgrade check`, `upgrade verify`, `host acknowledge-swap`, `events replay` and `audit verify` need no member passphrase and never unlock anything.
- A passphrase, a recovery secret or the admin recovery code is only ever read from an interactive prompt, never from an argument, an environment variable or a file.
- The CLI talks to the Core through an administration socket that only root can open, so every command needs root on the host, and the commands that act for a member also need that member's passphrase as above. The socket is unreachable from every sandboxed service (plugins, AI processes, Gateway), verified by a test.
- Every CLI command writes an audit entry, including failed attempts.
- `vilicus status` reports service health, members (locked or unlocked, never data), pending migrations, audit chain state and notification delivery failures.

#### FR-53: Backup and restore [V0.1]

Backups run unattended and are verified; the operator can create, verify and restore complete backups from the CLI without holding any data key (`doc/architecture.md` section 18, DC-19, DC-51, DC-61).

**Consequences (testable):**
- A backup contains every encrypted database file, every plugin state store (D95), `wrappers.db`, `core.db`, `audit.db`, the audit key, the instance key, and a manifest with generation and hashes. The audit key and the instance key are wrapped to a backup public key; its private key is derived from a backup secret of at least 128 bits that the Core generates at bootstrap and shows once to the instance admin, never chosen, and that the host never stores, so a backup needs no secret and a restore needs it.
- Within each backup, passphrase wrappers and file names are additionally sealed to the backup public key; recovery-secret and household-key wrappers stay as on the host (DC-61).
- Secrets of device adapters that drive physical security devices are not in a backup; they are entered again after a restore on another host (DC-44).
- A systemd timer runs `vilicus backup` as root, which assembles the archive (architecture spine AD-31) and uploads it through the egress proxy to an off-host S3-compatible object storage target, with credentials that can write but not delete or overwrite, or object lock. The operator sets the target with `vilicus backup target set` (root). The instance admin is alerted when the last successful backup is older than a limit. `[ASSUMPTION]` Daily backups, alert after 3 days.
- Retention is 7 daily and 4 weekly backups, shown to every adult as a privacy setting (DC-61).
- Changing the target or the backup secret raises an out-of-browser alert to every adult and follows the delay and veto of FR-8.
- The manifest carries a monotonic backup sequence number and a MAC under a key derived from the audit key. `vilicus backup verify` checks a backup's manifest, MAC, hashes and completeness without the backup secret, after each upload; that is what "verified" means. CI runs a full restore drill on a fresh Debian 13 VM for every release.
- `vilicus restore` runs on the host with the services stopped, targets an empty data directory, and is documented as an operation equivalent to root; `vilicus restore --replace` restores over an existing installation (FR-54). It checks the manifest before writing anything and refuses a manifest whose MAC fails, or whose sequence number is older than the latest one the remote sink recorded, unless the operator acknowledges it. It writes the instance and audit keys as new credentials bound to the new host's TPM, or as file credentials without one. After a restore on a fresh host with the backup secret, a member who unlocks gets their data back intact.
- A restore invalidates every paired device, web session, enrollment token, channel binding and WireGuard peer, so an old backup cannot bring back a revoked device. Each member logs in with a passkey and pairs a browser with `vilicus device pair` and their own passphrase, or re-enrolls a passkey with FR-108; a household that restores while away from home has no remote access until a peer is added again (FR-86).
- After a restore, every adult is shown the security state the backup brought back (wrapper generations, household key version, safety-relevant marks, grants) and acknowledges it.
- When a remote sink is configured, a restore reports a mismatch when the restored chain does not contain the last head hash recorded by the remote sink, or contains it at a different sequence number (FR-32).

#### FR-54: Controlled upgrades [V0.1]

Upgrades are always an explicit operator action, never automatic.

**Consequences (testable):**
- The package does not enable automatic upgrades. In V0.1, each `.deb` is published with a detached signature, and `vilicus upgrade verify <package>` checks it against the project key embedded in the installed version before install; a signed apt repository comes at V1.
- After a package upgrade, the new version waits for an instance admin acknowledgement with step-up, showing the version change; every adult is notified on the out-of-browser notification channel. Only then does it migrate each database (`wrappers.db` and `core.db` at once; `core.<partition>.db` and module databases, which need the partition key, at each partition's next unlock).
- While the upgrade waits for the acknowledgement, the Core runs in maintenance mode: login, the acknowledgement and status only. The home partition has already migrated (FR-84), and the new version reads the previous `core.db` schema until the acknowledgement.
- Each migration runs on a copy of the file, which is swapped in only on success (DC-50). A failed migration keeps the previous file, stops only that file's module for that partition, leaves every other file and module running, and alerts the instance admin; the fix is a later release.
- `vilicus upgrade check` reports pending and failed migrations, per file.
- Installing an older version than the one that last ran is refused (anti-rollback); the Core enforces it by its recorded version marker, not by verifying a signature at runtime. The last resort is a restore with the version that wrote the backup: `vilicus restore` targets an empty data directory, and to restore over an existing installation, `vilicus restore --replace` (root) moves the data directory aside, after which the maintainer script finds no marker and accepts the version that wrote the backup; the marker is then set from the backup manifest.
- Package maintainer scripts do the minimum as root and never touch member data files beyond ownership of the data directory.

#### FR-109: Verification harness [V0.1]

The release gates run against defined artifacts, and the V0.1 screens that need a module are exercised without shipping one (DC-57).

**Consequences (testable):**
- Doubles of plugins, AI processes, channels and model connectors are separate executables under `testing/`, installed in the CI Debian 13 VM as plugin and AI units.
- The reference module is linked only into a `vilicus-testbed` binary built from the same crates as `vilicus` and never packaged. Release gates that need a module or a double run against `vilicus-testbed`; every other gate runs against the shipped `.deb`.
- The shipped binary accepts only the project key; `vilicus-testbed` also accepts a CI test key.
- UJ-1, UJ-2 and UJ-3 run automated in the VM with a browser virtual authenticator, and once per release manually on one Android phone and one desktop browser, with the result recorded in the release notes.

#### FR-111: Documentation [V0.1]

Each release ships the documentation the operator needs to run it (DC-68).

**Consequences (testable):**
- The documentation covers installation, the naming and certificate options of FR-65, the TPM and no-TPM statement of FR-2, the backup and restore runbook (FR-53), the TPM unseal recovery runbook (architecture spine AD-22) and the upgrade procedure (FR-54).

#### FR-112: Release [V0.1]

Each release is built, signed and published by a written procedure (DC-68).

**Consequences (testable):**
- The project's offline signing key is generated and kept offline by the project maintainer on removable media, under a written custody procedure.
- Each release publishes the signed `.deb`, its detached signature and its SBOM on the project's GitHub releases page.
- The key that `vilicus upgrade verify` checks against is embedded at build (FR-54).

### 4.2 Bootstrap and instance administration

**Description:** the first start produces a one-time bootstrap token; the wizard fixes the instance name and its certificate, then creates the instance admin, and offers to enroll the first member (DC-42). The instance admin manages the system and never holds a data key (`doc/architecture.md` section 7.1, D5, D32). Realizes UJ-1.

#### FR-4: First-start bootstrap [V0.1]

The operator can create the instance admin once, through the wizard, with the token printed on the console.

**Consequences (testable):**
- The token has 128 random bits, is single use, expires after 15 minutes, and is rate limited.
- The token and the certificate fingerprint are written to the Core unit's journal and shown by `vilicus status` while bootstrap is pending; `vilicus bootstrap token` (root) issues a new one and invalidates the previous one.
- Before bootstrap completes, the wizard answers only on loopback and private addresses, over a temporary self-signed certificate whose fingerprint is printed with the token. Private addresses are those of FR-6; until bootstrap completes, the Gateway refuses any peer whose address is not private.
- The steps run in this order (DC-42, DC-60): bootstrap token; instance name and certificate (FR-65), validated in the wizard's browser; the instance admin's passkey, on the instance name; the instance admin's out-of-browser destination, confirmed by redeeming the token of a test notification (FR-56); the backup secret, generated by the Core and shown once (FR-53); the first member (FR-7). No WebAuthn ceremony runs over the temporary self-signed certificate (E24).
- The admin recovery code (FR-5) is printed on the host console only, at bootstrap.
- Once the instance admin's passkey exists, the remaining steps are setup routes authenticated as the instance admin on the instance name, and every wizard route returns not found, including after a restart.

#### FR-65: Instance name and certificate [V0.1]

The operator holding the bootstrap token sets the instance name and provides a certificate for it, trusted by the household's devices, before any passkey is enrolled, the instance admin's included (DC-18, DC-42).

**Consequences (testable):**
- No passkey enrollment page, for the instance admin or a member, is served until an instance name is configured with a certificate that validates in the wizard's browser.
- The instance admin and every member are alerted on the out-of-browser notification channel before the instance certificate expires. `[ASSUMPTION]` 14 days before. The alert applies to the certificate file option; with a reverse proxy, the documentation states that the operator monitors expiry.
- The certificate source is the operator's choice: a certificate and key file (renewed by an external tool and reloaded by Vilicus), or a reverse proxy that terminates TLS for the instance name. `[ASSUMPTION]` No built-in ACME client in V0.1.
- The documentation describes at least three ways to get a name and a certificate at no cost: a free dynamic DNS subdomain with a DNS-01 certificate, a private-network name with its certificate, and a local certificate authority installed on each device. Which of them support passkeys and PWA installation on each target browser is established by E24.
- When a reverse proxy terminates TLS, the documentation says that the hybrid key exchange ends at the proxy (D27).

#### FR-66: Renaming the instance [V0.1]

The instance admin can change the instance name with `vilicus instance rename`.

**Consequences (testable):**
- After a rename, every passkey is unusable; each member re-enrolls a passkey with an enrollment token from `vilicus member reenroll` plus their passphrase (FR-108), the instance admin re-enrolls with the admin recovery code (FR-5), and no data is lost, because passkeys do not wrap data keys in V0.1.
- The rename is audited and every member is notified on the out-of-browser notification channel.

#### FR-5: Admin recovery code [V0.1]

The operator can regain admin control of an existing data directory with the admin recovery code printed at bootstrap, at the host CLI only, without gaining any data access (DC-56).

**Consequences (testable):**
- The code is printed only on the host console at bootstrap and stored only as an Argon2id hash. `vilicus admin recover` (root) reads it at the prompt and prints a one-time admin enrollment token, like `vilicus member reenroll`; no web route accepts the code.
- Using the token enrolls a new admin passkey on the instance name and invalidates the previous admin credential; this is also how the instance admin re-enrolls after a rename or the loss of their passkey.
- No member or household data becomes readable through this path.
- Every adult is notified on the out-of-browser notification channel.

#### FR-6: Exposure setting [V0.1]

The operator sets the listening addresses at the host CLI only, with `vilicus instance listen <addresses>` (root), which rewrites the Gateway's socket unit; no web route changes exposure (DC-56). Private interfaces are loopback, RFC 1918 addresses, IPv6 unique local addresses (fc00::/7) and link-local addresses; FR-4 uses the same list. A non-private address is refused without `--acknowledge-public-exposure`; every change is audited, and every adult is notified on the out-of-browser notification channel.

### 4.3 Members and enrollment

**Description:** a household has one or more adult members from day one. A member's personal partition is readable only by that member and that member's assistant. The household partition is shared. Adults are added from the CLI with the authorization of an existing adult (DC-1), can be suspended at once from the CLI, by another adult or by themselves, and re-enroll a lost passkey from the CLI with their own passphrase (DC-43, DC-56). Realizes UJ-1, UJ-2.

#### FR-7: First member enrollment [V0.1]

The person running the wizard can enroll as the first member right after setting the instance name and creating the instance admin's passkey (FR-4).

**Consequences (testable):**
- Enrollment requires a passkey, a passphrase that passes the strength check (FR-110), and a recovery secret shown once and partially re-typed.
- Enrollment completes only with exactly one passkey, the confirmed recovery secret, and a redeemed test notification: the member configures an out-of-browser destination and redeems the token of a test notification sent to it (FR-56, DC-60). Further passkeys are added afterwards with a step-up (FR-10).
- The Core generates the member's data key and key pair (DC-40); the household key is created and wrapped for this member, and the member's public key is authenticated as architecture spine AD-36 defines.
- While no member exists, `vilicus member enroll-first` (root, with the admin recovery code typed at the prompt) prints an enrollment token, so an interrupted wizard never leaves the instance without a way to enroll its first member. The command is refused as soon as one member exists (DC-56).

#### FR-8: Adding an adult from the CLI [V0.1]

An existing adult can authorize a new adult with `vilicus member add`, which prints an enrollment token.

**Consequences (testable):**
- The command fails without the passphrase of an existing adult member, and the failure is audited.
- The enrollment token has 128 random bits, is single use and expires after 15 minutes.
- When the command runs, the Core derives from the enrollment token a key that will authenticate the new member's public key, and wraps it under a key derived from the authorizing adult's household key (DC-40; construction in architecture spine AD-36).
- At enrollment the Core generates the new member's data key and the key pair to which the household key will be wrapped, so a compromised Gateway cannot substitute the public key; the new member's personal partition is usable at once.
- Every other adult is notified, in the primary channel and on the out-of-browser notification channel (FR-56), and a delay starts. `[ASSUMPTION]` 24 hours. During the delay, any other adult can veto with a passkey step-up, or at the host CLI with `vilicus member veto` and their own passphrase; a veto revokes the new member and is audited. When the authorizing adult is the only adult, nobody else can veto; that adult is notified at each step and can cancel during the delay (D88).
- When the delay ends without a veto, the household key is wrapped to the new member's public key the next time an existing adult unlocks, only after the Core has verified that public key against the authentication created by the command; the new member is notified when it happens. A public key that fails the check is refused and every adult is alerted.
- The instance admin alone, without an adult passphrase, cannot complete any step of this flow.

#### FR-9: Removing a member [after V0.1]

An existing adult can remove another member.

**Consequences (testable):**
- Removal requires the passphrase of an adult other than the one removed, takes effect after a delay with notification to every adult, and can be vetoed by any adult other than the initiator and the removed member.
- Only one removal can be pending at a time; a second request is refused.
- When it takes effect, removal revokes the removed member's sessions, devices, channel bindings and unlock window. The household key is then rotated while the initiator is unlocked, with visible progress. Each household file is re-keyed in turn; the guarantee "not decryptable with the former keys" holds per file once that file is re-keyed.
- The removed member's personal partition is kept encrypted until an explicit purge.

#### FR-107: Suspending a member [V0.1]

An adult can suspend another member, and a member can suspend their own account, at once with `vilicus member suspend`, without rotating the household key (DC-43, DC-56). Suspension is the immediate response to a compromised account or a departing adult; removal (FR-9) comes later.

**Consequences (testable):**
- The command fails without the passphrase of an adult other than the suspended member, or the member's own passphrase for their own account, and the failure is audited.
- Suspension takes effect at once: it revokes the suspended member's web sessions, paired devices, channel bindings, unlock window and outstanding capability tokens, and blocks their login; their keys and data are kept. Scheduled tasks, delegation sub-keys and disclosure grants of the suspended member are suspended too, once those features exist.
- Every adult, the suspended member included, is notified in the primary channel and on the out-of-browser notification channel.
- Lifting a suspension, a self-suspension included, is an H action approved in the app by an adult other than the suspended member, with a step-up bound to that action (FR-10), followed by the delay and veto of FR-8, with every adult notified on the out-of-browser notification channel at the request and when it takes effect; it needs no passphrase (D87). Before the native app, a compromised Gateway can misrepresent this step-up; the delay, the veto and the alerts bound it (section 8.2).

#### FR-10: Authenticators [V0.1]

With a passkey step-up, a member can add or remove a passkey and change their passphrase.

**Consequences (testable):**
- A member always keeps at least one passkey; removing the last one is refused.
- Adding or removing a passkey and changing the passphrase raise an out-of-browser alert (FR-56).
- TOTP is accepted as a login fallback only and is refused for step-up, pairing and recovery (D33). If every supported browser fails the login half of E2, TOTP temporarily becomes the primary second factor (DC-72).
- Every passkey step-up, for any action that requires one, signs a challenge derived from the canonical hash of exactly one pending action that the Core created before the prompt; one assertion authorizes that action only, never a time window or a second action (DC-37). This stops an assertion from being spent on another action; it does not stop a compromised Gateway from showing one action while the Core receives another (section 8.2).

#### FR-108: Passkey re-enrollment [V0.1]

A member who lost every passkey but kept their passphrase, or whose passkeys stopped working after a rename or a restore, can enroll a new passkey with an enrollment token printed by `vilicus member reenroll` (DC-43), without the waiting period of a recovery.

**Consequences (testable):**
- The command fails without the target member's own passphrase, and the failure is audited.
- The enrollment token has 128 random bits, is single use and expires after 15 minutes; in the browser, the token plus the member's passphrase enroll a new passkey and pair that browser.
- The re-enrollment completes only after the member redeems the token of a test notification sent to their out-of-browser destination (FR-56, DC-60).
- Completing a re-enrollment ends the member's unlock window and revokes every other passkey, paired device, web session and channel binding of that member, except those the member explicitly keeps on the completion screen.
- The member is notified on every paired device and on the out-of-browser notification channel; the alert lists what was revoked.
- The instance admin re-enrolls with the admin recovery code (FR-5), not with this command.
- A member who lost both their passkeys and their passphrase uses recovery (FR-14).

### 4.4 Keys and unlock

**Description:** keys and wrapping follow `doc/key-management.md`. In V0.1 a passkey authenticates and the passphrase unlocks; unlocking with the passkey PRF is a later addition (E1, E2). A member chooses how long their partition stays unlocked, separately from the web session (DC-3, D90). Realizes UJ-3.

#### FR-11: Passphrase unlock [V0.1]

A member can unlock their partition with their passphrase after a passkey login.

**Consequences (testable):**
- Argon2id runs only after a successful first factor, under a global concurrency limit, with parameters stored in the wrapper header.
- Unlock completes within a target latency on the reference host (section 7). `[ASSUMPTION]` under 2 seconds, parameters set by E12. Unlock completes when keys are derived and the session is usable; each file then goes through re-key, migration, ingestion and outbox delivery in the background (architecture spine AD-54).
- A restart leaves every member locked; there is no automatic unlock.

#### FR-12: Unlock window [V0.1]

A member can choose, at unlock, how long their partition stays unlocked, and can lock it at any time. The window starts at unlock and ends at the unlock time plus the chosen duration, whatever the web sessions do (DC-68).

**Consequences (testable):**
- The window has a maximum. `[ASSUMPTION]` 24 hours, default 12 hours.
- The web session and the unlock window are distinct: logging out ends the web session, not the window, and a web session that outlives the window keeps working without partition access until the member unlocks again. Locking on demand, the kill switch, and a completed re-enrollment or recovery (FR-108, FR-14) end the window immediately.
- Extending a window sets a new end no later than now plus the maximum and requires the passphrase.
- Choosing, extending or ending a window is audited; the member sees the remaining time on every page.
- When the window ends, the member's keys are dropped from memory.

#### FR-57: Unlock from the host [V0.1]

A member can unlock their partition with `vilicus unlock` on the host, so that the passphrase never transits through the Gateway.

**Consequences (testable):**
- The CLI unlock sets an unlock window like FR-12 and is audited.

#### FR-13: Key hygiene [V0.1]

Key material is held in locked memory, zeroized on drop, and kept out of logs and core dumps.

**Consequences (testable):**
- E16 passes on the reference host.
- No key type is visible to module crates (checked at build time).

### 4.5 Recovery

**Description:** the printed recovery secret is the last resort; there is no admin reset (`doc/key-management.md` section 6). In V0.1 recovery starts on the host, waits, alerts the member on the out-of-browser notification channel, and finishes in the browser with an enrollment token (DC-6).

#### FR-14: Recovery with waiting period [V0.1]

A member who lost their passkeys and passphrase can recover with their recovery secret, started on the host with `vilicus member recover`. A member without host access depends on the operator to start it (section 8.2).

**Consequences (testable):**
- The recovery secret is typed at the CLI prompt; a wrong secret is rate limited and audited.
- Recovery starts a waiting period. `[ASSUMPTION]` 48 hours. The member and every other adult receive a content-free alert on the out-of-browser notification channel and in the primary channel; the host journal records it; the member can cancel from any authenticated session.
- Each recovery alert carries a one-time acknowledgement token of 128 random bits in an action link (DC-41). The member redeems it at the Core from a device they control; the token is single use and redemption is rate limited. Without a redeemed token, the waiting period runs on to a cap, and every adult receives a reminder each day. `[ASSUMPTION]` cap of 7 days. Another adult's acknowledgement never shortens it.
- The token protects against an attacker who cannot read the member's push channel; a compromised device of the member, or a compromised Gateway, can redeem it (section 8.2).
- After the period, the CLI prints an enrollment token; in the browser, with that token and the recovery secret, the member sets a new passphrase, enrolls a passkey, redeems a test notification (FR-56) and receives a new recovery secret; the old secret no longer works.
- Completing a recovery rotates the member's DEK, so a wrapper left in an older backup opens no data written after the recovery (DC-61).
- Completing a recovery ends the member's unlock window and revokes every other passkey, paired device, web session and channel binding of that member, except those the member explicitly keeps on the completion screen; the out-of-browser alert lists what was revoked.
- No web route can start a recovery.

### 4.6 Devices and sessions

**Description:** the web client is the primary channel. A browser becomes a paired device either during an enrollment or with a pairing code issued by an already-paired device or by the CLI; no QR scan is needed (DC-2). Realizes UJ-1, UJ-2.

#### FR-15: Pairing the enrollment browser [V0.1]

The browser used to complete an enrollment becomes a paired device of that member.

**Consequences (testable):**
- The browser holds a non-extractable device key; web sessions are bound to it, so a stolen session cookie alone is rejected (E22).
- When the device key is lost (browser data cleared), the browser is treated as unpaired, and the member pairs it again with FR-16.

#### FR-16: Pairing further browsers [V0.1]

A member can pair another browser with a short-lived code issued from an already-paired device or by `vilicus device pair`.

**Consequences (testable):**
- The code is single use, expires after 2 minutes, and allows 3 attempts.
- The code is bound to the new browser's key exchange by a password-authenticated key exchange, so a party that observes or relays network traffic cannot use it. A compromised Gateway, which serves the page's code, can still capture it (section 8.2).
- A newly paired browser cannot issue pairing codes for 24 hours.
- A code issued by `vilicus device pair` notifies the member on every paired device and on the out-of-browser notification channel.
- A member can list and remove their devices; removal revokes the device's sessions immediately.

#### FR-17: Web session hardening [V0.1]

Web sessions follow `doc/architecture.md` section 6 (cookie flags; a session that ends after 15 minutes without activity and lasts 12 hours at most, every request signed by the browser's device key, re-authentication by a passkey assertion, D90; Core-side revocation; CSP with Trusted Types, external content in a sandboxed separate origin).

### 4.7 Partitions, taint and segmentation

**Description:** every record lives in exactly one partition and carries `source` and `taint` (`doc/architecture.md` section 5.4). The assistant builds segmented answers: the household context plus the requesting member's context, never another member's personal partition. Data the other adult wrote in the household partition is readable by the assistant as quoted data, with its taint (DC-4).

#### FR-18: Mandatory provenance [V0.1]

Every record of every module carries `source` and `taint`; the module registry refuses a table without them.

#### FR-19: Partition isolation [V0.1]

A member's web session, and any AI session acting for that member, can read the member's personal partition and the household partition, and nothing else.

**Consequences (testable):**
- A capability token issued for member A fails on any read of member B's personal partition (invariant I5).
- No tool result returned to a token of member A contains a marker planted in member B's partition, across every registered tool.

#### FR-20: Effective taint per viewer [V0.1]

The Core computes the effective taint of each record for the requesting member (`trusted` < `member` < `external`). An AI session that reads `external` data, or `member` free text, becomes tainted; structured fields of `member` taint do not taint it (DC-36).

**Consequences (testable):**
- A write that a member makes, or explicitly approves (a light confirmation of an elevated request included), is stored `trusted` with that member as author and provenance to its inputs (DC-36); an approval authorizes the write and stores its structured fields `trusted`, but free text drafted in a tainted session keeps `external` whatever the approval, and editing the draft, by any amount, does not change that; only text the member writes in full in an empty field of the approval screen is stored `trusted` (DC-54). A field the member writes that contains 8 or more consecutive words of the assistant's draft is stored `external`; this is a verbatim test, not an edit ratio (DC-59). Before the native app, the approval screen is served by the Gateway, so this rule bounds approvals given out of fatigue, not a compromised Gateway (R16). `member` taint is computed at read time and never stored.
- Only content that came from outside the household (a plugin, an import, the web, reader output, model free text that no member approved) is stored `external`.

#### FR-58: Structured fields and free text [V0.1]

Every field of every module schema is declared either structured or free text (titles, item names, notes, descriptions), with a maximum length. A field is structured only if its value set is fixed at build time: a compiled enumeration, a bounded number, a date or an opaque UUIDv7 (DC-59). A run-time vocabulary (tags, categories, room, scene, mode or ingredient names) is free text, unless it is declared a reviewed vocabulary: an adult confirms each new label, at most 32 characters from a restricted alphabet, and only confirmed labels are accepted as structured values.

**Consequences (testable):**
- The module registry refuses a field without the declaration.
- On every write, the storage layer validates every structured field against its declaration: a closed type (a compiled enumeration, a bounded number, a date, an opaque UUIDv7, or a confirmed label of a reviewed vocabulary) and its maximum length; a value outside the declaration is refused, never truncated or coerced; a fuzz test drives every module write path with values outside their declaration (DC-53, DC-59).
- Fields with `member` taint, structured or free text, reach the planner as quoted data within their declared length; free text taints the AI session, structured fields do not (DC-36).
- Free-text fields with `external` taint never reach the planner as text; they reach it only as typed reader output (FR-69), or not at all. The exception is a member-approved assistant draft, stored `external` (DC-54), which reaches the planner as quoted data within its maximum length and taints the AI session (DC-59).

#### FR-67: Member context in household proposals [after V0.1]

The assistant can use the requesting member's context to propose household writes, which are executed as that member (DC-17).

**Consequences (testable):**
- A household write proposed from member context is executed with the member as author, after the member's confirmation when the AI session is tainted; its structured fields and any text the member wrote in full are stored `trusted`; free text the assistant drafted in a tainted session stays `external` (DC-36, DC-54).
- A household write from an AI session that has read free text of the member's personal partition is elevated (DC-59).
- No free-text field of the member's personal partition is copied into a household record by the assistant; a test plants a marker in a personal note and checks that no household record contains it.

#### FR-59: Promotion from the host [after V0.1]

A member can promote records they authored, or imported themselves, from `external` to `trusted` with a CLI command on the host (DC-12): by batch and by category, after reviewing a sample, for records whose fields are all structured; a record with a free-text field is promoted one by one, or retyped (DC-67).

**Consequences (testable):**
- No promotion is possible through the Gateway or the web client.
- Every promotion is audited with the batch, the category and the sample shown.

#### FR-21: Cross-partition writes [V0.1]

A write that moves or copies a record from a personal partition into the household partition, or into another member's partition, is not available before the native app exists: it is a tier 2 action and stays unregistered (FR-60). FR-67 is not such a write: it creates a household record from the member's request, without copying personal records.

### 4.8 Module platform

**Description:** modules are crates compiled into the binary. Each owns one database per partition, its own migrations, its record types with taint, its tool definitions with tier, its events, and its journal and undo handlers (`doc/architecture.md` section 12). V0.1 ships the platform and proves it with a reference module that is never packaged.

#### FR-22: Module registry [V0.1]

The Core registers modules at build time, with their schemas, tools, tiers and capability matrix rows.

**Consequences (testable):**
- The build fails if a module declares a tool without a capability matrix row, or a matrix row without a tool (invariants I13, I18).
- The reference module exercises every part of the contract (tables, tool, event, outbox, journal, undo, migration) in the test suite.

#### FR-23: Migrations [V0.1]

Migrations follow D21: declarative SQL, frozen hash, dedicated connection with an authorizer, forward only, a cold copy before each run, kept until the next verified backup, at most three per file. They cover module databases and Core files alike.

**Consequences (testable):**
- E11 passes: hostile migrations using `ATTACH`, `DETACH`, a non-allowlisted `PRAGMA` or extension loading are rejected.
- A database newer than the code is refused, and the instance admin is alerted.

#### FR-24: Event bus and outbox [V0.1]

Modules exchange typed events through the Core with stamped emitters and per-topic ACLs; cross-module consistency uses the outbox pattern (D20). In V0.1, events are delivered only within their source partition; cross-partition delivery and sealed inboxes ship with the home milestone (DC-62).

**Consequences (testable):**
- An event claiming an emitter other than its real one is rejected.
- After a crash, undelivered outbox events are delivered once the partition unlocks, and a consumer processing an event twice produces one effect: it records the event id in the transaction of its effect (architecture spine AD-26).
- An event that a consumer keeps failing goes to a dead letter and the instance admin is alerted; `vilicus events replay <dead-letter id>` (root) replays it, and consumers tolerate a gap in order after a dead letter (architecture spine AD-29).

#### FR-25: Connection surface for internal apps [V0.1]

The Core exposes typed interfaces for every internal app class: modules (in-process API), plugins and AI processes (one Unix socket each, closed-type protocol, MCP for AI processes), and clients (through the Gateway).

**Consequences (testable):**
- A plugin test double started by `vilicus-testbed` (FR-109) completes the protocol handshake (architecture spine AD-12), receives a capability token, calls one allowed tool, and is refused on a tool outside its manifest.
- An AI process test double does the same over MCP.
- The wire protocol choice (D19) is recorded before V0.1 ships: CBOR with closed types, and MCP for AI processes (architecture spine AD-12).
- Before V1, only plugins signed by the project's offline key run (D92). Until V1, first-party plugins ship inside the signed main package, version-locked to the Core, so this rule is met by the package signature, and V0.1 has no plugin install command (DC-57).
- Each plugin gets an encrypted state store in its own state directory, keyed from the instance key for a household-owned plugin and from the owning member's partition key for a member-owned one; a member-owned plugin runs only while its owner is unlocked (D95, DC-66).

### 4.9 Action pipeline and control

**Description:** every tool call from an AI process or a plugin passes through the ordered pipeline of `doc/architecture.md` section 9.2. V0.1 has no alignment controller (D16, E6 fallback): an elevated tier 1 call goes to a light confirmation in the primary channel (DC-5). In V0.1 these requirements are exercised by the reference module and an AI process test double.

#### FR-26: Pipeline enforcement [V0.1]

The Core validates schema, capability token, deterministic rules and taint for every tool call, in that order, and stops at the first failure.

**Consequences (testable):**
- A call with an unknown field is rejected, never repaired.
- A call outside its token's module, partition, action set or budget is rejected and audited.

#### FR-27: Capability tokens [V0.1]

The Core issues short-lived tokens bound to one task, one member, one module set, one partition set, one action set and one budget. Tokens are never a tool.

**Consequences (testable):**
- A token lives 10 minutes; its budget in V0.1 is a number of tool calls, 50 by default (`doc/capability-matrix.md` section 11, DC-68).
- A token is accepted only from the peer unit it was issued to (architecture spine AD-11).

#### FR-28: Elevated tier 1 queue [V0.1]

When a call is elevated, the member receives a pending request in the primary channel and can approve or refuse it with one tap.

**Consequences (testable):**
- A pending request expires after a set time and the task is told so. `[ASSUMPTION]` 24 hours.
- On approval, the Core re-verifies the state the request depended on and aborts if it changed.
- The approval is signed by the browser's device key over the canonical hash of the request, which binds it to that request and that device and prevents replay. The signature does not protect against a compromised Gateway, which serves the code that signs (section 8.2). If E22 fails, the approval is a step-up bound to the request hash instead (section 9, DC-62).
- A light confirmation approves one request, or a batch whose every line is shown and whose canonical hash covers all lines. No model-written justification is shown on an approval screen.
- Three consecutive refusals on the same task suspend it.
- A fixed list of low-risk record kinds is exempt from elevation, declared per module and reviewed with the module. An exempt record kind accepts only structured fields from an AI principal, so a free-text name or note written by the assistant is elevated (DC-59). `[ASSUMPTION]` For the meals module: adding to the shopping list, updating stock.
- The number of elevated requests per member per day is recorded (metric SM-4).

#### FR-60: No tier 2 action in V0.1 [V0.1]

Tier 2 actions are not registered at all in V0.1, rather than degraded to a weaker confirmation.

**Consequences (testable):**
- The registry build check fails if any V0.1 tool is tier 2.
- The actions removed by this rule are listed in the release notes: moving data from a personal partition to the household partition, promotion through the web, purge.

#### FR-61: Release-gate invariants for V0.1 [V0.1]

The subset of the invariants that V0.1 can exercise is the decided list of `doc/ai-safety.md` section 3.1, and each is an automated test that blocks the release.

**Consequences (testable):**
- Invariants that need tier 2 or a native app (I1 to I3 and I16) are listed as not applicable to V0.1, with the milestone where they become gates.
- The binding of each step-up to one action (DC-37), the stored-taint rule with its free-text exception (DC-36, DC-54), structured field validation (DC-53), the provider binding (DC-46) and the data type set of every record (DC-58, I43) are each covered by a release-gate test.
- I11 covers, in V0.1, tool calls per task, system notifications per member per hour and consecutive refusals (DC-68).
- Gates that need a module or a test double run against `vilicus-testbed`; every other gate runs against the shipped `.deb` (FR-109).

#### FR-29: Journal and undo [V0.1]

Every tier 1 write is journaled and can be undone by the member.

**Consequences (testable):**
- Journal entries are kept 30 days in personal and household partitions, and undo is available for that period; expired entries are deleted under `secure_delete` (DC-68). This retention concerns the undo journal only, not the audit log.
- Undoing a write restores the previous state of every record it changed and is itself journaled and audited.
- Undo is refused, with an explanation, when a later write changed the same record; the member can undo the later write first.

#### FR-30: Caps, digest and kill switch [V0.1]

Caps from `doc/capability-matrix.md` section 11 apply to token principals and to playbooks; a daily digest lists every assistant write and every playbook run; any authenticated human web session, the instance admin's included, can trigger the kill switch, and so can root at the host with `vilicus killswitch` (no passphrase, audited, every adult notified); a tainted AI session never can (DC-56).

**Consequences (testable):**
- A Core detector (repeated denials, for example) suspends only the offending task or AI session; it never triggers the kill switch or ends an unlock window, so an injected session cannot lock the whole household by provoking denials. `[ASSUMPTION]` The repeated-denial detector suspends a task after 5 denials.
- The kill switch revokes every outstanding token within 5 seconds on the reference host (invariant I12).
- The kill switch revokes every token and suspends rules, playbooks and scheduled tasks of assistant origin (architecture spine AD-8).
- Resuming requires a passkey step-up by an adult.

### 4.10 Audit log

**Description:** the audit writer keeps a tamper-evident hash chain in its own process with its own key (D22). Without tier 2 events and native devices, V0.1 anchors the chain through an optional remote sink (DC-7).

#### FR-31: Audit chain [V0.1]

Every action, tool call, refusal, CLI command and authentication event is appended to the chain without sensitive parameters in clear.

**Consequences (testable):**
- `vilicus audit verify` finds the earliest broken entry after a deliberate tampering.
- When the audit writer is down, tier 0 and tier 1 actions continue while their audit entries are held in a bounded spool. When the spool is full, every write except the emergency set of `doc/architecture.md` section 17 is refused with a retryable error until the writer returns. `[ASSUMPTION]` The spool holds 10 000 entries.
- `audit.db` is a SQLCipher file under a key derived from the audit key, opened only by the audit writer (DC-69).

#### FR-32: Anchoring without native devices [V0.1]

The instance admin can configure a remote sink that receives the current head hash on a fixed interval and at shutdown, whether or not anything was audited (architecture spine AD-17), so the sink does not learn when the household is active. Each delivery is an HTTPS POST of a CBOR record carrying the head hash, its sequence number, and the latest backup sequence number and manifest hash (DC-61). The head hash is also shown to members, for information only.

**Consequences (testable):**
- Against root, tampering is detected for entries older than the last head hash sent.
- A restore from backup compares the restored chain with the last head hash recorded by the remote sink and reports a mismatch (FR-53).
- Configuring or changing the remote sink notifies every adult on the out-of-browser notification channel.
- The README security claim is reworded to what V0.1 provides: tampering is detected against an attacker without root; against root, only when a remote sink is configured.

### 4.11 Assistant runtime

**Description:** Vilicus ships its own assistant, which replaces the owner's current one. Models are untrusted (`doc/ai-safety.md`). AI processes are sandboxed, speak MCP to the Core over their socket, and call providers through model connectors behind the egress proxy. The assistant answers in the primary channel with full disclosure and builds segmented answers (FR-19). Its memory lives in each partition behind the `MemoryStore` interface (D23).

#### FR-68: Model connector interface [V0.1]

The Core defines the model connector interface, the provider policy and the credential delivery, exercised by a test double connector.

**Consequences (testable):**
- The provider policy is evaluated per data type before any call (DC-15, DC-58). `vilicus-types` holds the closed set of data types: `health`, `journal`, `budget`, `meals`, `meal_plan`, `stock`, `shopping_list`, `presence`, `home_state`, `alarm_state`, `calendar`, `child`, `mail_raw`, `household_other`, `personal_other`. A remote provider configured by an adult is allowed by default for `meals`, `meal_plan`, `stock` and `shopping_list`; `health` (children's included), `journal` and `budget` go to the local model only and can never be widened to a remote provider; every other type follows the strictest rule that applies to it.
- Every record kind declares in the module registry the data types its fields may hold, and the build fails on a record kind without a declaration, like FR-58 (DC-46). Every record stores the set of data types it contains; a derived record's set is the union of its inputs' sets, computed by the Core like taint (DC-58).
- When a capability token is issued, the Core binds the AI session's provider from the data type sets the token can read; a tool result whose data type the bound provider may not receive is refused, never downgraded silently.
- From the meals module: children's dietary constraints never reach a remote provider: the Core applies them as a deterministic filter to the request before a remote meal-planning call and to its result after it, and a result that breaks a constraint is refused (DC-46).
- A call that the policy routes to a provider that is not configured fails closed with a notification; there is no silent fallback to another provider.
- Configuring a provider is an H action with a step-up, and each adult can veto it within a delay (`doc/capability-matrix.md` section 1). In V0.1 it is reachable through the Core API only, exercised against the test double connector; its screen ships with the meals milestone (DC-56).
- Two connector kinds share the interface: completion connectors, used by role processes, and agent connectors, which run an agent binary that sees only the Vilicus MCP tools of its token (the Claude subscription connector, FR-33). The V0.1 test double covers both.
- No model connector enables a provider-side capability: server-executed tools, remote MCP or account connectors, response or file storage on the provider. API connectors build request bodies from an allowlisted set of parameters, and a connector test asserts the exact body against a test double.

#### FR-33: Model connectors [after V0.1]

This requirement ships with the first milestone that uses a model. An adult can configure model connectors for OpenAI, Anthropic and Mistral, a generic connector for OpenAI-compatible endpoints, and a local model runtime, through the H action of FR-68; the instance admin role never decides where household data goes.

**Consequences (testable):**
- A provider outage queues the task with a timeout, then fails with a notification.
- The local model runtime is its own component (DC-49): a separate systemd unit, reached only over per-role Unix sockets, with no network, no cache shared across members or roles, and model files pinned by hash. It is treated as untrusted, like an AI process.
- The quarantined reader and the researcher never share a runtime process with the planner or the drafter. Within each group, one runtime instance serves every role and member, with cache reuse disabled and requests serialised; per-member instances run only where E25 shows the memory fits (DC-65).
- The local model runtime meets a latency and quality bar on the reference host for the data types routed to it, in that shape (E25).
- Claude subscription connector (DC-52): an adult can connect their own Claude plan. The connector runs the unmodified Claude Code binary in headless mode, in one systemd unit per connected member under its own user, and serves only that member's own sessions and runs. Sign-in completes through Anthropic's own flow, started at the host CLI with `vilicus ai connect claude <member>` (root and that member's passphrase, only after the provider configuration H action of FR-68 has passed its delay, DC-56); Vilicus never reads, copies, stores or backs up the credential. The plan's account identifier is shown at sign-in, recorded, and checked at every start. The connector is its own provider-policy entry and allows no data type by default: the member opts in data types of their personal partition, and each household-partition data type needs the agreement of every adult (DC-65). The binary's hash and tested version ship in the signed Vilicus release and are installed by the root CLI into a read-only path; one child process of the binary serves one session (architecture spine AD-53). Every built-in tool of the binary is disabled: it sees only the Vilicus MCP tools of its token, loads no settings, hooks or plugins from disk, keeps no session transcript, does not update itself, and reaches the network only through the egress proxy. Connecting is the H action of FR-68; when the plan's usage limit is reached, the call fails closed like an outage. E30 tests it.

#### FR-55: Egress proxy and provider credentials [V0.1]

AI processes and plugins reach the network only through the egress proxy, with an exact-hostname allowlist per process.

**Consequences (testable):**
- A direct outbound connection from a test double AI process or plugin fails; a connection to an allowlisted host through the proxy succeeds (E14).
- The egress proxy resolves every name itself, checks each resolved address at connect time and connects to that exact address; it refuses internal, loopback and the household's own addresses (architecture spine AD-16). The only exception is a private destination named for Core-originated traffic (FR-56).
- A provider API key is stored encrypted in Core metadata and sent by the Core, over the peer-verified socket, to the single AI process that uses it, which keeps it in memory only; no module and no other process can read it.

#### FR-69: Quarantined reader [after V0.1]

This requirement ships with the full conversation. A reader process turns `external` content into typed, bounded output that the planner may use (`doc/architecture.md` section 11.1).

**Consequences (testable):**
- The reader has no network and no write tool; its output is validated by the Core against a closed type and marked `external` with the bounded flag.

#### FR-34: Conversation in the primary channel [after V0.1]

A member can converse with the assistant in the app, with history kept in their personal partition. A read-only (tier 0) conversation comes first, with the meals module; writes come with the full conversation.

#### FR-35: Assistant memory per partition [after V0.1]

The assistant keeps episodes, entities and dated facts in the `MemoryStore` of the partition they belong to: personal facts in the member's partition, household facts in the household partition.

#### FR-36: Memory migration from the previous assistant [after V0.1]

A member can import the memory and logs of their previous assistant into Vilicus: personal material into their partition, shared material into the household partition.

**Consequences (testable):**
- Each member imports only their own personal material; household material is imported by any adult.
- Every imported record carries `source` set to the import and `external` taint (DC-8). Facts the member wrote and validated can then be promoted from the host (FR-59): by batch only for records whose fields are all structured, one by one or retyped for free text (DC-67); facts that came from the web, mail or another agent stay `external`.
- A knowledge graph extracted by a model is imported as `external` and is not used for planning; this loss is stated in the import screen.

#### FR-62: Assistant parity before switch-off [after V0.1]

Vilicus covers what the previous assistant does before the household switches it off: scheduled reminders, a daily briefing, separate profiles for each adult, a weekly review, voice input and output, and every capability and activatable module of section 4.18. The switch-off checklist lists each recurring task and each skill of the previous assistant with the Vilicus requirement that replaces it, including the restricted profile of an adult with a few skills (FR-99). Host administration, source code, version control and development tooling are not part of the switch-off criteria; they stay with a separate development assistant.

**Consequences (testable):**
- Voice input is transcribed locally by default; sending audio to a remote provider is an explicit per-member choice under the provider policy (FR-68).
- The switch-off criteria are written as a checklist before memory migration starts, and the previous assistant stays active until every item passes.

#### FR-64: Evaluation before conversation [after V0.1]

The evaluation suite and the prompt-injection regression corpus (`doc/ai-safety.md` section 4), including member-authored injection cases, run in CI before any conversation ships, against every connector in use.

**Consequences (testable):**
- Each corpus case names its Core-observable expected outcome: the set of tool calls allowed, the elevation or queue expected for each, and a seeded canary that must not appear in any tool argument, notification parameter, delivery body, channel message or provider request. A case fails the release when an effect outside that outcome occurs, whatever the model did.
- A second, scripted mode replays each case with a test double model that always obeys the injection.
- The share of cases in which the real model attempted the injected action is recorded per role, model, connector and prompt template; a rise above the recorded baseline blocks a model or template switch.

### 4.12 Channels

**Description:** the primary channel is the app. Secondary channels are optional plugins, outbound and inbound, bound to a member, at a lower assurance level (DC-9, revising D30). V0.1 ships the channel model, proven by a channel test double, and one out-of-browser notification transport. Realizes UJ-6.

#### FR-37: Channel model and binding [V0.1 partial]

The channel model ships in V0.1, tested against a channel test double; the binding screens ship with the messaging connectors (FR-38). A member can bind a sender identity on a secondary channel to their profile, from the primary channel, with a passkey step-up.

**Consequences (testable, against a channel test double in V0.1):**

*Binding*
- The binding is proven by a challenge: a code sent to the sender on the channel and typed in the primary channel. The sender identity declared by the plugin alone never creates a binding.
- Only one-to-one conversations are bound; messages from group conversations are dropped.

*Inbound*
- A message from an unbound sender is dropped, never processed, and counted in the audit log.
- A bound sender is trusted as the member; the message content is treated as untrusted text and taints the AI session.
- A bound channel can trigger tier 0 and tier 1 actions only, never tier 2 or H actions, never pairing, recovery or binding changes.
- What a member sends is theirs to send: a bound member may write any of their own data types through the channel (a meal entry, for example), and it is processed under the provider policy (FR-68).

*Outbound*
- What Vilicus sends is limited: each channel has a ceiling, an allowlist of the data types Vilicus may send on it (DC-48, DC-58), applied as input gating when a token is issued for any session whose output may reach that channel. It never includes `budget`, `mail_raw` or `health`. `presence`, `home_state`, `alarm_state`, `calendar` and `child` are excluded by default; an adult can add one only with an H action, after a warning. `[ASSUMPTION]` The default ceiling is `meals`, `meal_plan`, `shopping_list` and confirmations of the member's own journal entries.
- Replies come from templates or stay within the ceiling, pass an outbound content check, and point to the app for details.

#### FR-56: Out-of-browser notification channel [V0.1]

Each member configures at least one notification channel that does not depend on an open browser, for security alerts (DC-14, DC-60).

**Consequences (testable):**
- In V0.1 the transport is a push webhook to a UnifiedPush server of the ntfy type. The default is a self-hosted server, reached through a private destination (next consequence); a public server is allowed when the household chooses it, and it sees only delivery timing metadata (DC-73). The payload is content-free either way (static templates, no title, sender, amount or model text). On a public server, the topic uses an access token or a random name of at least 128 bits.
- A self-hosted server on a private address is reached through a private destination: Core-originated traffic (push webhook, backup upload, remote audit sink, heartbeat) may reach a private host and port that the instance admin names through an H action with step-up, alerted to every adult; the egress proxy allows it to the Core and the backup caller only, never to an AI process or a plugin (DC-60).
- An enrollment or re-enrollment completes only after the member redeems the token of a test notification sent to their destination (FR-7, FR-108); the instance admin's destination is confirmed the same way at bootstrap (FR-4).
- While an adult has had no working destination for 24 hours, every page shows a blocking banner, and the waits of FR-8 and FR-14 run to their maximum.
- Security alerts are sent on it: recovery, member added, member suspended, instance renamed, exposure changed, certificate about to expire, and every event that adds a way in or widens access, whichever client requested it: a passkey added or removed; a passphrase changed; a browser or native device paired, from any source; a household display paired; a WireGuard peer added; a sender identity bound; a data type added to a channel ceiling; a tool policy widened; a delegation sub-key or disclosure grant created; a provider configured; a suspension lifted; an enrollment, re-enrollment or recovery completed. Each alert states how many passkeys and paired devices the member now has. A recovery alert carries the one-time acknowledgement token of FR-14.
- The instance admin configures their own notification destination, which receives the alerts addressed to the instance admin (failed migrations, a database newer than the code, backups, dead letters, crashing plugins).
- Delivery failures are visible in the primary channel and in `vilicus status`.

#### FR-63: Waiting-task notifications [after V0.1]

A member whose assistant task waits for an unlock receives a content-free notification (`doc/architecture.md` section 8.1).

#### FR-38: Messaging connectors and more transports [after V0.1]

Connectors for Signal, Telegram, WhatsApp and Discord run as sandboxed plugins behind the egress proxy, each in its own process. SMTP submission to an external relay (ports 587 or 465, never a local mail server or port 25) is a notification transport that ships earlier, with the home milestone, for home alerts (FR-82). `[ASSUMPTION]` Signal first, because its sender identity is cryptographic.

### 4.13 Web client [V0.1 partial]

**Description:** the web client is the primary channel. V0.1 ships the account and administration screens; the installable phone experience comes with the meals module. Realizes UJ-1, UJ-2, UJ-3.

#### FR-50: Account and administration screens [V0.1]

The web client provides the member and instance admin screens of V0.1. Every V0.1 action is reachable on exactly the surfaces listed below; an action not listed is not reachable in V0.1 (DC-56).

| Action | Actor | Surface | Confirmation |
|--------|-------|---------|--------------|
| Complete the bootstrap wizard (FR-4) | holder of the bootstrap token | web wizard, then instance admin web | bootstrap token; test notification token for the admin destination |
| Issue a new bootstrap token (FR-4) | operator | root CLI `vilicus bootstrap token` | none |
| Redeem the admin recovery code (FR-5) | operator | root CLI `vilicus admin recover`, then instance admin web with the printed token | admin recovery code |
| Enroll the first member after an interrupted wizard (FR-7) | operator | root CLI `vilicus member enroll-first`, then member web | admin recovery code |
| Complete an enrollment or re-enrollment (FR-7, FR-108) | member | member web | enrollment token, passphrase, redeemed test notification |
| Log in, unlock, choose, extend or end the unlock window (FR-11, FR-12) | member | member web; unlock also root CLI `vilicus unlock` (FR-57) | passkey, passphrase; extending needs the passphrase |
| Add an adult (FR-8) | adult | root CLI `vilicus member add` | that adult's passphrase |
| Veto a pending member (FR-8) | another adult | member web, or root CLI `vilicus member veto` | step-up, or own passphrase |
| Suspend a member (FR-107) | another adult, or the member for their own account | root CLI `vilicus member suspend` | passphrase |
| Lift a suspension (FR-107) | an adult other than the suspended member | member web | H: step-up bound to the action, then the delay and veto of FR-8 (D87) |
| Re-enroll a passkey (FR-108) | member | root CLI `vilicus member reenroll`, then member web | own passphrase |
| Recover (FR-14) | member | root CLI `vilicus member recover`, then member web | recovery secret, acknowledgement token or the cap |
| Cancel a pending recovery (FR-14) | the member concerned | member web | authenticated session |
| Cancel a pending addition as the only adult (FR-8, D88) | the authorizing adult, when no other adult exists | member web | step-up bound to the cancellation |
| Pair a browser (FR-16) | member | member web with a code from a paired device, or root CLI `vilicus device pair` | code; own passphrase at the CLI |
| List and remove devices (FR-16) | member | member web | authenticated session |
| Add or remove a passkey, change the passphrase (FR-10) | member | member web | step-up |
| Enrol a TOTP factor (FR-10) | none in V0.1 | not reachable, except under the E2 login fallback (DC-72), which adds its surface | n/a |
| Configure the own out-of-browser destination (FR-56) | member | member web | step-up, then test notification token |
| Configure the instance admin's destination (FR-56) | instance admin | instance admin web | step-up, then test notification token |
| Approve or refuse an elevated request (FR-28) | member | member web | light confirmation |
| Undo a tier 1 write, an undo included (FR-29) | member | member web, offered from the digest | authenticated session |
| Read the digest and the audit view (FR-30, FR-31) | member | member web | none |
| Trigger the kill switch (FR-30) | any human web session; root | member web, instance admin web, root CLI `vilicus killswitch` | none |
| Resume after the kill switch (FR-30) | adult | member web | step-up |
| Change the listening addresses or exposure (FR-6) | operator | root CLI `vilicus instance listen` | `--acknowledge-public-exposure` for a non-private address |
| Rename the instance (FR-66) | operator | root CLI `vilicus instance rename` | none |
| Reload the instance certificate (FR-65) | operator | the external renewal tool's hook, `systemctl reload-or-restart vilicus-gateway` (root) | none |
| Acknowledge an upgrade (FR-54) | instance admin | instance admin web | step-up |
| Check or verify an upgrade (FR-54) | operator | root CLI `vilicus upgrade check`, `vilicus upgrade verify` | none |
| Set the backup schedule, certificate alert lead time or audit spool size (section 12) | operator | `vilicus.toml` (root) | none |
| Set the backup target (FR-53) | operator | root CLI `vilicus backup target set` | delay and veto of FR-8, every adult alerted |
| Veto a pending backup target change (FR-53) | another adult | member web; no CLI veto for target changes in V0.1 | step-up bound to that veto |
| Change the backup secret (FR-53) | none in V0.1 | not reachable; a root CLI command comes with its own row when rotation is wanted | n/a |
| Back up, verify, restore (FR-53) | operator | root CLI | backup secret to restore |
| Configure the remote audit sink (FR-32) | instance admin | instance admin web | step-up, every adult notified |
| Name a private destination for Core traffic (FR-56) | instance admin | instance admin web | H: step-up, every adult alerted |
| Configure a model provider (FR-68) | adult | Core API only, exercised by the test double; screen with the meals milestone | H: step-up, delay, adult veto |
| Acknowledge unencrypted swap (section 7) | operator | root CLI `vilicus host acknowledge-swap` | none |
| Replay a dead letter (FR-24) | operator | root CLI `vilicus events replay` | none |
| Acknowledge a wall-clock jump that suspended pending delays (D59) | adult | member web | step-up bound to the acknowledgement, every adult notified |
| Read the member list with locked or suspended state | instance admin | instance admin web | none |
| Check status and the audit chain (FR-3, FR-31) | operator | root CLI `vilicus status`, `vilicus audit verify` | none |
| Acknowledge the security state after a restore (FR-53) | each adult | member web | authenticated session |

**Consequences (testable):**
- Screens receive changes over one server-sent event stream per web session that carries only change notices, and re-read through signed requests; polling every 30 seconds is the fallback (architecture spine AD-56).
- Supported browsers in V0.1 are the current and previous releases of Chrome and Firefox, on desktop and Android; Safari is best effort, and adults on iOS are not a supported V0.1 target (DC-62).

#### FR-51: Installable phone client [after V0.1]

The web client is installable as a PWA and usable on a phone; the shopping list works offline and syncs when back online. Offline changes merge without a prompt: additions are united, a checked item stays checked, and edits to the same item take the last writer. `[ASSUMPTION]` offline mode applies to the shopping list only.

#### FR-52: Framework constraints [V0.1]

The framework (D26) supports strict CSP with nonces and Trusted Types, and the sandboxed separate-origin rendering of external content.

#### FR-110: Languages [V0.1]

The web client and the notification templates exist in French and English (DC-68).

**Consequences (testable):**
- The language follows a member setting, defaulting to the browser's.
- The CLI is in English only.
- The recovery secret is grouped characters with a checksum, language neutral.
- The passphrase strength check uses French and English dictionaries.

### 4.14 Meals and groceries module [after V0.1]

**Description:** recipes, meal plan, stock and shopping list in the household partition. Before the native app, recipes live in the household partition only; a member's private recipe collection would need a tier 2 copy to be shared. Realizes UJ-4. Detailed FRs are written when the milestone is planned; the capabilities below combine the table stakes of comparable self-hosted products with the household's own needs.

- FR-39: recipes with structured ingredients (quantity, unit, food, note), unit conversion, scaling by servings, tags, images and full-text search; ingredient parsing and units work in French; every recipe can be exported in an open format.
- FR-40: recipe import from a URL (schema.org Recipe JSON-LD, with paste fallback) and from the export formats of the tools households actually use. The URL is supplied by a `Member` principal, or is text the member typed in the current turn, verbatim, never composed or edited by a model; it is fetched by a Core stage through the egress proxy, in a named Core egress mode that may reach any public host within per-host budgets, with protection against requests to internal addresses. A deterministic parser, never a model, runs in a sandboxed process with no network and no keys and produces bounded fields (normalized ingredient, quantity, unit, duration, servings) and is fuzzed in CI; unknown ingredients are matched to a canonical ingredient table by a human. Steps and descriptions stay `external` free text and never reach the planner (DC-10). `[ASSUMPTION]` Mealie, Tandoor and Paprika exports; whether the household's current recipe app offers an export or JSON-LD is unverified (open question 9).
- FR-41: meal plan per day and meal type, shared by the household, with household fields for who cooks, who is away and meals eaten out, and private per-member notes in each member's partition.
- FR-70: profiles of the household's children as subjects of household data (dietary constraints, portion factor), used by planning and scaling; health details in them follow the local-only policy, and dietary constraints never reach remote meal planning; the Core applies them as the deterministic filter of FR-68 (DC-46).
- FR-42: stock with quantities, locations, best-before dates and minimum levels, including leftovers from a cooked meal that feed a later meal; stock upkeep is low effort (checking items off the list adds them).
- FR-43: shopping list generated from the plan minus stock plus items below minimum, merged duplicates, grouped by aisle, checked off in real time by both members, usable on a phone as an installable PWA. With no stock data, the list is the plan's full needs.
- FR-44: every module action listed in the capability matrix with tier and taint behavior before any code is written, including the rows missing today (delete, check off, purge).

### 4.15 Personal journal [after V0.1]

**Description:** each member keeps a private journal in their personal partition: meals eaten (linked to household recipes and portions), estimated calories and macros, habit counters with reminders and a weekly review. Realizes UJ-6.

- FR-45: a member can log a meal by reference to a household recipe and portion, or by free text; nutrition estimates are labeled as estimates. The journal is strictly per member: it is never aggregated into the household partition or shown to another member.
- FR-46: a member can define habit counters with scheduled reminders; reminders are content-free on secondary channels.

### 4.16 Store connector [after V0.1]

**Description:** this feature ships after the meals module. A sandboxed store connector prepares a cart in the member's own store account from the shopping list. Payment and ordering always stay with the human on the store's website (DC-11, resolving D25's open cart tier). Realizes UJ-5.

- FR-47: a member can ask for a cart to be prepared from the current shopping list; the connector reports added, substituted and missing items, and can empty the cart it filled.
- FR-48: Vilicus never places an order and never handles payment. The store connector's manifest contains no ordering or payment operation, checked at build; this check states intent, it does not prove what the plugin sends. Because the egress proxy filters by host and not by path, this is also a policy: the household is told to keep no stored payment method on the store account, and the connector session holds the full authority of that account (section 8.2).
- FR-49: an official store API is used whenever one exists (E18); otherwise the connector is unofficial, opt-in, and carries the README disclaimer.

### 4.17 Home automation [after V0.1]

**Description:** the home automation module replaces the household's current home automation software, and is the first module shipped after V0.1. It runs the house with every member locked: devices, rules, modes and current state live in the home partition (DC-20), and history written while every member is locked waits in the household sealed inbox until an adult unlocks. Device adapters connect each technology as sandboxed plugins; the Zigbee coordinator moves to Vilicus on a cutover day (FR-83). Rules are deterministic and run in the Core under the rule principal (DC-25). They only move safety-relevant devices toward the safe state; letting someone in or switching protection off is not offered by Vilicus before the native app, then is tier 2 on it, and is never done by the assistant (DC-35). Realizes UJ-7, UJ-8, UJ-9. The first home milestone targets parity with the current software; detailed consequences are written when it is planned.

- FR-71: the home partition holds devices, rooms, groups, rules, scenes, modes, current state and a bounded rolling window of recent events that rules need; it is encrypted by the instance key (sealed to the TPM when the host has one) and is usable with every member locked. Older events and sensitive history (household presence, door, window and alarm events) are written to the household sealed inbox and moved into the household partition at the next adult unlock (DC-20). The rule journal in the home partition has a short retention, and the audit log records rule runs in aggregated form, so neither can be used to rebuild a detailed occupancy timeline. Adapter state reports are throttled per device, and energy readings are aggregated (for example per 5 minutes) before they are written. `[ASSUMPTION]` Rolling window and journal retention of 24 hours.
- FR-72: a device model owned by Vilicus, independent of any radio or vendor, so an adapter can be replaced without touching rules or screens: devices with typed capabilities and state, battery level, availability (last seen, stale after a threshold), rooms and floors, groups, virtual devices computed from other devices (per-room aggregates, battery summaries), attributes such as a facade's orientation or the device a plug powers, and energy metering. Locks, alarms, cameras, gates, garage doors and covers of unknown kind are safety-relevant from discovery and accept only safe-direction commands until an adult confirms their class (DC-38). An unclassified `switch`, `plug` or relay output accepts no command from a household display, the assistant or a rule until an adult classifies it; a `momentary` capability is safety-relevant from discovery, never tier 1, and follows the unlock and open rows when it drives an opener (DC-64). An adapter cannot change the class of a confirmed device: a report that tries is refused and alerted. Reclassifying a device, in either direction, is an H action.
- FR-73: device adapters are plugins; granting one a USB device, a Unix socket path, a shared private namespace with a named managed daemon, or a private address range with ports is an H action that names it, and the ports are enforced per unit; no unit receives a loopback address grant (DC-21, DC-70). `[ASSUMPTION]` An adapter that drives a physical security device drives no other device family. The secrets of an adapter that drives physical security devices are sealed to the host's TPM: a host without a TPM cannot run such an adapter, and these secrets are not in backups and are entered again after a restore on another host (DC-44). Secrets that let a device open the house never transit the Gateway: they are entered only at the host CLI as systemd credentials sealed to PCR 7 plus a signed PCR 11 policy, so only a host that runs unified kernel images can drive physical security devices (DC-63, E31). The grant screen states it.
- FR-74: Zigbee through the coordinator's local API and events, the coordinator moving from the current software to Vilicus on a cutover day (FR-83); whether the current network and device pairings survive the move is tested by E27. The coordinator daemon receives its network key as a systemd credential, with its own write-back of the key and its own backups disabled; where a daemon cannot, the documentation states that the radio key sits in clear in its configuration (DC-63). `[ASSUMPTION]` A native stack or a different coordinator is a later replacement behind FR-72.
- FR-75: adapters for every device family of the household's current software, listed in a parity inventory that stays private to the household. Typical families are Zigbee sensors, contacts, buttons, lights and plugs, heating through a vendor cloud, covers through a local gateway, energy production and consumption, an electricity meter, robot vacuums, irrigation, cameras, and the household display itself as a device. A family with no device in use is outside the parity scope. Adapters for physical security devices follow FR-72, FR-73 and FR-80: until the native app, parity for unlocking, disarming and opening is met by the device vendor's app or a physical gesture, not by Vilicus (DC-35).
- FR-76: presence detected from each adult's phone on the local network; a router admin credential used for it is a secret that opens the house (DC-63), and a read-only router account is preferred. Rules and the household display see household presence only (someone home or nobody). Each adult's individual presence and its history are visible to the other adult only if the adult concerned opts in; individual history is written to that adult's personal partition.
- FR-77: context sources usable by rules and displays, fetched through the egress proxy: public and school holidays (giving a day type), season, sun position, moon phase, weather, weather alerts, air quality, pollen, road travel times and train timetables for places configured in the home partition.
- FR-78: home rules with triggers (device state change, schedule in household local time across daylight saving changes, repetition within a time window, sun position, mode change, household presence, context source), conditions and actions on devices, groups and scenes. A person's manual change wins over rules for a configurable duration, except that it never blocks a safe-direction action on a safety-relevant device, and a manual change away from the safe state on such a device raises a home alert; while a smoke or water alert is active, no rule sends a lock, close or cut command (FR-80, D91); any rule can be suspended for a set time, and one control pauses every automation. Each rule can be run dry with a trace, a rule triggered by its own actions is stopped, and timers survive restarts. An adult writes rules in a rule editor. The assistant may propose a rule: at validation, the rule is re-created from its structured fields, keeps its origin, and every rule of assistant origin is suspended by the kill switch. A rule that acts on a safety-relevant device is created or changed only by an H action.
- FR-79: modes (home, away, night, vacation, alarm armed, and household-defined ones) changed by rules or by an adult, and by the household display only for modes that do not concern a safety-relevant device. A mode concerns a safety-relevant device when any rule it triggers or conditions acts on one.
- FR-80: device action classes (DC-23). Reading state is tier 0. Actions undone by restoring the previous state (lights, shutters, heating setpoint within a set range, vacuum start and stop, irrigation within a capped duration, plugs that power nothing safety-relevant) are tier 1, under a named exception class of invariant I13. On a safety-relevant device, rules and tier 1 callers only move toward the safe state: lock, arm, close, camera on; the camera goes off only after the alarm is disarmed. Unlocking, disarming, opening, and cutting power to the infrastructure (the server, a radio coordinator, a gateway) are not offered by Vilicus at all before the native app: no rule, display, assistant, playbook or web step-up can do them, and the household uses the device vendor's app or a physical gesture (DC-35). With the native app they become tier 2 actions confirmed on it. Vilicus arms, locks, closes and alerts. When household presence turns to someone home while armed, Vilicus notifies the adults and proposes nothing it cannot do. The assistant never performs these actions. The safe direction protects against intrusion, not against fire, water or frost, so life safety comes first (D91): while a smoke or water alert is active, lock, close and cut commands are suspended, shutters may open, and every adult is alerted; Vilicus still unlocks and disarms nothing. A heating valve is never closed below a floor temperature. A closing command on a gate or a garage door relies on the device's own obstacle detection and is refused when the device reports none.
- FR-81: the household display: a paired device without a member, enrolled by an adult through an H action, acting under the display principal (DC-25). It shows home state, household presence and context sources, and drives tier 1 home actions on devices that are not safety-relevant. It never shows member or household data outside the home domain and never offers an H action.
- FR-82: home alerts form their own notification class, with its own rate budget, separate from other notifications, and one static template per alert kind, shown in the app: intrusion while armed, smoke, water, device offline, low battery, adapter down; the push payload names no kind (architecture spine AD-32). They are sent on each adult's out-of-browser notification channels, by push and by mail through an external SMTP relay (port 587 or 465), and shown in the app with detail. The Core emits a regular heartbeat so that an outside monitor notices when it stops. The kill switch never suspends the transports of home alerts. `[ASSUMPTION]` The outside monitor is the push server or a free monitoring service chosen by the household.
- FR-83: a parity checklist (device families, the behaviors of the automations in use, alerts) is written before the home milestone starts. One Zigbee coordinator cannot serve two systems, so Zigbee is a direct cutover (DC-45): the current software keeps the coordinator until cutover day, then Vilicus takes it. The checklist runs in parallel for the other device families, and on Zigbee after the cutover, with a written rollback plan to the current software. The current software is switched off only when every item passes.
- FR-84: home failure behavior (DC-26): a package upgrade migrates a copy of the home partition at the first start of the new version, without waiting for the acknowledgement of FR-54, so that an upgrade does not stop the house when its migration succeeds. If that migration fails, the previous file is kept, the home module stops for that partition, and the instance admin and every adult are alerted (DC-50); `vilicus upgrade check` shows the pending home migration before the operator upgrades. Pausing automations (and, once the native app offers them, disarming and unlocking) joins the set of actions that proceed while the audit writer is down; on a wall-clock jump, schedule triggers continue on the monotonic clock and actions on safety-relevant devices wait for a human acknowledgement; an unreachable cloud adapter marks its devices stale, and the rules that depend on them fail visibly.
- FR-85: every home action and device class is listed in the capability matrix with tier, class and taint behavior before code, like FR-44.
- FR-86: acting on the house away from home goes through a WireGuard endpoint managed by Vilicus, reached through one UDP port forwarded on the household's router (DC-27). Adding a phone or computer as a peer is an H action tied to that device's pairing. Before the native app, the device uses the official WireGuard client with a configuration shown once as a QR code and routing only the Vilicus host; by default the client generates its key pair, and a Vilicus-generated private key is a fallback whose screen says that the page's server sees the key; so the browser and the installed web client reach Vilicus through it; the Android app embeds the tunnel. TLS stays end to end, and the instance name is the same inside and outside the house. A reverse proxy or an access proxy remains a documented alternative for households that already run one (E28).

### 4.18 Assistant parity and activatable modules [after V0.1]

**Description:** the previous assistant is general purpose: it is reached by messaging, by real-time voice and by scheduled tasks, keeps a memory per adult and per household, and gains skills by adding files. Before the household switches it off, Vilicus covers everything listed in this section (FR-62), through Core capabilities (scheduler, researcher, playbooks, tool policy, supervision) and through modules a household activates when it needs them. Host administration, source code, version control and development tooling are not household work: they stay with a separate development assistant and are outside the switch-off criteria. The detailed consequences of each item are written when its milestone is planned.

- FR-87: a scheduler in the Core runs assistant tasks at a time or on an event (briefing, reports, reminders, maintenance), on behalf of one member, with one capability token per run, caps per task, times that can differ on workdays, weekends, and holidays (day type of FR-77) and follow the household time zone across daylight saving changes, audit, and suspension by the kill switch. A task is a structured definition (trigger, tools, caps, delivery), never free text. A task has a `kind` from a closed set, each with a prompt template shipped with Vilicus, and an optional instruction text, `trusted` only when the member typed it in full; text drafted by the assistant in a tainted session stays `external` after validation, and a run starts tainted when any free-text field of its definition is `external`. A member creates their own tasks; the assistant may propose one, which keeps its origin and taint, is validated only by the member it runs for, and is suspended by the kill switch. After a restart or a missed time, a task runs at most once late, within a staleness limit (`[ASSUMPTION]` 12 hours), or is cancelled and recorded. Results land in the primary channel; a secondary channel receives only a template ("briefing ready") or content within its ceiling after the outbound check (D42). A task that reads external content goes through the quarantined reader, so such tasks wait until the quarantined reader ships (section 6.2).
- FR-88: a member can opt in, per scheduled task, to a delegation sub-key so the task runs on time while the member is locked (DC-28). Creating one is an H action with a step-up; a sub-key on a household-partition module also follows the delay and adult veto of rights changes. The sub-key is scoped to one module and one partition, sealed by the instance key, listed in the member's settings, revocable at any time, suspended when the member is suspended (FR-107), and destroyed when the member is removed. The Core keeps a run descriptor for each delegated task: the fire time and staleness limit in clear, visible to whoever holds the instance key, and the structured definition sealed under the sub-key (DC-66). A run that holds a sub-key reads the delegated module file and writes only through the owner's sealed inbox, so its output (a briefing, for example) is stored `external` and shown as such; revoking a sub-key marks the file for re-keying at the owner's next unlock, and the sub-key copy in older backups stays usable until then (D94). Every data type may be delegated: the household accepts that delegated data is readable by whoever controls the host or holds a backup and its backup secret (section 8.2). Without a sub-key, a task waits for the member's next unlock within its staleness limit, and the member gets a content-free notification.
- FR-89: quick check-ins extend FR-45 and FR-46: a scheduled question, at times that can differ on workdays and weekends, accepts a one-word or one-number reply. Because a secondary channel never says what is asked, each reminder carries a short opaque reference the member learns in the app; a reply that cannot be matched to a single pending reminder is refused and asked again. Retroactive entries (yesterday's meals logged this morning), rolling averages, a weekly review table, and an export (FR-106) complete the feature. Health data uses the local model only; a secondary channel only ever replies that the entry is logged, and the binding screen states that replies transit the messaging provider.
- FR-90: a researcher AI role reads untrusted web content to answer an open question (comparisons, regulations, travel, procedures) and writes a report with its sources (DC-29). It receives only the question as the member typed it, never partition data, memory or conversation context, and the screen says the question leaves the instance. Its first query goes through a Core template stage; afterwards it can only ask to follow a link that appears verbatim in a page already fetched for that task: the fetcher extracts each page's absolute links with a minimal URL resolver and the Core checks a requested URL by exact match against that list. Every request is made by a trusted fetcher that runs no model and no page code, after the Core checks the URL: GET only, the link verbatim, no query string composed by the model, a capped URL length, no cookies, and internal addresses blocked (DC-39). Researcher egress belongs to the fetcher; the researcher has no network of its own. The fetcher returns bytes, and hostile pages are parsed inside the sandboxed researcher, never in the Core. A browser renderer, if kept, has no network and only renders bytes the fetcher returned. Requests count against per-host budgets (FR-105). The model behind it follows the provider policy, with the question classified at the strictest rule unless the member picks a data type. It has no write tool; its report is `external`, shown to the human, and never handed to the planner as text. Several researcher processes may run in parallel, each with its own token and budget.
- FR-91: a mail module reads, searches, and classifies mail, alerts on important messages and forgotten replies, and drafts and sends replies, for each member's own accounts only, never across members (D24). Reading goes through the quarantined reader and drafting through the drafter. Sending to a third party is tier 2, confirmed on the native app; sending a message to the member's own address is own-account delivery (DC-33), which follows the provider policy by data type and passes the outbound content check: local-only data types are never delivered to an account the household does not host (DC-47). A delivery body is plain text, or HTML rendered by the Core from a template that references no remote resource; model-composed text contains no URL except those that appear verbatim in the source records it cites; the delivery tool takes no destination argument, and the Core resolves the destination from the member's account registered by an H action. Support for accounts under a company policy is best effort.
- FR-92: a member can share with another adult a minimal value derived from their own personal data (for example a status and a practical hint), never the source data, through a disclosure grant (DC-30). The grant is an H action that names the fields, the derivation, the frequency, the recipient and the duration. The Core computes the value deterministically as closed types only, keeps its data type (a value derived from health data stays health data, local model only), stores it with the taint of its inputs and the granting member as author, so the recipient's assistant reads it as `member` taint (DC-59), then seals it into the recipient's sealed inbox with a household-key MAC bound to the grant, its owner, its recipient and a sequence number. The granting member can revoke it at any time; every computation is audited; the value never appears on a secondary channel.
- FR-93: children's routines and episodes extend FR-70: routines with reminders, a journal of episodes (what triggered them, what helped), and a periodic report for professionals who follow a child, generated as a document a member downloads (FR-106). This data lives in the household partition, follows the local-only health policy, uses a fixed set of fields defined with the module, is kept for a limited period (`[ASSUMPTION]` 12 months, then deleted), is excluded from memory consolidation, memory migration and digests, never appears on a secondary channel, and is never sent outside without a tier 2 action.
- FR-94: real-time voice conversation extends FR-62: end-of-turn detection, local speech recognition and synthesis, interruption, varied acknowledgements while an answer takes time, a car mode with audio that keeps playing in the background, and spoken delegation of tasks. Audio is transcribed locally only, because its data type is unknown before transcription. The client releases the microphone while Vilicus speaks, opens it without echo processing in car mode so a car's audio stays on its media stream, plays a test chime before opening the microphone, and offers an audio diagnostic (E29). A spoken "yes" approves an elevated tier 1 request that carries no I13 exception class, and nothing else: never a cart, an own-account delivery or a restorable physical action, never a rule, a scheduled task, a playbook, an H action or tier 2 (DC-34). Before a spoken yes, Vilicus reads the request back from a fixed template filled only with the request's structured fields, never from model text, and the yes approves only the request read back, bound to its hash (DC-55). The yes is recognized by the Core's speech stage on the local transcript, never by an AI process, within a confirmation window of a few seconds after the read-back of exactly one request; a voice conversation approves only requests it created. A transcribed turn carries `spoken` provenance: it does not taint the session, but a memory fact drawn from it is stored `external` until the member confirms it in the app, and voice-session writes are listed separately in the digest (DC-67).
- FR-95: memory upkeep extends FR-35: provenance recorded per conversation turn, so a fact drawn only from the member's own words stays usable for planning while facts of external origin stay quarantined; nightly consolidation of conversations into dated facts and weekly consolidation into stable knowledge, run only inside the owner's unlock window (DC-66), each model context built from inputs of one label, with the provenance of a consolidated fact computed by the Core, never stated by the model; automatic retrieval returns `trusted` facts only, and an `external` fact reaches a planner only through an explicit search tool call, which taints the session; a fact drawn from a `spoken` turn stays `external` until the member confirms it (DC-67); a memory search before answering about the past; dated invalidation of a stale fact. Forgetting on request, which is tier 2 confirmed on the native app, shows the candidate list first and destroys the record keys; the forgetting screen states that existing backups still hold the record until they expire.
- FR-96: supervision extends FR-3 and FR-50: an administration view and `vilicus status` show services, scheduled tasks, processes, assistant latency and memory health, with alerts on the out-of-browser notification channel a few days before any external credential or certificate expires (model providers, mail, store, file server, blog, messaging, vendor-cloud device adapters, push and mail relays, the instance certificate). The administration view shows counts and states per member, never task titles or content; each member sees their own tasks. Metrics carry no sensitive data.
- FR-97: cost control: a token and cost budget per member and per task, alerts before a budget is reached, and the measured cost of a pilot period before a remote provider becomes the default for the data types the provider policy already allows to go to a remote provider. The Claude subscription connector (FR-33) is measured like any provider, against its plan's usage limits instead of a cost.
- FR-98: playbooks: deterministic chains (trigger, tool steps, message templates) written as declarative, versioned, schema-validated documents, run by the Core under a playbook principal (DC-31). A playbook triggers only on records written by a `Member`, `Rule`, `Adapter` or `Cli` principal (DC-64). A message step picks a template from the closed set shipped with Vilicus, or uses text the member typed in full; text drafted by the assistant is never a notification template. A playbook has no model step; its steps go through the action pipeline, reach at most tier 1 and safe-direction home commands, and send outside only through the system notification path or own-account delivery. Caps, the digest and the kill switch apply to playbook runs as to token principals; a playbook may deliver to an account its owner owns without a confirmation at each run once the owner grants a standing approval for that destination; the approval is revocable, listed in the member's settings, and still follows the provider policy by data type (D89, DC-47). A member writes or validates the playbooks that act for them; the assistant may propose one, which keeps its origin and is suspended by the kill switch. A playbook touching a safety-relevant device follows the same rules as home rules (FR-78, FR-80).
- FR-99: per-member tool policy: a subset of the capability matrix, never adding an actor or raising a tier, that binds every token principal acting for the member (assistant sessions, scheduled tasks, plugins, bound channels) and every playbook that acts for the member. A member can widen only their own policy, with a step-up; another adult may narrow it, and the member is notified. A new adult starts with the household's standard tools and every activatable module off (`[ASSUMPTION]`).
- FR-100: activatable modules: a module that is not core to every household (watch, files, publishing, professional activity, and later ones) is off until activated; a module that is off exposes no tool, starts no plugin and opens no file (DC-32). Activating it for the household is an H action with delay and adult veto; activating it for one member is that member's action with a step-up. Deactivating it revokes its tokens and delegation sub-keys and suspends the tasks and playbooks that use it; its data is kept. The module registry and capability matrix checks (FR-22) cover activatable modules like any other.
- FR-101: watch and digests (activatable): RSS feeds and lists of popular code repositories, deduplicated by topic, scored for relevance by the quarantined reader (typed score and topic), and turned into a daily and a weekly digest stored in the member's partition and shown to the human; sending the digest to the member's own address is own-account delivery under the provider policy (DC-33, DC-47). A feed URL is supplied by a member, never by an AI principal (FR-40). Feeds are fetched by a Core stage through the egress proxy, within per-host budgets, never by a model, and parsed in a sandboxed process with no network and no keys; all content is `external`.
- FR-102: files (activatable): listing, reading and depositing files on a self-hosted file server through an isolated plugin; depositing in a dedicated folder is own-account delivery (DC-33); content read from it is `external`; deleting a file is tier 2.
- FR-103: publishing (activatable): creating and editing post drafts, tags and images on a self-hosted blog through an isolated plugin, as own-account delivery (DC-33) while nothing is public; publishing has a public effect and is tier 2, confirmed on the native app after a human review of the final text.
- FR-104: professional activity (activatable): daily activity notes, a monthly activity report generated as a document (FR-106), tracking of job applications and tailoring a CV to an offer, in the member's personal partition only; job offers are collected by a plugin within per-host budgets.
- FR-105: per-host request budgets in the egress proxy, shared by every process that reaches a host (recipe import, feeds, context sources, store connector, researcher, plugins), so that no combination of tasks gets the household's address blocked by a site.
- FR-106: documents and exports: a document generated by the Core and downloaded by a member in the app is a read by that member, never an assistant action; sending it anywhere else is tier 2.

## 5. Non-goals

- Beyond the non-users of section 2.2: no API of any kind for outside AI assistants. MCP is internal, between Vilicus's AI processes and its Core (DC-16).
- Vilicus never pays, orders or sends money without a human on a device that can prove what was shown.
- The web client never confirms a tier 2 action.
- Vilicus is not zero-knowledge: the running Core holds unlocked keys, and the documentation says so.
- No Docker requirement, no paid service required to run it.
- No single sign-on (OIDC) before V1: members authenticate with passkeys.
- No prices, catalog comparison or grocery budget before the budget module.
- Secondary channels are not where trust is decided; nothing sensitive is sent there.
- No chat-only product: the app is the primary channel and must be good enough that secondary channels stay marginal.
- No claim of post-quantum safety.
- No media server: Vilicus has no media feature.
- Not a development or system administration assistant: no host administration, no work on source code or version control, and no development agents.
- Not an integration hub for every device on the market: home automation supports, through adapters, the device families a household brings, and grows one adapter at a time.
- Not a certified alarm or life-safety system: smoke, water and intrusion alerts are best effort and do not replace a monitored alarm or the devices' own sirens.
- Vilicus does not open, unlock or disarm anything before the native app, and the assistant never does (FR-80).

## 6. Milestones

### 6.1 V0.1: the Core

In scope:
- every requirement tagged `[V0.1]`, and the V0.1 part of each `[V0.1 partial]` one: sections 4.1 to 4.10, the model connector interface, provider policy, egress proxy and provider credentials (FR-68, FR-55), the channel model (FR-37) and one notification transport (FR-56), the account and administration screens (FR-50, FR-52) and languages (FR-110);
- member suspension and passkey re-enrollment (FR-107, FR-108), unattended and verified backups (FR-53);
- the reference module and the test doubles, in the verification harness (FR-109);
- the documentation and release deliverables (FR-111, FR-112);
- the spikes of section 9 that gate V0.1, including the construction of architecture spine AD-36 and the HPKE gate of the `hpke` crate (D61), both before FR-8 code.

Every interface without a shipped consumer is proven by a test double, never by a half-built connector.

Out of scope: any user-facing module (the shopping list included), concrete model connectors, conversation, the quarantined reader, messaging connectors, store connectors, member removal, the native app, every tier 2 action (FR-60), the alignment controller, delegation sub-keys, a plugin install command (DC-57), cross-partition event delivery and sealed inboxes (DC-62), a signed apt repository.

Exit criteria:
- UJ-1 and UJ-3 work on a clean Debian 13 system; UJ-2 works, including the delay, the public key check and the household key wrap at the next unlock; automated in the VM and checked manually once on real devices (FR-109).
- The AD-36 construction is settled with the key prototype, and the HPKE gate of section 9 is done, before FR-8 code is written (DC-40, DC-62). If the HPKE gate cannot be closed, or the AD-36 construction does not hold (DC-72), V0.1 exits under its fallback: UJ-2 limited to the first member, and FR-8 ships in V0.1.x.
- Every release-gate invariant of FR-61 passes.
- The restore drill of FR-53 passes in CI.

Two documentation criteria were verified and closed on 2026-10-16, before the epics: the V0.1 design changes of section 8.1 are recorded in `doc/decisions.md` (D34 to D115), and the README is corrected (no external MCP, no QR pairing in V0.1, bound channels can trigger tier 0 and 1, audit anchoring as in FR-32, roadmap matching section 6). The residual risks of section 8.2 are kept in `doc/architecture.md` section 20 by every change that adds one.

### 6.2 After V0.1

Ordered by value to the household. The split into V0.2, V0.3 and so on is decided when V0.1 ships.

1. Home automation module (4.17), the first module after V0.1, with the first shipped plugins (device adapters), mail alerts through an SMTP relay (FR-38, FR-82), the installable web client (the installability part of FR-51), and the architecture changes it depends on (DC-20 to DC-27, DC-35, DC-38, DC-44, DC-45, DC-62 for cross-partition events and sealed inboxes, DC-63, DC-64, DC-70), at parity with the current software (FR-83). It works without a model and exercises the module platform, the plugin runtime and the home partition first. Unlocking, disarming and opening stay with the device vendors' apps and physical gestures until step 8 (FR-80). The current software keeps running until the parity checklist passes, except that it hands the Zigbee coordinator to Vilicus on cutover day (FR-83).
2. Meals and groceries module (4.14), with the first concrete model connectors, the Claude subscription connector among them, and the local model runtime (FR-33), a read-only (tier 0) conversation over meals data (FR-34) after the evaluation suite (FR-64), the scheduler with opt-in delegation sub-keys for member-created tasks that read no external content (FR-87, FR-88), supervision without memory health (FR-96), and per-host request budgets (FR-105), under the runtime isolation and connector rules of DC-65. Until the per-member tool policy ships (step 4), scheduled tasks are limited to the household's standard tools. Requires E18 and the recipe app export check (open question 9) before it starts.
3. Store connector (4.16), as soon as the meals module produces a list. Cart preparation is started by a member from the shopping list (principal `Member`); the assistant path arrives with step 4.
4. Full assistant conversation with writes, memory and the quarantined reader (FR-34, FR-35, FR-67, FR-69), including reading the house and proposing home rules and tasks, waiting-task notifications (FR-63), the researcher with its trusted fetcher (FR-90), memory upkeep and memory health (FR-95, FR-96), cost control (FR-97), playbooks (FR-98), the per-member tool policy (FR-99), activatable modules (FR-100) and documents (FR-106).
5. Messaging connectors (FR-38) with the binding screens (FR-37), before the personal journal, because meal logging happens through messages today and a journal without them would not be used.
6. Personal journal (4.15) with quick check-ins (FR-89) and real-time voice (FR-94), after E29.
7. Activatable modules and remaining parity: mail without sending to third parties, with the drafter it needs (FR-91), watch and digests (FR-101), files (FR-102), publishing drafts (FR-103), professional activity (FR-104), children's routines (FR-93), disclosure grants (FR-92).
8. Native Android app with tier 2, which completes sending mail (FR-91), publishing (FR-103) and final forgetting (FR-95), and brings unlocking, disarming, opening and cutting infrastructure power into Vilicus as tier 2 actions (FR-80). It is gated by E4, E5, E7, E19 and E20 (section 9) and sized before the switch-off order is committed.
9. Calendar and tasks modules, which the briefing and reminders read.
10. Memory migration (FR-36), host promotion (FR-59) and assistant parity (FR-62), then switch-off of the previous assistant, once every item of section 4.18 is in place.
11. Member removal (FR-9), then the other modules of the README roadmap.

The previous assistant keeps running until step 10, so the assistant work does not need to come earlier.

Why home automation comes before meals: the household's current home automation software is the system the household most wants to leave, it runs the house every day, and it exercises the module platform, the plugin runtime and the home partition without any model. The grocery automation that one adult asks for most depends on the meals module, the first model connectors and the store connector, which come right after; until then the household keeps its current list. The meals module comes second, after the home module has proven the module platform, taint and partitions.

### 6.3 V1: community release

V1 is the first release offered to other households. Beyond the features it contains, it requires:

- installation and upgrade documentation, and an upgrade path tested from every earlier milestone;
- a signed apt repository and signed releases with anti-rollback (D28);
- import from at least Mealie, Tandoor and Paprika, and export of every recipe;
- an external security review of the Core;
- third-party plugins signed by their author, installed through an H action with delay and veto; any of their write operations that does not map to a capability matrix row is tier 2, and they declare no I13 exception class (D92);
- the README claims matching what is built.

## 7. Cross-cutting NFRs

The design documents hold the detail; this section names what is release-blocking.

- **Security:** every release-gate invariant (FR-61) is an automated test that blocks the release. The prompt-injection regression corpus runs on every release once any conversation ships (FR-64).
- **Privacy:** no sensitive parameter in audit entries, notifications or secondary-channel replies; provider policy by data type (FR-68). No audit entry carries presence state or a presence trigger; the home partition keeps the shortest event window the active rules need, within the maximum of FR-71. Arming and disarming remain individual audit entries, which reveal departures and arrivals (section 8.2).
- **Reliability:** failure behavior as in `doc/architecture.md` section 17; idempotency keys on every write; a failed migration is recoverable by FR-54. Home rules resume after a restart with every member locked, and an adapter failure never stops the rules of other adapters.
- **Performance:** handles a household's volume (thousands to low millions of rows) on a small host; unlock latency per FR-11. A home rule acts shortly after its local trigger. `[ASSUMPTION]` under 1 second from a Zigbee event to a Zigbee action. Reference host: 4 cores, 8 GB RAM, an SSD, no GPU, Debian 13 amd64 (DC-68). Every latency target of this PRD is measured on it. E25 is run on the reference host and on the household's host; the household's host is not a reference for any other target.
- **Host hygiene:** the installer refuses to start the Core on a host with unencrypted swap unless root acknowledges the risk with `vilicus host acknowledge-swap`, audited, and shown to the instance admin at bootstrap and in `vilicus status` (`doc/architecture.md` section 4).
- **Supply chain:** `cargo deny`, `cargo vet`, `cargo audit` clean; minimal Core dependencies; SBOM per release (D28).
- **Honesty of claims:** a property that depends on deployment or hardware (TPM, reverse proxy, certificate source) is documented as a condition (`doc/architecture.md` section 2, rule 7).

## 8. Design changes and residual risks

### 8.1 Design changes required

The product as specified needs these changes to the design documents. Each becomes a decision record in `doc/decisions.md` (next free IDs) before the milestone that needs it, taking its detail from the requirements listed.

| ID | Change | Requirements | Resolves or amends | Milestone |
|----|--------|--------------|--------------------|-----------|
| DC-1 | Adding an adult is authorized from the CLI by an existing adult's passphrase, with a delay, a veto and the household key wrapped at the next adult unlock; it replaces "signed by every other adult" until the native app exists, and removal follows the same pattern | FR-8, FR-9 | D7; arch 19.3 review item I-11 (recorded as D34) | V0.1 |
| DC-2 | A browser is paired during an enrollment or with a PAKE-bound code; its non-extractable device key binds web sessions and signs light confirmations | FR-15, FR-16, FR-28 | D32 and T19 for browsers (recorded as D35) | V0.1 |
| DC-3 | The unlock window is chosen by the member, separate from the web session; no delegation sub-key in V0.1; amended by DC-68 (window measured from unlock) | FR-12, FR-57 | D8; key-management section 4 (recorded as D36) | V0.1 |
| DC-4 | Every schema field is declared structured or free text; `member` taint reaches the planner as quoted data, `external` free text only through the reader | FR-58, FR-69 | arch 5.4 rule 6 (recorded as D37) | V0.1 |
| DC-5 | Elevated tier 1 calls go to a queue in the primary channel | FR-28 | D16 (no alignment controller in V0.1) (recorded as D38) | V0.1 |
| DC-6 | Recovery starts on the host, waits for the member's own out-of-browser acknowledgement up to a cap, and finishes in the browser with an enrollment token | FR-14 | D6; arch 19.3 review item I-12 (recorded as D39) | V0.1 |
| DC-7 | The audit chain is anchored by a remote sink until native devices exist; the README claim is reworded | FR-32 | D22, T15, T29 (recorded as D40) | V0.1 |
| DC-8 | Memory imported from the previous assistant is `external`; member-validated facts are promoted by batch from the host | FR-36 | Import path (recorded as D41) | after V0.1 |
| DC-9 | Secondary channels: challenge-proven binding, tier 0 and 1 only, tainted inbound content, outbound ceiling | FR-37 | D30, I15, the last item of P7, the static-template rule of P2 and arch 13.4 for replies (recorded as D42) | V0.1 |
| DC-10 | Imported recipes are never promoted as a whole: a deterministic parser yields bounded fields, free text stays `external` and out of the planner | FR-40 | arch 5.4 rule 5 (recorded as D43) | after V0.1 |
| DC-11 | Cart preparation is tier 1 with light confirmation; ordering and payment stay human; I13 gains a named exception class (reversible external state, no effect visible to a third party) | FR-47, FR-48 | D25; I13 (recorded as D44) | after V0.1 |
| DC-12 | Promotion from `external` to `trusted` happens only from the host CLI | FR-59 | DC-8, DC-10 (recorded as D45) | after V0.1 |
| DC-13 | Tier 2 actions are unregistered, not degraded, until the native app exists; V0.1 lists its release-gate invariants | FR-21, FR-60, FR-61 | Tier 2 absence (recorded as D46) | V0.1 |
| DC-14 | A content-free out-of-browser notification channel is mandatory per member; amended by DC-60 (confirmed by a test notification at enrollment) | FR-56 | DC-1, DC-6 (recorded as D47) | V0.1 |
| DC-15 | Provider policy is evaluated per data type | FR-68 | P10 (recorded as D48) | V0.1 |
| DC-16 | No MCP endpoint, or other API, for outside AI assistants; the README's "any MCP-capable assistant drives Vilicus" is withdrawn | FR-25 | README; D13; E21 dropped (recorded as D49) | V0.1 |
| DC-17 | The requesting member's context may shape household proposals, executed as that member, without copying personal free text | FR-67 | Segmentation; arch 9.4 (recorded as D50) | after V0.1 |
| DC-18 | The instance name is fixed before the first enrollment, the certificate source is the operator's choice, and a rename re-enrolls passkeys | FR-65, FR-66 | WebAuthn origin binding (recorded as D51) | V0.1 |
| DC-19 | Backups are complete, with the keys wrapped by a backup secret (amended by DC-61: generated by the Core); a restore invalidates every device, web session, token and channel binding | FR-53 | Backup and restore on a fresh host; arch 18 (recorded as D52) | V0.1 |
| DC-20 | A home partition encrypted by the instance key, usable with every member locked; history produced while every member is locked goes to the household sealed inbox, ingested at the next adult unlock | FR-71, FR-76 | D9 (instance key protects metadata only), key-management sections 2 and 5, arch 5.2 (recorded as D53) | after V0.1 |
| DC-21 | Device adapters may receive access to a named USB device or a named local address range, granted by an H action; everything else stays behind the egress proxy; amended by DC-70 (no loopback grants, ports enforced per unit) | FR-73 | arch 4 network rule (recorded as D54) | after V0.1 |
| DC-22 | A household display is a paired device without a member, limited to the home domain and to tier 0 and tier 1 home actions | FR-81, FR-79 | arch 6 roles and devices (recorded as D55) | after V0.1 |
| DC-23 | Device action classes: a physical action undone by restoring the previous state is tier 1 under a named I13 exception class; rules move safety-relevant devices only toward the safe state; letting someone in, hiding an intrusion or cutting infrastructure power is H; amended by DC-35: not offered before the native app, then tier 2 | FR-80, FR-78, FR-85 | D15; I13; capability matrix (recorded as D56) | after V0.1 |
| DC-24 | Home rules run in the Core with every member locked, under a rule principal, without a model and without a member key | FR-78 | D8 background tasks (recorded as D57) | after V0.1 |
| DC-25 | Two new principals, rule and display, outside capability tokens bound to one member; the display is a paired device without a member, limited to the home domain | FR-78, FR-81, FR-19 | arch 6, arch 9.2; spine AD-8 and AD-11 (recorded as D58) | after V0.1 |
| DC-26 | Home failure behavior: home partition migrated at start; disarm, unlock and pause in the audit emergency set; safety-relevant actions held on a clock jump; a heartbeat for outside monitoring | FR-84, FR-82 | arch 17; FR-54 (recorded as D59) | after V0.1 |
| DC-27 | Remote access by a WireGuard endpoint managed by Vilicus: the interface owned by the host network configuration, peers changed by a dedicated unit with network administration rights on the Core's instruction | FR-86 | arch 15 exposure, D27 (recorded as D60) | after V0.1 |
| DC-28 | Delegation sub-keys come back after V0.1 for scheduled tasks: opt-in per member and per task by an H action, delay and veto for household modules, scoped to one module and one partition, sealed by the instance key, revocable with re-keying; every data type may be delegated | FR-87, FR-88 | D8, D36; key-management section 7; R4, T26 (recorded as D62) | after V0.1 |
| DC-29 | A fourth AI role, the researcher: only the member's question, a templated first query, then only links found verbatim in fetched pages, parsing in the sandbox, per-host budgets, human-only report | FR-90, FR-105 | P2 roles, P7, I4, AD-15, AD-16, arch 11.1 (recorded as D63) | after V0.1 |
| DC-30 | A disclosure grant, an H action, lets a member share a deterministic Core-computed value with another adult, keeping its data type and delivered through the recipient's sealed inbox; amends D46 for this case only | FR-92 | D46, D50, D53 (recorded as D64) | after V0.1 |
| DC-31 | Playbooks: declarative, schema-validated chains run by the Core under a playbook principal, no model step, at most tier 1, outbound only through notifications or own-account delivery | FR-98 | D58; D57; AD-7, AD-8, P3, I21 (recorded as D65) | after V0.1 |
| DC-32 | Activatable modules (household activation is H with delay and veto) and a per-member tool policy that only narrows the matrix and binds every token principal acting for the member | FR-99, FR-100 | AD-9, AD-11, FR-22 (recorded as D66) | after V0.1 |
| DC-33 | Own-account delivery: writing to an account the member owns (mail to self, file deposit in a dedicated folder, unpublished blog draft) is tier 1 with light confirmation, a named I13 exception class | FR-91, FR-101, FR-102, FR-103 | D15, I13 (recorded as D67) | after V0.1 |
| DC-34 | A spoken confirmation can approve an elevated tier 1 request, and nothing else | FR-94 | D38; confirmation kinds (arch 9.1) (recorded as D68) | after V0.1 |
| DC-35 | Unlocking, disarming, opening and cutting infrastructure power are not offered by Vilicus before the native app; the household uses the vendor's app or a physical gesture; then they are tier 2 on the native app | FR-80, FR-75, FR-84, UJ-9 | D56, DC-23 (recorded as D69) | after V0.1 |
| DC-36 | A write made or approved by a member is stored `trusted` with that member as author; `member` taint is a read-time view; structured fields of `member` taint do not taint the AI session; E23 gets a fallback | FR-20, FR-58, FR-67 | D14, D37, DC-4; spine AD-6, AD-7 (recorded as D70) | V0.1 |
| DC-37 | Every step-up assertion is bound to the canonical hash of exactly one pending action | FR-10, FR-61 | D33 (recorded as D71) | V0.1 |
| DC-38 | Locks, alarms, cameras, gates, garage doors and covers of unknown kind are safety-relevant from discovery; an adapter cannot change the class of a confirmed device; reclassifying is H | FR-72 | D56 (recorded as D72) | after V0.1 |
| DC-39 | Researcher requests are made by a trusted fetcher without a model, after the Core checks each URL; a browser renderer, if kept, has no network | FR-90 | D63, DC-29 (recorded as D73) | after V0.1 |
| DC-40 | The Core generates each member's key pair at enrollment; at `member add` the Core derives a key from the enrollment token, wrapped under a key derived from the authorizing adult's household key, that authenticates the public key; the AD-36 construction and the D61 review and cross-test gate V0.1; amended by DC-62 (done state and fallback) | FR-7, FR-8 | D34, D61 (recorded as D74) | V0.1 |
| DC-41 | Out-of-browser acknowledgement by a one-time token per alert, redeemed at the Core from a device the member controls, with its limits stated; without it the waiting period runs to its cap | FR-14, FR-56 | D39, DC-6 (recorded as D75) | V0.1 |
| DC-42 | Bootstrap order: token, instance name and certificate, instance admin passkey, first member (amended by DC-60: the admin destination after the admin passkey); no WebAuthn over the temporary self-signed certificate | FR-4, FR-65, FR-7, UJ-1 | D32, D51 (recorded as D76) | V0.1 |
| DC-43 | `vilicus member reenroll` and `vilicus member suspend` in V0.1; `device pair`, `unlock` and `reenroll` require the target member's own passphrase; amended by DC-56 (host-only commands, self-suspension) | FR-3, FR-107, FR-108, FR-66 | D34 (recorded as D77) | V0.1 |
| DC-44 | Secrets of adapters that drive physical security devices are sealed to the TPM, not restorable from a backup alone, and entered again after a restore on another host; amended by DC-63 (host CLI entry, signed boot policy) | FR-73, FR-53 | D53, D54 (recorded as D78) | after V0.1 |
| DC-45 | Zigbee cutover: the current software keeps the coordinator until cutover day; parity checked in parallel for other families and on Zigbee after cutover, with a rollback plan | FR-83, FR-74 | FR-83 (recorded as D79) | after V0.1 |
| DC-46 | Each record kind declares its data type; the provider is bound at token issuance from the readable data types; children's dietary constraints are applied by a deterministic Core filter around remote meal planning | FR-68, FR-70 | D48, DC-15 (recorded as D80) | V0.1 |
| DC-47 | Own-account delivery follows the provider policy by data type and the outbound content check; local-only data types never go to a hosted account | FR-91, FR-101, FR-102, FR-103 | D67, DC-33 (recorded as D81) | after V0.1 |
| DC-48 | A secondary channel's ceiling is an allowlist of data classes; presence, home state, alarm state, calendar and children's data are excluded by default; amended by DC-58 (data types, input gating) | FR-37 | D42, DC-9 (recorded as D82) | V0.1 |
| DC-49 | The local model runtime is a component: own unit, Unix sockets only, no network, no cache shared across members or roles, model files pinned by hash; amended by DC-65 (process grouping) | FR-33 | spine AD-51 (recorded as D83) | after V0.1 |
| DC-50 | Migrations run on a copy swapped in on success; failure is handled per file; `vilicus upgrade check` reports pending and failed migrations | FR-54, FR-84, FR-23 | D21 (recorded as D84) | V0.1 |
| DC-51 | Backups run unattended, wrapped to a backup public key whose private key stays offline, on a timer, to an off-host target, checked by `vilicus backup verify`, with a restore drill in CI | FR-53 | D52, DC-19 (recorded as D85) | V0.1 |
| DC-52 | Claude subscription connector: the unmodified Claude Code binary in headless mode, one unit per connected member, serving only that member; sign-in through Anthropic's own flow, the credential never handled by Vilicus | FR-33, FR-97 | recorded as D97, spine AD-53 | after V0.1 |
| DC-53 | Every structured field is validated against its declaration on write (closed type, length, character set), with a fuzz test of every write path | FR-58 | D37, DC-4; spine AD-6 (recorded as D98) | V0.1 |
| DC-54 | An approval does not launder free text: free text drafted in a tainted session stays `external`, edited or not; only text the member writes in full is stored `trusted` | FR-20, FR-58 | DC-36; spine AD-6, AD-7 (recorded as D99) | V0.1 |
| DC-55 | A spoken yes follows a read-back of the request from a fixed template, bound to the request's hash | FR-94 | DC-34, DC-37; spine AD-20 (recorded as D100) | after V0.1 |
| DC-56 | V0.1 action surfaces: FR-50 lists every V0.1 action with its actor, surface and confirmation; exposure, admin recovery code redemption, `member enroll-first` and, after V0.1, `ai connect claude` run at the root CLI only; a host kill switch; a member may suspend their own account; provider configuration is API-only in V0.1; lifting a suspension stays as D87 | FR-3, FR-5, FR-6, FR-7, FR-30, FR-33, FR-50, FR-107 | D76, D77, D97; DC-43 (recorded as D101) | V0.1 |
| DC-57 | First-party plugins ship inside the signed main package until V1, version-locked to the Core; a `vilicus-testbed` binary carries the reference module and the test doubles for the release gates | FR-25, FR-61, FR-109 | D92; spine AD-3 (recorded as D102) | V0.1 |
| DC-58 | One closed taxonomy of data types; every record stores the set of data types it contains, a derived record's set being the union of its inputs'; channel ceilings are allowlists of data types applied as input gating at token issuance | FR-37, FR-61, FR-68 | D48, D80, D82; DC-15, DC-46, DC-48 (recorded as D103) | V0.1 |
| DC-59 | A field is structured only if its value set is fixed at build time, with reviewed vocabularies; exempt record kinds accept only structured fields from an AI principal; approved assistant drafts reach the planner as quoted data; a verbatim test of 8 consecutive words; disclosure grant derivations return closed types; a household write from a session that read personal free text is elevated | FR-20, FR-28, FR-58, FR-67, FR-92 | D37, D38, D64, D70, D98; DC-36, DC-53, DC-54 (recorded as D104) | V0.1 |
| DC-60 | The out-of-browser destination is confirmed by a test notification at enrollment, re-enrollment and bootstrap; a blocking banner and maximum waits without one; E13 gets a threshold; named private destinations for Core-originated traffic | FR-4, FR-7, FR-56, FR-108 | D47, D76; DC-14, DC-42 (recorded as D105) | V0.1 |
| DC-61 | Backups go to S3-compatible object storage with write-only or object-lock credentials, 7 daily and 4 weekly; passphrase wrappers sealed; a backup secret generated by the Core; DEK rotation after a recovery; target changes alerted with delay and veto; a CBOR record for the remote sink | FR-14, FR-32, FR-53 | D52, D85; DC-19, DC-51 (recorded as D106) | V0.1 |
| DC-62 | V0.1 events stay within their source partition; the HPKE gate gets a done state and a fallback; E22 gets three fallbacks; supported browsers are named | FR-24, FR-28, FR-50 | D61, D74; DC-40 (recorded as D107) | V0.1 |
| DC-63 | Secrets that let a device open the house are entered only at the host CLI as credentials sealed to PCR 7 plus a signed PCR 11 policy; the instance key stays on PCR 7 with a pcrlock re-seal; the coordinator key arrives as a credential | FR-73, FR-74, FR-76 | D78, D96; DC-44 (recorded as D108) | after V0.1 |
| DC-64 | An unclassified relay accepts no command from a display, the assistant or a rule; a `momentary` capability; playbooks trigger only on records written by `Member`, `Rule`, `Adapter` or `Cli` | FR-72, FR-98 | D65, D72; DC-31, DC-38 (recorded as D109) | after V0.1 |
| DC-65 | Hostile-content roles never share a runtime process with the planner or the drafter; the Claude subscription connector allows no data type by default, checks its account identifier, and runs a binary pinned by the release | FR-33 | D83, D97; DC-49, DC-52 (recorded as D110) | after V0.1 |
| DC-66 | Delegated run descriptors sealed under the sub-key; member-owned plugins run only while their owner is unlocked; consolidation only in the unlock window; delegated output stored `external` | FR-25, FR-87, FR-88, FR-95 | D62, D94, D95; DC-28 (recorded as D111) | after V0.1 |
| DC-67 | Spoken provenance: facts drawn from a spoken turn stay `external` until confirmed; voice-session writes listed separately; batch promotion only for records whose fields are all structured | FR-36, FR-59, FR-94, FR-95 | D41, D45; DC-8, DC-12 (recorded as D112) | after V0.1 |
| DC-68 | V0.1 values: the unlock window measured from unlock, a 30-day undo journal, the reference host, languages, token lifetime and budget, the I11 caps, three operator-tunable values, documentation and release requirements, and the approved dependencies | FR-11, FR-12, FR-27, FR-29, FR-61, FR-110, FR-111, FR-112 | D36; DC-3 (recorded as D113) | V0.1 |
| DC-69 | `audit.db` and every inbox file are SQLCipher files under derived keys; an inbox row's type travels inside the sealed payload | FR-31, FR-71 | D22, D53; DC-20 (recorded as D114) | V0.1 |
| DC-70 | No loopback address grants: device grants are USB devices, Unix sockets, a namespace shared with a managed daemon, or a private range with ports enforced per unit; the Claude subscription connector runs in a private network namespace with a forwarder | FR-33, FR-73 | D54, D97; DC-21, DC-52 (recorded as D115) | after V0.1 |
| DC-71 | E32 passes at p99 under 100 ms for one action through the full pipeline (policy, write, audit) on the reference host, under a simulated load of two active adults plus the testbed; on failure the execution model is revised before the Core process is built | section 7, FR-109 | E32; architecture spine AD-9 (recorded as D116) | V0.1 |
| DC-72 | If the AD-36 construction does not hold, V0.1 exits with a single member and FR-8 ships in V0.1.x; a browser that fails the login half of E2 leaves the supported list, and if every supported browser fails, TOTP temporarily becomes the primary second factor | FR-8, FR-10, FR-50 | D33, D74, D107; DC-40, DC-62 (recorded as D117) | V0.1 |
| DC-73 | The out-of-browser channel defaults to a self-hosted UnifiedPush server reached through a named private destination; a public server is allowed when the household chooses it and sees only delivery timing metadata; E13 is measured on both | FR-56 | D47, D105; DC-14, DC-60; open question 8 (recorded as D118) | V0.1 |

### 8.2 Residual risks to record

Until the native app exists, the human guard of V0.1 is a tap in a browser served by the Gateway. The design treated a compromised Gateway as an edge case; in V0.1 its consequences are the nominal case. These risks are accepted and must be written into `doc/architecture.md` section 20:

- **A compromised Gateway controls the browser:** it serves the page's code, so it can alter what a light confirmation shows, make the device key sign an approval the member did not intend, and capture pairing codes (R16, T24). Signing, PAKE and device binding protect against network attackers and replay, not against a compromised Gateway.
- **A Gateway-served step-up can be misrepresented:** each step-up is bound to one action (DC-37), so an assertion cannot be spent on a second action, but a compromised Gateway can show one action while the Core receives another. Letting someone in and cutting infrastructure power are therefore kept off the web (DC-35). Pairing, WireGuard peers, plugin grants, provider configuration and lifting a suspension remain browser step-ups before the native app, so a compromised Gateway can still obtain lasting access through one misrepresented step-up (FR-10); for a lifted suspension, the delay, the veto and the out-of-browser alerts at request and at effect are the guard (FR-107). Exposure, the admin recovery code and the first enrollment after an interrupted wizard are kept at the host CLI (DC-56).
- **R3 extends to the passphrase and the secrets shown in the browser:** a passphrase typed in the browser, a new passphrase, and a recovery secret displayed at enrollment or at the end of a recovery transit through the Gateway. FR-57 offers a host-side unlock for households that want to avoid it for unlocking.
- **R1 is aggravated by the unlock window:** a member's data key stays in memory for up to the window maximum without an active web session (FR-12).
- **The operator is an adult:** in a self-hosted household, the person with root on the host is usually one of the adults. Isolation between adults is then a matter of policy, audit and friction against that adult, not a cryptographic guarantee (R1, R17). An adult without host access needs the operator to change exposure, as for recovery (DC-56).
- **Injection between adults:** the other adult's household text reaches the planner as quoted data (FR-58); a hostile or compromised adult account can try to steer the other adult's assistant. Free text of `member` taint taints the AI session and non-exempt writes need the member's confirmation; once a member approves a write, its structured fields are stored `trusted` (DC-36), while free text the assistant drafted in a tainted session stays `external` (DC-54), so the approval is the guard for structured data and taint remains the guard for text.
- **Recovery depends on the operator, and the secret is a bearer token:** a member without host access cannot start their own recovery, and only the waiting period and the out-of-browser alerts protect a member whose recovery secret is stolen (FR-14). The acknowledgement token that shortens the wait protects against an attacker who cannot read the member's push channel, not against a compromised device of the member or a compromised Gateway, which can redeem it.
- **Store connector authority:** the connector session holds the full authority of the store account; "ordering stays human" is enforced by the manifest and by keeping no stored payment method, not by the egress proxy (FR-48).
- **Bound channel takeover:** SIM swap or account theft on a messaging service makes the attacker a bound sender, limited to tier 0 and tier 1 within the channel's ceiling, which excludes presence, home and alarm state, the calendar and children's data unless an adult added them (DC-48). A compromised messaging plugin can claim to be any member bound on its channel, within the same limits (FR-37).
- **The home partition is protected by the instance key only:** root on the host can read it, and so can someone who steals the disk of a host without a TPM. On a host with a TPM, the instance key is sealed to PCR 7 only, so a live image signed under the same Secure Boot authorities can unseal it: whole-host theft reveals home metadata and occupancy. It holds device configuration, current state, a 24-hour window of recent events and a short rule journal, enough to tell whether the house is occupied right now (FR-71). It also holds the credentials of device adapters that cannot open the house (vendor clouds for heating or energy, for example), and whoever holds the instance key can drive those devices through the vendor. Secrets that let a device open the house (security adapter credentials, the Zigbee coordinator's network key, a router admin credential used for presence) are entered only at the host CLI as credentials sealed to a signed boot policy and kept out of backups (DC-44, DC-63), which a host without a TPM or without unified kernel images cannot offer; where the coordinator daemon cannot take its key from a credential, the radio key sits in clear in its configuration, and whoever reads it can join the Zigbee network within radio range.
- **Device daemons and adapters can act around Vilicus's tiers:** the radio daemon, a vendor app or a compromised adapter can drive devices directly; Vilicus's tiers govern what goes through Vilicus, not what the devices accept from elsewhere (FR-73, FR-74).
- **Remote access endpoint:** the WireGuard port is reachable from the internet (silent to unauthenticated packets), the unit that changes peers holds network administration rights, and on Android the tunnel takes the single VPN slot, so it conflicts with another VPN on the same phone (FR-86).
- **Delegated data is readable by whoever controls the host or a backup:** a delegation sub-key makes that module's data in that partition readable to root on the host, to the instance admin with a backup and its backup secret, or to the thief of a disk on a host without a TPM, for as long as the sub-key exists; the fire times of delegated tasks are readable to whoever holds the instance key. The household accepts this internal risk; the design protects against third parties (FR-88).
- **The researcher browses the open web:** fetched pages can carry injection; every visited site sees the household's address and the trusted fetcher's fingerprint; a browser renderer, if kept, runs the pages' scripts in its sandbox without network (DC-39). Exfiltration through the choice of links is limited to links found in fetched pages and to the member's own question, but not eliminated (FR-90).
- **Source data can be inferred from a disclosure grant, and a grant can be coerced:** the recipient learns a derived value over time, and one adult can pressure the other to grant one (FR-92).
- **Scheduled actions run unattended:** a task or playbook acts while nobody watches; caps, the digest and the kill switch bound it (FR-87, FR-98).
- **Arming and disarming reveal departures and arrivals** in the audit log (section 7).
- **Claude subscription connector:** its credential lives in the connector unit's state directory, outside the Core's key hierarchy and outside backups, and the plan's usage limits can stop a task (FR-33, E30). An allowlisted provider hostname does not bind the account; the account identifier recorded at sign-in is checked at every start (DC-65).
- **Remote provider hosts are shared:** a remote provider serves the household's requests on infrastructure shared with its other customers, outside Vilicus's isolation (DC-65).
- **Presence is spoofable:** a cloned phone on the local network can make Vilicus tell the adults that someone is home while armed, or change modes that do not concern a safety-relevant device; it cannot disarm or unlock, which Vilicus does not offer before the native app (FR-80). Presence is excluded from secondary channel ceilings by default (DC-48).
- **Own-account delivery to a hosted account is seen by its provider:** mail to self on a hosted mail service is read by that service; the provider policy keeps local-only data types out of it, and other data types reach it (FR-91, DC-47).
- **The local model runtime sees every member's local-only data:** it receives each member's health, journal and budget prompts and every hostile document the reader sees; separation rests on per-role sockets and no shared cache, and the reader and the researcher never share a runtime process with the planner or the drafter (FR-33, DC-49, DC-65).
- **The remote sink bounds, not prevents, a rewrite:** root can rewrite undetected the entries written since the last head hash sent (FR-32).
- **Own-account delivery assumes nobody else sees the destination:** Vilicus cannot see a forwarding rule, a shared folder or other editors set up by the member, and a standing approval removes the per-run confirmation (R52).
- **Played audio can speak in a voice session:** a television or a call on speaker can issue tier 1 commands in an untainted voice session; facts drawn from spoken turns stay `external` until the member confirms them, and voice-session writes are listed separately in the digest (DC-67).
- **Shared host:** on a host that also runs other services (a media server exposed to the internet, for example), a compromise of one of them that reaches root compromises Vilicus (R1); GPU and CPU are shared with them.
- **Device adapters on the local network:** an adapter granted local network access can reach other devices on that range; the grant is named and audited, but its content is not filtered (FR-73).
- **Vendor clouds:** heating, meter, irrigation and similar adapters depend on vendor services that can change or stop; a rule that depends on them fails visibly (FR-82).
- **The household display is physically accessible:** anyone in the house can use it, within tier 0 and tier 1 home actions (FR-81).
- **Name and certificate depend on third parties:** with a free dynamic DNS or a private-network name, renewal and resolution depend on that service; losing the name means a rename and passkey re-enrollment (FR-66).

## 9. Spikes

V0.1 experiments run in this order, because the first groups can invalidate the design: the AD-36 construction with the HPKE gate (key prototype), E22 (non-extractable device key in the browser), E24 (passkeys and installable web app with each naming option), E10 (sandbox and peer identity); then the others. E1 and E2 (PRF) run early on the household's real phones, but PRF unlock is not in V0.1, so they inform it without gating it.

| Experiment | Gates | What it settles |
|------------|-------|-----------------|
| AD-36 construction (key prototype) | V0.1, before FR-8 code | How a member's public key is authenticated from `member add` to the household key wrap, for the first member and every added adult (DC-40). Fallback (DC-72): V0.1 exits with a single member and FR-8 ships in V0.1.x |
| HPKE review and cross-test (D61) | V0.1, before FR-8 code | Internal review of the `hpke` crate and of Vilicus's use of it (DC-40). Done when: the RFC 9180 test vectors pass, a cross-test in CI against an independent implementation, used as a dev-dependency only, agrees on 10 000 random cases, and a written review with every finding closed or accepted is committed. Fallback: a defect is fixed upstream and the fix pinned; failing that, V0.1 exits with UJ-2 limited to the first member and FR-8 ships in V0.1.x (DC-62) |
| E1, E2 (PRF half) | PRF unlock after V0.1; run early | Run early on the household's real phones: without PRF, members type a passphrase every day, which pushes toward weak passphrases and maximum unlock windows |
| E2 (login half) | V0.1 | Passkey login through the chosen WebAuthn library. Pass: passkey login and a step-up whose challenge derives from an action hash succeed on every supported browser (FR-50). Fallback (DC-72): a browser that fails leaves the supported list; if every supported browser fails, TOTP temporarily becomes the primary second factor |
| E3 | V0.1, README wording only | Honest wording of the hybrid transport claim; its result informs the README wording and blocks nothing else |
| E10 | V0.1 | Sandbox profile, Core-created sockets and peer identity for Gateway, audit writer, plugins and AI processes. Fallback: if `SO_PEERPIDFD` and the cgroup unit cannot be read, each first-party unit runs under its own static user and the Core checks the uid with `SO_PEERCRED`, recorded as weaker |
| E11 | V0.1 | Migration authorizer |
| E12 | V0.1 | Argon2id parameters on the reference host. Fallback: lower the concurrency limit, keep the memory floor, accept a longer unlock |
| E14 | V0.1 | Egress proxy domain filtering against real client traffic |
| E16 | V0.1 | Locked memory and zeroization. Fallback: a shorter unlock window maximum (FR-12), stated in the documentation |
| E17 | V0.1 | `secure_delete` and WAL behavior, which protects the V0.1 claim that expired journal entries are deleted (FR-29) |
| E22 (new) | V0.1 | Non-extractable device key in the browser, PAKE-bound code pairing, signed light confirmations (DC-2, DC-5), on every supported browser (FR-50). Fallbacks (DC-62): sessions are re-proven by a passkey assertion every 15 minutes of activity, stated to the user; pairing codes are issued only by `vilicus device pair`; approvals are made by a step-up bound to the request hash |
| E23 (new) | The full conversation milestone (section 6.2 step 4), measured over its first four weeks of household use; scheduled tasks of step 2 are counted from their first week | Rate of elevated tier 1 requests in real use, under the stored-taint rule of DC-36 as amended by DC-54 and DC-59 (DC-5). Pass: at or under the SM-4 threshold. Fallback: widen each module's list of exempt record kinds (FR-28), reviewed with the module, never by loosening taint (SM-C2). V0.1 ships only the counter of FR-28 (SM-4) |
| E24 (new) | V0.1 | Passkeys and PWA installation on the supported browsers of FR-50 (Safari best effort) with each documented naming option: free dynamic DNS, private-network name, local certificate authority (FR-65); and confirmation that browsers refuse WebAuthn over the temporary self-signed certificate, which the bootstrap order avoids (FR-4, DC-42). Fallback: a naming option that fails is removed from the documentation |
| E18 | Meals module, checked before it starts | Official store API, and whether the household's current recipe app can export |
| E30 (new) | Meals milestone, before the Claude subscription connector ships | The connector in the shape of architecture spine AD-53: the unmodified binary headless with every built-in tool disabled, one child per session over the stdio bridge, killed within the 5-second bound, request bodies inspected through a test proxy with a test CA, offered tools exactly the token's Vilicus MCP tools, no account-level connector offered, no route to another loopback port; rerun for every pinned binary version (FR-33, DC-65, DC-70). Fallback: the connector does not ship |
| E8, E9 | Mail module (section 6.2 step 7), before it starts | The cost of the OAuth procedures for a household that brings its own client, and how work accounts behave under corporate policy (FR-91) |
| E15 | Mail module and forgetting (FR-95) | Whether per-record keys coexist with full-text search |
| E25 (new) | FR-33 | Local model quality and latency on the reference host for the data types routed to it, and on a larger host where models run on the CPU, with the runtime in the shape of DC-49 and the latency the household accepts stated beforehand |
| E26 (new) | V0.1 | Separate origin by port for sandboxed external content, on the supported browsers of FR-50, with each FR-65 naming option and with reverse proxies. Fallback: if a port-based origin is not workable, external content is shown as sanitized plain text, never as HTML |
| E13 | V0.1 | Push delivery reliability for content-free notifications (FR-56), measured on the default self-hosted server and on a public server (DC-73). Pass: 99 % of alerts delivered within 10 minutes over 7 days per phone, idle nights included. Fallback: a second push distributor within the same webhook transport, plus the maximum waits of FR-56 (DC-60) |
| E32 (new) | V0.1 | Core execution model (architecture spine AD-9): home rule latency during two concurrent unlocks and a backup. Pass (DC-71): p99 under 100 ms for one action through the full pipeline (policy, write, audit) on the reference host, under a simulated load of two active adults plus the testbed. Fallback: the execution model is revised before the Core process is built |
| E27 (new) | Home milestone, before it starts | Device adapters under the sandbox, on the target host: the USB serial unit profile with a dynamic user (fallback: a static user per adapter), enforcement of the IP filter by a negative connection test, multicast discovery, presence from the router's leases or API and unprivileged ping, latency from a Zigbee event to an action, and moving the Zigbee coordinator from the current software to Vilicus with its network and pairings, and negative tests from an adapter to every other loopback port (FR-73, FR-74, FR-76, FR-83, DC-70) |
| E31 (new) | Home milestone, before an adapter that drives a physical security device | A signed PCR 11 policy with unified kernel images and a pcrlock re-seal of the instance key before Secure Boot database or SBAT updates, on Debian 13 (DC-63) |
| E28 (new) | Home milestone, before it starts | WireGuard endpoint managed by Vilicus: peer changes applied live without root in the Core, the instance name resolving to the private address inside and through the tunnel (including resolvers that block private answers), the official client on Android and desktop, and the single VPN slot on Android (FR-86). Fallback: the documented reverse proxy or access proxy path becomes the default |
| E4, E5, E7, E19, E20 | Native app (section 6.2, step 8), before it starts | Protected Confirmation availability, Keystore signing with attestation, the Android shell, canonical hashing identical in the Core and the app, and an inner channel the Gateway cannot read (`doc/research-notes.md`) |
| E29 (new) | Personal journal milestone | Real-time voice in the installed web client on Android: background audio, microphone released while Vilicus speaks, raw microphone in car mode, car Bluetooth media routing, test chime (FR-94) |

## 10. Success metrics

**Primary**
- **SM-1:** the owner switches off the previous assistant. Target: within one month of the memory migration shipping. Validates FR-34 to FR-36, FR-62, FR-87 to FR-106.
- **SM-2:** both adults use Vilicus for the weekly groceries. Target: four consecutive weeks with the plan and the list made in Vilicus. Validates FR-41 to FR-43, FR-47.

**Secondary**
- **SM-3:** on a clean Debian 13 system, UJ-1 and UJ-3 complete in under 30 minutes, and UJ-2 completes once its delay has run. Validates FR-1 to FR-17, FR-65.
- **SM-4:** elevated tier 1 requests per member per day stay under an agreed threshold. `[ASSUMPTION]` 3. Validates FR-28.
- **SM-5:** the personal journal is used by its intended member at least five days a week for a month. Validates FR-45, FR-38.
- **SM-6:** the household's current home automation software is switched off. Target: within one month of the home milestone shipping, with every parity checklist item passing. Validates FR-71 to FR-86.

**Counter-metrics (do not optimize)**
- **SM-C1:** share of interactions through secondary channels. A rising share means the app falls short; it is not a success signal. Counterbalances SM-1.
- **SM-C2:** a drop in elevated requests achieved by loosening taint rules rather than by better bounded outputs. Counterbalances SM-4.
- **SM-C3:** count of home rules disabled to stop a nuisance. A rising count means rules misbehave; switching off rules is not parity. Counterbalances SM-6.

## 11. Open questions

1. License (D29): resolved, Apache-2.0 (owner, 2026-10-16).
2. Front-end framework (D26): resolved in the architecture spine (Lit with Vite).
3. Which store has an official API (E18), and which store the first connector targets.
4. Which local model runtime and model families are supported (FR-33, E25), and the reference host's hardware for them.
5. Whether children get managed accounts before V1.
6. Whether the household's existing shared calendar is imported or connected, and when.
7. When web recovery becomes available for members without host access (FR-14).
8. Resolved (owner, 2026-10-16): the out-of-browser channel defaults to a self-hosted UnifiedPush server reached through a named private destination; a public server is allowed when the household chooses it (FR-56, DC-73).
9. Whether the household's current recipe app offers an export or JSON-LD (FR-40).
10. Which speech-to-text and text-to-speech engines run locally (FR-62).
11. Whether a built-in ACME client is worth adding after V0.1 for the free dynamic DNS option (FR-65).
12. The AEAD and key-wrapping construction (`doc/key-management.md` section 12): resolved in the architecture spine; HPKE from the `hpke` crate under a recorded D28 exception with an internal review and a cross-test before FR-8 code (D61, DC-40).
13. Whether the camera records (and where) or is only watched live; recording would add storage and retention requirements.
14. What frustrates the household in the current home automation software, to shape the rule editor and the screens.
15. The long-term Zigbee coordinator, if the one in use is no longer maintained.
16. Which outside monitor watches the heartbeat of FR-82.
17. Resolved (owner, 2026-10-16): Vilicus ships a Claude subscription connector (FR-33, DC-52).
18. Resolved (owner, 2026-10-16): the previous assistant is switched off only once every item of section 4.18 is complete, so the native app and the calendar and tasks modules come before the switch-off (section 6.2).

## 12. Assumptions index

Values confirmed by the owner (DC-68) are named constants in `vilicus-types`: the unlock window semantics (FR-12), the 30-day undo journal (FR-29), the reference host (section 7), languages (FR-110), the 10-minute token lifetime and the budget of 50 tool calls (FR-27). Only three values are operator-tunable, in `vilicus.toml`: the backup schedule, the certificate alert lead time and the audit spool size. Security delays and caps are compiled in.

- 2.2: iOS not planned before V1; children are not users before V1.
- FR-1: amd64 only in V0.1, arm64 before V1; other distributions decided for V1.
- FR-2: `systemd-analyze security` threshold 2.0.
- FR-8: delay of 24 hours before an added adult receives the household key.
- FR-11: unlock under 2 seconds on the reference host.
- FR-12: unlock window maximum 24 hours, default 12 hours.
- FR-14: recovery waiting period 48 hours with a redeemed acknowledgement token, running on to a cap of 7 days without one.
- FR-28: elevated request expiry 24 hours; low-risk exempt record kinds for meals are shopping list additions and stock updates.
- FR-30: the repeated-denial detector suspends a task after 5 denials.
- FR-31: the audit spool holds 10 000 entries.
- FR-37: the default secondary channel ceiling is meals, meal plan, shopping list and confirmations of the member's own journal entries.
- FR-38: Signal is the first messaging connector.
- FR-40: Mealie, Tandoor and Paprika as import formats.
- FR-51: offline mode covers the shopping list only.
- FR-53: daily backups, with an alert when the last successful backup is older than 3 days.
- FR-65: no built-in ACME client in V0.1; certificate expiry alert 14 days ahead.
- FR-71: rolling event window and rule journal retention of 24 hours.
- FR-73: an adapter that drives a physical security device drives no other device family.
- FR-74: the Zigbee radio stays with a coordinator daemon driven through its local API in the first home milestone; a native stack or a different coordinator comes later.
- FR-82: the heartbeat is watched by the push server or a free monitoring service.
- FR-87: a late task runs at most once, within 12 hours.
- FR-93: children's routine and episode data is kept for 12 months.
- FR-99: a new adult starts with the household's standard tools and every activatable module off.
- 7 Performance: under 1 second from a Zigbee event to a Zigbee action.
- SM-4: elevated request threshold of 3 per member per day.

Assumptions of the architecture spine, indexed here so that each story finds them:

- AD-9: one writer thread per open file.
- AD-12: maximum frame of 1 MiB on control sockets and 16 MiB on data sockets.
- AD-17: rule runs aggregated per hour in the audit log; the remote sink receives the head hash every 15 minutes and at shutdown.
- AD-22: data, state and runtime paths of the units.
- AD-26: home rule journal kept 24 hours; outbox rows kept 30 days after delivery.
- AD-32: one generic push text per severity; a heartbeat every 5 minutes.
- AD-33: CI on GitHub Actions, with a Debian 13 VM that needs nested virtualisation.
- Egress proxy health checked every 30 seconds (`doc/architecture.md` section 17).
- Conventions: UUIDv7 identifiers, whose embedded time is accepted as disclosed.
