---
title: 'Vilicus V0.1 backlog'
author: Rwx-G
status: draft
created: 2026-10-16
scope: 'V0.1 (the Core)'
---

# Vilicus V0.1 backlog

Status: draft. This backlog breaks milestone V0.1 of [`prd.md`](prd.md) into epics and stories, following the [architecture spine](architecture-spine.md) and the design documents in this directory. Each story is one file under [`stories/`](stories/), named `story-<epic>.<n>-<slug>.md`, with its acceptance criteria, dependencies and references; its `implements` list names the requirements, decisions, invariants and experiments it delivers or gates. Stories depend only on earlier stories.

Epic 1 holds the experiments that gate V0.1, as spike stories with a pass criterion, a timebox and the documented fallback. The build epics follow the bootstrap order of spine AD-52 and their dependencies. Requirements tagged `[after V0.1]` in the PRD have no story here: FR-9, FR-33 to FR-36, the binding screens of FR-37 with FR-38, FR-39 to FR-49, FR-51, FR-59, FR-62 to FR-64, FR-67 and FR-69 to FR-106.

## Epics

### Epic 1: Prove the V0.1 design assumptions

The owner knows, before the code that depends on each assumption, whether it holds or which documented fallback applies: the key prototype (AD-36), the HPKE review and cross-test (D61), E22, E24, the login half of E2, E10, E11, E12, E19, E16, E17, E14, E13, E26, E32 and E3, plus the early non-gating PRF run (E1, E2 PRF half).

1. [Story 1.1: Key prototype: AD-36 public-key authentication](stories/story-1.1-key-prototype-ad36-public-key-authentication.md)
2. [Story 1.2: HPKE internal review and cross-test](stories/story-1.2-hpke-internal-review-and-cross-test.md)
3. [Story 1.3: E22: browser device key, PAKE pairing and signed confirmations](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md)
4. [Story 1.4: E24: passkeys and PWA with each naming option](stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md)
5. [Story 1.5: E2 login half: passkey login and action-bound step-up](stories/story-1.5-e2-passkey-login-and-action-bound-step-up.md)
6. [Story 1.6: E10: sandbox profile and peer identity](stories/story-1.6-e10-sandbox-profile-and-peer-identity.md)
7. [Story 1.7: E11: SQLite migration authorizer](stories/story-1.7-e11-sqlite-migration-authorizer.md)
8. [Story 1.8: E12: Argon2id parameters on the reference host](stories/story-1.8-e12-argon2id-parameters-on-the-reference-host.md)
9. [Story 1.9: E19: canonical CBOR in Rust and TypeScript](stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md)
10. [Story 1.10: E16: locked memory and zeroization](stories/story-1.10-e16-locked-memory-and-zeroization.md)
11. [Story 1.11: E17: secure_delete and WAL behaviour](stories/story-1.11-e17-secure-delete-and-wal-behaviour.md)
12. [Story 1.12: E14: egress proxy domain filtering](stories/story-1.12-e14-egress-proxy-domain-filtering.md)
13. [Story 1.13: E13: push delivery reliability](stories/story-1.13-e13-push-delivery-reliability.md)
14. [Story 1.14: E26: separate origin by port for external content](stories/story-1.14-e26-separate-origin-by-port-for-external-content.md)
15. [Story 1.15: E32: Core execution model](stories/story-1.15-e32-core-execution-model.md)
16. [Story 1.16: E3: hybrid key exchange negotiation](stories/story-1.16-e3-hybrid-key-exchange-negotiation.md)
17. [Story 1.17: E1 and E2 PRF half: early run](stories/story-1.17-e1-e2-prf-early-run.md)

### Epic 2: Workspace, merge gates and verification harness

Maintainers build, check and test every crate under the gates that block a merge, in a Debian 13 VM with systemd, with the shared vocabulary and wire types every later epic uses.

1. [Story 2.1: Cargo workspace and crate graph check](stories/story-2.1-cargo-workspace-and-crate-graph-check.md)
2. [Story 2.2: Merge gates: format, lint and supply chain](stories/story-2.2-merge-gates-format-lint-and-supply-chain.md)
3. [Story 2.3: Debian 13 VM CI harness](stories/story-2.3-debian-13-vm-ci-harness.md)
4. [Story 2.4: Shared vocabulary in vilicus-types](stories/story-2.4-shared-vocabulary-in-vilicus-types.md)
5. [Story 2.5: Wire framing and canonical encoding in vilicus-proto](stories/story-2.5-wire-framing-and-canonical-encoding-in-vilicus-proto.md)
6. [Story 2.6: vilicus-testbed binary and testing tree](stories/story-2.6-vilicus-testbed-binary-and-testing-tree.md)

### Epic 3: Encrypted storage and the module platform

A module stores records in encrypted per-partition files with mandatory provenance, validated fields, a Core-owned journal, forward-only migrations on copies and in-partition events, proven end to end by the reference module.

1. [Story 3.1: SQLCipher storage layer and connection authorizer](stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md)
2. [Story 3.2: Module registry and record envelope](stories/story-3.2-module-registry-and-record-envelope.md)
3. [Story 3.3: Tool declarations and capability matrix check](stories/story-3.3-tool-declarations-and-capability-matrix-check.md)
4. [Story 3.4: Structured field validation and reviewed vocabularies](stories/story-3.4-structured-field-validation-and-reviewed-vocabularies.md)
5. [Story 3.5: Typed record writes with taint and data type stamping](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md)
6. [Story 3.6: Core journal tables and caller idempotency](stories/story-3.6-core-journal-tables-and-caller-idempotency.md)
7. [Story 3.7: Forward-only migrations on copies](stories/story-3.7-forward-only-migrations-on-copies.md)
8. [Story 3.8: In-partition events and outbox delivery](stories/story-3.8-in-partition-events-and-outbox-delivery.md)
9. [Story 3.9: Module availability states and fault isolation](stories/story-3.9-module-availability-states-and-fault-isolation.md)
10. [Story 3.10: Reference module exercising the whole contract](stories/story-3.10-reference-module-exercising-the-whole-contract.md)

### Epic 4: Keys and cryptography

Every member key, wrapper and derived file key exists in the kernel only, under the crypto suite of AD-18, with the household key wrapped by HPKE behind its review gate and every member public key authenticated (AD-36).

1. [Story 4.1: Crypto suite and versioned wrappers](stories/story-4.1-crypto-suite-and-versioned-wrappers.md)
2. [Story 4.2: Locked memory and key hygiene](stories/story-4.2-locked-memory-and-key-hygiene.md)
3. [Story 4.3: Key hierarchy and derived file keys](stories/story-4.3-key-hierarchy-and-derived-file-keys.md)
4. [Story 4.4: Passphrase KEK, Argon2id gate and strength check](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md)
5. [Story 4.5: Recovery secret format and recovery KEK](stories/story-4.5-recovery-secret-format-and-recovery-kek.md)
6. [Story 4.6: Household key HPKE wrap with CI cross-test](stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md)
7. [Story 4.7: Member public key authentication (AD-36)](stories/story-4.7-member-public-key-authentication-ad36.md)
8. [Story 4.8: Backup key pair from the backup secret](stories/story-4.8-backup-key-pair-from-the-backup-secret.md)

### Epic 5: Core runtime, processes and packaging

The operator installs a Debian package whose Core, Gateway, audit writer and egress proxy run as sandboxed units on Core-owned sockets with verified peers, with durable time, a Core alert queue, the egress proxy and the root CLI framework.

1. [Story 5.1: Core process and execution model](stories/story-5.1-core-process-and-execution-model.md)
2. [Story 5.2: Core metadata, durable deadlines and alert queue](stories/story-5.2-core-metadata-durable-deadlines-and-alert-queue.md)
3. [Story 5.3: Socket inventory and peer identity](stories/story-5.3-socket-inventory-and-peer-identity.md)
4. [Story 5.4: Systemd units and sandbox profile check](stories/story-5.4-systemd-units-and-sandbox-profile-check.md)
5. [Story 5.5: Egress proxy with per-caller allowlists](stories/story-5.5-egress-proxy-with-per-caller-allowlists.md)
6. [Story 5.6: Admin socket and CLI framework](stories/story-5.6-admin-socket-and-cli-framework.md)
7. [Story 5.7: Debian package install, remove and purge](stories/story-5.7-debian-package-install-remove-and-purge.md)

### Epic 6: Tamper-evident audit log

Every action, refusal, CLI command and authentication event lands in a hash chain held by its own process, survives a writer outage through a bounded spool, and can be verified from the host.

1. [Story 6.1: Audit writer and HMAC chain](stories/story-6.1-audit-writer-and-hmac-chain.md)
2. [Story 6.2: Core audit append path](stories/story-6.2-core-audit-append-path.md)
3. [Story 6.3: Audit spool and emergency set](stories/story-6.3-audit-spool-and-emergency-set.md)
4. [Story 6.4: Audit verify from the host](stories/story-6.4-audit-verify-from-the-host.md)

### Epic 7: Gateway, web client foundation and authentication

Members reach the Core through an HTTPS Gateway and a Lit web client under strict CSP, in French or English, authenticated by passkeys, with step-ups bound to one action and every request signed by a non-extractable device key.

1. [Story 7.1: Gateway HTTPS, certificate and private addresses](stories/story-7.1-gateway-https-certificate-and-private-addresses.md)
2. [Story 7.2: Client API typed once with generated TypeScript](stories/story-7.2-client-api-typed-once-with-generated-typescript.md)
3. [Story 7.3: Web client shell under strict CSP](stories/story-7.3-web-client-shell-under-strict-csp.md)
4. [Story 7.4: French and English catalogs](stories/story-7.4-french-and-english-catalogs.md)
5. [Story 7.5: External content on a separate origin](stories/story-7.5-external-content-on-a-separate-origin.md)
6. [Story 7.6: Passkey authentication and action-bound step-up](stories/story-7.6-passkey-authentication-and-action-bound-step-up.md)
7. [Story 7.7: Device key signed requests and session hardening](stories/story-7.7-device-key-signed-requests-and-session-hardening.md)
8. [Story 7.8: Server-sent change stream](stories/story-7.8-server-sent-change-stream.md)

### Epic 8: Security notifications and first-start bootstrap

The operator turns a fresh install into a named instance with its certificate, an instance admin with a confirmed out-of-browser destination, a backup secret and an admin recovery code, in the fixed order of AD-52; security alerts reach every adult content-free.

1. [Story 8.1: Out-of-browser notification stage](stories/story-8.1-out-of-browser-notification-stage.md)
2. [Story 8.2: Bootstrap token and pre-bootstrap mode](stories/story-8.2-bootstrap-token-and-pre-bootstrap-mode.md)
3. [Story 8.3: Instance name and certificate setup](stories/story-8.3-instance-name-and-certificate-setup.md)
4. [Story 8.4: Instance admin passkey, destination and backup secret](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md)
5. [Story 8.5: Admin recovery code redemption](stories/story-8.5-admin-recovery-code-redemption.md)

### Epic 9: Members, devices and unlock

Adults enroll, unlock, pair browsers, manage their authenticators, add another adult with a delay and veto, suspend accounts, re-enroll a lost passkey and recover with the printed secret (UJ-1 to UJ-3).

1. [Story 9.1: First member enrollment in the wizard](stories/story-9.1-first-member-enrollment-in-the-wizard.md)
2. [Story 9.2: Enroll the first member from the host](stories/story-9.2-enroll-first-member-from-the-host.md)
3. [Story 9.3: Unlock and unlock window in the web client](stories/story-9.3-unlock-and-unlock-window-in-the-web-client.md)
4. [Story 9.4: Unlock from the host](stories/story-9.4-unlock-from-the-host.md)
5. [Story 9.5: Add an adult from the CLI](stories/story-9.5-add-an-adult-from-the-cli.md)
6. [Story 9.6: Member addition delay, veto and household key wrap](stories/story-9.6-member-addition-delay-veto-and-household-key-wrap.md)
7. [Story 9.7: Pair further browsers](stories/story-9.7-pair-further-browsers.md)
8. [Story 9.8: List and remove devices](stories/story-9.8-list-and-remove-devices.md)
9. [Story 9.9: Manage passkeys, passphrase and own destination](stories/story-9.9-manage-passkeys-passphrase-and-own-destination.md)
10. [Story 9.10: Suspend a member from the CLI](stories/story-9.10-suspend-a-member-from-the-cli.md)
11. [Story 9.11: Lift a suspension in the app](stories/story-9.11-lift-a-suspension-in-the-app.md)
12. [Story 9.12: Passkey re-enrollment](stories/story-9.12-passkey-re-enrollment.md)
13. [Story 9.13: Start recovery from the host with a waiting period](stories/story-9.13-start-recovery-from-the-host-with-a-waiting-period.md)
14. [Story 9.14: Complete recovery in the browser](stories/story-9.14-complete-recovery-in-the-browser.md)

### Epic 10: Action pipeline, policy and internal apps

Plugins and AI processes (as test doubles) act only through capability tokens and the ordered pipeline, within partitions and taint rules, with the elevated queue, undo, caps, digest, kill switch, provider policy and channel model enforced by the Core.

1. [Story 10.1: Plugin and AI process handshake with test doubles](stories/story-10.1-plugin-and-ai-process-handshake-with-test-doubles.md)
2. [Story 10.2: Capability tokens](stories/story-10.2-capability-tokens.md)
3. [Story 10.3: Ordered pipeline enforcement](stories/story-10.3-ordered-pipeline-enforcement.md)
4. [Story 10.4: Partition isolation](stories/story-10.4-partition-isolation.md)
5. [Story 10.5: Effective taint and session taint](stories/story-10.5-effective-taint-and-session-taint.md)
6. [Story 10.6: Elevated tier 1 queue and light confirmation](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md)
7. [Story 10.7: Journal undo for members](stories/story-10.7-journal-undo-for-members.md)
8. [Story 10.8: Caps, detectors and daily digest](stories/story-10.8-caps-detectors-and-daily-digest.md)
9. [Story 10.9: Kill switch and resume](stories/story-10.9-kill-switch-and-resume.md)
10. [Story 10.10: Model connector interface and provider policy](stories/story-10.10-model-connector-interface-and-provider-policy.md)
11. [Story 10.11: Provider configuration and credential delivery](stories/story-10.11-provider-configuration-and-credential-delivery.md)
12. [Story 10.12: Channel model against a channel test double](stories/story-10.12-channel-model-against-a-channel-test-double.md)
13. [Story 10.13: Encrypted plugin state store](stories/story-10.13-encrypted-plugin-state-store.md)

### Epic 11: Instance operations and administration

The operator and the instance admin run the instance: status, exposure, rename, swap guard, dead-letter replay, remote audit sink, named private destinations, the member list, clock-jump acknowledgement and the members' audit view.

1. [Story 11.1: vilicus status](stories/story-11.1-vilicus-status.md)
2. [Story 11.2: Exposure setting from the host](stories/story-11.2-exposure-setting-from-the-host.md)
3. [Story 11.3: Rename the instance](stories/story-11.3-rename-the-instance.md)
4. [Story 11.4: Unencrypted swap guard](stories/story-11.4-unencrypted-swap-guard.md)
5. [Story 11.5: Dead-letter replay from the host](stories/story-11.5-dead-letter-replay-from-the-host.md)
6. [Story 11.6: Remote audit sink](stories/story-11.6-remote-audit-sink.md)
7. [Story 11.7: Named private destination for Core traffic](stories/story-11.7-named-private-destination-for-core-traffic.md)
8. [Story 11.8: Member list for the instance admin](stories/story-11.8-member-list-for-the-instance-admin.md)
9. [Story 11.9: Acknowledge a wall-clock jump](stories/story-11.9-acknowledge-a-wall-clock-jump.md)
10. [Story 11.10: Member audit view and head hash](stories/story-11.10-member-audit-view-and-head-hash.md)

### Epic 12: Backups and restore

Backups run unattended to off-host object storage, are verified after each upload, and restore on a fresh host, invalidating every device and session, with a restore drill in CI.

1. [Story 12.1: Backup target configuration](stories/story-12.1-backup-target-configuration.md)
2. [Story 12.2: Unattended backup assembly and upload](stories/story-12.2-unattended-backup-assembly-and-upload.md)
3. [Story 12.3: Backup verification](stories/story-12.3-backup-verification.md)
4. [Story 12.4: Restore on a fresh host](stories/story-12.4-restore-on-a-fresh-host.md)
5. [Story 12.5: Post-restore security state acknowledgement](stories/story-12.5-post-restore-security-state-acknowledgement.md)
6. [Story 12.6: Restore drill in CI](stories/story-12.6-restore-drill-in-ci.md)

### Epic 13: Upgrades, documentation and release

Upgrades are signed, verified, acknowledged and never rolled back; each release ships its documentation and is published by a written procedure with an offline signing key.

1. [Story 13.1: Signed packages and upgrade verify](stories/story-13.1-signed-packages-and-upgrade-verify.md)
2. [Story 13.2: Acknowledged upgrade and maintenance mode](stories/story-13.2-acknowledged-upgrade-and-maintenance-mode.md)
3. [Story 13.3: Anti-rollback version marker](stories/story-13.3-anti-rollback-version-marker.md)
4. [Story 13.4: Upgrade check and CI upgrade test](stories/story-13.4-upgrade-check-and-ci-upgrade-test.md)
5. [Story 13.5: Operator documentation](stories/story-13.5-operator-documentation.md)
6. [Story 13.6: Release procedure and offline signing key custody](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md)

### Epic 14: Release gates and V0.1 exit

Every V0.1 release-gate invariant blocks the release, the FR-50 surfaces are enforced, UJ-1 to UJ-3 run automated and on real devices, and the V0.1 exit criteria are checked.

1. [Story 14.1: V0.1 release-gate invariant suite](stories/story-14.1-v01-release-gate-invariant-suite.md)
2. [Story 14.2: FR-50 surface conformance](stories/story-14.2-fr-50-surface-conformance.md)
3. [Story 14.3: Automated user journeys in the VM](stories/story-14.3-automated-user-journeys-in-the-vm.md)
4. [Story 14.4: Manual device run and release notes](stories/story-14.4-manual-device-run-and-release-notes.md)
5. [Story 14.5: V0.1 exit checklist](stories/story-14.5-v01-exit-checklist.md)

## V0.1 requirements coverage

Every V0.1 functional requirement and every V0.1 release-gate invariant maps to at least one story. Story numbers link to the story files.

### V0.1 functional requirements

| Requirement | Stories |
|-------------|---------|
| FR-1 | [5.7](stories/story-5.7-debian-package-install-remove-and-purge.md) |
| FR-2 | [1.6](stories/story-1.6-e10-sandbox-profile-and-peer-identity.md), [5.3](stories/story-5.3-socket-inventory-and-peer-identity.md), [5.4](stories/story-5.4-systemd-units-and-sandbox-profile-check.md), [13.5](stories/story-13.5-operator-documentation.md) |
| FR-3 | [5.6](stories/story-5.6-admin-socket-and-cli-framework.md), [6.2](stories/story-6.2-core-audit-append-path.md), [6.4](stories/story-6.4-audit-verify-from-the-host.md), [8.2](stories/story-8.2-bootstrap-token-and-pre-bootstrap-mode.md), [9.2](stories/story-9.2-enroll-first-member-from-the-host.md), [9.4](stories/story-9.4-unlock-from-the-host.md), [9.5](stories/story-9.5-add-an-adult-from-the-cli.md), [9.10](stories/story-9.10-suspend-a-member-from-the-cli.md), [9.12](stories/story-9.12-passkey-re-enrollment.md), [10.9](stories/story-10.9-kill-switch-and-resume.md), [11.1](stories/story-11.1-vilicus-status.md), [11.2](stories/story-11.2-exposure-setting-from-the-host.md), [11.3](stories/story-11.3-rename-the-instance.md), [11.4](stories/story-11.4-unencrypted-swap-guard.md), [11.5](stories/story-11.5-dead-letter-replay-from-the-host.md), [12.1](stories/story-12.1-backup-target-configuration.md), [12.2](stories/story-12.2-unattended-backup-assembly-and-upload.md), [12.3](stories/story-12.3-backup-verification.md), [12.4](stories/story-12.4-restore-on-a-fresh-host.md) |
| FR-53 | [4.8](stories/story-4.8-backup-key-pair-from-the-backup-secret.md), [8.4](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md), [12.1](stories/story-12.1-backup-target-configuration.md), [12.2](stories/story-12.2-unattended-backup-assembly-and-upload.md), [12.3](stories/story-12.3-backup-verification.md), [12.4](stories/story-12.4-restore-on-a-fresh-host.md), [12.5](stories/story-12.5-post-restore-security-state-acknowledgement.md), [12.6](stories/story-12.6-restore-drill-in-ci.md), [14.5](stories/story-14.5-v01-exit-checklist.md) |
| FR-54 | [3.7](stories/story-3.7-forward-only-migrations-on-copies.md), [5.7](stories/story-5.7-debian-package-install-remove-and-purge.md), [13.1](stories/story-13.1-signed-packages-and-upgrade-verify.md), [13.2](stories/story-13.2-acknowledged-upgrade-and-maintenance-mode.md), [13.3](stories/story-13.3-anti-rollback-version-marker.md), [13.4](stories/story-13.4-upgrade-check-and-ci-upgrade-test.md) |
| FR-109 | [2.3](stories/story-2.3-debian-13-vm-ci-harness.md), [2.6](stories/story-2.6-vilicus-testbed-binary-and-testing-tree.md), [3.10](stories/story-3.10-reference-module-exercising-the-whole-contract.md), [10.1](stories/story-10.1-plugin-and-ai-process-handshake-with-test-doubles.md), [13.1](stories/story-13.1-signed-packages-and-upgrade-verify.md), [14.3](stories/story-14.3-automated-user-journeys-in-the-vm.md), [14.4](stories/story-14.4-manual-device-run-and-release-notes.md), [14.5](stories/story-14.5-v01-exit-checklist.md) |
| FR-111 | [13.5](stories/story-13.5-operator-documentation.md) |
| FR-112 | [13.1](stories/story-13.1-signed-packages-and-upgrade-verify.md), [13.6](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md), [14.4](stories/story-14.4-manual-device-run-and-release-notes.md) |
| FR-4 | [1.4](stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md), [7.1](stories/story-7.1-gateway-https-certificate-and-private-addresses.md), [8.2](stories/story-8.2-bootstrap-token-and-pre-bootstrap-mode.md), [8.3](stories/story-8.3-instance-name-and-certificate-setup.md), [8.4](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md), [11.1](stories/story-11.1-vilicus-status.md) |
| FR-65 | [1.4](stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md), [7.1](stories/story-7.1-gateway-https-certificate-and-private-addresses.md), [8.3](stories/story-8.3-instance-name-and-certificate-setup.md), [13.5](stories/story-13.5-operator-documentation.md) |
| FR-66 | [11.3](stories/story-11.3-rename-the-instance.md) |
| FR-5 | [8.4](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md), [8.5](stories/story-8.5-admin-recovery-code-redemption.md) |
| FR-6 | [7.1](stories/story-7.1-gateway-https-certificate-and-private-addresses.md), [11.2](stories/story-11.2-exposure-setting-from-the-host.md) |
| FR-7 | [1.1](stories/story-1.1-key-prototype-ad36-public-key-authentication.md), [4.4](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md), [4.5](stories/story-4.5-recovery-secret-format-and-recovery-kek.md), [4.6](stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md), [4.7](stories/story-4.7-member-public-key-authentication-ad36.md), [9.1](stories/story-9.1-first-member-enrollment-in-the-wizard.md), [9.2](stories/story-9.2-enroll-first-member-from-the-host.md) |
| FR-8 | [1.1](stories/story-1.1-key-prototype-ad36-public-key-authentication.md), [4.7](stories/story-4.7-member-public-key-authentication-ad36.md), [9.5](stories/story-9.5-add-an-adult-from-the-cli.md), [9.6](stories/story-9.6-member-addition-delay-veto-and-household-key-wrap.md), [9.11](stories/story-9.11-lift-a-suspension-in-the-app.md), [12.1](stories/story-12.1-backup-target-configuration.md) |
| FR-107 | [9.10](stories/story-9.10-suspend-a-member-from-the-cli.md), [9.11](stories/story-9.11-lift-a-suspension-in-the-app.md), [10.2](stories/story-10.2-capability-tokens.md), [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md) |
| FR-10 | [1.5](stories/story-1.5-e2-passkey-login-and-action-bound-step-up.md), [7.6](stories/story-7.6-passkey-authentication-and-action-bound-step-up.md), [9.9](stories/story-9.9-manage-passkeys-passphrase-and-own-destination.md) |
| FR-108 | [9.12](stories/story-9.12-passkey-re-enrollment.md), [10.2](stories/story-10.2-capability-tokens.md), [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md) |
| FR-11 | [1.8](stories/story-1.8-e12-argon2id-parameters-on-the-reference-host.md), [3.9](stories/story-3.9-module-availability-states-and-fault-isolation.md), [4.4](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md), [9.3](stories/story-9.3-unlock-and-unlock-window-in-the-web-client.md) |
| FR-12 | [2.4](stories/story-2.4-shared-vocabulary-in-vilicus-types.md), [9.3](stories/story-9.3-unlock-and-unlock-window-in-the-web-client.md), [10.9](stories/story-10.9-kill-switch-and-resume.md) |
| FR-57 | [9.4](stories/story-9.4-unlock-from-the-host.md) |
| FR-13 | [1.10](stories/story-1.10-e16-locked-memory-and-zeroization.md), [4.1](stories/story-4.1-crypto-suite-and-versioned-wrappers.md), [4.2](stories/story-4.2-locked-memory-and-key-hygiene.md) |
| FR-14 | [4.5](stories/story-4.5-recovery-secret-format-and-recovery-kek.md), [9.13](stories/story-9.13-start-recovery-from-the-host-with-a-waiting-period.md), [9.14](stories/story-9.14-complete-recovery-in-the-browser.md), [10.2](stories/story-10.2-capability-tokens.md), [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md) |
| FR-15 | [1.3](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md), [7.7](stories/story-7.7-device-key-signed-requests-and-session-hardening.md), [9.1](stories/story-9.1-first-member-enrollment-in-the-wizard.md) |
| FR-16 | [1.3](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md), [9.7](stories/story-9.7-pair-further-browsers.md), [9.8](stories/story-9.8-list-and-remove-devices.md) |
| FR-17 | [1.14](stories/story-1.14-e26-separate-origin-by-port-for-external-content.md), [7.3](stories/story-7.3-web-client-shell-under-strict-csp.md), [7.5](stories/story-7.5-external-content-on-a-separate-origin.md), [7.7](stories/story-7.7-device-key-signed-requests-and-session-hardening.md) |
| FR-18 | [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md) |
| FR-19 | [10.4](stories/story-10.4-partition-isolation.md) |
| FR-20 | [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md), [10.5](stories/story-10.5-effective-taint-and-session-taint.md) |
| FR-58 | [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.4](stories/story-3.4-structured-field-validation-and-reviewed-vocabularies.md), [10.5](stories/story-10.5-effective-taint-and-session-taint.md) |
| FR-21 | [3.3](stories/story-3.3-tool-declarations-and-capability-matrix-check.md) |
| FR-22 | [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.3](stories/story-3.3-tool-declarations-and-capability-matrix-check.md), [3.10](stories/story-3.10-reference-module-exercising-the-whole-contract.md) |
| FR-23 | [1.7](stories/story-1.7-e11-sqlite-migration-authorizer.md), [3.1](stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md), [3.7](stories/story-3.7-forward-only-migrations-on-copies.md), [3.9](stories/story-3.9-module-availability-states-and-fault-isolation.md) |
| FR-24 | [3.6](stories/story-3.6-core-journal-tables-and-caller-idempotency.md), [3.8](stories/story-3.8-in-partition-events-and-outbox-delivery.md), [11.5](stories/story-11.5-dead-letter-replay-from-the-host.md) |
| FR-25 | [10.1](stories/story-10.1-plugin-and-ai-process-handshake-with-test-doubles.md), [10.3](stories/story-10.3-ordered-pipeline-enforcement.md), [10.13](stories/story-10.13-encrypted-plugin-state-store.md) |
| FR-26 | [10.3](stories/story-10.3-ordered-pipeline-enforcement.md) |
| FR-27 | [2.4](stories/story-2.4-shared-vocabulary-in-vilicus-types.md), [10.2](stories/story-10.2-capability-tokens.md) |
| FR-28 | [1.3](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md), [10.6](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md) |
| FR-60 | [3.3](stories/story-3.3-tool-declarations-and-capability-matrix-check.md), [13.6](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md), [14.4](stories/story-14.4-manual-device-run-and-release-notes.md) |
| FR-61 | [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md), [14.5](stories/story-14.5-v01-exit-checklist.md) |
| FR-29 | [1.11](stories/story-1.11-e17-secure-delete-and-wal-behaviour.md), [3.6](stories/story-3.6-core-journal-tables-and-caller-idempotency.md), [10.7](stories/story-10.7-journal-undo-for-members.md) |
| FR-30 | [10.8](stories/story-10.8-caps-detectors-and-daily-digest.md), [10.9](stories/story-10.9-kill-switch-and-resume.md) |
| FR-31 | [6.1](stories/story-6.1-audit-writer-and-hmac-chain.md), [6.2](stories/story-6.2-core-audit-append-path.md), [6.3](stories/story-6.3-audit-spool-and-emergency-set.md), [6.4](stories/story-6.4-audit-verify-from-the-host.md), [10.8](stories/story-10.8-caps-detectors-and-daily-digest.md), [11.10](stories/story-11.10-member-audit-view-and-head-hash.md) |
| FR-32 | [11.6](stories/story-11.6-remote-audit-sink.md), [11.10](stories/story-11.10-member-audit-view-and-head-hash.md), [12.5](stories/story-12.5-post-restore-security-state-acknowledgement.md), [14.5](stories/story-14.5-v01-exit-checklist.md) |
| FR-68 | [2.4](stories/story-2.4-shared-vocabulary-in-vilicus-types.md), [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [10.10](stories/story-10.10-model-connector-interface-and-provider-policy.md), [10.11](stories/story-10.11-provider-configuration-and-credential-delivery.md), [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md) |
| FR-55 | [1.12](stories/story-1.12-e14-egress-proxy-domain-filtering.md), [5.5](stories/story-5.5-egress-proxy-with-per-caller-allowlists.md), [10.11](stories/story-10.11-provider-configuration-and-credential-delivery.md) |
| FR-37 | [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md) |
| FR-56 | [1.13](stories/story-1.13-e13-push-delivery-reliability.md), [8.1](stories/story-8.1-out-of-browser-notification-stage.md), [8.4](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md), [9.1](stories/story-9.1-first-member-enrollment-in-the-wizard.md), [9.5](stories/story-9.5-add-an-adult-from-the-cli.md), [9.6](stories/story-9.6-member-addition-delay-veto-and-household-key-wrap.md), [9.7](stories/story-9.7-pair-further-browsers.md), [9.9](stories/story-9.9-manage-passkeys-passphrase-and-own-destination.md), [9.12](stories/story-9.12-passkey-re-enrollment.md), [9.13](stories/story-9.13-start-recovery-from-the-host-with-a-waiting-period.md), [9.14](stories/story-9.14-complete-recovery-in-the-browser.md), [10.11](stories/story-10.11-provider-configuration-and-credential-delivery.md), [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md), [11.2](stories/story-11.2-exposure-setting-from-the-host.md), [11.3](stories/story-11.3-rename-the-instance.md), [11.6](stories/story-11.6-remote-audit-sink.md), [11.7](stories/story-11.7-named-private-destination-for-core-traffic.md), [12.1](stories/story-12.1-backup-target-configuration.md), [13.2](stories/story-13.2-acknowledged-upgrade-and-maintenance-mode.md) |
| FR-50 | [7.2](stories/story-7.2-client-api-typed-once-with-generated-typescript.md), [7.8](stories/story-7.8-server-sent-change-stream.md), [8.4](stories/story-8.4-instance-admin-passkey-destination-and-backup-secret.md), [9.8](stories/story-9.8-list-and-remove-devices.md), [9.9](stories/story-9.9-manage-passkeys-passphrase-and-own-destination.md), [10.6](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md), [11.6](stories/story-11.6-remote-audit-sink.md), [11.7](stories/story-11.7-named-private-destination-for-core-traffic.md), [11.8](stories/story-11.8-member-list-for-the-instance-admin.md), [11.10](stories/story-11.10-member-audit-view-and-head-hash.md), [12.5](stories/story-12.5-post-restore-security-state-acknowledgement.md), [13.2](stories/story-13.2-acknowledged-upgrade-and-maintenance-mode.md), [14.2](stories/story-14.2-fr-50-surface-conformance.md) |
| FR-52 | [1.14](stories/story-1.14-e26-separate-origin-by-port-for-external-content.md), [7.3](stories/story-7.3-web-client-shell-under-strict-csp.md), [7.5](stories/story-7.5-external-content-on-a-separate-origin.md) |
| FR-110 | [4.4](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md), [4.5](stories/story-4.5-recovery-secret-format-and-recovery-kek.md), [5.6](stories/story-5.6-admin-socket-and-cli-framework.md), [7.4](stories/story-7.4-french-and-english-catalogs.md), [8.1](stories/story-8.1-out-of-browser-notification-stage.md), [9.1](stories/story-9.1-first-member-enrollment-in-the-wizard.md), [9.14](stories/story-9.14-complete-recovery-in-the-browser.md) |

### V0.1 release-gate invariants (`doc/ai-safety.md` section 3.1)

| Invariant | Stories |
|-----------|---------|
| I4 | [1.12](stories/story-1.12-e14-egress-proxy-domain-filtering.md), [5.5](stories/story-5.5-egress-proxy-with-per-caller-allowlists.md), [10.11](stories/story-10.11-provider-configuration-and-credential-delivery.md), [11.7](stories/story-11.7-named-private-destination-for-core-traffic.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I5 | [10.2](stories/story-10.2-capability-tokens.md), [10.4](stories/story-10.4-partition-isolation.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I6 | [1.7](stories/story-1.7-e11-sqlite-migration-authorizer.md), [3.1](stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md), [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.10](stories/story-3.10-reference-module-exercising-the-whole-contract.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I8 | [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.10](stories/story-3.10-reference-module-exercising-the-whole-contract.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I9 | [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md), [10.7](stories/story-10.7-journal-undo-for-members.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I10 | [10.9](stories/story-10.9-kill-switch-and-resume.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I11 | [8.1](stories/story-8.1-out-of-browser-notification-stage.md), [10.8](stories/story-10.8-caps-detectors-and-daily-digest.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I12 | [10.9](stories/story-10.9-kill-switch-and-resume.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I13 | [3.3](stories/story-3.3-tool-declarations-and-capability-matrix-check.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I15 | [10.12](stories/story-10.12-channel-model-against-a-channel-test-double.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I18 | [3.3](stories/story-3.3-tool-declarations-and-capability-matrix-check.md), [10.2](stories/story-10.2-capability-tokens.md), [10.3](stories/story-10.3-ordered-pipeline-enforcement.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I21 | [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md), [10.5](stories/story-10.5-effective-taint-and-session-taint.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I22 | [10.10](stories/story-10.10-model-connector-interface-and-provider-policy.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I24 | [10.1](stories/story-10.1-plugin-and-ai-process-handshake-with-test-doubles.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I33 | [7.6](stories/story-7.6-passkey-authentication-and-action-bound-step-up.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I35 | [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md), [10.5](stories/story-10.5-effective-taint-and-session-taint.md), [10.6](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I36 | [3.2](stories/story-3.2-module-registry-and-record-envelope.md), [3.10](stories/story-3.10-reference-module-exercising-the-whole-contract.md), [10.10](stories/story-10.10-model-connector-interface-and-provider-policy.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I40 | [3.4](stories/story-3.4-structured-field-validation-and-reviewed-vocabularies.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| I43 | [3.5](stories/story-3.5-typed-record-writes-with-taint-and-data-type-stamping.md), [10.10](stories/story-10.10-model-connector-interface-and-provider-policy.md), [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |

### Non-functional and UX design requirements

| Requirement | Stories |
|-------------|---------|
| NFR-1 | [14.1](stories/story-14.1-v01-release-gate-invariant-suite.md) |
| NFR-2 | [4.2](stories/story-4.2-locked-memory-and-key-hygiene.md), [6.2](stories/story-6.2-core-audit-append-path.md), [8.1](stories/story-8.1-out-of-browser-notification-stage.md), [11.10](stories/story-11.10-member-audit-view-and-head-hash.md) |
| NFR-3 | [3.6](stories/story-3.6-core-journal-tables-and-caller-idempotency.md) |
| NFR-4 | [1.8](stories/story-1.8-e12-argon2id-parameters-on-the-reference-host.md), [1.15](stories/story-1.15-e32-core-execution-model.md), [9.3](stories/story-9.3-unlock-and-unlock-window-in-the-web-client.md) |
| NFR-5 | [11.4](stories/story-11.4-unencrypted-swap-guard.md) |
| NFR-6 | [2.2](stories/story-2.2-merge-gates-format-lint-and-supply-chain.md), [13.6](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md) |
| NFR-7 | [1.16](stories/story-1.16-e3-hybrid-key-exchange-negotiation.md), [4.1](stories/story-4.1-crypto-suite-and-versioned-wrappers.md), [4.6](stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md), [13.5](stories/story-13.5-operator-documentation.md) |
| NFR-8 | [7.4](stories/story-7.4-french-and-english-catalogs.md) |
| NFR-9 | [1.3](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md), [1.4](stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md), [1.5](stories/story-1.5-e2-passkey-login-and-action-bound-step-up.md), [1.14](stories/story-1.14-e26-separate-origin-by-port-for-external-content.md), [7.3](stories/story-7.3-web-client-shell-under-strict-csp.md) |
| UX-DR1 | [14.2](stories/story-14.2-fr-50-surface-conformance.md) |
| UX-DR2 | [7.3](stories/story-7.3-web-client-shell-under-strict-csp.md) |
| UX-DR3 | [7.5](stories/story-7.5-external-content-on-a-separate-origin.md) |
| UX-DR4 | [8.1](stories/story-8.1-out-of-browser-notification-stage.md), [9.3](stories/story-9.3-unlock-and-unlock-window-in-the-web-client.md) |
| UX-DR5 | [10.6](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md) |
| UX-DR6 | [7.4](stories/story-7.4-french-and-english-catalogs.md) |
| UX-DR7 | [7.8](stories/story-7.8-server-sent-change-stream.md) |

### V0.1-gating experiments

| Experiment | Stories |
|------------|---------|
| AD-36 | [1.1](stories/story-1.1-key-prototype-ad36-public-key-authentication.md), [4.7](stories/story-4.7-member-public-key-authentication-ad36.md), [9.1](stories/story-9.1-first-member-enrollment-in-the-wizard.md), [9.5](stories/story-9.5-add-an-adult-from-the-cli.md), [9.6](stories/story-9.6-member-addition-delay-veto-and-household-key-wrap.md) |
| D61 | [1.2](stories/story-1.2-hpke-internal-review-and-cross-test.md), [4.6](stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md) |
| E2 | [1.5](stories/story-1.5-e2-passkey-login-and-action-bound-step-up.md), [1.17](stories/story-1.17-e1-e2-prf-early-run.md), [7.6](stories/story-7.6-passkey-authentication-and-action-bound-step-up.md) |
| E3 | [1.16](stories/story-1.16-e3-hybrid-key-exchange-negotiation.md), [14.5](stories/story-14.5-v01-exit-checklist.md) |
| E10 | [1.6](stories/story-1.6-e10-sandbox-profile-and-peer-identity.md), [5.3](stories/story-5.3-socket-inventory-and-peer-identity.md) |
| E11 | [1.7](stories/story-1.7-e11-sqlite-migration-authorizer.md), [3.1](stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md), [3.7](stories/story-3.7-forward-only-migrations-on-copies.md) |
| E12 | [1.8](stories/story-1.8-e12-argon2id-parameters-on-the-reference-host.md), [4.4](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md) |
| E13 | [1.13](stories/story-1.13-e13-push-delivery-reliability.md), [8.1](stories/story-8.1-out-of-browser-notification-stage.md) |
| E14 | [1.12](stories/story-1.12-e14-egress-proxy-domain-filtering.md), [5.5](stories/story-5.5-egress-proxy-with-per-caller-allowlists.md) |
| E16 | [1.10](stories/story-1.10-e16-locked-memory-and-zeroization.md), [4.2](stories/story-4.2-locked-memory-and-key-hygiene.md), [13.5](stories/story-13.5-operator-documentation.md) |
| E17 | [1.11](stories/story-1.11-e17-secure-delete-and-wal-behaviour.md), [3.6](stories/story-3.6-core-journal-tables-and-caller-idempotency.md) |
| E19 | [1.9](stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md), [2.5](stories/story-2.5-wire-framing-and-canonical-encoding-in-vilicus-proto.md) |
| E22 | [1.3](stories/story-1.3-e22-browser-device-key-pake-and-signed-confirmations.md), [7.7](stories/story-7.7-device-key-signed-requests-and-session-hardening.md), [9.7](stories/story-9.7-pair-further-browsers.md), [10.6](stories/story-10.6-elevated-tier-1-queue-and-light-confirmation.md) |
| E24 | [1.4](stories/story-1.4-e24-passkeys-and-pwa-with-each-naming-option.md), [7.6](stories/story-7.6-passkey-authentication-and-action-bound-step-up.md), [8.3](stories/story-8.3-instance-name-and-certificate-setup.md), [13.5](stories/story-13.5-operator-documentation.md) |
| E26 | [1.14](stories/story-1.14-e26-separate-origin-by-port-for-external-content.md), [7.5](stories/story-7.5-external-content-on-a-separate-origin.md) |
| E32 | [1.15](stories/story-1.15-e32-core-execution-model.md), [5.1](stories/story-5.1-core-process-and-execution-model.md) |

## Decision tasks placed in stories

Open points settled inside a story, each with its recommended answer. The story that carries the task records the outcome; a change to a decision record goes to [`decisions.md`](decisions.md) in the same change. Points the owner settled on 2026-10-16 (D116 to D118, and the rows they added to PRD FR-50) are marked settled in their stories and no longer listed here.

- [Story 1.2](stories/story-1.2-hpke-internal-review-and-cross-test.md): Decide which independent HPKE implementation the cross-test uses, before the review starts. Recommended: `hpke-rs` with its RustCrypto provider, as a dev-dependency only. Gives up: a second Rust implementation shares the language and ecosystem, so a C implementation would be more independent but costs FFI in the test harness.
- [Story 1.2](stories/story-1.2-hpke-internal-review-and-cross-test.md): Decide where the written review is committed. Recommended: `doc/reviews/hpke-review.md`. Gives up: nothing material; the path only needs to be stable for later links.
- [Story 1.9](stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md): Decide the Rust CBOR crate between `cbor4ii` and `dcbor` (spine Deferred). Recommended: `dcbor`, because it enforces the deterministic profile and rejects non-canonical input natively, which is the property AD-13 relies on. Gives up: `cbor4ii` speed and serde integration, so closed-type mapping takes more code in `vilicus-proto`.
- [Story 1.9](stories/story-1.9-e19-canonical-cbor-in-rust-and-typescript.md): Decide the TypeScript CBOR decoder package (approved by D113). Recommended: `cbor2`. Gives up: a smaller decoder that would need its own canonical checks.
- [Story 3.1](stories/story-3.1-sqlcipher-storage-layer-and-connection-authorizer.md): Decide the SQLCipher version (spine Deferred). Recommended: keep the bundled 4.14.0 of `rusqlite` 0.40.2 unless a reading of the SQLCipher changelog from 4.14.0 to 4.19.x shows a security fix, in which case pin a self-built 4.19.x; record the reading and the choice before V0.1 ships. Gives up: the self-built path costs a build script and a vendored source.
- [Story 4.4](stories/story-4.4-passphrase-kek-argon2id-gate-and-strength-check.md): Decide the passphrase strength library (approved by D113). Recommended: the `zxcvbn` crate, run in the Core with an added French dictionary; verify first that the crate accepts additional dictionaries, and if it cannot, stop and report before choosing another library. Gives up: a JavaScript estimator would give feedback in the browser, but the passphrase reaches the Core anyway and one check in one place is simpler.
- [Story 4.6](stories/story-4.6-household-key-hpke-wrap-with-ci-cross-test.md): Decide the independent HPKE implementation (carried from Story 1.2). Recommended: `hpke-rs`, as a dev-dependency only. Gives up: a second Rust implementation shares the language and ecosystem, so a C implementation would be more independent but costs FFI in the test harness.
- [Story 9.9](stories/story-9.9-manage-passkeys-passphrase-and-own-destination.md): Confirm the FR-50 level for changing one's own destination. Recommended: step-up then test notification token, as FR-50 states, because the destination is where recovery and veto alerts go. Gives up: a member must have a working passkey to fix a broken destination, which recovery covers.
- [Story 11.6](stories/story-11.6-remote-audit-sink.md): Decide the confirmation level for configuring or changing the remote sink. Recommended: a step-up bound to the configuration with every adult notified, as FR-50 states, since a wrong sink silently weakens the root-tamper claim. Gives up: nothing material.
- [Story 12.2](stories/story-12.2-unattended-backup-assembly-and-upload.md): Decide the S3-compatible client (approved by D106). Recommended: `rusty-s3` (request signing only, no bundled HTTP stack, so uploads reuse the workspace HTTP client through the egress proxy), pinned in the Stack. Gives up: a full SDK's retry and multipart helpers.
- [Story 12.5](stories/story-12.5-post-restore-security-state-acknowledgement.md): Decide the confirmation level for acknowledging the restored security state. Recommended: an authenticated session, as FR-50 states, because the acknowledgement reads state and grants nothing. Gives up: nothing material.
- [Story 13.6](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md): Decide the release location. Recommended: the project's GitHub releases page, as FR-112 states, with the detached signature as the trust anchor rather than the hosting. Gives up: independence from one hosting provider.
- [Story 13.6](stories/story-13.6-release-procedure-and-offline-signing-key-custody.md): Decide the custody procedure. Recommended: primary key generated on an offline machine, stored on two encrypted removable media kept in separate places, a revocation certificate stored with them, signing done offline over the copied artefact hashes, every use logged in the procedure. Gives up: signing speed.
