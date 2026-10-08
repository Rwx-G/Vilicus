# Key management

Status: design phase, no code yet. Revision 1. Components and processes are described in [architecture.md](architecture.md); this document owns everything about keys: hierarchy, enrollment, unlock, recovery, delegation, rotation and loss. Open items are marked **open** and repeated in [research-notes.md](research-notes.md).

## 1. Principles

1. Data is protected by random keys, never directly by passwords or passkeys. Secrets only wrap keys, so a factor can be added, removed or changed without re-encrypting data.
2. Every member key has several independent ways to be unwrapped. Losing one way loses nothing.
3. The passkey is never the only way in: a passphrase is mandatory, and an offline recovery secret is generated at enrollment.
4. The instance admin is separate from data keys. The admin runs the system, not the members' data. No admin operation re-wraps a member's key.
5. The Core sees unlocked keys. This is **not zero-knowledge**. The protection is against stolen disks, stolen backups and offline attackers, and against other members and other modules. It is not a protection against a compromised running host (`threat-model.md`, A7).
6. Use audited libraries and standard constructions only. No home-made primitives.

## 2. Key hierarchy

| Key | Type | Lifetime | Stored as | Purpose |
|-----|------|----------|-----------|---------|
| Instance key | 256-bit random | Instance life, rotated by admin | systemd credential, TPM-sealed when available | Encrypts `core.db` metadata; seals delegation sub-keys; never decrypts member or household data. Not needed to unlock data |
| Audit key | 256-bit random | Instance life | Credential of the audit process only | HMAC chain of the audit log |
| Member DEK | 256-bit random | Member life, rotatable | Wrapped N times (one wrapper per KEK) in `core.db` | Root of the member's personal partition |
| Member KEK, passkey | 256-bit, derived | Per enrolled authenticator | Not stored; recomputed from the authenticator | Wraps the DEK |
| Member KEK, passphrase | 256-bit, derived | Until passphrase change | Not stored; derived by Argon2id | Wraps the DEK |
| Member KEK, recovery | 256-bit, derived | Until regenerated | Not stored; derived from the printed secret | Wraps the DEK |
| Member key pair | X25519 or equivalent, in HPKE form | Member life | Public key in `wrappers.db`; private key wrapped by the member DEK | Lets any unlocked adult wrap HK for a member who is locked |
| Household key (HK) | 256-bit random, versioned | Rotated when a member leaves | Wrapped once per adult member to that member's public key; and under the threshold recovery key | Root of the household partition | Root of the household partition |
| Database keys | 256-bit, derived | Per file | Not stored; HKDF from the partition root with the module name and file generation | SQLCipher raw key of one `<module>.<partition>.db` file |
| Record keys | 256-bit random | Per sensitive record | Wrapped in the same database by the database key's derivative | Crypto-shredding (delete = destroy key) |
| Delegation sub-key | 256-bit random | Until revoked or member removal | Wrapped by the instance key | Lets background tasks open one module's database for one partition |
| Device signing key | Asymmetric, in hardware | Device life | Android Keystore / StrongBox, TPM, Secure Enclave | Signs tier 2 confirmations; never wraps data keys |

Derivations use HKDF-SHA-256 with a version and a domain label in `info` such as `vilicus/v1/db/<module>/<partition>/<generation>`. Wrapping uses an authenticated encryption primitive from an audited library (AES-256-GCM or an AES key-wrap construction; the choice is made at implementation and stored in the algorithm identifier of every wrapper).

## 3. Enrollment of a member

1. The admin creates the member account (an invitation). No key exists yet. The invitation link is completed only with a short code shown to an existing adult, who reads it to the invitee out of band, so a leaked link alone does not create a member.
2. The member opens the invitation on a device, chooses a **passphrase** (strength check, not a composition rule), and enrolls the first **authenticator**.
3. The Core generates the **member DEK** with its CSPRNG during the enrollment ceremony (it sees the key anyway, see principle 5). The Core wraps it under the passphrase KEK, and under the KEK of the enrolled passkey if the authenticator returns a PRF result.
4. The Core generates a **recovery secret** of at least 128 bits of entropy (printed as words or grouped characters with a checksum), shows it once, and requires the member to re-type part of it to prove it was copied. The Core derives the recovery KEK, wraps the DEK, and discards the secret.
5. Enrollment is only completed with **at least two authenticators, or one authenticator plus the printed recovery secret** confirmed as above. The wizard says plainly that losing every authenticator, the passphrase and the printed secret destroys the personal partition.
6. Each additional authenticator is a new wrapper. It requires an unlocked session and a passkey step-up, so the existing unwrapped DEK can be re-wrapped for it.

### Passkey wrapping details

- The WebAuthn PRF extension (built on the CTAP hmac-secret extension) is evaluated **per credential**: the secret is specific to the authenticator and credential, so there is one wrapper per authenticator and a synced passkey from one provider does not produce the same secret on another provider.
- Per credential, the Core stores a random PRF input salt. The client evaluates PRF with that input, obtaining a 32-byte output; the KEK is `HKDF-SHA-256(prf_output, salt = credential_salt, info = "vilicus/v1/kek/passkey/" || member_id || credential_id)`.
- The PRF output is computed **client-side** and sent to the Core (over TLS, through the Gateway) in the same exchange as the login assertion. The Core derives the KEK, unwraps the DEK, keeps the DEK in memory for the session, and drops the KEK. The Core therefore sees the PRF output and the DEK. This is stated everywhere as a limit (R3 in `architecture.md`).
- Not every authenticator, browser and OS supports PRF; support differs between platform and roaming authenticators and between password managers acting as passkey providers. Where PRF is unavailable the passkey authenticates the login and the passphrase unlocks the data. Compatibility is a **test item** (`research-notes.md`, E1, E2).

### Passphrase wrapping details

- KEK = Argon2id(passphrase, salt, m, t, p) with a per-wrapper random salt; the parameters are stored in the wrapper header so they can be raised later. Parameters are tuned on the target hardware (floor chosen from current published guidance, ceiling from acceptable unlock latency on a small host). Because the Core does the work, unauthenticated requests must not be able to trigger it freely: the passphrase path runs only after a first authentication factor, with a global concurrency limit.

## 4. Unlocking

| Path | Needs | Result |
|------|-------|--------|
| Passkey with PRF | Authenticator present, user verification | Login and unlock in one gesture |
| Passkey without PRF + passphrase | Authenticator for login, passphrase for unlock | Login then unlock |
| Fallback login (TOTP) + passphrase | TOTP code and passphrase | Login and unlock on a device with no passkey; the session cannot do tier 2, pairing or step-up |
| Recovery | See section 6 | Slow path with waiting period |

After unlock the Core holds the DEK (and the HK for adults) in locked memory for the session. Opening a module database for a partition derives its key at that moment. Closing: session expiry or logout drops the keys when no delegation or running task still needs them; each member is unlocked independently. Locking is also available on demand.

An instance restart locks everything. There is no auto-unlock: the keys are never on disk in usable form. The cost is that unattended restarts leave the instance locked until a member signs in; the design pays that cost deliberately, with queued background tasks waiting (section 7).

## 5. The household key

- The household partition uses a household key HK with a **version**. Every adult member holds a wrapper of HK sealed to their own public key (HPKE), whose private half is wrapped by their DEK. Any unlocked adult opens the shared partition, and any unlocked adult can create or replace the wrapper of a locked adult without that adult's secrets. If no adult is unlocked, nothing about the household partition changes until one is. Children members read and write the household partition through the Core's policy under an adult-granted capability, not by holding HK, unless the household chooses otherwise (open, to decide with the first real use).
- **Adding or removing an adult** needs a signed confirmation from every other adult (a quorum rule can be configured), a delay (proposal: 24 hours) and a notification to the person concerned, so one adult cannot enrol an accomplice or expel the other alone. Adding is a human-only H action: the approving adult's session wraps HK for the new member. The admin cannot do it and cannot see HK.
- **Rotation on departure.** When a member leaves: a new HK version n+1 is generated; wrappers for the departed member are deleted; the new key is wrapped for the remaining adults. Data is re-encrypted in the background soon after the rotation (deferred, not instantaneous) with visible progress (the household sees how much remains), and the old version remains available to remaining adults until every file is rekeyed, then is destroyed. Backups taken before the rotation are treated as exposed to the departed member. What rotation protects: data written after the departure, and the old data once rekeyed against any later leak of the departed member's wrapper. What it does not: anything the departed member already read, copied or exported.
- **Threshold recovery.** A household recovery key is split among adults with Shamir secret sharing (2 adults of N required) and wraps HK as an additional wrapper. It is used when no single adult can unwrap HK any more (for example every adult lost their DEK access but at least two kept their share) and it prevents any single adult, or the admin, from resetting household access alone. Each share is printed and stored by its adult, separate from that adult's personal recovery secret. For a two-adult household, N equals 2 and k equals 2, so the benefit over individual wrappers is small and the cost is real; the feature is optional there. Whether to ship it in v1 is **open** (D7).

## 6. Recovery

- Every member has a printed **recovery secret** from enrollment. It is the only factor of last resort. No admin function can reset it.
- Recovery flow: the member presents the recovery secret (not through any channel that would pass it to the AI). The Core starts a **waiting period** (proposal: 48 hours, adjustable by the household) and sends an alert to every enrolled device and notification channel of that member, with a one-tap cancel. Each device must acknowledge the alert; if some enrolled device has not acknowledged, the waiting period is extended and the Core signals the silence, because a compromised Gateway or notification path could otherwise drop the alerts. Apps show an alarm when the Core's signed heartbeat stops. After the delay, and if not canceled, the member sets a new passphrase and re-enrolls authenticators; the old wrappers are deleted; a new recovery secret is issued.
- During the waiting period the member's existing sessions and devices keep working, and the cancel button is available to any of them. Recovery of the household partition (threshold) follows the same waiting period and alerts all adults.
- If a member loses every authenticator, the passphrase and the recovery secret, the personal partition is **permanently lost**. The Core cannot help, by design. Data of the household partition survives if another adult exists.
- A recovery attempt with a wrong secret is rate limited and alerts. TOTP and passkey fallback are never valid for recovery.

## 7. Background tasks and delegation

Background tasks (mail polling, calendar sync, shopping list preparation) need a database open while no human is present. Options, in order of preference:

1. **Unlocked members only.** The task runs while its member is unlocked. Default for everything.
2. **Sealed inbox (preferred for ingest tasks).** A task that only needs to *write* while the member is locked (mail polling, calendar sync) appends to an append-only inbox sealed to the member's public key; it never holds a database key, and the member's next unlock ingests the inbox. This keeps the database closed.
3. **Delegation sub-key**, only when a task must also *read*. A member, with a passkey step-up, explicitly creates a delegation: a random sub-key that encrypts a copy of the database key of **one module in one partition** (for example the meals database of the household partition for the shopping task). The sub-key is stored under the instance key so the task can run while the member is locked. The delegation is revocable, of reduced scope, never grants access to HK itself or to other modules, and **dies with the member's removal or revocation**: revocation re-keys the module database (the delegated key becomes useless) and destroys the sub-key.
4. **Otherwise wait.** If the instance is locked and the task has no delegation, it waits for an unlock up to a maximum (proposal: 12 hours), then is canceled, and the cancellation is logged. The member gets a content-free notification in the app and the web client.

A TPM with PCR binding is recommended when delegations exist. Trade-off, stated plainly: a delegated module is decryptable by whoever holds the instance key (a stolen disk with the TPM unsealed, or root on the host). It trades some at-rest protection for availability. The default is no delegation, the UI shows active delegations, and the audit log records creation, use and revocation.

## 8. Rotation

| Key | Trigger | Procedure |
|-----|---------|-----------|
| Passphrase | User request, suspected exposure | New Argon2id wrapper, old one deleted |
| Passkey | New authenticator, lost authenticator | Add wrapper (unlocked session), delete wrapper of a lost one |
| Recovery secret | After use, or on request | Generate new, show once, delete old wrapper |
| Member DEK | Suspected key exposure (rare) | Generate new DEK, rekey every member database file, re-wrap, and re-issue or revoke every delegation of that member; heavy, offered as a maintenance task |
| Household key | Member departure; suspected exposure | Section 5 |
| Database keys | Part of DEK or HK rotation, or per-file `generation` bump | Rekey the file, bump `generation` in the derivation |
| Delegation sub-key | Revocation, member removal | Section 7 |
| Instance key | Admin request, TPM change | Re-encrypt `core.db`, re-seal delegation sub-keys |
| Audit key | Admin request | New chain segment, old head hash anchored |
| Algorithms | Deprecation of a primitive | Wrapper header carries an algorithm identifier; new wrappers use the new one; old ones are rewritten at the next unlock |

## 9. Wrapper format and crypto agility

Every wrapper is a versioned structure: format version, algorithm identifiers (KDF, KEK derivation, AEAD), KDF parameters, salt or credential reference, nonce, ciphertext, tag, creation time and wrapper id. Keys never appear unversioned. The version lets the Core refuse to downgrade, rewrite old wrappers during an unlock, and run two algorithms side by side during migration. This is the entire post-quantum preparation at rest: symmetric 256-bit keys are not the weak point; hybrid transport is handled in `architecture.md`, section 15.

## 10. Memory handling

DEKs, HK and derived keys live in locked memory (`mlock`), are zeroized on drop, and are never logged, swapped or dumped; core dumps are disabled; keys are not passed to modules, plugins or AI processes (modules receive opened handles; the AI receives data only through tools). Process crashes drop keys and lock the instance. This reduces exposure but does not stop a root attacker (R1).

## 11. Loss and failure matrix

| Situation | Outcome |
|-----------|---------|
| Lose one authenticator | Nothing lost; remove its wrapper, enroll another |
| Lose all authenticators, remember passphrase | Unlock with passphrase, enroll new authenticators |
| Lose passphrase, keep an authenticator with PRF | Unlock with passkey, set a new passphrase |
| Lose all authenticators and passphrase, keep recovery secret | Recovery flow with waiting period |
| Lose everything for one member | Personal partition lost. Household partition survives if another adult can unwrap HK |
| Lose everything for all adults | Household partition lost unless threshold shares remain |
| Admin account lost | No data impact. The admin recovery code printed at bootstrap restores system control only |
| Instance key lost (TPM change, restore on a new host) | Metadata in `core.db` and delegation sub-keys are lost; data stays unlockable from `wrappers.db`; the admin rebuilds `core.db` |
| Attacker obtains the recovery secret | Waiting period alert is the defense; member cancels |
| Attacker obtains the disk | Sees metadata if they also have the instance key; no data |
| Attacker obtains backup | As stolen disk |
| Departed member keeps an old wrapper copy | Can read data of versions they already could, not newer versions after rotation |
| Weak passphrase | Argon2id raises cost, does not fix a weak secret; passkey with PRF is preferred |

## 12. Open questions

- Whether children's accounts hold HK or only a policy-granted capability (section 5).
- Whether threshold recovery ships in v1 (section 5, D7).
- Exact AEAD and wrap construction, to be fixed with the first prototype.
- PRF behavior in the native Android credential API and in `webauthn-rs` (E1, E2).
- How the native app establishes an inner encrypted channel to the Core that bypasses the Gateway for the PRF output (R3).
- Interaction between per-record keys and full-text search for the mail and document modules.
