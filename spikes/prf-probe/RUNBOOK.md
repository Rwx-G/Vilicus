---
title: 'PRF probe: household device run'
author: Rwx-G
story: 1.17
---

# PRF probe: household device run

The real run of story 1.17 (E1, E2 PRF half): does each household device, browser and passkey
provider return a stable 32-byte PRF output per credential and salt across sessions? `run.sh`
only proves the pipeline with a virtual authenticator; this runbook produces the result.

## What is recorded, and what is not

Per ceremony the server appends one line to `results.jsonl` in its Docker volume: the label you
type, a short hash of the credential ID, the AAGUID, the signed flags (user verified, backup
eligible, backup state), the authenticator extension keys, `prf.enabled`, the SHA-256 and the
length of each PRF output, the transports and the browser user agent.

The PRF outputs never leave the page; only their digests are sent. The user agent can name a
phone model, so `results.jsonl` stays in the Docker volume and is never copied into the
repository. The table from `./serve.sh report` carries no user agent: the label is the only
device identifier, and it is yours to choose.

## Prerequisites

- A host on the household LAN with Docker; the commands below run from Git Bash or Linux in
  `spikes/prf-probe/`.
- A DNS name for that host that every device resolves on the LAN, set in the router or the
  local DNS server, for example `prf-probe.home.arpa` (RFC 8375). WebAuthn refuses an IP
  address as relying party, so a name is required. Use the same name for the whole run: the
  certificates are generated for it once.
- TCP port 8443 reachable from the devices (host firewall).

## Steps

1. **Start the probe.**
   `./serve.sh start prf-probe.home.arpa`
   It builds the probe, generates a local CA and a server certificate at the first start, and
   prints a `SERVER` line ending in `ca_sha256=...`. Note that fingerprint.

2. **Export the CA.** `./serve.sh ca > ca.crt`. The CA is name-constrained to the probe's host
   name and its private key was never written, so it can vouch for that one name only.

3. **Install the CA on each device** (copy `ca.crt` by USB or a file share; menu paths vary by
   vendor and version):
   - Android: Settings, Security (or Security and privacy), Encryption and credentials, Install
     a certificate, CA certificate. Chrome on Android is expected to trust user-installed CAs;
     if the page shows a certificate warning, stop: WebAuthn refuses such a page.
   - Firefox on Android: it has its own trust store; enable its option to use third-party
     (user-installed) CA certificates. Its location has moved between versions (at the time
     of writing, a hidden setting unlocked from About Firefox), so check Firefox's help.
   - iOS or iPadOS, if any: install the profile, then enable full trust for it in Settings,
     General, About, Certificate Trust Settings.
   - Desktop browsers, if tested: the system or browser certificate store.
   Where the device shows the certificate's SHA-256 fingerprint, compare it with step 1.

4. **Register, once per combination.** On the device, open
   `https://prf-probe.home.arpa:8443/`. A combination is a device, a browser and a passkey
   provider. Type a label that names no person and no phone model, for example
   `device-1 chrome gpm`, press Register, and pick the provider in the system sheet. The page
   shows the stored record; `prf_enabled` and `first_sha256` say at once whether PRF was
   offered at registration.

5. **Log in now, then in later sessions.** Press Log in next to the label right after
   registering (session 1). Then fully close the browser, and log in again on another day,
   after a reboot if possible (session 2, ideally 3). A credential needs at least two logins
   before the table can call it stable.

6. **Combinations worth covering**, as far as the household has them:
   - Chrome on Android with Google Password Manager (platform authenticator).
   - Chrome on Android with each third-party passkey provider installed (password managers;
     Android 14 and later route them through Credential Manager).
   - Firefox on Android with the same providers.
   - A roaming authenticator (security key over NFC or USB), if one exists: AC1 asks for a
     platform and a roaming authenticator.
   - Cross-device: a desktop browser registering with the phone over the QR code (hybrid).
   - The desktop browsers of the E2 supported list, if the PRF half should cover them.

7. **Read the result.** `./serve.sh report` prints the Markdown table, also served at
   `/api/report`. The verdicts are documented on `Verdict` in `src/probe.rs`. An AAGUID names
   a provider model, not a phone; the community list of passkey provider AAGUIDs maps it to a
   name. Copy the table into the story's Result section, keeping the labels as they are.

8. **Clean up.**
   - `./serve.sh stop`.
   - Delete the test passkeys from each provider; they are named `vilicus-prf-probe <label>`.
   - Remove the CA from each device.
   - `docker volume rm vilicus-prf-probe-lan` once the table is recorded.

## What this run does not cover

- **The native Credential Manager API from an Android app** (AC1 as written). The browsers on
  Android 14 and later use Credential Manager for third-party providers, so the browser rows
  exercise it indirectly, but an app calling it directly is not built: it needs an Android
  toolchain and a Digital Asset Links file for the relying party domain, which Google Play
  services is expected to fetch from a publicly reachable HTTPS origin (not verified here).
- **Unlock.** The probe never derives a key from the output; the KEK derivation of
  `doc/key-management.md` (Passkey wrapping details) is out of scope until PRF unlock is
  scheduled after V0.1.
