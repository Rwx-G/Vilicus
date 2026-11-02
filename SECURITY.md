# Security Policy

## Supported Versions

Vilicus has no release yet. Nothing is supported for production use: the `main` branch is development code, and no instance should hold real household data.

| Version | Supported |
|---------|-----------|
| `main` (development) | Reports welcome, no production support |

Once releases exist, this table will name the release lines that receive fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report them privately, either by email to **romain@rwx-g.fr** or through a [private security advisory](https://github.com/Rwx-G/Vilicus/security/advisories/new) on this repository.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

A weakness in the design documents counts too: a threat the [threat model](doc/threat-model.md) misses, or a mitigation that does not hold, is worth reporting before the code that relies on it is written.

## Response Timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 30 days for critical issues

## Security Design

What Vilicus is meant to protect, against whom, and what it does not protect against is written down before the code:

- [Threat model](doc/threat-model.md): assets, adversaries, threats and mitigations
- [Key management](doc/key-management.md): key hierarchy, unlock, recovery, rotation
- [AI safety](doc/ai-safety.md): the rules and invariants for an assistant that acts
- [Architecture](doc/architecture.md), section 2 and the remaining risks: what is guaranteed, what depends on the deployment, and what is out of scope
- [Decisions](doc/decisions.md): every security-relevant choice, with its status

Properties that depend on the deployment or the hardware (a TPM, a paired native app, an off-host audit sink) are stated as conditions, never as guarantees.

## Supply Chain

Every merge runs `cargo deny`, `cargo vet` and `cargo audit` against the locked and vendored dependency tree; dependencies are built from `vendor/`, checked against `Cargo.lock`, and the SQLCipher source is vendored and checked against its hashes. No home-made cryptography: only audited libraries, and any exception is recorded in the decision log.
