---
title: 'Vendored SQLCipher amalgamation'
author: Rwx-G
---

# Vendored SQLCipher amalgamation

`sqlite3.c` is the SQLCipher 4.19.0 community amalgamation, generated from the official release tag of <https://github.com/sqlcipher/sqlcipher>. `vilicus-storage`'s `build.rs` compiles it into every build, in place of the SQLCipher 4.14.0 that `rusqlite`'s `bundled-sqlcipher` feature would compile (D143). SQLCipher 4.15.0 fixed CVE-2026-51936, a defensive mode bypass through `sqlcipher_export` (Story 3.1, Implementation Notes).

## Origin

- Tag: `v4.19.0`, tag object `58beb4a302f0e3c37341d2312cef521f858b1273`, on commit `c4b275a47932888216bade83aff2bbc73df0ff85`.
- `sqlite3.c`: generated with `configure` and `make sqlite3.c` from that commit. SHA-256 `8640c653acadf665cce6331646f60b5b74a4690746f2c4a2d8f688a0570a0c0c`. SQLite 3.53.4 inside, SQLCipher 4.19.0.
- `LICENSE.md`: SQLCipher's licence, the BSD 3-clause licence of Zetetic LLC, copied from the tag. SHA-256 `2a2826f6acf46fa650730cf42cbb22a642be33a7ef119c9c4f4bf6daf3bef48e`.
- `SQLITE_LICENSE.md`: the public domain dedication of the SQLite code, copied from the tag. SHA-256 `595e823c2ada6c839679e693bee1f4d7f88e2d34ac99a913ae41e3d43fb10c7d`.

`SHA256SUMS` holds these hashes. Two CI checks hold the directory:

- `ci/check_sqlcipher_source.py`, in the `workspace-policy` job, fails when a file differs from `SHA256SUMS`, when a file not listed there sits in this directory, when this README, `regenerate.sh` and `SHA256SUMS` disagree, or when `regenerate.sh` names a repository other than the official one.
- The `sqlcipher-regenerate` job runs `regenerate.sh` and fails unless the tag produces the committed files, byte for byte. It runs when this directory, the workflow or either script changes, and weekly. A change to `sqlite3.c` that also updates `SHA256SUMS` and this README passes the first check and fails this one.

## Regenerating

`regenerate.sh` clones the tag, checks the tag object and the commit, runs `configure` and `make sqlite3.c`, and compares the result with `SHA256SUMS`. Generation needs git, a C compiler and make, and no tclsh: SQLite's build compiles its bundled `jimsh` for the amalgamation script. It needs the network for the clone. From the repository root:

```sh
docker run --rm -v "$PWD:/w:ro" -w /w \
  rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a \
  bash crates/vilicus-storage/sqlcipher/regenerate.sh
```

It prints `regenerates to the files of SHA256SUMS, byte for byte` and exits 0 when the committed files are what the tag produces, compared both by hash and with `cmp`. The output does not depend on the build directory or on the `configure` options.

To move to another release, change `TAG`, `TAG_OBJECT` and `COMMIT` in `regenerate.sh` and run it with `--write`, with the checkout mounted without `:ro`. That replaces `sqlite3.c`, the licence files and `SHA256SUMS`. Then update this README, and review the SQLCipher changelog and the diff. The engine test of `vilicus-storage` asserts the pinned version, and the version change needs a decision record (D143).
