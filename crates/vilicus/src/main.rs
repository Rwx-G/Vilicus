//! The `vilicus` executable: one binary whose subcommands run the Core, the Gateway, the audit
//! writer, the egress proxy and each AI process role as separate systemd units, and the host CLI
//! (`vilicus <noun> <verb>`).
//!
//! It links no test crate: the reference module and the test doubles reach `vilicus-testbed`
//! only (`doc/architecture-spine.md`, AD-2, AD-3 and Consistency Conventions, CLI).

fn main() {}
