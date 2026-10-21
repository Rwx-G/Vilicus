//! The module registry of the shipped binary (FR-22, AD-9, D144): a `const` item over the
//! modules `vilicus` ships, so a declaration the registry refuses stops the build, and the
//! capability matrix check of its tool table against `doc/capability-matrix.md`.
//!
//! V0.1 ships no module: every user-facing module is out of its scope (PRD section 6.1), and the
//! reference module is linked into `vilicus-testbed` only (D102). A shipped module joins by its
//! declaration in [`REGISTRY`], which brings its tools and the matrix sections it claims under
//! the check.
//!
//! Until `main` starts the Core with it, this module is compiled with the binary's tests only,
//! which CI builds and runs on every change: naming the Core in the binary itself links
//! SQLCipher, and with it the system `libcrypto`, into an executable that does not use them yet.

use vilicus_core::registry::Registry;

/// The modules the binary ships.
pub(crate) const REGISTRY: Registry = match Registry::new(&[]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

#[cfg(test)]
mod tests {
    use std::path::Path;

    use vilicus_core::registry::CapabilityMatrix;

    use super::REGISTRY;

    /// The capability matrix check of AD-9 on the shipped binary (Story 3.3, AC2): its tool table
    /// and `doc/capability-matrix.md` agree in both directions, and the matrix reads back.
    #[test]
    fn the_shipped_tool_table_matches_the_capability_matrix() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../doc/capability-matrix.md");
        let text = std::fs::read_to_string(path).expect("read doc/capability-matrix.md");
        if let Err(error) = CapabilityMatrix::check(&text, &REGISTRY) {
            panic!("{error}");
        }
    }
}
