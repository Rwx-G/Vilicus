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

use vilicus_core::handlers::Handlers;
use vilicus_core::registry::Registry;

/// The modules the binary ships.
pub(crate) const REGISTRY: Registry = match Registry::new(&[]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

/// The code of the modules the binary ships, bound to their declarations (AD-9): a module whose
/// tool, undo handler or consumer has no function stops the build.
pub(crate) const HANDLERS: Handlers = match Handlers::new(REGISTRY, &[]) {
    Ok(handlers) => handlers,
    Err(error) => panic!("{}", error.rule()),
};

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use vilicus_core::registry::CapabilityMatrix;

    use super::{HANDLERS, REGISTRY};

    /// Story 3.9: the handler table binds the code of every module the binary ships.
    #[test]
    fn the_handler_table_binds_every_shipped_module() {
        assert_eq!(HANDLERS.registry().modules(), REGISTRY.modules());
        for module in REGISTRY.modules() {
            if !module.tools.is_empty() || !module.consumers.is_empty() {
                assert!(HANDLERS.code(module.name).is_some(), "{}", module.name);
            }
        }
    }

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

    /// The write path fuzz test of Story 3.4 (D98, I40) on the shipped modules: every insert and
    /// update of every table refuses values outside their declarations and leaves the file
    /// unchanged.
    #[test]
    fn every_shipped_write_path_refuses_values_outside_its_declaration() {
        let directory =
            std::env::temp_dir().join(format!("vilicus-shipped-fuzz-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create the scratch directory");
        let report = REGISTRY
            .fuzz_write_paths(&directory, &[0x6b; 32], 0x5419_7ed0, 256)
            .unwrap_or_else(|error| panic!("{error}"));
        let tables: usize = REGISTRY
            .modules()
            .iter()
            .map(|module| module.tables.len())
            .sum();
        assert_eq!(
            report.paths.len(),
            2 * tables,
            "an insert and an update per table"
        );
        if tables > 0 {
            assert!(report.refused > 0 && report.accepted > 0, "{report:?}");
        }
        std::fs::remove_dir_all(&directory).expect("remove the scratch directory");
    }

    /// Every Rust source file of the binary, with its text.
    fn sources(directory: &Path, found: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(directory).expect("read the source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path).expect("read a source file");
                found.push((path, text));
            }
        }
    }

    /// The binary builds its registry here only, and while this module is compiled with the
    /// tests only, no other source of the binary names the Core: code that starts the Core from
    /// `main` must bring the registry into the build with it (Story 3.3 review, minor 1).
    #[test]
    fn the_registry_is_the_binary_s_only_use_of_the_core_while_it_is_test_only() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&directory, &mut files);
        let main = &files
            .iter()
            .find(|(path, _)| path.ends_with("main.rs"))
            .expect("main.rs")
            .1;
        let lines: Vec<&str> = main.lines().map(str::trim).collect();
        let test_only = lines
            .windows(2)
            .any(|pair| pair == ["#[cfg(test)]", "mod registry;"]);
        for (path, text) in &files {
            if path.ends_with("registry.rs") {
                continue;
            }
            assert!(
                !text.contains("Registry::new("),
                "{} builds a registry outside registry.rs",
                path.display()
            );
            assert!(
                !(test_only && text.contains("vilicus_core")),
                "{} names the Core while the registry is compiled with the tests only",
                path.display()
            );
        }
    }
}
