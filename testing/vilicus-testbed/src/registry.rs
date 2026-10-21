//! The module registry of the testbed (FR-109, D102): a `const` item over the modules the
//! testbed links, so a declaration the registry refuses stops the build, and the gates that need
//! a module run against it.
//!
//! It is empty until Story 3.10 adds the reference module. Like the shipped binary's registry
//! (Story 3.3), it is compiled with the tests only until `main` starts the Core: naming the Core
//! in the executable links SQLCipher, and with it the system `libcrypto`, into an executable that
//! does not use them yet.

use vilicus_core::handlers::Handlers;
use vilicus_core::registry::Registry;

/// The modules the testbed links.
pub(crate) const REGISTRY: Registry = match Registry::new(&[]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

/// The code of the modules the testbed links, bound to their declarations (AD-9): a module whose
/// tool, undo handler or consumer has no function stops the build.
pub(crate) const HANDLERS: Handlers = match Handlers::new(REGISTRY, &[]) {
    Ok(handlers) => handlers,
    Err(error) => panic!("{}", error.rule()),
};

#[cfg(test)]
mod tests {
    use super::{HANDLERS, REGISTRY};

    /// Test key only; the Core derives one key per file.
    const KEY: [u8; 32] = [0x7e; 32];

    /// AC4 of Story 3.4 (DC-53, D98, I40): the fuzz test drives every module write path
    /// registered in the testbed, the insert and the update of each table, with values outside
    /// their declarations; every one is refused and the file is unchanged afterwards. The labels
    /// of reviewed vocabularies are confirmed by the fuzz test in the files it creates, the only
    /// way a label is confirmed in V0.1 (AC5).
    /// Story 3.9: the handler table binds the code of every module the testbed links.
    #[test]
    fn the_handler_table_binds_every_linked_module() {
        assert_eq!(HANDLERS.registry().modules(), REGISTRY.modules());
        for module in REGISTRY.modules() {
            if !module.tools.is_empty() || !module.consumers.is_empty() {
                assert!(HANDLERS.code(module.name).is_some(), "{}", module.name);
            }
        }
    }

    #[test]
    fn every_registered_write_path_refuses_values_outside_its_declaration() {
        let tables: usize = REGISTRY
            .modules()
            .iter()
            .map(|module| module.tables.len())
            .sum();
        for seed in [0x7e57_bed0, 0x0003_0004] {
            let directory = std::env::temp_dir().join(format!(
                "vilicus-testbed-fuzz-{}-{seed:x}",
                std::process::id()
            ));
            std::fs::create_dir_all(&directory).expect("create the scratch directory");
            let report = REGISTRY
                .fuzz_write_paths(&directory, &KEY, seed, 256)
                .unwrap_or_else(|error| panic!("seed {seed:x}: {error}"));
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
    }
}
