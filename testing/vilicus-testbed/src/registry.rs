//! The module registry of the testbed (FR-109, D102): a `const` item over the modules the
//! testbed links, so a declaration the registry refuses stops the build, and the gates that need
//! a module run against it.
//!
//! It holds the reference module and the testbed's second module, `reader`, which reads the
//! reference module's records through its typed API (Story 3.10). Like the shipped binary's
//! registry (Story 3.3), it is compiled with the tests only until `main` starts the Core: naming
//! the Core in the executable links SQLCipher, and with it the system `libcrypto`, into an
//! executable that does not use them yet.

use vilicus_core::handlers::Handlers;
use vilicus_core::registry::Registry;
use vilicus_mod_reference::{REFERENCE, REFERENCE_CODE};

use crate::reader::{READER, READER_CODE};

/// The modules the testbed links.
pub(crate) const REGISTRY: Registry = match Registry::new(&[&REFERENCE, &READER]) {
    Ok(registry) => registry,
    Err(error) => panic!("{}", error.rule()),
};

/// The code of the modules the testbed links, bound to their declarations (AD-9): a module whose
/// tool, undo handler or consumer has no function stops the build.
pub(crate) const HANDLERS: Handlers =
    match Handlers::new(REGISTRY, &[&REFERENCE_CODE, &READER_CODE]) {
        Ok(handlers) => handlers,
        Err(error) => panic!("{}", error.rule()),
    };

#[cfg(test)]
mod tests {
    use std::path::Path;

    use vilicus_core::registry::CapabilityMatrix;
    use vilicus_module_api::{DataType, FieldKind, Structured, Tier};

    use super::{HANDLERS, REGISTRY};

    /// Test key only; the Core derives one key per file.
    const KEY: [u8; 32] = [0x7e; 32];

    fn read(path: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

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

    /// Story 3.10, AC1 (FR-22, I8, I36), the build-time test of AD-9 and Story 3.2 on the
    /// testbed's registry: each module's migrations, checked against their frozen hashes (Story
    /// 3.7), run in order through the migration runner and produce exactly the schema each
    /// declaration implies, the envelope of every table included. The reference module declares
    /// what the contract has: free-text and structured fields, each with its bound, a reviewed
    /// vocabulary, a record kind exempt from elevation and one of a data type the provider policy
    /// keeps local.
    #[test]
    fn the_linked_modules_register_and_their_migrations_produce_their_declarations() {
        let directory =
            std::env::temp_dir().join(format!("vilicus-testbed-verify-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create the scratch directory");
        let verified = REGISTRY.verify_migrations(&directory, &KEY);
        std::fs::remove_dir_all(&directory).expect("remove the scratch directory");
        verified.unwrap_or_else(|error| panic!("{error}"));

        let reference = &vilicus_mod_reference::REFERENCE;
        assert!(
            reference.migrations.len() >= 2,
            "two migrations in sequence"
        );
        let fields = || reference.tables.iter().flat_map(|table| table.fields);
        assert!(
            fields()
                .any(|field| matches!(field.kind, FieldKind::FreeText { max_len } if max_len > 0))
        );
        assert!(fields().any(|field| matches!(field.kind, FieldKind::Structured(_))));
        assert!(fields().any(|field| matches!(
            field.kind,
            FieldKind::Structured(Structured::ReviewedVocabulary(_))
        )));
        assert!(
            reference
                .tables
                .iter()
                .any(|table| table.data_types.contains(&DataType::Journal)
                    || table.data_types.contains(&DataType::Health))
        );
    }

    /// Story 3.10, AC2 (FR-22, AD-9, D145): the testbed's tool table and its matrix fixture under
    /// `testing/` agree in both directions, with a tier 0 and a tier 1 tool each backed by a row
    /// of it; `doc/capability-matrix.md` holds no row of a module the testbed links; and a record
    /// kind is declared exempt from elevation.
    #[test]
    fn the_testbed_tool_table_matches_its_matrix_fixture_and_the_matrix_has_none_of_it() {
        let fixture = read("capability-matrix.md");
        if let Err(error) = CapabilityMatrix::check(&fixture, &REGISTRY) {
            panic!("{error}");
        }
        let fixture = CapabilityMatrix::parse(&fixture).expect("the fixture reads back");
        let matrix = CapabilityMatrix::parse(&read("../../doc/capability-matrix.md"))
            .expect("the matrix reads back");
        let tools: Vec<_> = REGISTRY.tools().collect();
        for tier in [Tier::Read, Tier::ReversibleWrite] {
            assert!(
                tools.iter().any(|registered| registered.tool.tier == tier
                    && fixture.row(&registered.tool.matrix_row).is_some()),
                "{tier:?}"
            );
        }
        for registered in &tools {
            assert!(
                matrix.row(&registered.tool.matrix_row).is_none(),
                "{} has a row of doc/capability-matrix.md",
                registered.qualified_name()
            );
        }
        let claimed = REGISTRY
            .modules()
            .iter()
            .flat_map(|module| module.matrix_sections);
        for section in claimed {
            let in_fixture = fixture.section(section).expect("a section of the fixture");
            if let Some(in_matrix) = matrix.section(section) {
                assert!(
                    in_fixture.rows.iter().all(|row| in_matrix
                        .rows
                        .iter()
                        .all(|other| other.action != row.action)),
                    "section {section}"
                );
            }
        }
        assert!(
            REGISTRY
                .modules()
                .iter()
                .flat_map(|module| module.tables)
                .any(|table| table.elevation_exempt)
        );
    }

    /// AC4 of Story 3.4 (DC-53, D98, I40): the fuzz test drives every module write path
    /// registered in the testbed, the insert and the update of each table, with values outside
    /// their declarations; every one is refused and the file is unchanged afterwards. The labels
    /// of reviewed vocabularies are confirmed by the fuzz test in the files it creates, the only
    /// way a label is confirmed in V0.1 (AC5).
    #[test]
    fn every_registered_write_path_refuses_values_outside_its_declaration() {
        let tables: usize = REGISTRY
            .modules()
            .iter()
            .map(|module| module.tables.len())
            .sum();
        assert!(tables > 0, "the testbed registers tables (Story 3.10)");
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
            assert!(report.refused > 0 && report.accepted > 0, "{report:?}");
            std::fs::remove_dir_all(&directory).expect("remove the scratch directory");
        }
    }
}
