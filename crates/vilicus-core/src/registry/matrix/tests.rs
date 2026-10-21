//! Story 3.3: the capability matrix read back, and the registry's tool table compared with it in
//! both directions (AC2), on a fixture and on `doc/capability-matrix.md`; no H action of the
//! matrix reachable as a tool (AC5).

use vilicus_module_api::{
    Confirmation, DeclarationError, MatrixRow, ModuleDeclaration, Tier, Tool,
};

use super::*;
use crate::registry::{Registry, RegistryError};

const FIXTURE: &str = "# Capability matrix

## Legend

**Tier.** Text that is not a table.

## 2. Tasks

| Action | Actor | Tier | Confirmation | Tainted session | Notes |
|--------|-------|------|--------------|-----------------|-------|
| List and read tasks | any | 0 | none | allow-b | |
| Create or edit a task | any | 1 | none | allow-b | Journaled, undoable |
| Prepare a list | any | 1 | light, in the app | elevate | |
| Purge deleted tasks | any | 2 (D46) | signed | deny | |
| Pair a device | human | H | step-up | deny | |
| Create or revoke a capability token | Core | n/a | n/a | deny | Not a tool |

## 3. Other

| Action | Principals allowed | Tier | Confirmation | Tainted session (assistant) | Stored taint | Notes |
|:-------|:-------------------|:----:|-------------:|-----------------------------|--------------|-------|
| Read other things | member | 0 | none | allow-b | n/a | |
| Change a mode | member | 1 toward the safe state; H otherwise | none | n/a | n/a | |

## 11. Default caps

| Cap | Initial value |
|-----|---------------|
| Orders per week | 2 |
";

fn leak<T>(items: Vec<T>) -> &'static [T] {
    items.leak()
}

fn tool(
    name: &'static str,
    section: &'static str,
    action: &'static str,
    tier: Tier,
    confirmation: Confirmation,
) -> Tool {
    Tool {
        name,
        arguments: &[],
        tier,
        network_effect: false,
        exception_class: None,
        confirmation,
        crosses_partitions: false,
        undo_handler: None,
        matrix_row: MatrixRow { section, action },
    }
}

fn module(name: &'static str, sections: Vec<&'static str>, tools: Vec<Tool>) -> ModuleDeclaration {
    ModuleDeclaration {
        name,
        tables: &[],
        fts5_tables: &[],
        migrations: &[],
        matrix_sections: leak(sections),
        tools: leak(tools),
    }
}

fn registry_of(modules: Vec<ModuleDeclaration>) -> Result<Registry, RegistryError> {
    let modules: Vec<&'static ModuleDeclaration> = modules
        .into_iter()
        .map(|module| &*Box::leak(Box::new(module)))
        .collect();
    Registry::new(leak(modules))
}

fn build_registry(modules: Vec<ModuleDeclaration>) -> Registry {
    registry_of(modules).expect("a valid registry")
}

/// The tools of the fixture's section 2: one per row a tool can implement.
fn task_tools() -> Vec<Tool> {
    vec![
        tool(
            "list_tasks",
            "2",
            "List and read tasks",
            Tier::Read,
            Confirmation::None,
        ),
        tool(
            "edit_task",
            "2",
            "Create or edit a task",
            Tier::ReversibleWrite,
            Confirmation::None,
        ),
        tool(
            "prepare_list",
            "2",
            "Prepare a list",
            Tier::ReversibleWrite,
            Confirmation::Light,
        ),
    ]
}

fn fixture() -> CapabilityMatrix {
    CapabilityMatrix::parse(FIXTURE).expect("the fixture reads")
}

fn differences(modules: Vec<ModuleDeclaration>) -> Vec<MatrixDifference> {
    fixture().differences(&build_registry(modules))
}

fn read_doc(name: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../doc")
            .join(name),
    )
    .expect("read the design document")
}

fn document() -> CapabilityMatrix {
    CapabilityMatrix::parse(&read_doc("capability-matrix.md"))
        .expect("doc/capability-matrix.md reads")
}

#[test]
fn the_fixture_reads_back_into_its_sections_and_rows() {
    let matrix = fixture();
    let numbers: Vec<&str> = matrix
        .sections()
        .iter()
        .map(|section| section.number.as_str())
        .collect();
    assert_eq!(numbers, ["2", "3", "11"]);
    let tasks = matrix.section("2").expect("section 2");
    assert_eq!(tasks.title, "Tasks");
    assert_eq!(tasks.rows.len(), 6);
    assert_eq!(tasks.rows[0].action, "List and read tasks");
    assert_eq!(tasks.rows[0].line, 11);
    assert_eq!(tasks.rows[2].confirmation, "light, in the app");
    let other = matrix.section("3").expect("section 3");
    assert_eq!(other.rows[1].tier, "1 toward the safe state; H otherwise");
    assert!(matrix.section("11").expect("section 11").rows.is_empty());
    let row = MatrixRow {
        section: "2",
        action: "Purge deleted tasks",
    };
    assert_eq!(
        matrix.row(&row).map(|entry| entry.tier.as_str()),
        Some("2 (D46)")
    );
    let absent = MatrixRow {
        section: "4",
        action: "Purge deleted tasks",
    };
    assert!(matrix.row(&absent).is_none());
}

/// The Tier and Confirmation cells, read as the Legend writes them; anything else is not a tool's.
#[test]
fn tier_and_confirmation_cells_read_as_the_legend_writes_them() {
    let entry = |tier: &str, confirmation: &str| MatrixEntry {
        action: "Act".to_owned(),
        tier: tier.to_owned(),
        confirmation: confirmation.to_owned(),
        line: 1,
    };
    let tiers = [
        ("0", RowTier::Registrable(Tier::Read)),
        ("1", RowTier::Registrable(Tier::ReversibleWrite)),
        ("2", RowTier::Irreversible),
        ("2 (D46)", RowTier::Irreversible),
        ("2 (D69)", RowTier::Irreversible),
        ("H", RowTier::HumanOnly),
        ("n/a", RowTier::NotApplicable),
        ("0 or 1", RowTier::NotOneTier),
        ("per manifest", RowTier::NotOneTier),
        ("H outside a rule", RowTier::NotOneTier),
        (
            "1; H when it touches a safety-relevant device",
            RowTier::NotOneTier,
        ),
        ("2 (D)", RowTier::NotOneTier),
        ("2 (D46", RowTier::NotOneTier),
        ("2 (46)", RowTier::NotOneTier),
        ("h", RowTier::NotOneTier),
        ("", RowTier::NotOneTier),
    ];
    for (tier, expected) in tiers {
        assert_eq!(entry(tier, "none").row_tier(), expected, "{tier:?}");
    }
    let confirmations = [
        ("none", Some(Confirmation::None)),
        (
            "none (safe direction, one action)",
            Some(Confirmation::None),
        ),
        ("light", Some(Confirmation::Light)),
        ("light, in the app", Some(Confirmation::Light)),
        (
            "light, in the primary channel; never spoken",
            Some(Confirmation::Light),
        ),
        ("light to grant, never spoken; none to revoke", None),
        ("signed", None),
        ("step-up", None),
        ("spoken", None),
        ("provider policy", None),
        ("as the target row", None),
        ("Light", None),
        ("", None),
    ];
    for (confirmation, expected) in confirmations {
        assert_eq!(
            entry("1", confirmation).tool_confirmation(),
            expected,
            "{confirmation:?}"
        );
    }
}

/// AC2: a registry whose tools match the matrix has no difference, and the check passes.
#[test]
fn a_registry_that_matches_the_matrix_has_no_difference() {
    let registry = build_registry(vec![module("tasks", vec!["2"], task_tools())]);
    assert_eq!(fixture().differences(&registry), []);
    assert_eq!(CapabilityMatrix::check(FIXTURE, &registry), Ok(()));
    let names: Vec<String> = registry.tools().map(|tool| tool.qualified_name()).collect();
    assert_eq!(
        names,
        ["tasks.list_tasks", "tasks.edit_task", "tasks.prepare_list"]
    );
}

/// AC2: a tool without a matrix row and a row of a shipped module without a tool each fail the
/// check, and each is named.
#[test]
fn a_tool_without_a_row_and_a_row_without_a_tool_are_each_named() {
    let mut tools = task_tools();
    tools[1].matrix_row.action = "Create or edit tasks";
    let registry = build_registry(vec![module("tasks", vec!["2"], tools)]);
    let expected = [
        MatrixDifference::ToolWithoutRow {
            tool: "tasks.edit_task".to_owned(),
            row: MatrixRow {
                section: "2",
                action: "Create or edit tasks",
            },
        },
        MatrixDifference::RowWithoutTool {
            module: "tasks",
            section: "2",
            action: "Create or edit a task".to_owned(),
        },
    ];
    assert_eq!(fixture().differences(&registry), expected);
    let Err(error) = CapabilityMatrix::check(FIXTURE, &registry) else {
        panic!("the check passed");
    };
    assert_eq!(error, MatrixCheckError::Differences(expected.to_vec()));
    assert_eq!(
        error.to_string(),
        "the tool table and the capability matrix differ:\n\
         - tool tasks.edit_task has no matrix row: section 2 has no row \"Create or edit tasks\"\n\
         - matrix row \"Create or edit a task\" of section 2, claimed by module tasks, has no tool"
    );
    let mut tools = task_tools();
    tools.truncate(1);
    let fewer = build_registry(vec![module("tasks", vec!["2"], tools)]);
    assert_eq!(
        fixture().differences(&fewer),
        [
            MatrixDifference::RowWithoutTool {
                module: "tasks",
                section: "2",
                action: "Create or edit a task".to_owned(),
            },
            MatrixDifference::RowWithoutTool {
                module: "tasks",
                section: "2",
                action: "Prepare a list".to_owned(),
            },
        ]
    );
}

/// AC2: a section the module claims and the matrix lacks, and a tool's row in it, are named.
#[test]
fn a_section_the_matrix_lacks_is_named() {
    let mut tools = task_tools();
    tools.push(tool(
        "list_places",
        "4",
        "Read places and travel times",
        Tier::Read,
        Confirmation::None,
    ));
    let differences = differences(vec![module("tasks", vec!["2", "4"], tools)]);
    assert_eq!(
        differences,
        [
            MatrixDifference::SectionMissing {
                module: "tasks",
                section: "4",
            },
            MatrixDifference::ToolWithoutRow {
                tool: "tasks.list_places".to_owned(),
                row: MatrixRow {
                    section: "4",
                    action: "Read places and travel times",
                },
            },
        ]
    );
    assert_eq!(
        differences[0].to_string(),
        "module tasks claims section 4, which the matrix does not have"
    );
}

/// AC2 (AD-9, "any difference"): a tool's tier and confirmation are its row's.
#[test]
fn a_tool_takes_its_rows_tier_and_confirmation() {
    let mut tools = task_tools();
    tools[0].tier = Tier::ReversibleWrite;
    tools[1].confirmation = Confirmation::Light;
    tools[2].confirmation = Confirmation::None;
    let differences = differences(vec![module("tasks", vec!["2"], tools)]);
    assert_eq!(
        differences,
        [
            MatrixDifference::TierMismatch {
                tool: "tasks.list_tasks".to_owned(),
                row: MatrixRow {
                    section: "2",
                    action: "List and read tasks",
                },
                matrix: "0".to_owned(),
                declared: Tier::ReversibleWrite,
            },
            MatrixDifference::ConfirmationMismatch {
                tool: "tasks.edit_task".to_owned(),
                row: MatrixRow {
                    section: "2",
                    action: "Create or edit a task",
                },
                matrix: "none".to_owned(),
                declared: Confirmation::Light,
            },
            MatrixDifference::ConfirmationMismatch {
                tool: "tasks.prepare_list".to_owned(),
                row: MatrixRow {
                    section: "2",
                    action: "Prepare a list",
                },
                matrix: "light, in the app".to_owned(),
                declared: Confirmation::None,
            },
        ]
    );
    assert_eq!(
        differences[0].to_string(),
        "tool tasks.list_tasks is tier 1, its row \"List and read tasks\" of section 2 tier \"0\""
    );
}

/// AC3 and AC5: a tool cannot implement a tier H, `n/a`, tier 2 or mixed-tier row, whatever tier
/// it declares.
#[test]
fn a_tool_cannot_implement_a_row_that_is_not_a_tools() {
    let rows = [
        ("2", "Pair a device", "H"),
        ("2", "Create or revoke a capability token", "n/a"),
        ("2", "Purge deleted tasks", "2 (D46)"),
        ("3", "Change a mode", "1 toward the safe state; H otherwise"),
    ];
    for (section, action, tier) in rows {
        for declared in [Tier::Read, Tier::ReversibleWrite] {
            let mut tools = task_tools();
            tools.push(tool("probe", section, action, declared, Confirmation::None));
            let differences = differences(vec![module("tasks", vec!["2", "3"], tools)]);
            let expected = MatrixDifference::RowNotATool {
                tool: "tasks.probe".to_owned(),
                row: MatrixRow { section, action },
                tier: tier.to_owned(),
            };
            assert!(
                differences.contains(&expected),
                "{action} {declared}: {differences:?}"
            );
        }
    }
}

/// A claimed section's row that names no single tier is a difference until it is split; rows of
/// sections no module claims need no tool.
#[test]
fn claimed_rows_need_a_tool_and_one_tier() {
    let differences = differences(vec![
        module("tasks", vec!["2"], task_tools()),
        module("other", vec!["3"], Vec::new()),
    ]);
    assert_eq!(
        differences,
        [
            MatrixDifference::RowWithoutTool {
                module: "other",
                section: "3",
                action: "Read other things".to_owned(),
            },
            MatrixDifference::RowWithoutOneTier {
                module: "other",
                section: "3",
                action: "Change a mode".to_owned(),
                tier: "1 toward the safe state; H otherwise".to_owned(),
            },
        ]
    );
    assert_eq!(
        differences[1].to_string(),
        "matrix row \"Change a mode\" of section 3, claimed by module other, names no single \
         tier: \"1 toward the safe state; H otherwise\""
    );
}

/// One section, one module: two modules claiming one section are refused when the registry is
/// built.
#[test]
fn two_modules_cannot_claim_one_section() {
    let outcome = registry_of(vec![
        module("tasks", vec!["2"], task_tools()),
        module("other", vec!["3", "2"], Vec::new()),
    ]);
    assert_eq!(
        outcome.map(|_| ()),
        Err(RegistryError::DuplicateMatrixSection {
            module: "other",
            section: "2",
        })
    );
}

/// The reader refuses a table of actions it cannot read, naming the line.
#[test]
fn an_unreadable_matrix_is_refused() {
    let section = "## 2. Tasks\n\n";
    let header = "| Action | Tier | Confirmation |\n|---|---|---|\n";
    let cases = [
        (
            format!("{section}| Action | Confirmation |\n|---|---|\n| Read | none |\n"),
            MatrixError::MissingColumn {
                line: 3,
                column: "Tier",
            },
        ),
        (
            format!("{section}| Action | Tier |\n|---|---|\n| Read | 0 |\n"),
            MatrixError::MissingColumn {
                line: 3,
                column: "Confirmation",
            },
        ),
        (
            format!("{section}{header}| Read | 0 |\n"),
            MatrixError::CellCount { line: 5 },
        ),
        (
            format!("{section}{header}| Read | 0 | none | extra |\n"),
            MatrixError::CellCount { line: 5 },
        ),
        (
            format!("{section}{header}| Read | 0 | none\n"),
            MatrixError::MalformedRow { line: 5 },
        ),
        (
            format!("{section}| Action | Tier | Confirmation |\n| Read | 0 | none |\n"),
            MatrixError::MissingSeparator { line: 4 },
        ),
        (
            format!("{section}{header}|  | 0 | none |\n"),
            MatrixError::EmptyAction { line: 5 },
        ),
        (
            format!("{section}{header}| Read | 0 | none |\n| Read | 1 | none |\n"),
            MatrixError::DuplicateAction {
                line: 6,
                section: "2".to_owned(),
                action: "Read".to_owned(),
            },
        ),
        (
            format!("{section}{header}| Read | 0 | none |\n\n## 2. Again\n"),
            MatrixError::DuplicateSection {
                line: 7,
                section: "2".to_owned(),
            },
        ),
        (
            format!("## Legend\n\n{header}| Read | 0 | none |\n"),
            MatrixError::TableOutsideSection { line: 3 },
        ),
        (
            format!("{header}| Read | 0 | none |\n"),
            MatrixError::TableOutsideSection { line: 1 },
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            CapabilityMatrix::parse(&text),
            Err(expected.clone()),
            "{text}"
        );
        assert_eq!(
            CapabilityMatrix::check(&text, &build_registry(Vec::new())),
            Err(MatrixCheckError::Unreadable(expected))
        );
    }
    let same_action_in_two_sections = format!(
        "{section}{header}| Read | 0 | none |\n\n## 3. Other\n\n{header}| Read | 0 | none |\n"
    );
    assert!(CapabilityMatrix::parse(&same_action_in_two_sections).is_ok());
}

/// `doc/capability-matrix.md` reads back, with rows of every kind the check distinguishes.
#[test]
fn the_capability_matrix_document_reads_back() {
    let matrix = document();
    assert!(!matrix.sections().is_empty());
    let kinds: Vec<RowTier> = matrix
        .sections()
        .iter()
        .flat_map(|section| &section.rows)
        .map(MatrixEntry::row_tier)
        .collect();
    for kind in [
        RowTier::Registrable(Tier::Read),
        RowTier::Registrable(Tier::ReversibleWrite),
        RowTier::Irreversible,
        RowTier::HumanOnly,
        RowTier::NotApplicable,
    ] {
        assert!(kinds.contains(&kind), "{kind:?}");
    }
}

/// AC2 on `doc/capability-matrix.md`: a module claiming any section, with one tool per row a tool
/// can implement, at the row's tier and confirmation, matches the matrix except for the rows the
/// check cannot assign a tool (no single tier, or a confirmation no tool requires); removing any
/// one tool makes its row a difference, named.
#[test]
fn every_document_section_needs_a_tool_for_each_tool_row() {
    let text = read_doc("capability-matrix.md");
    let matrix = document();
    for section in matrix.sections() {
        let number: &'static str = section.number.clone().leak();
        let mut tools = Vec::new();
        let mut expected = Vec::new();
        for (index, entry) in section.rows.iter().enumerate() {
            let action: &'static str = entry.action.clone().leak();
            match (entry.row_tier(), entry.tool_confirmation()) {
                (RowTier::Registrable(tier), Some(confirmation)) => {
                    let name: &'static str = format!("tool_{index}").leak();
                    tools.push(tool(name, number, action, tier, confirmation));
                }
                (RowTier::Registrable(_), None) => {
                    expected.push(MatrixDifference::RowWithoutTool {
                        module: "probe",
                        section: number,
                        action: entry.action.clone(),
                    });
                }
                (RowTier::NotOneTier, _) => expected.push(MatrixDifference::RowWithoutOneTier {
                    module: "probe",
                    section: number,
                    action: entry.action.clone(),
                    tier: entry.tier.clone(),
                }),
                _ => {}
            }
        }
        let complete = build_registry(vec![module("probe", vec![number], tools.clone())]);
        assert_eq!(matrix.differences(&complete), expected, "section {number}");
        for removed in 0..tools.len() {
            let mut fewer = tools.clone();
            let gone = fewer.remove(removed);
            let incomplete = build_registry(vec![module("probe", vec![number], fewer)]);
            let differences = matrix.differences(&incomplete);
            let missing = MatrixDifference::RowWithoutTool {
                module: "probe",
                section: number,
                action: gone.matrix_row.action.to_owned(),
            };
            assert!(
                differences.contains(&missing),
                "section {number}: {differences:?}"
            );
            assert!(CapabilityMatrix::check(&text, &incomplete).is_err());
        }
    }
}

/// AC5 (I18, AD-8): every tier H and `n/a` row of `doc/capability-matrix.md` (pairing, recovery,
/// rights changes, token creation, plugin install, provider configuration and the others) is
/// unreachable as a tool: a tool of tier 0 or 1 naming it fails the matrix check, and a tool of
/// tier H naming it fails the registry build.
#[test]
fn no_h_action_of_the_document_is_reachable_as_a_tool() {
    let matrix = document();
    let mut unreachable = 0;
    for section in matrix.sections() {
        let number: &'static str = section.number.clone().leak();
        for entry in &section.rows {
            if !matches!(
                entry.row_tier(),
                RowTier::HumanOnly | RowTier::NotApplicable
            ) {
                continue;
            }
            unreachable += 1;
            let action: &'static str = entry.action.clone().leak();
            for tier in [Tier::Read, Tier::ReversibleWrite] {
                let probe = tool("probe", number, action, tier, Confirmation::None);
                let probing = build_registry(vec![module("probe", vec![number], vec![probe])]);
                let expected = MatrixDifference::RowNotATool {
                    tool: "probe.probe".to_owned(),
                    row: MatrixRow {
                        section: number,
                        action,
                    },
                    tier: entry.tier.clone(),
                };
                assert!(matrix.differences(&probing).contains(&expected), "{action}");
            }
            let human = tool("probe", number, action, Tier::HumanOnly, Confirmation::None);
            assert_eq!(
                registry_of(vec![module("probe", vec![number], vec![human])]).map(|_| ()),
                Err(RegistryError::Declaration {
                    module: "probe",
                    error: DeclarationError::HumanOnlyTool { tool: "probe" },
                }),
                "{action}"
            );
        }
    }
    assert!(unreachable > 0);
    // The actions AC5 names, as the matrix writes them: each is a row no tool can claim.
    for (section, action) in [
        ("1", "Pair a device"),
        ("1", "Start or cancel recovery"),
        ("1", "Create or revoke a capability token"),
        ("1", "Configure a model provider or its data policy"),
        ("10", "Install or enable a plugin"),
        ("10", "Change a plugin's rights"),
    ] {
        let entry = matrix
            .row(&MatrixRow { section, action })
            .unwrap_or_else(|| panic!("section {section} has the row {action:?}"));
        assert!(
            matches!(
                entry.row_tier(),
                RowTier::HumanOnly | RowTier::NotApplicable
            ),
            "{action}"
        );
    }
}
