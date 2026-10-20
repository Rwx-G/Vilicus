//! Story 2.7, AC3: the failing inputs of past fuzz runs, committed under
//! `crates/vilicus-proto/tests/data/fuzz/<target>/`, replayed through their target's check on the
//! stable toolchain of `build-and-test`, without any fuzzing dependency. The memory limits apply
//! in the `fuzz` job only, which seeds every run with these inputs.

use vilicus_fuzz::{TARGETS, input_files, regression_inputs, regressions_dir, vector_inputs};

#[test]
fn every_committed_failing_input_passes_its_target() {
    let mut replayed = 0;
    for target in TARGETS {
        for input in regression_inputs(target) {
            (target.check)(&input);
            replayed += 1;
        }
    }
    assert!(replayed > 0, "no failing input is committed");
}

#[test]
fn every_regression_directory_names_a_target_and_holds_only_inputs() {
    let directory = regressions_dir();
    let entries = std::fs::read_dir(&directory).expect("the regression directory exists");
    for entry in entries {
        let path = entry.expect("directory entry").path();
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        assert!(
            path.is_dir(),
            "{} is not a target directory",
            path.display()
        );
        assert!(
            TARGETS.iter().any(|target| target.name == name),
            "{} names no fuzz target",
            path.display()
        );
        assert!(
            input_files(&path).len() == std::fs::read_dir(&path).expect("listed").count(),
            "{} holds something other than input files",
            path.display()
        );
    }
}

/// The seed corpus of every run passes every check: an invariant the checks state wrongly fails
/// here, on stable, rather than as a finding of the first fuzz run.
#[test]
fn every_seed_passes_its_target() {
    assert!(
        !vector_inputs().is_empty(),
        "the vector files were not read"
    );
    for target in TARGETS {
        for seed in target.seeds() {
            (target.check)(&seed);
        }
    }
}
