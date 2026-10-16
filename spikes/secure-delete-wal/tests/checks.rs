use secure_delete_wal::checks;

#[test]
fn every_check_passes() {
    let failures: Vec<String> = checks::all()
        .iter()
        .filter_map(|check| {
            check
                .run()
                .err()
                .map(|error| format!("{}: {error}", check.name))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
