//! The function allowlist covers the engine: every SQL function this build offers has been
//! reviewed, either allowed or deliberately left out.

mod common;

use common::report;
use rusqlite::Connection;
use sqlite_authorizer::{ALLOWED_FUNCTIONS, DENIED_FUNCTIONS};

fn listed(list: &[&str], name: &str) -> bool {
    list.iter().any(|entry| entry.eq_ignore_ascii_case(name))
}

#[test]
fn every_engine_function_is_reviewed_exactly_once() {
    let connection = Connection::open_in_memory().expect("open in memory");
    let engine: Vec<String> = connection
        .prepare("SELECT DISTINCT name FROM pragma_function_list ORDER BY name")
        .expect("prepare function list")
        .query_map([], |row| row.get(0))
        .expect("query function list")
        .collect::<Result<_, _>>()
        .expect("read function list");

    let unreviewed: Vec<&String> = engine
        .iter()
        .filter(|name| !listed(ALLOWED_FUNCTIONS, name) && !listed(DENIED_FUNCTIONS, name))
        .collect();
    let in_both: Vec<&&str> = ALLOWED_FUNCTIONS
        .iter()
        .filter(|name| listed(DENIED_FUNCTIONS, name))
        .collect();
    let stale: Vec<&&str> = ALLOWED_FUNCTIONS
        .iter()
        .chain(DENIED_FUNCTIONS)
        .filter(|name| {
            !engine
                .iter()
                .any(|offered| offered.eq_ignore_ascii_case(name))
        })
        .collect();

    let passed = report(
        unreviewed.is_empty(),
        "functions.every_engine_function_reviewed",
        &format!("{} offered; unreviewed {unreviewed:?}", engine.len()),
    ) & report(
        in_both.is_empty(),
        "functions.no_function_both_allowed_and_denied",
        &format!("{in_both:?}"),
    ) & report(
        stale.is_empty(),
        "functions.no_reviewed_function_missing_from_engine",
        &format!("{stale:?}"),
    );
    assert!(passed);
}
