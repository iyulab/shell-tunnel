//! Every feature a test suite is gated behind has to be on CI's command line.
//!
//! A suite behind `#![cfg(feature = "…")]` compiles to *zero tests* without that
//! feature and reports `test result: ok`. Nothing fails, nothing recompiles, and
//! the suite is simply absent — which is how `relay_tls_e2e`'s four tests went
//! unrun on all three platforms while CI stayed green, and how a relay defect
//! before it survived three minor versions.
//!
//! The comment on CI's test step used to carry this rule in prose. Prose does
//! not fail when a third gate appears, so it is a check now: a set difference
//! rather than a sentence someone has to remember to reread.
//!
//! Deliberately behind no feature gate of its own. A guard that the thing it
//! guards can switch off is not a guard.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Everything before a `//` on each line, so a feature name quoted inside a
/// comment does not become a requirement.
fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Feature names appearing in `feature = "…"` within one source file.
///
/// `all(…)` and `any(…)` need no special handling: requiring every name they
/// mention is at worst stricter than necessary, and being stricter cannot hide
/// a test. `not(feature = "…")` is the one form where that reasoning inverts —
/// enabling the feature is what would remove those tests — so it is refused
/// rather than modelled wrongly.
fn gates_in(source: &str, file: &Path) -> BTreeSet<String> {
    let source = without_line_comments(source);
    assert!(
        !source.contains("not(feature"),
        "{} carries a negated feature gate, which this check does not model: \
         enabling the feature would *remove* those tests, so the subset rule below \
         would be exactly backwards. Teach this check that form before using it.",
        file.display()
    );

    let mut found = BTreeSet::new();
    let mut rest = source.as_str();
    while let Some(at) = rest.find("feature = \"") {
        rest = &rest[at + "feature = \"".len()..];
        if let Some(end) = rest.find('"') {
            found.insert(rest[..end].to_string());
            rest = &rest[end..];
        }
    }
    found
}

/// This file's own name, so the scan can skip itself.
///
/// It quotes every gate form it reasons about, including the one it refuses, so
/// scanning itself makes it report its own prose as a gate. Found by running it:
/// the first version failed on its own error message.
fn own_file_name() -> String {
    Path::new(file!())
        .file_name()
        .expect("file!() names a file")
        .to_string_lossy()
        .to_string()
}

/// Every feature gate across the integration tests.
fn gates_across_tests() -> BTreeSet<(String, String)> {
    let dir = repo_root().join("tests");
    let mut gates = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("tests/ is readable") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        if path
            .file_name()
            .is_some_and(|name| name == own_file_name().as_str())
        {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a test file is readable");
        let name = path
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .to_string();
        for feature in gates_in(&source, &path) {
            gates.insert((feature, name.clone()));
        }
    }
    gates
}

/// The `--features` set of one CI command, or an empty set if it names none.
fn features_on(command: &str) -> BTreeSet<String> {
    let mut tokens = command.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "--features" {
            return tokens
                .next()
                .unwrap_or("")
                .split(',')
                .filter(|f| !f.is_empty())
                .map(|f| f.to_string())
                .collect();
        }
    }
    BTreeSet::new()
}

/// CI commands that build the integration tests, and so decide which of them
/// exist at all: `cargo test`, and `cargo clippy --all-targets`.
///
/// A command that builds neither (the MSRV job's `cargo build`) is not listed
/// here, because no suite can go missing from it.
fn commands_that_build_the_tests(workflow: &str) -> Vec<String> {
    workflow
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.contains("cargo test")
                || (line.contains("cargo clippy") && line.contains("--all-targets"))
        })
        .map(|line| line.to_string())
        .collect()
}

#[test]
fn ci_passes_every_feature_the_test_suites_are_gated_behind() {
    let workflow_path = repo_root().join(".github/workflows/ci.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("the CI workflow is readable");

    let commands = commands_that_build_the_tests(&workflow);
    assert!(
        !commands.is_empty(),
        "no command in {} builds the integration tests. Either the workflow changed shape \
         or this check stopped recognising it -- and an unrecognised command is checked \
         against nothing at all.",
        workflow_path.display()
    );

    let gates = gates_across_tests();
    assert!(
        !gates.is_empty(),
        "no feature gates were found under tests/, which this check has never been true of. \
         Suspect the scan before concluding the gates are gone."
    );

    for command in &commands {
        let enabled = features_on(command);
        let missing: Vec<&(String, String)> = gates
            .iter()
            .filter(|(feature, _)| !enabled.contains(feature))
            .collect();

        assert!(
            missing.is_empty(),
            "this CI command does not enable every feature the test suites are gated behind:\n  \
             {command}\nenables: {enabled:?}\nmissing:\n{}\n\
             Each missing feature silently removes the tests behind it -- they do not fail, \
             they stop existing, and the run still reports ok. Add the feature to the command \
             in {}.",
            missing
                .iter()
                .map(|(feature, file)| format!("  - `{feature}` (gates tests/{file})"))
                .collect::<Vec<_>>()
                .join("\n"),
            workflow_path.display()
        );
    }
}

/// The scan is the part most likely to rot in silence: if it quietly stopped
/// matching anything, the check above would pass for the wrong reason.
#[test]
fn the_scan_finds_the_gates_that_are_known_to_exist() {
    let gates = gates_across_tests();
    let features: BTreeSet<&str> = gates.iter().map(|(feature, _)| feature.as_str()).collect();

    assert!(
        features.contains("tls"),
        "tests/relay_tls_e2e.rs opens with `#![cfg(feature = \"tls\")]`: {gates:?}"
    );
    assert!(
        features.contains("relay-client"),
        "the relay suites are gated behind `relay-client`: {gates:?}"
    );
    // Item-level gates hide tests exactly as file-level ones do -- one test in
    // `relay_e2e.rs` sits behind `#[cfg(feature = "relay-client")]` rather than
    // a `#![cfg(…)]` header. A scan that only read file headers would miss it.
    assert!(
        gates.contains(&("relay-client".to_string(), "relay_e2e.rs".to_string())),
        "an item-level gate must be found too: {gates:?}"
    );
}
