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

/// The one exemption from the feature rule, spelled out in the workflow itself.
///
/// A command carrying this marker is asserting that running the *default* build
/// is its whole point, so requiring it to enable every gate would defeat it.
/// Nothing infers the exemption — it has to be written next to the command, so
/// that dropping features from some other command can never be mistaken for it.
const DEFAULT_BUILD_MARKER: &str = "# default-build-on-purpose";

/// CI commands that build the integration tests, and so decide which of them
/// exist at all: `cargo test`, and `cargo clippy --all-targets`.
///
/// A command that builds neither (the MSRV job's `cargo build`) is not listed
/// here, because no suite can go missing from it. Nor is a command marked
/// [`DEFAULT_BUILD_MARKER`]: the default build is precisely the one nothing else
/// runs, and the check below would otherwise forbid the job that covers it.
fn commands_that_build_the_tests(workflow: &str) -> Vec<String> {
    workflow
        .lines()
        .map(str::trim)
        // A comment is not a command. This scan is textual, so a comment that
        // *names* a command was being checked as though it were one — writing
        // "every `cargo test` here must enable every feature" in the workflow
        // made this file fail on its own prose. Present since the check was
        // written; only reached once a comment happened to say the words.
        .filter(|line| !line.starts_with('#'))
        .filter(|line| !line.contains(DEFAULT_BUILD_MARKER))
        .filter(|line| {
            line.contains("cargo test")
                || (line.contains("cargo clippy") && line.contains("--all-targets"))
        })
        .map(|line| line.to_string())
        .collect()
}

/// CI must actually run the default build's tests, and exactly once.
///
/// `CLAUDE.md` recorded the failure this closes: CI checked that build by
/// *building* it and never ran its tests, so a test that only passes with a
/// feature could sit red there indefinitely while all three OS jobs stayed
/// green. One did.
///
/// "Exactly once" is the other half. The marker is an exemption from the
/// feature rule above, so more than one of them would be a way to opt whole
/// commands out of that rule while this file still reports ok.
#[test]
fn ci_runs_the_default_builds_tests_exactly_once() {
    let workflow_path = repo_root().join(".github/workflows/ci.yml");
    let workflow = std::fs::read_to_string(&workflow_path).expect("the CI workflow is readable");

    let marked: Vec<&str> = workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.contains(DEFAULT_BUILD_MARKER) && line.contains("cargo test"))
        .collect();

    assert_eq!(
        marked.len(),
        1,
        "expected exactly one `cargo test` marked `{DEFAULT_BUILD_MARKER}` in {}, found {}: {marked:?}\n\
         None means nothing runs the default build's tests, and a feature-gated test can go red \
         there without any job noticing. More than one means the exemption is being used to \
         excuse commands from the feature rule this file exists to enforce.",
        workflow_path.display(),
        marked.len()
    );

    let command = marked[0];
    assert!(
        features_on(command).is_empty(),
        "the default-build command must enable no features -- that is what makes it the default \
         build. Got: {command}"
    );
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

/// Each alias in `.cargo/config.toml`, flattened into something
/// [`features_on`] can read.
///
/// An alias is a TOML array (`["test", "--all", "--features", "relay-client,tls"]`)
/// which `cargo fmt`-style wrapping may spread over several lines, so neither
/// "one line is one command" nor a raw whitespace split works on its own. Each
/// alias is gathered from its `name = ` up to the next one, then the array
/// punctuation is stripped so the same reader serves both this and CI's
/// command lines — which is the whole point of checking them against one rule.
///
/// **Commas are stripped per token, not globally.** A blanket replace also eats
/// the separator inside `relay-client,tls`, which leaves the feature list
/// looking like two arguments and the check reporting `tls` as missing when it
/// is right there. Found by running it.
fn alias_commands(config: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current: Option<String> = None;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        // A new alias starts at `name = ` outside any array. `[alias]` itself
        // has no `=`, so the section header does not start one.
        let starts_alias = trimmed.contains('=') && !trimmed.starts_with('[');
        if starts_alias {
            if let Some(done) = current.take() {
                commands.push(done);
            }
            current = Some(String::new());
        }
        if let Some(buffer) = current.as_mut() {
            let bare = trimmed.replace(['[', ']', '"'], " ");
            for token in bare.split_whitespace() {
                buffer.push(' ');
                buffer.push_str(token.trim_end_matches(','));
            }
        }
    }
    commands.extend(current);
    commands
}

/// The same rule, applied to the command a person types before pushing.
///
/// CI being right does not stop a contributor from running `cargo test --all`,
/// getting `ok` from nine binaries instead of sixteen, and concluding their
/// relay change is fine. `.cargo/config.toml` exists to give that person a
/// complete command — and an alias is only worth having if it stays complete,
/// which is the same drift this file already guards CI against. One rule, two
/// consumers.
///
/// A missing `.cargo/config.toml` fails rather than skips: the alias is the
/// only thing standing between a local run and a false green, so its absence
/// is the condition worth reporting, not a reason to pass quietly.
#[test]
fn the_local_alias_passes_every_feature_the_test_suites_are_gated_behind() {
    let config_path = repo_root().join(".cargo/config.toml");
    let config = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        panic!(
            "{} could not be read ({e}). It carries the alias that runs the full \
             suite locally; without it `cargo test --all` silently skips every \
             feature-gated suite and still reports ok.",
            config_path.display()
        )
    });

    let commands = alias_commands(&config);
    assert!(
        !commands.is_empty(),
        "no aliases were found in {}. An alias that does not exist cannot be the \
         complete command anyone runs.",
        config_path.display()
    );

    let gates = gates_across_tests();
    for command in &commands {
        let enabled = features_on(command);
        let missing: Vec<&(String, String)> = gates
            .iter()
            .filter(|(feature, _)| !enabled.contains(feature))
            .collect();
        assert!(
            missing.is_empty(),
            "the local alias in {} does not enable every feature the test suites are \
             gated behind.\nenables: {enabled:?}\nmissing:\n{}\n\
             Somebody running that alias would get a green run with those suites absent.",
            config_path.display(),
            missing
                .iter()
                .map(|(feature, file)| format!("  - `{feature}` (gates tests/{file})"))
                .collect::<Vec<_>>()
                .join("\n")
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
