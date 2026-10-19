//! The environment variables that let a test steer an update — where releases
//! come from, how long the waits are, what version the binary claims, whether
//! the publisher is checked — must not exist in a release build.
//!
//! A release binary that honoured `SHELL_TUNNEL_UPDATE_BASE_URL` or
//! `SHELL_TUNNEL_UPDATE_SKIP_AUTHENTICODE` would let anyone who can set the
//! environment of a device's service point it at their own "release". Nothing
//! behavioural can show their absence from a test (tests are debug builds), so
//! this pins the structure instead: every use in `src/` sits directly under a
//! `#[cfg(debug_assertions)]`.

use std::path::Path;

const PREFIX: &str = "\"SHELL_TUNNEL_UPDATE_";

/// How far above a use the attribute may sit: a statement `cargo fmt` wrapped
/// over a couple of lines still counts as directly under it.
const REACH: usize = 3;

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(file, line number, line)` for each use of an override in `text` that is
/// not directly under `#[cfg(debug_assertions)]`. Test modules and comments
/// are not code a release build compiles, so they are skipped.
fn unguarded(file: &str, text: &str) -> Vec<(String, usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let end = lines
        .iter()
        .position(|l| l.trim() == "#[cfg(test)]")
        .unwrap_or(lines.len());
    let mut found = Vec::new();
    for (i, line) in lines[..end].iter().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") || !code.contains(PREFIX) {
            continue;
        }
        let guarded = lines[i.saturating_sub(REACH)..i]
            .iter()
            .any(|l| l.trim() == "#[cfg(debug_assertions)]");
        if !guarded {
            found.push((file.to_string(), i + 1, line.trim().to_string()));
        }
    }
    found
}

#[test]
fn every_update_override_is_compiled_only_into_debug_builds() {
    let mut files = Vec::new();
    rust_files(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut files,
    );
    let mut uses = 0;
    let mut bad = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        uses += text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && l.contains(PREFIX))
            .count();
        bad.extend(unguarded(&path.display().to_string(), &text));
    }
    assert!(
        bad.is_empty(),
        "update overrides reachable from a release build: {bad:#?}"
    );
    // Without this the test passes on a tree whose overrides were renamed.
    assert!(
        uses >= 5,
        "expected the update overrides in src/, found {uses}"
    );
}

#[test]
fn the_check_tells_a_guarded_use_from_an_unguarded_one() {
    let guarded = "fn f() {\n    #[cfg(debug_assertions)]\n    let x = std::env::var(\"SHELL_TUNNEL_UPDATE_X\");\n}\n";
    assert!(unguarded("g.rs", guarded).is_empty());

    let wrapped = "    #[cfg(debug_assertions)]\n    let check =\n        std::env::var_os(\"SHELL_TUNNEL_UPDATE_Y\").is_none();\n";
    assert!(unguarded("w.rs", wrapped).is_empty());

    let open = "fn f() {\n    let x = std::env::var(\"SHELL_TUNNEL_UPDATE_X\");\n}\n";
    assert_eq!(unguarded("o.rs", open).len(), 1);

    // An attribute on an earlier, unrelated item does not reach this far.
    let far = "    #[cfg(debug_assertions)]\n    a();\n    b();\n    c();\n    let x = std::env::var(\"SHELL_TUNNEL_UPDATE_X\");\n";
    assert_eq!(unguarded("f.rs", far).len(), 1);
}
