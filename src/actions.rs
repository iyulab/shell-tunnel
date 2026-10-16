//! Named actions: commands a device's owner has defined, which a token can be
//! allowed to run without being allowed to run anything else.
//!
//! `exec` is all-or-nothing — a token holding it runs whatever the account
//! running the server can. A program driving machines it does not own (a
//! deploy hook, a health probe, a remediation service) needs something
//! narrower, and the narrowing has to happen **on the device**: whatever the
//! caller restricts on its own side is bypassed by whoever holds the token.
//!
//! So the device's owner writes the definitions, in a file the server reads at
//! startup, and a token is granted `action:<id>` (or `action:*`) rather than
//! `exec`. Three properties carry the whole design:
//!
//! - **No shell.** An action runs as an argv, so nothing interprets what a
//!   caller supplies. A parameter is substituted *inside* one argv element and
//!   stays one argument, whatever it contains.
//! - **Parameters are typed, not patterned.** The types below are the only
//!   shapes a caller's value can take. A regular expression would be a new
//!   dependency, and a pattern written slightly wrong is a hole that looks
//!   like a rule.
//! - **The caller never sees the argv.** It sees an action's id and its
//!   parameters, so the owner can change how an action is carried out without
//!   breaking whoever calls it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::execution::Command;

/// The capability that grants every defined action.
pub const ANY_ACTION: &str = "action:*";

/// The capability that grants the action `id`.
pub fn capability_for(id: &str) -> String {
    format!("action:{id}")
}

/// Why a definitions file was refused. Each one names the action and field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionError(pub String);

impl std::fmt::Display for DefinitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DefinitionError {}

/// Why a caller's parameters were refused, before anything ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamError {
    /// The parameter at fault.
    pub param: String,
    /// What was wrong with it, in words a caller can act on.
    pub reason: String,
}

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parameter '{}': {}", self.param, self.reason)
    }
}

/// The shapes a parameter's value may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ParamType {
    /// One of a fixed list of strings.
    Enum {
        /// The values allowed.
        values: Vec<String>,
    },
    /// A whole number within an inclusive range. Both bounds are required: an
    /// unbounded number is a definition mistake, not a convenience.
    Integer {
        /// Smallest value allowed.
        min: i64,
        /// Largest value allowed.
        max: i64,
    },
    /// A name: 1–128 of `A-Z a-z 0-9 . _ -`, not starting with `-` (so it
    /// cannot be read as an option) and not `.` or `..` (so it cannot step
    /// out of a directory it is joined onto).
    Name,
}

/// The longest value a `name` parameter may have.
pub const MAX_NAME_LEN: usize = 128;

impl ParamType {
    /// Check a caller's value and render it as the text substituted into argv.
    fn accept(&self, value: &serde_json::Value) -> Result<String, String> {
        match self {
            ParamType::Enum { values } => {
                let text = value
                    .as_str()
                    .ok_or_else(|| "must be a string".to_string())?;
                if values.iter().any(|v| v == text) {
                    Ok(text.to_string())
                } else {
                    Err(format!("must be one of {}", values.join(", ")))
                }
            }
            ParamType::Integer { min, max } => {
                let n = value
                    .as_i64()
                    .ok_or_else(|| "must be a whole number".to_string())?;
                if n < *min || n > *max {
                    return Err(format!("must be between {min} and {max}"));
                }
                Ok(n.to_string())
            }
            ParamType::Name => {
                let text = value
                    .as_str()
                    .ok_or_else(|| "must be a string".to_string())?;
                check_name(text)?;
                Ok(text.to_string())
            }
        }
    }
}

fn check_name(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > MAX_NAME_LEN {
        return Err(format!("must be 1 to {MAX_NAME_LEN} characters"));
    }
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("may contain only letters, digits, '.', '_' and '-'".into());
    }
    if text.starts_with('-') {
        return Err("must not start with '-'".into());
    }
    if text == "." || text == ".." {
        return Err("must not be '.' or '..'".into());
    }
    Ok(())
}

/// Whether `id` is a valid action id: 1–64 of `A-Z a-z 0-9 . _ -`, starting
/// with a letter or digit.
fn check_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err("must be 1 to 64 characters".into());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("may contain only letters, digits, '.', '_' and '-'".into());
    }
    if !id.as_bytes()[0].is_ascii_alphanumeric() {
        return Err("must start with a letter or digit".into());
    }
    Ok(())
}

/// One piece of an argv element: literal text, or a parameter's value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Literal(String),
    Param(String),
}

/// Split an argv element into pieces. `{name}` is a parameter; `{{` and `}}`
/// are literal braces.
fn parse_element(element: &str) -> Result<Vec<Piece>, String> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut chars = element.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                literal.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                literal.push('}');
            }
            '{' => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(format!("'{{{name}' is not closed")),
                    }
                }
                if name.is_empty() {
                    return Err("'{}' names no parameter".into());
                }
                if !literal.is_empty() {
                    pieces.push(Piece::Literal(std::mem::take(&mut literal)));
                }
                pieces.push(Piece::Param(name));
            }
            '}' => return Err("a lone '}' (write '}}' for a literal one)".into()),
            c => literal.push(c),
        }
    }
    if !literal.is_empty() || pieces.is_empty() {
        pieces.push(Piece::Literal(literal));
    }
    Ok(pieces)
}

/// An action as written in the definitions file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAction {
    argv: Vec<String>,
    #[serde(default)]
    params: BTreeMap<String, ParamType>,
    timeout_secs: Option<u64>,
    working_dir: Option<PathBuf>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    actions: BTreeMap<String, RawAction>,
}

/// One action, checked and ready to run.
#[derive(Debug, Clone)]
pub struct Action {
    id: String,
    argv: Vec<Vec<Piece>>,
    params: BTreeMap<String, ParamType>,
    timeout: Option<Duration>,
    working_dir: Option<PathBuf>,
    env: BTreeMap<String, String>,
}

/// What a caller is told about an action: its id, its parameters, and its
/// deadline — never its argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionInfo {
    /// The action's id.
    pub id: String,
    /// Its parameters and the shape each must take.
    pub params: BTreeMap<String, ParamType>,
    /// The deadline it runs under, if the definition set one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

impl Action {
    fn from_raw(id: String, raw: RawAction) -> Result<Self, DefinitionError> {
        let fail = |what: String| DefinitionError(format!("action '{id}': {what}"));
        check_id(&id).map_err(|e| fail(format!("id {e}")))?;
        if raw.argv.is_empty() {
            return Err(fail("argv is empty".into()));
        }
        let mut argv = Vec::with_capacity(raw.argv.len());
        let mut used = std::collections::BTreeSet::new();
        for (index, element) in raw.argv.iter().enumerate() {
            let pieces = parse_element(element).map_err(|e| fail(format!("argv[{index}]: {e}")))?;
            for piece in &pieces {
                if let Piece::Param(name) = piece {
                    if index == 0 {
                        // The program is the owner's choice, never the caller's.
                        return Err(fail(format!(
                            "argv[0] uses parameter '{name}'; the program cannot be a parameter"
                        )));
                    }
                    if !raw.params.contains_key(name) {
                        return Err(fail(format!(
                            "argv[{index}] uses '{{{name}}}', which is not in params"
                        )));
                    }
                    used.insert(name.clone());
                }
            }
            argv.push(pieces);
        }
        for (name, kind) in &raw.params {
            check_name(name).map_err(|e| fail(format!("parameter name '{name}' {e}")))?;
            if !used.contains(name) {
                // Almost always a typo in argv; an unused parameter would
                // accept values that change nothing.
                return Err(fail(format!(
                    "parameter '{name}' is defined but argv never uses it"
                )));
            }
            match kind {
                ParamType::Enum { values } if values.is_empty() => {
                    return Err(fail(format!("parameter '{name}': enum has no values")));
                }
                ParamType::Integer { min, max } if min > max => {
                    return Err(fail(format!(
                        "parameter '{name}': min {min} is greater than max {max}"
                    )));
                }
                _ => {}
            }
        }
        if raw.timeout_secs == Some(0) {
            return Err(fail("timeout_secs must be at least 1".into()));
        }
        Ok(Self {
            id,
            argv,
            params: raw.params,
            timeout: raw.timeout_secs.map(Duration::from_secs),
            working_dir: raw.working_dir,
            env: raw.env,
        })
    }

    /// The action's id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What a caller may know about this action.
    pub fn info(&self) -> ActionInfo {
        ActionInfo {
            id: self.id.clone(),
            params: self.params.clone(),
            timeout_secs: self.timeout.map(|t| t.as_secs()),
        }
    }

    /// Check `params` against the definition and build the argv they produce.
    ///
    /// Every defined parameter is required, and one the definition does not
    /// name is refused rather than ignored — a misspelt parameter silently
    /// dropped is a call that did something other than what was asked.
    /// Returns the argv together with the accepted values, which are what the
    /// audit trail records.
    pub fn render(
        &self,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(Vec<String>, BTreeMap<String, String>), ParamError> {
        if let Some(unknown) = params.keys().find(|k| !self.params.contains_key(*k)) {
            return Err(ParamError {
                param: unknown.clone(),
                reason: "is not a parameter of this action".into(),
            });
        }
        let mut accepted = BTreeMap::new();
        for (name, kind) in &self.params {
            let value = params.get(name).ok_or_else(|| ParamError {
                param: name.clone(),
                reason: "is required".into(),
            })?;
            let text = kind.accept(value).map_err(|reason| ParamError {
                param: name.clone(),
                reason,
            })?;
            accepted.insert(name.clone(), text);
        }
        let argv = self
            .argv
            .iter()
            .map(|pieces| {
                pieces
                    .iter()
                    .map(|piece| match piece {
                        Piece::Literal(text) => text.as_str(),
                        Piece::Param(name) => accepted[name].as_str(),
                    })
                    .collect::<String>()
            })
            .collect();
        Ok((argv, accepted))
    }

    /// The command that carries this action out with `argv`.
    pub fn command(&self, argv: Vec<String>) -> Command {
        let mut command = Command::argv(argv).envs(self.env.clone());
        if let Some(timeout) = self.timeout {
            command = command.timeout(timeout);
        }
        if let Some(dir) = &self.working_dir {
            command = command.working_dir(dir.clone());
        }
        command
    }
}

/// Every action a server was started with.
#[derive(Debug, Clone, Default)]
pub struct ActionSet {
    actions: BTreeMap<String, Action>,
}

impl ActionSet {
    /// Parse a definitions file's contents.
    pub fn from_json(text: &str) -> Result<Self, DefinitionError> {
        let raw: RawFile = serde_json::from_str(text)
            .map_err(|e| DefinitionError(format!("not a valid actions file: {e}")))?;
        let mut actions = BTreeMap::new();
        for (id, action) in raw.actions {
            let action = Action::from_raw(id.clone(), action)?;
            actions.insert(id, action);
        }
        Ok(Self { actions })
    }

    /// Read and parse the definitions file at `path`, and check what can only
    /// be checked against this machine.
    ///
    /// A `working_dir` that does not exist is refused here rather than when the
    /// action runs: it is a definition mistake, and those are reported at
    /// startup, not to the first caller as a `500`. The program in `argv[0]` is
    /// not checked — where it resolves depends on `PATH` at the moment it runs,
    /// which is the operating system's answer to give, not this file's.
    ///
    /// The messages do not repeat `path`; whoever reports the error names the
    /// file once.
    pub fn load(path: &Path) -> Result<Self, DefinitionError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| DefinitionError(format!("cannot be read: {e}")))?;
        let set = Self::from_json(&text)?;
        for action in set.iter() {
            if let Some(dir) = &action.working_dir {
                if !dir.is_dir() {
                    return Err(DefinitionError(format!(
                        "action '{}': working_dir {} is not a directory",
                        action.id,
                        dir.display()
                    )));
                }
            }
        }
        Ok(set)
    }

    /// The action `id`, if one is defined.
    pub fn get(&self, id: &str) -> Option<&Action> {
        self.actions.get(id)
    }

    /// Every action, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.actions.values()
    }

    /// How many actions are defined.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn set(value: serde_json::Value) -> Result<ActionSet, DefinitionError> {
        ActionSet::from_json(&value.to_string())
    }

    fn params(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().expect("an object").clone()
    }

    fn tail_log() -> ActionSet {
        set(json!({"actions": {"tail-log": {
            "argv": ["tail", "-n", "{lines}", "/var/log/{service}.log"],
            "params": {
                "lines": {"type": "integer", "min": 1, "max": 1000},
                "service": {"type": "enum", "values": ["nginx", "app"]}
            },
            "timeout_secs": 10
        }}}))
        .expect("valid")
    }

    #[test]
    fn a_parameter_is_substituted_inside_one_argv_element() {
        let actions = tail_log();
        let (argv, accepted) = actions
            .get("tail-log")
            .unwrap()
            .render(&params(json!({"lines": 50, "service": "nginx"})))
            .expect("valid params");
        assert_eq!(argv, ["tail", "-n", "50", "/var/log/nginx.log"]);
        assert_eq!(accepted["lines"], "50");
    }

    #[test]
    fn every_way_a_caller_can_get_a_parameter_wrong_is_refused_by_name() {
        let action = tail_log();
        let action = action.get("tail-log").unwrap();
        let refuse = |p: serde_json::Value| action.render(&params(p)).unwrap_err().param;

        assert_eq!(refuse(json!({"service": "nginx"})), "lines"); // missing
        assert_eq!(refuse(json!({"lines": 0, "service": "nginx"})), "lines"); // below
        assert_eq!(refuse(json!({"lines": 1001, "service": "nginx"})), "lines"); // above
        assert_eq!(refuse(json!({"lines": "5", "service": "nginx"})), "lines"); // a string
        assert_eq!(refuse(json!({"lines": 1.5, "service": "nginx"})), "lines"); // not whole
        assert_eq!(refuse(json!({"lines": 5, "service": "db"})), "service"); // not listed
        assert_eq!(
            refuse(json!({"lines": 5, "service": "nginx", "extra": 1})),
            "extra"
        ); // unknown
    }

    /// The type whose job is to keep a free-form value harmless: no option
    /// injection, no traversal, no shell metacharacters.
    #[test]
    fn a_name_cannot_be_an_option_a_traversal_or_a_shell_fragment() {
        for bad in [
            "-rf", "--help", ".", "..", "", "a/b", "a\\b", "a b", "x;rm", "$(id)", "a&&b", "`id`",
        ] {
            assert!(
                ParamType::Name.accept(&json!(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
        let long = "a".repeat(MAX_NAME_LEN + 1);
        assert!(ParamType::Name.accept(&json!(long)).is_err());
        for good in ["nginx", "app.log", "release-1.2_3", "a", ".hidden"] {
            assert_eq!(ParamType::Name.accept(&json!(good)), Ok(good.to_string()));
        }
    }

    #[test]
    fn a_definition_mistake_refuses_the_whole_file_naming_the_action() {
        let cases = [
            (json!({"actions": {"x": {"argv": []}}}), "argv is empty"),
            (
                json!({"actions": {"x": {"argv": ["{p}"], "params": {"p": {"type": "name"}}}}}),
                "program cannot be a parameter",
            ),
            (
                json!({"actions": {"x": {"argv": ["a", "{q}"]}}}),
                "not in params",
            ),
            (
                json!({"actions": {"x": {"argv": ["a"], "params": {"p": {"type": "name"}}}}}),
                "never uses it",
            ),
            (
                json!({"actions": {"x": {"argv": ["a", "{p}"], "params": {"p": {"type": "integer", "min": 5, "max": 1}}}}}),
                "greater than max",
            ),
            (
                json!({"actions": {"x": {"argv": ["a", "{p}"], "params": {"p": {"type": "enum", "values": []}}}}}),
                "no values",
            ),
            (
                json!({"actions": {"x": {"argv": ["a", "{p"], "params": {"p": {"type": "name"}}}}}),
                "not closed",
            ),
            (json!({"actions": {"x": {"argv": ["a}"]}}}), "lone '}'"),
            (json!({"actions": {"-x": {"argv": ["a"]}}}), "id must start"),
            (
                json!({"actions": {"x": {"argv": ["a"], "timeout_secs": 0}}}),
                "at least 1",
            ),
            (
                json!({"actions": {"x": {"argv": ["a"], "shell": true}}}),
                "unknown field",
            ),
            (
                json!({"actions": {"x": {"argv": ["a", "{p}"], "params": {"p": {"type": "regex"}}}}}),
                "unknown variant",
            ),
        ];
        for (file, expected) in cases {
            let err = set(file.clone()).unwrap_err().to_string();
            assert!(
                err.contains(expected),
                "{file} should fail with {expected:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn doubled_braces_are_literal() {
        let actions = set(json!({"actions": {"x": {
            "argv": ["printf", "{{{v}}}"],
            "params": {"v": {"type": "name"}}
        }}}))
        .expect("valid");
        let (argv, _) = actions
            .get("x")
            .unwrap()
            .render(&params(json!({"v": "ok"})))
            .unwrap();
        assert_eq!(argv, ["printf", "{ok}"]);
    }

    #[test]
    fn a_caller_is_told_the_parameters_and_never_the_argv() {
        let info = tail_log().get("tail-log").unwrap().info();
        let text = serde_json::to_string(&info).unwrap();
        assert!(!text.contains("/var/log"), "{text}");
        assert!(text.contains("\"lines\""), "{text}");
        assert_eq!(info.timeout_secs, Some(10));
    }
}
