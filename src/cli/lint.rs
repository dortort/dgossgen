use serde::Serialize;

/// How serious a lint finding is. `Error` marks a file that could not be parsed
/// at all (nothing else can be checked); `Warning` marks a likely-flaky but
/// valid suite. Serialized lowercase so JSON consumers (CI annotators) can map
/// it straight onto their own severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LintIssue {
    pub file: String,
    /// 1-based line of the offending key in the source, located by a
    /// best-effort scan. `None` when the finding is file-wide or the key could
    /// not be found verbatim, so a wrong line is never reported.
    pub line: Option<usize>,
    pub severity: Severity,
    /// The diagnosis — what is wrong.
    pub message: String,
    /// The remediation — how to fix it. Empty only when no concrete fix applies.
    pub suggestion: String,
}

/// Whether `line`'s first non-whitespace token is `key` immediately followed by
/// a colon, matching the bare, single-quoted and double-quoted spellings that
/// goss suites use. Requiring the trailing colon stops `a` from matching `abc:`
/// or the value half of `other: a`.
fn key_on_line(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    let after_key = trimmed
        .strip_prefix(key)
        .or_else(|| trimmed.strip_prefix(&format!("\"{key}\"")))
        .or_else(|| trimmed.strip_prefix(&format!("'{key}'")));
    matches!(after_key, Some(rest) if rest.starts_with(':'))
}

/// Leading-whitespace width of `line`, used as its block indentation. Goss
/// suites indent with spaces (YAML forbids tabs for indentation), so a byte
/// count is the column.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Best-effort 1-based line of a top-level mapping key in the YAML source.
///
/// Scans for the first line whose first non-whitespace token is `key` followed
/// immediately by a colon. Returns `None` when no such line exists, so callers
/// emit a null line rather than guessing.
fn find_key_line(content: &str, key: &str) -> Option<usize> {
    content
        .lines()
        .enumerate()
        .find_map(|(i, line)| key_on_line(line, key).then_some(i + 1))
}

/// Best-effort 1-based line of `key` as a *direct* child entry of the top-level
/// `section` mapping.
///
/// Unlike a global scan, this only matches lines that belong to `section` — from
/// its column-0 header to the next column-0 key — and only at the section's
/// direct-child indentation, so a key reused in another section (a `command`
/// and a `file` entry sharing a name) or a command named after a nested
/// property (`exec:`, `timeout:`) resolves to the right occurrence. Returns
/// `None` when the section or the key is not found.
fn find_entry_line(content: &str, section: &str, key: &str) -> Option<usize> {
    let mut in_section = false;
    // The indentation of the section's direct children, learned from the first
    // child line. Deeper lines are an entry's own properties, not entries.
    let mut child_indent: Option<usize> = None;
    for (i, line) in content.lines().enumerate() {
        // Blank and comment lines never open or close a block.
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = indent_of(line);
        if !in_section {
            if indent == 0 && key_on_line(line, section) {
                in_section = true;
            }
            continue;
        }
        // A return to column 0 ends the section (duplicate top-level keys are
        // rejected as invalid YAML earlier, so the section occurs once).
        if indent == 0 {
            return None;
        }
        let depth = *child_indent.get_or_insert(indent);
        if indent == depth && key_on_line(line, key) {
            return Some(i + 1);
        }
    }
    None
}

/// Which suite file is being linted.
///
/// The readiness gate (`Wait`) legitimately asserts on volatile paths — that is
/// what its retry loop exists for — so the ephemeral-path flake rule, whose own
/// remediation is "move readiness-sensitive checks to `goss_wait.yml`", does not
/// apply there. All other rules apply to both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteKind {
    /// The main `goss.yml`, run once.
    Main,
    /// The `goss_wait.yml` readiness gate, retried until ready or timeout.
    Wait,
}

pub fn lint_goss_content(
    content: &str,
    filename: &str,
    kind: SuiteKind,
    issues: &mut Vec<LintIssue>,
) {
    // Check YAML validity
    let options = serde_saphyr::options! {
        // Goss suites routinely reuse one anchor many times, which the ratio heuristic rejects.
        budget: serde_saphyr::budget! { enforce_alias_anchor_ratio: false },
        reject_non_finite_typeless_float: false,
    };
    let parsed: Result<serde_json::Value, _> =
        serde_saphyr::from_str_with_options(content, options);
    if parsed.is_err() {
        issues.push(LintIssue {
            file: filename.to_string(),
            line: None,
            severity: Severity::Error,
            message: "Invalid YAML syntax".to_string(),
            suggestion: "fix the YAML syntax so the file can be parsed".to_string(),
        });
        return;
    }

    let doc = parsed.expect("checked above");

    // Check for common flake patterns
    if let Some(mapping) = doc.as_object() {
        // Check for ephemeral paths. Skipped for the readiness gate, whose retry
        // loop is exactly how a volatile-path assertion is meant to be made
        // robust — flagging it there would contradict this rule's own advice to
        // move such checks into goss_wait.yml.
        if let (SuiteKind::Main, Some(files)) = (kind, mapping.get("file")) {
            if let Some(file_map) = files.as_object() {
                for path in file_map.keys() {
                    if path.contains("/tmp/")
                        || path.contains("/var/cache/")
                        || path.contains("/proc/")
                    {
                        issues.push(LintIssue {
                            file: filename.to_string(),
                            line: find_entry_line(content, "file", path),
                            severity: Severity::Warning,
                            message: format!(
                                "File assertion on ephemeral path '{}' may be flaky",
                                path
                            ),
                            suggestion: "remove this assertion or move readiness-sensitive \
                                 checks to `goss_wait.yml`"
                                .to_string(),
                        });
                    }
                }
            }
        }

        // Check for process assertions (often flaky)
        if let Some(processes) = mapping.get("process") {
            if let Some(proc_map) = processes.as_object() {
                if proc_map.len() > 3 {
                    issues.push(LintIssue {
                        file: filename.to_string(),
                        line: find_key_line(content, "process"),
                        severity: Severity::Warning,
                        message: "Many process assertions (>3) increase flake risk".to_string(),
                        suggestion: "keep only the primary process, or regenerate with \
                             `--profile minimal` to drop low-confidence process checks"
                            .to_string(),
                    });
                }
            }
        }

        // Check command timeouts
        if let Some(commands) = mapping.get("command") {
            if let Some(cmd_map) = commands.as_object() {
                for (key, val) in cmd_map {
                    if let Some(cmd_val) = val.as_object() {
                        let timeout = cmd_val.get("timeout").and_then(|v| v.as_u64());

                        if timeout.is_none() || timeout == Some(0) {
                            issues.push(LintIssue {
                                file: filename.to_string(),
                                line: find_entry_line(content, "command", key),
                                severity: Severity::Warning,
                                message: format!("Command '{}' has no timeout (may hang)", key),
                                suggestion: "add `timeout: 10000`".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_invalid_yaml() {
        let mut issues = Vec::new();
        lint_goss_content("file: [", "goss.yml", SuiteKind::Main, &mut issues);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].message, "Invalid YAML syntax");
    }

    #[test]
    fn test_lint_ephemeral_path() {
        let yaml = "file:\n  /tmp/file:\n    exists: true\n";
        let mut issues = Vec::new();
        lint_goss_content(yaml, "goss.yml", SuiteKind::Main, &mut issues);
        assert!(issues.iter().any(|i| i.message.contains("ephemeral path")));
    }

    fn lint(yaml: &str) -> Vec<String> {
        let mut issues = Vec::new();
        lint_goss_content(yaml, "goss.yml", SuiteKind::Main, &mut issues);
        issues.into_iter().map(|i| i.message).collect()
    }

    #[test]
    fn test_lint_non_string_keys_are_checked_as_strings() {
        assert_eq!(
            lint("command:\n  123:\n    exec: x\n  true:\n    exec: y\n"),
            vec![
                "Command '123' has no timeout (may hang)",
                "Command 'true' has no timeout (may hang)",
            ]
        );
        assert!(lint("1: x\nfile:\n  42:\n    exists: true\n").is_empty());
    }

    #[test]
    fn test_lint_null_values_parse() {
        assert!(lint("command:\nfile:\n").is_empty());
        assert!(lint("command:\n  a:\n").is_empty());
        assert_eq!(
            lint("command:\n  a:\n    exec: x\n    timeout: ~\n"),
            vec!["Command 'a' has no timeout (may hang)"]
        );
        assert!(lint("").is_empty());
    }

    #[test]
    fn test_lint_null_or_complex_keys_are_invalid() {
        assert_eq!(
            lint("command:\n  ~:\n    exec: x\n"),
            vec!["Invalid YAML syntax"]
        );
        assert_eq!(
            lint("command:\n  ? [a, b]\n  : exec: x\n"),
            vec!["Invalid YAML syntax"]
        );
    }

    #[test]
    fn test_lint_resolves_anchors_aliases_and_merge_keys() {
        let yaml = "command:\n  a: &d\n    exec: x\n    timeout: 1000\n  b: *d\n  c:\n    <<: *d\n    exec: y\n";
        assert!(lint(yaml).is_empty());
    }

    #[test]
    fn test_lint_accepts_many_aliases_of_one_anchor() {
        let mut yaml = String::from("defaults: &d {timeout: 1000}\ncommand:\n");
        for i in 0..300 {
            yaml.push_str(&format!("  c{i}:\n    <<: *d\n    exec: x\n"));
        }
        assert!(lint(&yaml).is_empty());
    }

    #[test]
    fn test_lint_accepts_non_finite_floats() {
        assert!(lint("command:\n  a:\n    exec: .nan\n    timeout: .inf\n")
            .iter()
            .all(|m| m != "Invalid YAML syntax"));
    }

    #[test]
    fn test_lint_reports_in_document_order() {
        assert_eq!(
            lint("command:\n  zeta:\n    exec: x\n  alpha:\n    exec: y\n"),
            vec![
                "Command 'zeta' has no timeout (may hang)",
                "Command 'alpha' has no timeout (may hang)",
            ]
        );
    }

    #[test]
    fn test_lint_duplicate_key_is_invalid() {
        assert_eq!(
            lint("command:\n  a:\n    exec: x\n  a:\n    exec: y\n"),
            vec!["Invalid YAML syntax"]
        );
    }

    fn lint_issues(yaml: &str) -> Vec<LintIssue> {
        let mut issues = Vec::new();
        lint_goss_content(yaml, "goss.yml", SuiteKind::Main, &mut issues);
        issues
    }

    #[test]
    fn test_invalid_yaml_is_an_error_with_remediation() {
        let issues = lint_issues("file: [");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(!issues[0].suggestion.is_empty());
        // A failed parse cannot be located, so no line is guessed.
        assert_eq!(issues[0].line, None);
    }

    #[test]
    fn test_ephemeral_path_issue_carries_remediation_severity_and_line() {
        let yaml = "file:\n  /tmp/file:\n    exists: true\n";
        let issues = lint_issues(yaml);
        let issue = issues
            .iter()
            .find(|i| i.message.contains("ephemeral path"))
            .expect("ephemeral-path issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(
            issue.suggestion.contains("goss_wait.yml"),
            "suggestion should name the remediation, got: {}",
            issue.suggestion
        );
        // The offending key sits on the second physical line.
        assert_eq!(issue.line, Some(2));
    }

    #[test]
    fn test_missing_timeout_issue_suggests_a_concrete_timeout() {
        let yaml = "command:\n  check:\n    exec: /bin/true\n";
        let issues = lint_issues(yaml);
        let issue = issues
            .iter()
            .find(|i| i.message.contains("no timeout"))
            .expect("missing-timeout issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(
            issue.suggestion.contains("timeout: 10000"),
            "suggestion should give the one-line fix, got: {}",
            issue.suggestion
        );
        assert_eq!(issue.line, Some(2));
    }

    #[test]
    fn test_process_count_issue_suggests_minimal_profile() {
        let mut yaml = String::from("process:\n");
        for name in ["a", "b", "c", "d"] {
            yaml.push_str(&format!("  {name}:\n    running: true\n"));
        }
        let issues = lint_issues(&yaml);
        let issue = issues
            .iter()
            .find(|i| i.message.contains("process assertions"))
            .expect("process-count issue");
        assert_eq!(issue.severity, Severity::Warning);
        assert!(issue.suggestion.contains("--profile minimal"));
        // The file-wide finding anchors to the `process:` section header.
        assert_eq!(issue.line, Some(1));
    }

    #[test]
    fn test_find_key_line_matches_quoted_spellings_and_rejects_prefixes() {
        // Bare, single- and double-quoted keys all resolve; a longer key that
        // merely starts with the query must not match.
        assert_eq!(find_key_line("a:\n", "a"), Some(1));
        assert_eq!(find_key_line("  \"a\": x\n", "a"), Some(1));
        assert_eq!(find_key_line("other: 1\n  'a': x\n", "a"), Some(2));
        assert_eq!(find_key_line("abc: 1\n", "a"), None);
        assert_eq!(find_key_line("value: a\n", "a"), None);
    }

    #[test]
    fn test_find_entry_line_is_scoped_to_its_section() {
        // The same key `dup` appears under two sections. Each lookup must
        // resolve within its own section rather than returning the first global
        // match.
        let yaml = "\
file:
  dup:
    exists: true
command:
  dup:
    exec: x
";
        assert_eq!(find_entry_line(yaml, "file", "dup"), Some(2));
        assert_eq!(find_entry_line(yaml, "command", "dup"), Some(5));
        // A key that lives in another section is not borrowed across.
        assert_eq!(find_entry_line(yaml, "process", "dup"), None);
    }

    #[test]
    fn test_find_entry_line_matches_only_direct_children() {
        // A command named `exec` collides with another command's nested `exec:`
        // property. The lookup must point at the command entry (indent 2), not
        // the earlier property line (indent 4).
        let yaml = "\
command:
  first:
    exec: /bin/true
  exec:
    stdout: hi
";
        assert_eq!(find_entry_line(yaml, "command", "exec"), Some(4));

        // A command named `timeout` after a sibling carrying a `timeout:`
        // property must resolve to the command entry, not the property line.
        let collide = "\
command:
  foo:
    exec: x
    timeout: 0
  timeout:
    exec: y
";
        assert_eq!(find_entry_line(collide, "command", "timeout"), Some(5));
    }

    #[test]
    fn test_ephemeral_path_rule_is_skipped_for_the_readiness_gate() {
        // The ephemeral-path remediation tells users to move readiness checks
        // into goss_wait.yml; linting the wait file with the same rule would
        // make that advice impossible to satisfy, so Wait suites skip it.
        let yaml = "file:\n  /tmp/ready:\n    exists: true\n";
        let mut main_issues = Vec::new();
        lint_goss_content(yaml, "goss_wait.yml", SuiteKind::Main, &mut main_issues);
        assert!(
            main_issues
                .iter()
                .any(|i| i.message.contains("ephemeral path")),
            "a Main suite must still flag the ephemeral path"
        );

        let mut wait_issues = Vec::new();
        lint_goss_content(yaml, "goss_wait.yml", SuiteKind::Wait, &mut wait_issues);
        assert!(
            wait_issues.is_empty(),
            "the readiness gate must not flag ephemeral paths, got: {wait_issues:?}"
        );
    }

    #[test]
    fn test_timeout_finding_line_points_into_the_command_section() {
        // Regression guard: a command key that collides with an earlier `file`
        // entry must locate the command, not the file entry.
        let yaml = "\
file:
  shared:
    exists: true
command:
  shared:
    exec: /bin/true
";
        let issue = lint_issues(yaml)
            .into_iter()
            .find(|i| i.message.contains("no timeout"))
            .expect("missing-timeout issue");
        assert_eq!(
            issue.line,
            Some(5),
            "the timeout finding must point at the command entry, not the file key"
        );
    }
}
