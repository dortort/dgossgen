#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintIssue {
    pub file: String,
    pub message: String,
}

pub fn lint_goss_content(content: &str, filename: &str, issues: &mut Vec<LintIssue>) {
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
            message: "Invalid YAML syntax".to_string(),
        });
        return;
    }

    let doc = parsed.expect("checked above");

    // Check for common flake patterns
    if let Some(mapping) = doc.as_object() {
        // Check for ephemeral paths
        if let Some(files) = mapping.get("file") {
            if let Some(file_map) = files.as_object() {
                for path in file_map.keys() {
                    if path.contains("/tmp/")
                        || path.contains("/var/cache/")
                        || path.contains("/proc/")
                    {
                        issues.push(LintIssue {
                            file: filename.to_string(),
                            message: format!(
                                "File assertion on ephemeral path '{}' may be flaky",
                                path
                            ),
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
                        message: "Many process assertions (>3) increase flake risk".to_string(),
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
                                message: format!("Command '{}' has no timeout (may hang)", key),
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
        lint_goss_content("file: [", "goss.yml", &mut issues);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].message, "Invalid YAML syntax");
    }

    #[test]
    fn test_lint_ephemeral_path() {
        let yaml = "file:\n  /tmp/file:\n    exists: true\n";
        let mut issues = Vec::new();
        lint_goss_content(yaml, "goss.yml", &mut issues);
        assert!(issues.iter().any(|i| i.message.contains("ephemeral path")));
    }

    fn lint(yaml: &str) -> Vec<String> {
        let mut issues = Vec::new();
        lint_goss_content(yaml, "goss.yml", &mut issues);
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
}
