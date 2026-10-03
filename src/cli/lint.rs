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
}
