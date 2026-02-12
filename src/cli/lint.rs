#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintIssue {
    pub file: String,
    pub message: String,
}

pub fn lint_goss_content(content: &str, filename: &str, issues: &mut Vec<LintIssue>) {
    // Check YAML validity
    let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(content);
    if parsed.is_err() {
        issues.push(LintIssue {
            file: filename.to_string(),
            message: "Invalid YAML syntax".to_string(),
        });
        return;
    }

    let doc = parsed.expect("checked above");

    // Check for common flake patterns
    if let Some(mapping) = doc.as_mapping() {
        // Check for ephemeral paths
        if let Some(files) = mapping.get(serde_yaml::Value::String("file".to_string())) {
            if let Some(file_map) = files.as_mapping() {
                for (key, _) in file_map {
                    if let Some(path) = key.as_str() {
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
        }

        // Check for process assertions (often flaky)
        if let Some(processes) = mapping.get(serde_yaml::Value::String("process".to_string())) {
            if let Some(proc_map) = processes.as_mapping() {
                if proc_map.len() > 3 {
                    issues.push(LintIssue {
                        file: filename.to_string(),
                        message: "Many process assertions (>3) increase flake risk".to_string(),
                    });
                }
            }
        }

        // Check command timeouts
        if let Some(commands) = mapping.get(serde_yaml::Value::String("command".to_string())) {
            if let Some(cmd_map) = commands.as_mapping() {
                for (key, val) in cmd_map {
                    if let Some(cmd_val) = val.as_mapping() {
                        let timeout = cmd_val
                            .get(serde_yaml::Value::String("timeout".to_string()))
                            .and_then(|v| v.as_u64());

                        if timeout.is_none() || timeout == Some(0) {
                            if let Some(name) = key.as_str() {
                                issues.push(LintIssue {
                                    file: filename.to_string(),
                                    message: format!(
                                        "Command '{}' has no timeout (may hang)",
                                        name
                                    ),
                                });
                            }
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
        assert!(issues
            .iter()
            .any(|i| i.message.contains("ephemeral path")));
    }
}
