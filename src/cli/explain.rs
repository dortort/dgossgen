use crate::extractor::AssertionKind;

pub fn assertion_type_name(kind: &AssertionKind) -> &'static str {
    match kind {
        AssertionKind::FileExists { .. } => "file",
        AssertionKind::PortListening { .. } => "port",
        AssertionKind::ProcessRunning { .. } => "process",
        AssertionKind::CommandExit { .. } => "command",
        AssertionKind::CommandOutput { .. } => "command (with output)",
        AssertionKind::UserExists { .. } => "user",
        AssertionKind::HealthcheckPasses { .. } => "healthcheck",
        AssertionKind::HttpStatus { .. } => "http",
        AssertionKind::PackageInstalled { .. } => "package",
    }
}

pub fn assertion_description(kind: &AssertionKind) -> String {
    match kind {
        AssertionKind::FileExists {
            path,
            filetype,
            mode,
        } => {
            let mut desc = format!("File '{}' exists", path);
            if let Some(ft) = filetype {
                desc.push_str(&format!(" (type: {})", ft));
            }
            if let Some(m) = mode {
                desc.push_str(&format!(" (mode: {})", m));
            }
            desc
        }
        AssertionKind::PortListening { protocol, port } => {
            format!("Port {}/{} is listening", port, protocol)
        }
        AssertionKind::ProcessRunning { name } => {
            format!("Process '{}' is running", name)
        }
        AssertionKind::CommandExit {
            command,
            exit_status,
        } => {
            format!("Command '{}' exits with status {}", command, exit_status)
        }
        AssertionKind::CommandOutput {
            command,
            exit_status,
            expected_output,
        } => {
            format!(
                "Command '{}' exits with status {} and outputs {:?}",
                command, exit_status, expected_output
            )
        }
        AssertionKind::UserExists { username } => {
            format!("User '{}' exists", username)
        }
        AssertionKind::HealthcheckPasses { command } => {
            format!("Healthcheck '{}' passes", command)
        }
        AssertionKind::HttpStatus { url, status } => {
            format!("HTTP {} returns status {}", url, status)
        }
        AssertionKind::PackageInstalled {
            package, manager, ..
        } => {
            format!("Package '{}' installed via {:?}", package, manager)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::PackageManager;

    /// Compile-time guard: a wildcard-free match over every `AssertionKind`
    /// variant. Adding a new variant breaks compilation of this test module
    /// until it is listed here (and in [`one_of_each`] and the `explain` arms).
    fn assert_every_variant_is_covered(kind: &AssertionKind) {
        match kind {
            AssertionKind::FileExists { .. }
            | AssertionKind::PortListening { .. }
            | AssertionKind::ProcessRunning { .. }
            | AssertionKind::CommandExit { .. }
            | AssertionKind::CommandOutput { .. }
            | AssertionKind::UserExists { .. }
            | AssertionKind::HealthcheckPasses { .. }
            | AssertionKind::HttpStatus { .. }
            | AssertionKind::PackageInstalled { .. } => {}
        }
    }

    /// One value of every `AssertionKind` variant, in declaration order, used to
    /// pin the type names and descriptions below.
    fn one_of_each() -> Vec<AssertionKind> {
        vec![
            AssertionKind::FileExists {
                path: "/etc/app.conf".to_string(),
                filetype: None,
                mode: None,
            },
            AssertionKind::PortListening {
                protocol: "tcp".to_string(),
                port: 8080,
            },
            AssertionKind::ProcessRunning {
                name: "nginx".to_string(),
            },
            AssertionKind::CommandExit {
                command: "true".to_string(),
                exit_status: 0,
            },
            AssertionKind::CommandOutput {
                command: "echo hi".to_string(),
                exit_status: 0,
                expected_output: vec!["hi".to_string()],
            },
            AssertionKind::UserExists {
                username: "app".to_string(),
            },
            AssertionKind::HealthcheckPasses {
                command: "curl -f http://localhost/".to_string(),
            },
            AssertionKind::HttpStatus {
                url: "http://127.0.0.1:80/healthz".to_string(),
                status: 200,
            },
            AssertionKind::PackageInstalled {
                package: "curl".to_string(),
                manager: PackageManager::Apt,
                version_cmd: None,
            },
        ]
    }

    #[test]
    fn test_assertion_type_name_for_every_kind() {
        let kinds = one_of_each();
        kinds.iter().for_each(assert_every_variant_is_covered);
        let names: Vec<&str> = kinds.iter().map(assertion_type_name).collect();
        assert_eq!(
            names,
            vec![
                "file",
                "port",
                "process",
                "command",
                "command (with output)",
                "user",
                "healthcheck",
                "http",
                "package",
            ]
        );
    }

    #[test]
    fn test_assertion_description_for_every_kind() {
        let descriptions: Vec<String> = one_of_each().iter().map(assertion_description).collect();
        assert_eq!(
            descriptions,
            vec![
                "File '/etc/app.conf' exists".to_string(),
                "Port 8080/tcp is listening".to_string(),
                "Process 'nginx' is running".to_string(),
                "Command 'true' exits with status 0".to_string(),
                "Command 'echo hi' exits with status 0 and outputs [\"hi\"]".to_string(),
                "User 'app' exists".to_string(),
                "Healthcheck 'curl -f http://localhost/' passes".to_string(),
                "HTTP http://127.0.0.1:80/healthz returns status 200".to_string(),
                "Package 'curl' installed via Apt".to_string(),
            ]
        );
    }

    #[test]
    fn test_file_exists_description_appends_filetype_and_mode() {
        // The optional filetype and mode enrich the description in order when present.
        let desc = assertion_description(&AssertionKind::FileExists {
            path: "/usr/local/bin/app".to_string(),
            filetype: Some("file".to_string()),
            mode: Some("0755".to_string()),
        });
        assert_eq!(
            desc,
            "File '/usr/local/bin/app' exists (type: file) (mode: 0755)"
        );
    }

    #[test]
    fn test_file_exists_description_appends_mode_without_filetype() {
        let desc = assertion_description(&AssertionKind::FileExists {
            path: "/data".to_string(),
            filetype: None,
            mode: Some("0700".to_string()),
        });
        assert_eq!(desc, "File '/data' exists (mode: 0700)");
    }
}
