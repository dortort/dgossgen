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
