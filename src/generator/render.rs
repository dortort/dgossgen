use super::GossResource;
use crate::Confidence;

/// Render a list of GossResources into a goss.yml formatted string.
/// Uses stable ordering and includes provenance comments.
pub fn render_goss(resources: &[GossResource]) -> String {
    let mut output = String::new();

    // Group resources by type for stable ordering
    let files: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r, GossResource::File { .. }))
        .collect();
    let ports: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r, GossResource::Port { .. }))
        .collect();
    let processes: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r, GossResource::Process { .. }))
        .collect();
    let commands: Vec<_> = resources
        .iter()
        .filter(|r| {
            matches!(
                r,
                GossResource::Command { .. } | GossResource::CommandWithOutput { .. }
            )
        })
        .collect();
    let http: Vec<_> = resources
        .iter()
        .filter(|r| matches!(r, GossResource::Http { .. }))
        .collect();

    // Render each section
    if !files.is_empty() {
        output.push_str("file:\n");
        for resource in &files {
            render_file_resource(&mut output, resource);
        }
    }

    if !ports.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("port:\n");
        for resource in &ports {
            render_port_resource(&mut output, resource);
        }
    }

    if !processes.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("process:\n");
        for resource in &processes {
            render_process_resource(&mut output, resource);
        }
    }

    if !commands.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("command:\n");
        for resource in &commands {
            render_command_resource(&mut output, resource);
        }
    }

    if !http.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("http:\n");
        for resource in &http {
            render_http_resource(&mut output, resource);
        }
    }

    if output.is_empty() {
        // Emit a minimal valid goss.yml
        output.push_str("# No assertions generated. Consider using --profile strict or providing more Dockerfile context.\n");
        output.push_str("command: {}\n");
    }

    output
}

/// Render goss_wait.yml with wait-specific resources.
pub fn render_goss_wait(resources: &[GossResource]) -> String {
    // Same structure as goss.yml but focused on readiness
    render_goss(resources)
}

/// Render a minimal viable wait file with just a port check.
pub fn render_goss_wait_minimal(port: u16, protocol: &str) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "# Minimal viable wait: port readiness check\n"
    ));
    output.push_str(&format!(
        "# derived from EXPOSE {}; confidence: medium\n",
        port
    ));
    output.push_str("port:\n");
    output.push_str(&format!("  {}:{}:\n", protocol, port));
    output.push_str("    listening: true\n");
    output
}

fn render_provenance_comment(output: &mut String, provenance: &str, confidence: Confidence) {
    output.push_str(&format!(
        "  # derived from {}; confidence: {}\n",
        provenance, confidence
    ));
}

fn render_file_resource(output: &mut String, resource: &GossResource) {
    if let GossResource::File {
        path,
        exists,
        filetype,
        mode,
        provenance,
        confidence,
    } = resource
    {
        render_provenance_comment(output, provenance, *confidence);
        output.push_str(&format!("  {}:\n", yaml_escape_key(path)));
        output.push_str(&format!("    exists: {}\n", exists));
        if let Some(ft) = filetype {
            output.push_str(&format!("    filetype: {}\n", ft));
        }
        if let Some(m) = mode {
            output.push_str(&format!("    mode: \"{}\"\n", m));
        }
    }
}

fn render_port_resource(output: &mut String, resource: &GossResource) {
    if let GossResource::Port {
        address,
        listening,
        provenance,
        confidence,
    } = resource
    {
        render_provenance_comment(output, provenance, *confidence);
        output.push_str(&format!("  {}:\n", address));
        output.push_str(&format!("    listening: {}\n", listening));
    }
}

fn render_process_resource(output: &mut String, resource: &GossResource) {
    if let GossResource::Process {
        name,
        running,
        provenance,
        confidence,
    } = resource
    {
        render_provenance_comment(output, provenance, *confidence);
        output.push_str(&format!("  {}:\n", yaml_escape_key(name)));
        output.push_str(&format!("    running: {}\n", running));
    }
}

fn render_command_resource(output: &mut String, resource: &GossResource) {
    match resource {
        GossResource::Command {
            name,
            command,
            exit_status,
            timeout,
            provenance,
            confidence,
        } => {
            render_provenance_comment(output, provenance, *confidence);
            output.push_str(&format!("  {}:\n", yaml_escape_key(name)));
            output.push_str(&format!("    exec: \"{}\"\n", yaml_escape_value(command)));
            output.push_str(&format!("    exit-status: {}\n", exit_status));
            output.push_str(&format!("    timeout: {}\n", timeout));
        }
        GossResource::CommandWithOutput {
            name,
            command,
            exit_status,
            stdout,
            timeout,
            provenance,
            confidence,
        } => {
            render_provenance_comment(output, provenance, *confidence);
            output.push_str(&format!("  {}:\n", yaml_escape_key(name)));
            output.push_str(&format!("    exec: \"{}\"\n", yaml_escape_value(command)));
            output.push_str(&format!("    exit-status: {}\n", exit_status));
            if !stdout.is_empty() {
                output.push_str("    stdout:\n");
                for line in stdout {
                    output.push_str(&format!("      - \"{}\"\n", yaml_escape_value(line)));
                }
            }
            output.push_str(&format!("    timeout: {}\n", timeout));
        }
        _ => {}
    }
}

fn render_http_resource(output: &mut String, resource: &GossResource) {
    if let GossResource::Http {
        url,
        status,
        provenance,
        confidence,
    } = resource
    {
        render_provenance_comment(output, provenance, *confidence);
        output.push_str(&format!("  {}:\n", yaml_escape_key(url)));
        output.push_str(&format!("    status: {}\n", status));
    }
}

/// Escape a YAML key (wrap in quotes if it contains special characters).
fn yaml_escape_key(key: &str) -> String {
    if key.contains(':')
        || key.contains(' ')
        || key.contains('#')
        || key.contains('{')
        || key.contains('}')
        || key.contains('[')
        || key.contains(']')
        || key.contains(',')
        || key.contains('&')
        || key.contains('*')
        || key.contains('!')
        || key.contains('|')
        || key.contains('>')
        || key.contains('\'')
        || key.contains('"')
        || key.contains('%')
        || key.contains('@')
        || key.contains('`')
    {
        format!("\"{}\"", key.replace('"', "\\\""))
    } else {
        key.to_string()
    }
}

/// Escape a YAML string value.
fn yaml_escape_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_empty() {
        let output = render_goss(&[]);
        assert!(output.contains("command: {}"));
    }

    #[test]
    fn test_render_file_resource() {
        let resources = vec![GossResource::File {
            path: "/app".to_string(),
            exists: true,
            filetype: Some("directory".to_string()),
            mode: None,
            provenance: "WORKDIR /app".to_string(),
            confidence: Confidence::High,
        }];
        let output = render_goss(&resources);
        assert!(output.contains("file:"));
        assert!(output.contains("/app:"));
        assert!(output.contains("exists: true"));
        assert!(output.contains("filetype: directory"));
    }

    #[test]
    fn test_render_port_resource() {
        let resources = vec![GossResource::Port {
            address: "tcp:8080".to_string(),
            listening: true,
            provenance: "EXPOSE 8080".to_string(),
            confidence: Confidence::Medium,
        }];
        let output = render_goss(&resources);
        assert!(output.contains("port:"));
        assert!(output.contains("tcp:8080"));
        assert!(output.contains("listening: true"));
    }

    #[test]
    fn test_yaml_escape_key() {
        assert_eq!(yaml_escape_key("simple"), "simple");
        assert_eq!(yaml_escape_key("tcp:8080"), "\"tcp:8080\"");
    }

    #[test]
    fn test_stable_ordering() {
        let resources = vec![
            GossResource::Process {
                name: "nginx".to_string(),
                running: true,
                provenance: "CMD".to_string(),
                confidence: Confidence::Medium,
            },
            GossResource::File {
                path: "/app".to_string(),
                exists: true,
                filetype: None,
                mode: None,
                provenance: "COPY".to_string(),
                confidence: Confidence::Medium,
            },
            GossResource::Port {
                address: "tcp:80".to_string(),
                listening: true,
                provenance: "EXPOSE".to_string(),
                confidence: Confidence::Medium,
            },
        ];
        let output = render_goss(&resources);
        let file_pos = output.find("file:").unwrap();
        let port_pos = output.find("port:").unwrap();
        let process_pos = output.find("process:").unwrap();
        // Stable order: file, port, process, command, http
        assert!(file_pos < port_pos);
        assert!(port_pos < process_pos);
    }
}
