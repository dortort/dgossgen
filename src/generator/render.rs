use super::GossResource;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Default)]
struct GossDocument {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    file: BTreeMap<String, FileAssertion>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    port: BTreeMap<String, PortAssertion>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    process: BTreeMap<String, ProcessAssertion>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    command: BTreeMap<String, CommandAssertion>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    http: BTreeMap<String, HttpAssertion>,
}

impl GossDocument {
    fn is_empty(&self) -> bool {
        self.file.is_empty()
            && self.port.is_empty()
            && self.process.is_empty()
            && self.command.is_empty()
            && self.http.is_empty()
    }
}

#[derive(Debug, Serialize)]
struct FileAssertion {
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    filetype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
}

#[derive(Debug, Serialize)]
struct PortAssertion {
    listening: bool,
}

#[derive(Debug, Serialize)]
struct ProcessAssertion {
    running: bool,
}

#[derive(Debug, Serialize)]
struct CommandAssertion {
    exec: String,
    #[serde(rename = "exit-status")]
    exit_status: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stdout: Vec<String>,
    timeout: i32,
}

#[derive(Debug, Serialize)]
struct HttpAssertion {
    status: u16,
}

/// Render a list of GossResources into a goss.yml formatted string.
pub fn render_goss(resources: &[GossResource]) -> String {
    let mut doc = GossDocument::default();

    for resource in resources {
        match resource {
            GossResource::File {
                path,
                exists,
                filetype,
                mode,
                ..
            } => {
                doc.file.insert(
                    path.clone(),
                    FileAssertion {
                        exists: *exists,
                        filetype: filetype.clone(),
                        mode: mode.clone(),
                    },
                );
            }
            GossResource::Port {
                address, listening, ..
            } => {
                doc.port.insert(
                    address.clone(),
                    PortAssertion {
                        listening: *listening,
                    },
                );
            }
            GossResource::Process { name, running, .. } => {
                doc.process
                    .insert(name.clone(), ProcessAssertion { running: *running });
            }
            GossResource::Command {
                name,
                command,
                exit_status,
                timeout,
                ..
            } => {
                doc.command.insert(
                    name.clone(),
                    CommandAssertion {
                        exec: command.clone(),
                        exit_status: *exit_status,
                        stdout: Vec::new(),
                        timeout: *timeout,
                    },
                );
            }
            GossResource::CommandWithOutput {
                name,
                command,
                exit_status,
                stdout,
                timeout,
                ..
            } => {
                doc.command.insert(
                    name.clone(),
                    CommandAssertion {
                        exec: command.clone(),
                        exit_status: *exit_status,
                        stdout: stdout.clone(),
                        timeout: *timeout,
                    },
                );
            }
            GossResource::Http { url, status, .. } => {
                doc.http
                    .insert(url.clone(), HttpAssertion { status: *status });
            }
        }
    }

    if doc.is_empty() {
        return "command: {}\n".to_string();
    }

    serde_yml::to_string(&doc).unwrap_or_else(|_| "command: {}\n".to_string())
}

/// Render goss_wait.yml with wait-specific resources.
pub fn render_goss_wait(resources: &[GossResource]) -> String {
    render_goss(resources)
}

/// Render a minimal viable wait file with just a port check.
pub fn render_goss_wait_minimal(port: u16, protocol: &str) -> String {
    let mut doc = GossDocument::default();
    doc.port.insert(
        format!("{}:{}", protocol, port),
        PortAssertion { listening: true },
    );
    serde_yml::to_string(&doc).unwrap_or_else(|_| "command: {}\n".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;

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
        assert!(output.contains("/app"));
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
    fn test_rendered_yaml_is_parseable() {
        let resources = vec![GossResource::Command {
            name: "check".to_string(),
            command: "echo hello && echo world".to_string(),
            exit_status: 0,
            timeout: 1000,
            provenance: "RUN".to_string(),
            confidence: Confidence::Low,
        }];

        let output = render_goss(&resources);
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(parsed.is_ok());
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
        assert!(file_pos < port_pos);
        assert!(port_pos < process_pos);
    }
}
