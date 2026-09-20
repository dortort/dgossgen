use super::GossResource;
use crate::Confidence;
use serde::Serialize;
use std::collections::BTreeMap;

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

/// A single rendered assertion: its map key, the provenance comment to place
/// above it, and the serialized YAML for the value body.
struct Entry {
    /// The map key exactly as `serde_yml` renders it (with any quoting).
    rendered_key: String,
    /// `# derived from ...; confidence: ...`
    comment: String,
    /// The value body serialized by `serde_yml`, e.g. `  exists: true`.
    body: String,
}

/// The five goss sections, emitted in this fixed order.
#[derive(Default)]
struct Sections {
    file: BTreeMap<String, Entry>,
    port: BTreeMap<String, Entry>,
    process: BTreeMap<String, Entry>,
    command: BTreeMap<String, Entry>,
    http: BTreeMap<String, Entry>,
}

impl Sections {
    fn is_empty(&self) -> bool {
        self.file.is_empty()
            && self.port.is_empty()
            && self.process.is_empty()
            && self.command.is_empty()
            && self.http.is_empty()
    }
}

/// Build the `# derived from ...; confidence: ...` line promised in the README.
///
/// `GossResource` is a public type, so a provenance string could carry a line
/// break. `write_section` prefixes only the first line with `#`, so an embedded
/// `\n`/`\r` would let the remainder escape the comment and become active YAML.
/// Collapse line breaks to spaces to keep the comment a single line.
fn comment_line(provenance: &str, confidence: Confidence) -> String {
    let sanitized = provenance.replace(['\n', '\r'], " ");
    format!("# derived from {}; confidence: {}", sanitized, confidence)
}

/// Serialize a single `{ key: value }` map through `serde_yml` and split it into
/// the rendered key (with any quoting `serde_yml` applied) and the value body
/// (every line after the key line). Reusing `serde_yml` here keeps key quoting
/// and value formatting identical to a whole-document serialization.
fn render_entry<T: Serialize>(key: &str, value: &T) -> (String, String) {
    let mut map = BTreeMap::new();
    map.insert(key, value);
    let yaml = serde_yml::to_string(&map).unwrap_or_default();
    let yaml = yaml.trim_end_matches('\n');

    let (key_line, body) = yaml.split_once('\n').unwrap_or((yaml, ""));
    // The key line is `<rendered_key>:`; strip the trailing colon.
    let rendered_key = key_line.strip_suffix(':').unwrap_or(key_line).to_string();
    (rendered_key, body.to_string())
}

/// Convert one `GossResource` into a section-keyed `Entry`.
fn resource_to_entry(resource: &GossResource) -> (Section, String, Entry) {
    match resource {
        GossResource::File {
            path,
            exists,
            filetype,
            mode,
            provenance,
            confidence,
        } => {
            let (rendered_key, body) = render_entry(
                path,
                &FileAssertion {
                    exists: *exists,
                    filetype: filetype.clone(),
                    mode: mode.clone(),
                },
            );
            (
                Section::File,
                path.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
        }
        GossResource::Port {
            address,
            listening,
            provenance,
            confidence,
        } => {
            let (rendered_key, body) = render_entry(
                address,
                &PortAssertion {
                    listening: *listening,
                },
            );
            (
                Section::Port,
                address.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
        }
        GossResource::Process {
            name,
            running,
            provenance,
            confidence,
        } => {
            let (rendered_key, body) = render_entry(name, &ProcessAssertion { running: *running });
            (
                Section::Process,
                name.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
        }
        GossResource::Command {
            name,
            command,
            exit_status,
            timeout,
            provenance,
            confidence,
        } => {
            let (rendered_key, body) = render_entry(
                name,
                &CommandAssertion {
                    exec: command.clone(),
                    exit_status: *exit_status,
                    stdout: Vec::new(),
                    timeout: *timeout,
                },
            );
            (
                Section::Command,
                name.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
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
            let (rendered_key, body) = render_entry(
                name,
                &CommandAssertion {
                    exec: command.clone(),
                    exit_status: *exit_status,
                    stdout: stdout.clone(),
                    timeout: *timeout,
                },
            );
            (
                Section::Command,
                name.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
        }
        GossResource::Http {
            url,
            status,
            provenance,
            confidence,
        } => {
            let (rendered_key, body) = render_entry(url, &HttpAssertion { status: *status });
            (
                Section::Http,
                url.clone(),
                Entry {
                    rendered_key,
                    comment: comment_line(provenance, *confidence),
                    body,
                },
            )
        }
    }
}

enum Section {
    File,
    Port,
    Process,
    Command,
    Http,
}

/// Indent every non-empty line of `block` by `spaces` spaces.
fn indent(block: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    block
        .lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{pad}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Append one section (if non-empty) to `out`, emitting each entry's provenance
/// comment immediately above its key, both indented two spaces.
fn write_section(out: &mut String, name: &str, entries: &BTreeMap<String, Entry>) {
    if entries.is_empty() {
        return;
    }
    out.push_str(name);
    out.push_str(":\n");
    for entry in entries.values() {
        out.push_str("  ");
        out.push_str(&entry.comment);
        out.push('\n');
        out.push_str("  ");
        out.push_str(&entry.rendered_key);
        out.push_str(":\n");
        if !entry.body.is_empty() {
            out.push_str(&indent(&entry.body, 2));
            out.push('\n');
        }
    }
}

/// Render a list of `GossResource`s into a goss.yml formatted string, with a
/// `# derived from <provenance>; confidence: <level>` comment above every
/// assertion key.
pub fn render_goss(resources: &[GossResource]) -> String {
    let mut sections = Sections::default();

    for resource in resources {
        let (section, key, entry) = resource_to_entry(resource);
        // Last-writer-wins on a shared key, matching the previous
        // `BTreeMap::insert` de-duplication semantics.
        match section {
            Section::File => sections.file.insert(key, entry),
            Section::Port => sections.port.insert(key, entry),
            Section::Process => sections.process.insert(key, entry),
            Section::Command => sections.command.insert(key, entry),
            Section::Http => sections.http.insert(key, entry),
        };
    }

    if sections.is_empty() {
        return "command: {}\n".to_string();
    }

    let mut out = String::new();
    write_section(&mut out, "file", &sections.file);
    write_section(&mut out, "port", &sections.port);
    write_section(&mut out, "process", &sections.process);
    write_section(&mut out, "command", &sections.command);
    write_section(&mut out, "http", &sections.http);
    out
}

/// Render goss_wait.yml with wait-specific resources.
pub fn render_goss_wait(resources: &[GossResource]) -> String {
    render_goss(resources)
}

/// Render a minimal viable wait file with just a port check. The synthesized
/// port assertion carries a provenance comment so the minimal fallback stays
/// consistent with every other generated file.
pub fn render_goss_wait_minimal(port: u16, protocol: &str) -> String {
    let resource = GossResource::Port {
        address: format!("{}:{}", protocol, port),
        listening: true,
        provenance: format!("EXPOSE {}/{} (minimal readiness gate)", port, protocol),
        confidence: Confidence::Medium,
    };
    render_goss(&[resource])
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
    fn test_provenance_comment_precedes_key() {
        let resources = vec![GossResource::Port {
            address: "tcp:80".to_string(),
            listening: true,
            provenance: "EXPOSE 80/tcp".to_string(),
            confidence: Confidence::Medium,
        }];
        let output = render_goss(&resources);
        assert!(
            output.contains("# derived from EXPOSE 80/tcp; confidence: medium"),
            "output should carry the provenance comment, got:\n{output}"
        );
        // The comment must appear immediately above the key it annotates.
        let comment_pos = output
            .find("# derived from EXPOSE 80/tcp; confidence: medium")
            .unwrap();
        let key_pos = output.find("tcp:80:").unwrap();
        assert!(
            comment_pos < key_pos,
            "comment should precede its key, got:\n{output}"
        );
    }

    #[test]
    fn test_comment_confidence_levels_render() {
        for (confidence, level) in [
            (Confidence::Low, "low"),
            (Confidence::Medium, "medium"),
            (Confidence::High, "high"),
        ] {
            let resources = vec![GossResource::Process {
                name: "nginx".to_string(),
                running: true,
                provenance: "CMD nginx".to_string(),
                confidence,
            }];
            let output = render_goss(&resources);
            assert!(
                output.contains(&format!("confidence: {level}")),
                "confidence {level} should render, got:\n{output}"
            );
        }
    }

    #[test]
    fn test_output_with_comments_is_parseable() {
        let resources = vec![
            GossResource::File {
                path: "/app".to_string(),
                exists: true,
                filetype: Some("directory".to_string()),
                mode: Some("0755".to_string()),
                provenance: "WORKDIR /app".to_string(),
                confidence: Confidence::High,
            },
            GossResource::Command {
                name: "check".to_string(),
                command: "echo hello && echo world".to_string(),
                exit_status: 0,
                timeout: 1000,
                provenance: "RUN echo".to_string(),
                confidence: Confidence::Low,
            },
            GossResource::Http {
                url: "http://127.0.0.1:80/healthz".to_string(),
                status: 200,
                provenance: "CLI: --health-path flag".to_string(),
                confidence: Confidence::High,
            },
        ];

        let output = render_goss(&resources);
        // Comments must not break YAML parsing.
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(
            parsed.is_ok(),
            "commented YAML should parse, got:\n{output}"
        );
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
    fn test_minimal_wait_carries_provenance_comment() {
        let output = render_goss_wait_minimal(8080, "tcp");
        assert!(output.contains("port:"));
        assert!(output.contains("tcp:8080"));
        assert!(output.contains("listening: true"));
        assert!(
            output.contains(
                "# derived from EXPOSE 8080/tcp (minimal readiness gate); confidence: medium"
            ),
            "minimal wait should carry a synthesized provenance comment, got:\n{output}"
        );
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(parsed.is_ok(), "minimal wait should parse, got:\n{output}");
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

    #[test]
    fn test_provenance_line_breaks_are_sanitized() {
        // A provenance carrying a newline must not escape the comment into
        // active YAML; the whole file must stay valid and single-comment.
        let resources = vec![GossResource::Process {
            name: "srv".to_string(),
            running: true,
            provenance: "line one\nmalicious: true\r\nmore".to_string(),
            confidence: Confidence::Medium,
        }];
        let output = render_goss(&resources);
        assert!(
            !output.contains("\nmalicious: true"),
            "line break must not inject active YAML, got:\n{output}"
        );
        assert!(
            output.contains("# derived from line one malicious: true  more; confidence: medium"),
            "provenance line breaks should collapse to spaces, got:\n{output}"
        );
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(
            parsed.is_ok(),
            "sanitized output should parse, got:\n{output}"
        );
    }

    #[test]
    fn test_last_writer_wins_on_shared_key() {
        // Two commands sharing a key must not emit a duplicate YAML key.
        let resources = vec![
            GossResource::Command {
                name: "check".to_string(),
                command: "first".to_string(),
                exit_status: 0,
                timeout: 1000,
                provenance: "first".to_string(),
                confidence: Confidence::Low,
            },
            GossResource::Command {
                name: "check".to_string(),
                command: "second".to_string(),
                exit_status: 0,
                timeout: 1000,
                provenance: "second".to_string(),
                confidence: Confidence::High,
            },
        ];
        let output = render_goss(&resources);
        assert_eq!(
            output.matches("check:").count(),
            1,
            "shared key should render once, got:\n{output}"
        );
        assert!(output.contains("exec: second"));
        assert!(output.contains("# derived from second; confidence: high"));
    }
}
