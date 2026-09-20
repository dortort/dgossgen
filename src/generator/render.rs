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

/// A single rendered assertion: the provenance comment to place above it, and
/// the complete `serde_yml`-serialized mapping entry (key and value together).
struct Entry {
    /// `# derived from ...; confidence: ...`
    comment: String,
    /// The whole `serde_yml` mapping entry, e.g. `/app:\n  exists: true`, or
    /// the explicit `? <key>\n: <value>` form `serde_yml` uses for keys past
    /// the YAML simple-key length limit. Stored verbatim (never re-split) so we
    /// never corrupt an explicit-form key.
    block: String,
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

/// True if `c` is allowed in a single-line YAML comment: YAML 1.2's
/// `c-printable` set minus the line breaks (`\n`/`\r`, which would end the
/// comment). Rust `char`s can never be surrogates, so those need no exclusion;
/// U+FFFE/U+FFFF and the C0/C1 control ranges fall outside the ranges below and
/// are therefore rejected.
fn is_comment_safe(c: char) -> bool {
    matches!(c,
        '\t'
        | '\u{20}'..='\u{7E}'
        | '\u{85}'
        | '\u{A0}'..='\u{D7FF}'
        | '\u{E000}'..='\u{FFFD}'
        | '\u{10000}'..='\u{10FFFF}'
    )
}

/// Build the `# derived from ...; confidence: ...` line promised in the README.
///
/// `GossResource` is a public type, so a provenance string could carry
/// characters the YAML character set forbids. This comment is hand-written (not
/// routed through `serde_yml`, which escapes such data in scalars), so any such
/// character would make the whole document unparseable — a line break lets the
/// remainder escape the comment into active YAML, and control characters and
/// Unicode noncharacters (U+FFFE/U+FFFF) are rejected by the parser even inside
/// a comment. Replace every character outside YAML's single-line `c-printable`
/// set with a space so the comment stays one valid, printable line.
fn comment_line(provenance: &str, confidence: Confidence) -> String {
    let sanitized: String = provenance
        .chars()
        .map(|c| if is_comment_safe(c) { c } else { ' ' })
        .collect();
    format!("# derived from {}; confidence: {}", sanitized, confidence)
}

/// Serialize a single `{ key: value }` map through `serde_yml` and return the
/// entry verbatim (trailing newline trimmed). Reusing `serde_yml` keeps key
/// quoting and value formatting identical to a whole-document serialization,
/// including the explicit `? <key>\n: <value>` form it emits for keys past the
/// YAML simple-key length limit. The caller must indent the whole block as a
/// unit rather than decomposing it, so explicit-form keys are never corrupted.
fn render_entry<T: Serialize>(key: &str, value: &T) -> String {
    let mut map = BTreeMap::new();
    map.insert(key, value);
    let yaml = serde_yml::to_string(&map).unwrap_or_default();
    yaml.trim_end_matches('\n').to_string()
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
            let block = render_entry(
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
                    comment: comment_line(provenance, *confidence),
                    block,
                },
            )
        }
        GossResource::Port {
            address,
            listening,
            provenance,
            confidence,
        } => {
            let block = render_entry(
                address,
                &PortAssertion {
                    listening: *listening,
                },
            );
            (
                Section::Port,
                address.clone(),
                Entry {
                    comment: comment_line(provenance, *confidence),
                    block,
                },
            )
        }
        GossResource::Process {
            name,
            running,
            provenance,
            confidence,
        } => {
            let block = render_entry(name, &ProcessAssertion { running: *running });
            (
                Section::Process,
                name.clone(),
                Entry {
                    comment: comment_line(provenance, *confidence),
                    block,
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
            let block = render_entry(
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
                    comment: comment_line(provenance, *confidence),
                    block,
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
            let block = render_entry(
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
                    comment: comment_line(provenance, *confidence),
                    block,
                },
            )
        }
        GossResource::Http {
            url,
            status,
            provenance,
            confidence,
        } => {
            let block = render_entry(url, &HttpAssertion { status: *status });
            (
                Section::Http,
                url.clone(),
                Entry {
                    comment: comment_line(provenance, *confidence),
                    block,
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
/// comment immediately above its serialized mapping entry, both indented two
/// spaces. The entry block is indented as a unit so an explicit `? key`/`: value`
/// form survives intact.
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
        out.push_str(&indent(&entry.block, 2));
        out.push('\n');
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
    fn test_provenance_control_chars_are_sanitized() {
        // Control characters forbidden by the YAML character set (NUL, form
        // feed, vertical tab, …) must not leak into the comment, or the whole
        // document becomes unparseable even though they sit inside a `#` line.
        let resources = vec![GossResource::Process {
            name: "srv".to_string(),
            running: true,
            provenance: "a\u{0}b\u{c}c\u{b}d".to_string(),
            confidence: Confidence::High,
        }];
        let output = render_goss(&resources);
        assert!(
            !output.contains('\u{0}') && !output.contains('\u{c}') && !output.contains('\u{b}'),
            "control characters must be stripped from the comment"
        );
        assert!(
            output.contains("# derived from a b c d; confidence: high"),
            "control characters should collapse to spaces, got:\n{output:?}"
        );
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(
            parsed.is_ok(),
            "sanitized output should parse, got:\n{output}"
        );
    }

    #[test]
    fn test_provenance_unicode_noncharacters_are_sanitized() {
        // U+FFFE/U+FFFF are not `char::is_control()` but are forbidden by YAML's
        // character set; they must be stripped from the comment.
        let resources = vec![GossResource::Process {
            name: "srv".to_string(),
            running: true,
            provenance: "x\u{FFFE}y\u{FFFF}z".to_string(),
            confidence: Confidence::Medium,
        }];
        let output = render_goss(&resources);
        assert!(
            !output.contains('\u{FFFE}') && !output.contains('\u{FFFF}'),
            "Unicode noncharacters must be stripped from the comment"
        );
        assert!(
            output.contains("# derived from x y z; confidence: medium"),
            "noncharacters should collapse to spaces, got:\n{output:?}"
        );
        let parsed: Result<serde_yml::Value, _> = serde_yml::from_str(&output);
        assert!(
            parsed.is_ok(),
            "sanitized output should parse, got:\n{output}"
        );
    }

    #[test]
    fn test_long_key_past_simple_key_limit_renders_valid_yaml() {
        // A key long enough to exceed YAML's 128-byte simple-key limit forces
        // serde_yml into explicit `? key`/`: value` form. The whole entry block
        // must be indented as a unit so it stays valid and the key round-trips
        // as a scalar string (not corrupted into a nested mapping).
        let long_path = format!("/opt/{}", "a".repeat(200));
        let resources = vec![GossResource::File {
            path: long_path.clone(),
            exists: true,
            filetype: Some("directory".to_string()),
            mode: None,
            provenance: "WORKDIR (long path)".to_string(),
            confidence: Confidence::High,
        }];
        let output = render_goss(&resources);

        let parsed: serde_yml::Value =
            serde_yml::from_str(&output).unwrap_or_else(|e| panic!("must parse: {e}\n{output}"));
        let file = parsed
            .get("file")
            .and_then(|f| f.as_mapping())
            .expect("file section should be a mapping");
        let entry = file
            .get(serde_yml::Value::String(long_path.clone()))
            .expect("long path must round-trip as a scalar string key");
        assert_eq!(
            entry.get("exists").and_then(|v| v.as_bool()),
            Some(true),
            "value must survive explicit-key rendering, got:\n{output}"
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
