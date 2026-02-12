mod render;

pub use render::*;

use crate::config::PolicyConfig;
use crate::extractor::{AssertionKind, ContractAssertion, RuntimeContract};
use crate::{Confidence, Profile};

/// Output of the goss generator.
#[derive(Debug)]
pub struct GeneratorOutput {
    pub goss_yml: String,
    pub goss_wait_yml: Option<String>,
    pub warnings: Vec<String>,
}

/// Generate goss.yml and optional goss_wait.yml from a RuntimeContract.
pub fn generate(
    contract: &RuntimeContract,
    profile: Profile,
    policy: &PolicyConfig,
    force_wait: Option<bool>,
) -> GeneratorOutput {
    let min_confidence = match profile {
        Profile::Minimal => Confidence::High,
        Profile::Standard => Confidence::Medium,
        Profile::Strict => Confidence::Low,
    };

    let mut warnings = Vec::new();

    // Partition assertions into wait vs. main
    let (wait_assertions, main_assertions): (Vec<_>, Vec<_>) =
        contract.assertions.iter().partition(|a| is_wait_assertion(a));

    // Determine if we should generate goss_wait.yml
    let should_generate_wait = match force_wait {
        Some(true) => true,
        Some(false) => false,
        None => {
            // Auto-detect: generate if healthcheck exists OR exactly one exposed port
            contract.healthcheck.is_some()
                || contract.exposed_ports.len() == 1
                || !wait_assertions.is_empty()
        }
    };

    // Build goss_wait.yml
    let goss_wait_yml = if should_generate_wait {
        let wait_resources =
            build_wait_resources(&wait_assertions, &contract, min_confidence, policy, &mut warnings);
        if wait_resources.is_empty() {
            // Generate minimal viable wait from port check
            if let Some(port) = contract.exposed_ports.first() {
                let minimal_wait = render_goss_wait_minimal(port.port, &port.protocol);
                Some(minimal_wait)
            } else {
                None
            }
        } else {
            Some(render_goss_wait(&wait_resources))
        }
    } else {
        None
    };

    // Build goss.yml
    let main_resources =
        build_main_resources(&main_assertions, min_confidence, profile, policy, &mut warnings);
    let goss_yml = render_goss(&main_resources);

    GeneratorOutput {
        goss_yml,
        goss_wait_yml,
        warnings,
    }
}

/// Determine if an assertion belongs in goss_wait.yml (readiness gate).
fn is_wait_assertion(assertion: &ContractAssertion) -> bool {
    matches!(
        assertion.kind,
        AssertionKind::HealthcheckPasses { .. }
            | AssertionKind::PortListening { .. }
    )
}

/// Build wait file resources.
fn build_wait_resources(
    assertions: &[&ContractAssertion],
    contract: &RuntimeContract,
    min_confidence: Confidence,
    policy: &PolicyConfig,
    warnings: &mut Vec<String>,
) -> Vec<GossResource> {
    let mut resources = Vec::new();

    // Healthcheck-derived command (highest priority)
    for assertion in assertions {
        if assertion.confidence < min_confidence {
            warnings.push(format!(
                "Skipped wait assertion (confidence too low): {}",
                assertion.provenance
            ));
            continue;
        }

        match &assertion.kind {
            AssertionKind::HealthcheckPasses { command } => {
                resources.push(GossResource::Command {
                    name: "healthcheck".to_string(),
                    command: sanitize_command(command),
                    exit_status: 0,
                    timeout: 5000,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }
            AssertionKind::PortListening { protocol, port } => {
                if policy.assert_ports_enabled() {
                    resources.push(GossResource::Port {
                        address: format!("{}:{}", protocol, port),
                        listening: true,
                        provenance: assertion.provenance.clone(),
                        confidence: assertion.confidence,
                    });
                }
            }
            _ => {}
        }
    }

    // If no healthcheck but we have process info, add process check
    if resources.is_empty() || !resources.iter().any(|r| matches!(r, GossResource::Command { .. }))
    {
        if let Some(ep) = &contract.entrypoint {
            if let Some(binary) = ep.primary_binary() {
                if !is_shell_name(&binary) {
                    resources.push(GossResource::Process {
                        name: binary,
                        running: true,
                        provenance: "ENTRYPOINT (wait gate)".to_string(),
                        confidence: Confidence::Medium,
                    });
                }
            }
        }
    }

    resources
}

/// Build main goss.yml resources.
fn build_main_resources(
    assertions: &[&ContractAssertion],
    min_confidence: Confidence,
    profile: Profile,
    policy: &PolicyConfig,
    warnings: &mut Vec<String>,
) -> Vec<GossResource> {
    let mut resources = Vec::new();

    for assertion in assertions {
        if assertion.confidence < min_confidence {
            warnings.push(format!(
                "Skipped assertion (confidence too low): {}",
                assertion.provenance
            ));
            continue;
        }

        match &assertion.kind {
            AssertionKind::FileExists {
                path,
                filetype,
                mode,
            } => {
                // In minimal profile, skip mode assertions
                let effective_mode = if profile == Profile::Minimal {
                    None
                } else if policy.assert_file_modes {
                    mode.clone()
                } else {
                    None
                };

                resources.push(GossResource::File {
                    path: path.clone(),
                    exists: true,
                    filetype: filetype.clone(),
                    mode: effective_mode,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }

            AssertionKind::ProcessRunning { name } => {
                if policy.assert_process_enabled() {
                    resources.push(GossResource::Process {
                        name: name.clone(),
                        running: true,
                        provenance: assertion.provenance.clone(),
                        confidence: assertion.confidence,
                    });
                }
            }

            AssertionKind::CommandExit {
                command,
                exit_status,
            } => {
                resources.push(GossResource::Command {
                    name: command_to_name(command),
                    command: sanitize_command(command),
                    exit_status: *exit_status,
                    timeout: 10000,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }

            AssertionKind::CommandOutput {
                command,
                exit_status,
                expected_output,
            } => {
                resources.push(GossResource::CommandWithOutput {
                    name: command_to_name(command),
                    command: sanitize_command(command),
                    exit_status: *exit_status,
                    stdout: expected_output.clone(),
                    timeout: 10000,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }

            AssertionKind::UserExists { username } => {
                resources.push(GossResource::Command {
                    name: format!("user-{}-exists", username),
                    command: format!("getent passwd {}", sanitize_shell_arg(username)),
                    exit_status: 0,
                    timeout: 5000,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }

            AssertionKind::PortListening { protocol, port } => {
                // Port assertions in main goss.yml (hard check)
                if policy.assert_ports_enabled() {
                    resources.push(GossResource::Port {
                        address: format!("{}:{}", protocol, port),
                        listening: true,
                        provenance: assertion.provenance.clone(),
                        confidence: assertion.confidence,
                    });
                }
            }

            AssertionKind::HttpStatus { url, status } => {
                if policy.http_checks {
                    resources.push(GossResource::Http {
                        url: url.clone(),
                        status: *status,
                        provenance: assertion.provenance.clone(),
                        confidence: assertion.confidence,
                    });
                }
            }

            AssertionKind::HealthcheckPasses { .. } => {
                // Handled in wait file, skip in main
            }
        }
    }

    // Deduplicate resources
    deduplicate_resources(&mut resources);

    resources
}

/// Deduplicate resources by their identity key.
fn deduplicate_resources(resources: &mut Vec<GossResource>) {
    let mut seen = std::collections::HashSet::new();
    resources.retain(|r| {
        let key = r.identity_key();
        seen.insert(key)
    });
}

/// Convert a command string to a valid YAML key name.
fn command_to_name(command: &str) -> String {
    command
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Sanitize a command string for safe YAML embedding.
fn sanitize_command(command: &str) -> String {
    // Remove potentially dangerous characters but keep the command functional
    command
        .replace('\0', "")
        .replace('\r', "")
        .trim()
        .to_string()
}

/// Sanitize a shell argument to prevent injection.
fn sanitize_shell_arg(arg: &str) -> String {
    // Only allow safe characters in shell arguments
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn is_shell_name(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "dash" | "zsh" | "ash")
}

/// A typed goss resource for rendering.
#[derive(Debug, Clone)]
pub enum GossResource {
    File {
        path: String,
        exists: bool,
        filetype: Option<String>,
        mode: Option<String>,
        provenance: String,
        confidence: Confidence,
    },
    Port {
        address: String,
        listening: bool,
        provenance: String,
        confidence: Confidence,
    },
    Process {
        name: String,
        running: bool,
        provenance: String,
        confidence: Confidence,
    },
    Command {
        name: String,
        command: String,
        exit_status: i32,
        timeout: i32,
        provenance: String,
        confidence: Confidence,
    },
    CommandWithOutput {
        name: String,
        command: String,
        exit_status: i32,
        stdout: Vec<String>,
        timeout: i32,
        provenance: String,
        confidence: Confidence,
    },
    Http {
        url: String,
        status: u16,
        provenance: String,
        confidence: Confidence,
    },
}

impl GossResource {
    /// A key for deduplication purposes.
    pub fn identity_key(&self) -> String {
        match self {
            GossResource::File { path, .. } => format!("file:{}", path),
            GossResource::Port { address, .. } => format!("port:{}", address),
            GossResource::Process { name, .. } => format!("process:{}", name),
            GossResource::Command { name, .. } => format!("command:{}", name),
            GossResource::CommandWithOutput { name, .. } => format!("command:{}", name),
            GossResource::Http { url, .. } => format!("http:{}", url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyConfig;
    use crate::extractor::extract_contract;
    use crate::parser::parse_dockerfile_content;

    #[test]
    fn test_generate_basic() {
        let content = r#"
FROM node:18
WORKDIR /app
COPY . /app
EXPOSE 3000
CMD ["node", "server.js"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(!output.goss_yml.is_empty());
        assert!(output.goss_yml.contains("file:"));
        assert!(output.goss_yml.contains("/app"));
    }

    #[test]
    fn test_generate_with_healthcheck() {
        let content = r#"
FROM nginx
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(output.goss_wait_yml.is_some());
        let wait = output.goss_wait_yml.unwrap();
        assert!(wait.contains("command:"));
    }

    #[test]
    fn test_generate_no_wait_when_forced() {
        let content = r#"
FROM nginx
EXPOSE 80
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(
            &contract,
            Profile::Standard,
            &PolicyConfig::default(),
            Some(false),
        );

        assert!(output.goss_wait_yml.is_none());
    }

    #[test]
    fn test_command_to_name() {
        assert_eq!(command_to_name("nginx -v"), "nginx--v");
        assert_eq!(command_to_name("node --version"), "node---version");
    }

    #[test]
    fn test_sanitize_shell_arg() {
        assert_eq!(sanitize_shell_arg("myuser"), "myuser");
        assert_eq!(sanitize_shell_arg("user name"), "'user name'");
    }
}
