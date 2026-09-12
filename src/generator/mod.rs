mod render;

pub use render::*;

use crate::config::PolicyConfig;
use crate::extractor::{
    is_shell_interpreter, AssertionKind, ContractAssertion, PackageManager, RuntimeContract,
};
use crate::{Confidence, Profile};

/// Output of the goss generator.
#[derive(Debug)]
pub struct GeneratorOutput {
    pub goss_yml: String,
    pub goss_wait_yml: Option<String>,
    /// Genuine anomalies that should influence the exit code (e.g. an empty
    /// contract that produces a `goss.yml` asserting nothing).
    pub warnings: Vec<String>,
    /// Informational notes about routine, expected behavior — chiefly
    /// assertions dropped because they fell below the profile's confidence
    /// cutoff. Notes are surfaced to the user but do not, on their own, affect
    /// the exit code (unless `--strict-warnings` is requested).
    pub notes: Vec<String>,
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

    // Seed with diagnostics raised during extraction (e.g. dropped EXPOSE tokens)
    // so they surface to the user instead of being silently discarded.
    let mut warnings = contract.warnings.clone();
    let mut notes = Vec::new();

    // Partition assertions into wait vs. main
    let (wait_assertions, main_assertions): (Vec<_>, Vec<_>) = contract
        .assertions
        .iter()
        .partition(|a| is_wait_assertion(a));

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
        let wait_resources = build_wait_resources(
            &wait_assertions,
            contract,
            min_confidence,
            policy,
            &mut notes,
        );
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
    let main_resources = build_main_resources(
        &main_assertions,
        min_confidence,
        profile,
        policy,
        &mut notes,
    );

    // A run that produces no assertions at all — an empty goss.yml AND no
    // readiness gate — is a genuine anomaly, not routine filtering: dgoss would
    // "pass" while asserting nothing. Surface it as a warning (exit 2) with
    // guidance, rather than silently writing a bare `command: {}` and exiting 0.
    //
    // A contract whose only signal is a port or a healthcheck yields an empty
    // main file but a fully valid `goss_wait.yml`; that is NOT an anomaly, so
    // the wait file must be considered here (`goss_wait.yml` is `Some` only when
    // it carries at least one resource).
    if main_resources.is_empty() && goss_wait_yml.is_none() {
        warnings.push(empty_contract_diagnostic(contract, profile));
    }

    let goss_yml = render_goss(&main_resources);

    GeneratorOutput {
        goss_yml,
        goss_wait_yml,
        warnings,
        notes,
    }
}

/// Build a diagnostic message explaining why `goss.yml` ended up empty and how
/// to fix it, tailored to whether the Dockerfile carried any runtime signals.
fn empty_contract_diagnostic(contract: &RuntimeContract, profile: Profile) -> String {
    let has_signals = !contract.exposed_ports.is_empty()
        || contract.cmd.is_some()
        || contract.entrypoint.is_some()
        || contract.healthcheck.is_some()
        || contract.assertions.iter().any(|a| !is_wait_assertion(a));

    if has_signals {
        // Signals were declared but nothing survived to the output. The cause
        // may be confidence filtering, a policy toggle (.dgossgen.yml, e.g.
        // http_checks defaults off), or --no-wait suppressing a readiness gate,
        // so the message enumerates the levers rather than asserting one cause.
        format!(
            "goss.yml has no assertions: the Dockerfile's runtime signals were all \
             filtered out — below the '{profile}' profile's confidence cutoff, \
             disabled by policy (.dgossgen.yml), or suppressed by --no-wait. Relax \
             filtering with --profile strict, enable the relevant checks in \
             .dgossgen.yml, drop --no-wait, refine interactively with \
             --interactive, or gather runtime evidence with the `probe` subcommand."
        )
    } else {
        // No runtime signals at all. Advise only levers that actually produce a
        // main-file assertion under the default policy: a CMD/ENTRYPOINT yields
        // a process check and an EXPOSE yields a readiness gate, whereas
        // --health-path relies on http_checks, which defaults off — so it is
        // qualified rather than offered bare (making it effective on its own is
        // tracked separately).
        "goss.yml has no assertions: no EXPOSE, CMD, ENTRYPOINT, or HEALTHCHECK \
         was found, so there is nothing to assert. Add a CMD/ENTRYPOINT (a \
         process check) or an EXPOSE (a readiness gate) to the image, gather \
         runtime evidence with the `probe` subcommand, or supply a health \
         endpoint with --health-path (which also needs http_checks enabled in \
         .dgossgen.yml)."
            .to_string()
    }
}

/// Determine if an assertion belongs in goss_wait.yml (readiness gate).
fn is_wait_assertion(assertion: &ContractAssertion) -> bool {
    matches!(
        assertion.kind,
        AssertionKind::HealthcheckPasses { .. } | AssertionKind::PortListening { .. }
    )
}

/// Returns `true` if the assertion passes the confidence threshold; records an
/// informational note if not. Confidence filtering is routine, documented
/// behavior, so a skip is a note rather than a warning and does not affect the
/// exit code.
fn passes_confidence(
    assertion: &ContractAssertion,
    min_confidence: Confidence,
    context: &str,
    notes: &mut Vec<String>,
) -> bool {
    if assertion.confidence < min_confidence {
        notes.push(format!(
            "Skipped {} (confidence too low): {}",
            context, assertion.provenance
        ));
        false
    } else {
        true
    }
}

/// Build wait file resources.
fn build_wait_resources(
    assertions: &[&ContractAssertion],
    contract: &RuntimeContract,
    min_confidence: Confidence,
    policy: &PolicyConfig,
    notes: &mut Vec<String>,
) -> Vec<GossResource> {
    let mut resources = Vec::new();

    // Healthcheck-derived command (highest priority)
    for assertion in assertions {
        if !passes_confidence(assertion, min_confidence, "wait assertion", notes) {
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
            AssertionKind::PortListening { protocol, port } if policy.assert_ports_enabled() => {
                resources.push(GossResource::Port {
                    address: format!("{}:{}", protocol, port),
                    listening: true,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });
            }
            _ => {}
        }
    }

    // If no healthcheck but we have process info, add process check
    if resources.is_empty()
        || !resources
            .iter()
            .any(|r| matches!(r, GossResource::Command { .. }))
    {
        if let Some(ep) = &contract.entrypoint {
            if let Some(binary) = ep.primary_binary() {
                if !is_shell_interpreter(&binary) {
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
    notes: &mut Vec<String>,
) -> Vec<GossResource> {
    let mut resources = Vec::new();

    for assertion in assertions {
        if !passes_confidence(assertion, min_confidence, "assertion", notes) {
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
                // HTTP checks are gated off by default policy, but an assertion
                // the user explicitly asked for (--health-path, or the
                // interactive health prompt) must not be silently discarded:
                // explicit intent overrides the policy default.
                if policy.http_checks || assertion.user_requested {
                    resources.push(GossResource::Http {
                        url: url.clone(),
                        status: *status,
                        provenance: assertion.provenance.clone(),
                        confidence: assertion.confidence,
                    });
                }
            }

            AssertionKind::PackageInstalled {
                package,
                manager,
                version_cmd,
            } => {
                // Primary assertion: package-manager-native check (works for any package)
                let check_cmd = match manager {
                    PackageManager::Apt => format!("dpkg -s {}", sanitize_shell_arg(package)),
                    PackageManager::Apk => format!("apk info -e {}", sanitize_shell_arg(package)),
                    PackageManager::Pip => format!("pip show {}", sanitize_shell_arg(package)),
                    PackageManager::Npm => format!("npm list -g {}", sanitize_shell_arg(package)),
                    PackageManager::Composer => {
                        format!("composer show {}", sanitize_shell_arg(package))
                    }
                };
                resources.push(GossResource::Command {
                    name: format!("package-{}", command_to_name(package)),
                    command: check_cmd,
                    exit_status: 0,
                    timeout: 10000,
                    provenance: assertion.provenance.clone(),
                    confidence: assertion.confidence,
                });

                // Enrichment: if we know a version command, add it too
                if let Some(vcmd) = version_cmd {
                    resources.push(GossResource::Command {
                        name: command_to_name(vcmd),
                        command: sanitize_command(vcmd),
                        exit_status: 0,
                        timeout: 10000,
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
    let mut deduped = Vec::new();
    let mut key_to_index = std::collections::HashMap::new();

    for resource in resources.drain(..) {
        let key = resource.identity_key();
        if let Some(idx) = key_to_index.get(&key).copied() {
            merge_resource(&mut deduped[idx], resource);
        } else {
            key_to_index.insert(key, deduped.len());
            deduped.push(resource);
        }
    }

    *resources = deduped;
}

fn merge_resource(existing: &mut GossResource, incoming: GossResource) {
    if let (
        GossResource::File {
            filetype: existing_filetype,
            mode: existing_mode,
            confidence: existing_confidence,
            ..
        },
        GossResource::File {
            filetype: incoming_filetype,
            mode: incoming_mode,
            confidence: incoming_confidence,
            ..
        },
    ) = (existing, incoming)
    {
        if existing_filetype.is_none() {
            *existing_filetype = incoming_filetype;
        }
        if existing_mode.is_none() {
            *existing_mode = incoming_mode;
        }
        if incoming_confidence > *existing_confidence {
            *existing_confidence = incoming_confidence;
        }
    }
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
    command.replace(['\0', '\r'], "").trim().to_string()
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

    #[test]
    fn test_confidence_skips_are_notes_not_warnings() {
        // Package installs are Confidence::Low; under `standard` (Medium cutoff)
        // they are filtered. That filtering is routine and must land in `notes`,
        // never in `warnings` (which drive exit code 2).
        let content = r#"
FROM debian:12
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
RUN apt-get install -y nginx curl git
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(
            !output.notes.is_empty(),
            "confidence-filtered assertions should produce notes"
        );
        assert!(
            output
                .notes
                .iter()
                .any(|n| n.contains("confidence too low")),
            "notes should describe the confidence skip"
        );
        assert!(
            output.warnings.is_empty(),
            "routine confidence filtering must not populate warnings, got: {:?}",
            output.warnings
        );
    }

    #[test]
    fn test_empty_contract_no_signals_warns() {
        // No EXPOSE/CMD/ENTRYPOINT/HEALTHCHECK: nothing to assert. This is the
        // silent-wrong-output case and must surface as a warning (exit 2), with
        // a message naming the absent signals.
        let content = "FROM alpine:3.19\nRUN echo hello\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert_eq!(output.warnings.len(), 1, "expected one anomaly warning");
        let w = &output.warnings[0];
        assert!(w.contains("no assertions"), "warning: {w}");
        assert!(
            w.contains("EXPOSE") && w.contains("HEALTHCHECK"),
            "warning should name the absent signals: {w}"
        );
    }

    #[test]
    fn test_empty_contract_with_filtered_signals_warns_differently() {
        // Signals exist but every candidate was filtered by confidence. The
        // diagnostic should point at the profile cutoff rather than claim no
        // signals were found.
        let content = "FROM alpine:3.19\nRUN apk add --no-cache curl\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        // Minimal profile => High cutoff => the Low-confidence package is filtered.
        let output = generate(&contract, Profile::Minimal, &PolicyConfig::default(), None);

        assert_eq!(output.warnings.len(), 1, "expected one anomaly warning");
        let w = &output.warnings[0];
        assert!(
            w.contains("confidence cutoff"),
            "warning should reference the profile cutoff: {w}"
        );
    }

    #[test]
    fn test_wait_only_contract_is_not_an_anomaly() {
        // A port-only Dockerfile produces an empty goss.yml but a valid
        // goss_wait.yml (the port routes to the readiness gate). That is not
        // "nothing to assert" and must not warn.
        let content = "FROM nginx\nEXPOSE 80\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(
            output.goss_wait_yml.is_some(),
            "a port signal should produce a readiness gate"
        );
        assert!(
            output.warnings.is_empty(),
            "a populated wait file means the run is not empty: {:?}",
            output.warnings
        );
    }

    #[test]
    fn test_healthcheck_only_contract_is_not_an_anomaly() {
        // A healthcheck-only Dockerfile routes its assertion to the wait file;
        // the empty main must not be flagged as an anomaly.
        let content =
            "FROM alpine\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(output.goss_wait_yml.is_some());
        assert!(
            output.warnings.is_empty(),
            "a healthcheck readiness gate means the run is not empty: {:?}",
            output.warnings
        );
    }

    #[test]
    fn test_policy_emptied_output_warns_without_claiming_confidence_only() {
        // A High-confidence HttpStatus assertion dropped purely by policy
        // (http_checks defaults off), with no wait gate, empties the whole run.
        // It must warn, and the message must not mislead by blaming confidence
        // alone — it should mention policy too.
        let mut contract = RuntimeContract {
            base_image: "nginx".to_string(),
            ..Default::default()
        };
        contract.assertions.push(ContractAssertion::new(
            AssertionKind::HttpStatus {
                url: "http://127.0.0.1:8080/healthz".to_string(),
                status: 200,
            },
            "CLI: --health-path flag",
            0,
            Confidence::High,
        ));
        // Default policy has http_checks = false, so the assertion is dropped.
        let output = generate(
            &contract,
            Profile::Standard,
            &PolicyConfig::default(),
            Some(false),
        );

        assert_eq!(output.warnings.len(), 1, "policy-emptied run should warn");
        let w = &output.warnings[0];
        assert!(
            w.contains("policy"),
            "message must acknowledge the policy cause, not only confidence: {w}"
        );
    }

    #[test]
    fn test_user_requested_http_check_overrides_default_policy() {
        // A user who passes --health-path (or answers the interactive health
        // prompt) explicitly asked for the HTTP check. Even though the default
        // policy has http_checks = false, the assertion must appear in the
        // output rather than being silently dropped.
        let mut contract = RuntimeContract {
            base_image: "nginx".to_string(),
            ..Default::default()
        };
        contract.assertions.push(
            ContractAssertion::new(
                AssertionKind::HttpStatus {
                    url: "http://127.0.0.1:80/healthz".to_string(),
                    status: 200,
                },
                "CLI: --health-path flag",
                0,
                Confidence::High,
            )
            .user_requested(),
        );

        let output = generate(
            &contract,
            Profile::Standard,
            &PolicyConfig::default(),
            Some(false),
        );

        assert!(
            output.goss_yml.contains("http"),
            "user-requested http check must survive the default policy gate: {}",
            output.goss_yml
        );
        assert!(
            output.goss_yml.contains("/healthz"),
            "the health path must be rendered: {}",
            output.goss_yml
        );
        assert!(
            output.warnings.is_empty(),
            "a rendered http check means the run is not empty: {:?}",
            output.warnings
        );
    }

    #[test]
    fn test_nonempty_contract_has_no_anomaly_warning() {
        let content = r#"
FROM nginx
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        let output = generate(&contract, Profile::Standard, &PolicyConfig::default(), None);

        assert!(
            output.warnings.is_empty(),
            "a contract with real assertions must not warn: {:?}",
            output.warnings
        );
    }

    #[test]
    fn test_deduplicate_file_resources_prefers_mode_and_filetype() {
        let mut resources = vec![
            GossResource::File {
                path: "/docker-entrypoint.sh".to_string(),
                exists: true,
                filetype: None,
                mode: None,
                provenance: "COPY /docker-entrypoint.sh".to_string(),
                confidence: Confidence::Medium,
            },
            GossResource::File {
                path: "/docker-entrypoint.sh".to_string(),
                exists: true,
                filetype: Some("file".to_string()),
                mode: Some("0755".to_string()),
                provenance: "COPY /docker-entrypoint.sh (entrypoint script pattern)".to_string(),
                confidence: Confidence::High,
            },
        ];

        deduplicate_resources(&mut resources);
        assert_eq!(resources.len(), 1);
        assert!(matches!(
            &resources[0],
            GossResource::File {
                filetype: Some(ft),
                mode: Some(mode),
                confidence: Confidence::High,
                ..
            } if ft == "file" && mode == "0755"
        ));
    }
}
