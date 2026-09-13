mod heuristics;
mod model;

pub use heuristics::*;
pub use model::*;

use crate::config::{PolicyConfig, REDACTED_PLACEHOLDER};
use crate::parser::{CommandForm, Dockerfile, Instruction, PortSpec, VariableResolver};
use crate::Confidence;

/// Maximum number of individual ports expanded from a single `EXPOSE low-high`
/// range. Wider ranges are dropped with a warning rather than exploded into
/// thousands of assertions.
const MAX_EXPOSE_RANGE: u32 = 128;

/// Extract a RuntimeContract from a parsed Dockerfile.
///
/// `policy` governs secret redaction: any `ENV` value whose key
/// [`PolicyConfig::is_secret_key`] matches is replaced with
/// [`REDACTED_PLACEHOLDER`] before it is stored anywhere — both in the contract
/// and in the variable resolver's map. Redacting in the resolver too means a
/// later instruction that substitutes the secret variable (e.g. `WORKDIR
/// /$DB_PASSWORD`, `EXPOSE $DB_PASSWORD`, or another `ENV` referencing it) sees
/// the placeholder, so the cleartext value never enters the contract or any
/// derived assertion or diagnostic.
pub fn extract_contract(
    dockerfile: &Dockerfile,
    target: Option<&str>,
    build_args: &[(String, String)],
    policy: &PolicyConfig,
) -> RuntimeContract {
    let stage = match dockerfile.resolve_target(target) {
        Some(s) => s,
        None => return RuntimeContract::default(),
    };

    let mut resolver = VariableResolver::new();
    resolver.load_build_args(build_args);
    resolver.load_global_args(&dockerfile.global_args);

    // Resolve the base image against build args and pre-FROM globals only: a stage-body
    // ARG/ENV appears after FROM and cannot influence how the image reference resolved.
    let mut contract = RuntimeContract {
        base_image: resolver.resolve(&stage.image),
        ..Default::default()
    };

    let mut current_workdir = String::from("/");

    // Docker applies last-wins semantics to ENTRYPOINT, CMD, and HEALTHCHECK: only the
    // final occurrence in a stage takes effect. Rather than emit an assertion at each
    // encounter (which accumulates stale assertions from overridden instructions and can
    // emit a CMD-derived process before a later ENTRYPOINT is seen), we fold these three
    // instructions into their effective final state during the walk and emit their
    // assertions once, afterward, from the winning occurrence.
    let mut fold_entrypoint: Option<(CommandForm, usize)> = None;
    let mut fold_cmd: Option<(CommandForm, usize)> = None;
    let mut fold_healthcheck: Option<(HealthcheckInfo, usize)> = None;

    // Walk instructions in source order, updating the variable map as ARG/ENV are seen so
    // every instruction resolves against the variables defined above it. A later ENV
    // redefinition therefore cannot retroactively change how an earlier instruction resolved.
    for inst in &stage.instructions {
        match &inst.instruction {
            Instruction::Workdir(dir) => {
                let resolved = resolver.resolve(dir);
                if resolved.starts_with('/') {
                    current_workdir = resolved.clone();
                } else {
                    current_workdir =
                        format!("{}/{}", current_workdir.trim_end_matches('/'), resolved);
                }
                contract.workdir = Some(current_workdir.clone());
                contract.assertions.push(ContractAssertion::new(
                    AssertionKind::FileExists {
                        path: current_workdir.clone(),
                        filetype: Some("directory".to_string()),
                        mode: None,
                    },
                    format!("WORKDIR {}", dir),
                    inst.line_number,
                    Confidence::High,
                ));
            }

            Instruction::User(user) => {
                let resolved = resolver.resolve(user);
                contract.user = Some(resolved.clone());

                if resolved.chars().all(|c| c.is_ascii_digit()) {
                    contract.assertions.push(ContractAssertion::new(
                        AssertionKind::CommandOutput {
                            command: "id -u".to_string(),
                            exit_status: 0,
                            expected_output: vec![resolved.clone()],
                        },
                        format!("USER {}", user),
                        inst.line_number,
                        Confidence::High,
                    ));
                } else {
                    // Split user:group if present
                    let username = resolved.split(':').next().unwrap_or(&resolved);
                    contract.assertions.push(ContractAssertion::new(
                        AssertionKind::UserExists {
                            username: username.to_string(),
                        },
                        format!("USER {}", user),
                        inst.line_number,
                        Confidence::High,
                    ));
                }
            }

            Instruction::Expose(tokens) => {
                for raw_token in tokens {
                    if resolver.has_unresolved(raw_token) {
                        contract.warnings.push(format!(
                            "EXPOSE '{}' contains an unresolved variable (no ARG/ENV default \
                             in scope); no port assertion generated",
                            raw_token
                        ));
                        continue;
                    }

                    let resolved = resolver.resolve(raw_token);
                    let (specs, warning) = parse_expose_token(&resolved);
                    if let Some(w) = warning {
                        contract.warnings.push(w);
                    }
                    for port_spec in specs {
                        contract.exposed_ports.push(port_spec.clone());
                        contract.assertions.push(ContractAssertion::new(
                            AssertionKind::PortListening {
                                protocol: port_spec.protocol.clone(),
                                port: port_spec.port,
                            },
                            format!("EXPOSE {}/{}", port_spec.port, port_spec.protocol),
                            inst.line_number,
                            Confidence::Medium,
                        ));
                    }
                }
            }

            Instruction::Volume(volumes) => {
                for vol in volumes {
                    let resolved = resolver.resolve(vol);
                    contract.volumes.push(resolved);
                }
            }

            Instruction::Arg { name, default } => {
                resolver.declare_arg(name, default.as_deref());
            }

            Instruction::Env(pairs) => {
                for (key, value) in pairs {
                    let resolved_val = resolver.resolve(value);
                    // Redact a secret value *before* it is stored anywhere,
                    // including in the resolver's variable map. Feeding the
                    // placeholder (not the real value) back to the resolver is
                    // what keeps a later `$SECRET` substitution — e.g.
                    // `WORKDIR /$DB_PASSWORD` or an unparseable `EXPOSE
                    // $DB_PASSWORD` warning — from leaking the secret into a
                    // derived assertion or diagnostic. The trade-off is that a
                    // non-secret field derived from a secret-keyed variable sees
                    // the placeholder rather than the real value, which is the
                    // safe direction.
                    let stored_val = if policy.is_secret_key(key) {
                        REDACTED_PLACEHOLDER.to_string()
                    } else {
                        resolved_val
                    };
                    resolver.set_var(key, &stored_val);
                    contract.env.push((key.clone(), stored_val));
                }
            }

            Instruction::Entrypoint(cmd) => {
                // Docker treats an empty exec form (`ENTRYPOINT []`) as clearing the
                // entrypoint; any other form overrides the previous one (last wins).
                if is_reset_exec(cmd) {
                    fold_entrypoint = None;
                } else {
                    fold_entrypoint = Some((cmd.clone(), inst.line_number));
                }
            }

            Instruction::Cmd(cmd) => {
                // `CMD []` clears the command; anything else overrides (last wins).
                if is_reset_exec(cmd) {
                    fold_cmd = None;
                } else {
                    fold_cmd = Some((cmd.clone(), inst.line_number));
                }
            }

            Instruction::Healthcheck {
                cmd,
                interval,
                timeout,
                start_period,
                retries,
            } => {
                fold_healthcheck = Some((
                    HealthcheckInfo {
                        cmd: cmd.clone(),
                        interval: interval.clone(),
                        timeout: timeout.clone(),
                        start_period: start_period.clone(),
                        retries: *retries,
                    },
                    inst.line_number,
                ));
            }

            // `HEALTHCHECK NONE` disables any healthcheck inherited from an earlier
            // instruction, so it must clear the folded state (and thus the wait assertion).
            Instruction::HealthcheckNone => {
                fold_healthcheck = None;
            }

            Instruction::Copy {
                from_stage,
                sources: _,
                dest,
                chmod,
            } => {
                // Only assert on files copied from within the build (not from other stages
                // where we can't know what was built), unless the dest is an absolute path
                let full_dest = resolve_dest_path(dest, &resolver, &current_workdir);

                let confidence = Confidence::Medium;

                let is_dir = full_dest.ends_with('/');
                let is_entrypoint_script = is_entrypoint_path(&full_dest);
                let filetype = if is_entrypoint_script {
                    Some("file".to_string())
                } else if is_dir {
                    Some("directory".to_string())
                } else {
                    None
                };
                let mode = if is_entrypoint_script {
                    chmod.clone().or_else(|| Some("0755".to_string()))
                } else {
                    chmod.clone()
                };
                let provenance = if is_entrypoint_script {
                    format!("COPY {} (entrypoint script pattern)", dest)
                } else {
                    format!(
                        "COPY {} {}",
                        if from_stage.is_some() {
                            format!("--from={}", from_stage.as_ref().unwrap())
                        } else {
                            "".to_string()
                        },
                        dest
                    )
                    .trim()
                    .to_string()
                };

                contract.assertions.push(ContractAssertion::new(
                    AssertionKind::FileExists {
                        path: full_dest.clone(),
                        filetype,
                        mode,
                    },
                    provenance,
                    inst.line_number,
                    confidence,
                ));

                contract.filesystem_paths.push(full_dest);
            }

            Instruction::Add {
                sources: _,
                dest,
                chmod,
            } => {
                let full_dest = resolve_dest_path(dest, &resolver, &current_workdir);

                contract.assertions.push(ContractAssertion::new(
                    AssertionKind::FileExists {
                        path: full_dest.clone(),
                        filetype: None,
                        mode: chmod.clone(),
                    },
                    format!("ADD {}", dest),
                    inst.line_number,
                    Confidence::Medium,
                ));

                contract.filesystem_paths.push(full_dest);
            }

            Instruction::Run(cmd) => {
                // Apply heuristics to detect installed packages/services
                let run_assertions = heuristics::analyze_run_command(cmd, inst.line_number);
                contract.assertions.extend(run_assertions);

                // Detect installed components
                let components = heuristics::detect_installed_components(cmd);
                contract.installed_components.extend(components);
            }

            _ => {}
        }
    }

    // Emit phase: generate process and healthcheck assertions once, from the folded
    // final state. Docker's interaction rule: when an ENTRYPOINT is set, CMD supplies its
    // arguments rather than a process of its own, so a process assertion comes from the
    // entrypoint; only in the absence of an entrypoint does CMD name the process.
    contract.entrypoint = fold_entrypoint.as_ref().map(|(cmd, _)| cmd.clone());
    contract.cmd = fold_cmd.as_ref().map(|(cmd, _)| cmd.clone());

    if let Some((cmd, line)) = &fold_entrypoint {
        if let Some(assertion) = make_process_assertion(cmd, "ENTRYPOINT", *line) {
            contract.assertions.push(assertion);
        }
    } else if let Some((cmd, line)) = &fold_cmd {
        if let Some(assertion) = make_process_assertion(cmd, "CMD", *line) {
            contract.assertions.push(assertion);
        }
    }

    if let Some((info, line)) = &fold_healthcheck {
        contract.healthcheck = Some(info.clone());
        contract.assertions.push(ContractAssertion::new(
            AssertionKind::HealthcheckPasses {
                command: info.cmd.to_string_lossy(),
            },
            format!("HEALTHCHECK CMD {}", info.cmd.to_string_lossy()),
            *line,
            Confidence::High,
        ));
    }

    // Add service-specific assertions based on detected components
    let service_assertions =
        heuristics::generate_service_assertions(&contract.installed_components);
    contract.assertions.extend(service_assertions);

    contract
}

/// Whether a command form is an empty exec form (`[]`), which Docker treats as clearing
/// a previously-set ENTRYPOINT or CMD.
///
/// The parser lowers an empty JSON array to a `Shell("[]")` form rather than
/// `Exec(vec![])`, so both shapes are recognized here; without this, `ENTRYPOINT []`
/// would otherwise be mistaken for a process named `[]`.
fn is_reset_exec(cmd: &CommandForm) -> bool {
    match cmd {
        CommandForm::Exec(parts) => parts.is_empty(),
        CommandForm::Shell(s) => {
            let inner = s.trim();
            inner.starts_with('[')
                && inner.ends_with(']')
                && inner[1..inner.len() - 1].trim().is_empty()
        }
    }
}

/// Parse a single, already variable-resolved EXPOSE token into zero or more
/// `PortSpec`s. Supports `PORT`, `PORT/proto`, and inclusive `LOW-HIGH[/proto]`
/// ranges. Returns any concrete specs plus an optional warning for tokens that
/// could not be interpreted (unparseable, inverted, or over-wide ranges).
fn parse_expose_token(token: &str) -> (Vec<PortSpec>, Option<String>) {
    let (port_part, protocol) = match token.split_once('/') {
        Some((p, proto)) => (p, proto.to_lowercase()),
        None => (token, "tcp".to_string()),
    };

    if let Some((lo_str, hi_str)) = port_part.split_once('-') {
        let (lo, hi) = match (lo_str.parse::<u16>(), hi_str.parse::<u16>()) {
            (Ok(lo), Ok(hi)) => (lo, hi),
            _ => {
                return (
                    Vec::new(),
                    Some(format!(
                        "EXPOSE '{token}' is not a valid port range; no port assertion generated"
                    )),
                );
            }
        };

        if lo > hi {
            return (
                Vec::new(),
                Some(format!(
                    "EXPOSE range '{token}' is inverted (start > end); no port assertion generated"
                )),
            );
        }

        let span = u32::from(hi) - u32::from(lo) + 1;
        if span > MAX_EXPOSE_RANGE {
            return (
                Vec::new(),
                Some(format!(
                    "EXPOSE range '{token}' spans {span} ports (> {MAX_EXPOSE_RANGE}); \
                     skipped to avoid assertion explosion"
                )),
            );
        }

        let specs = (lo..=hi)
            .map(|port| PortSpec {
                port,
                protocol: protocol.clone(),
            })
            .collect();
        (specs, None)
    } else {
        match port_part.parse::<u16>() {
            Ok(port) => (vec![PortSpec { port, protocol }], None),
            Err(_) => (
                Vec::new(),
                Some(format!(
                    "EXPOSE '{token}' is not a valid port; no port assertion generated"
                )),
            ),
        }
    }
}

fn make_process_assertion(
    cmd: &CommandForm,
    provenance_prefix: &str,
    source_line: usize,
) -> Option<ContractAssertion> {
    let binary = cmd.primary_binary()?;
    let confidence = match cmd {
        CommandForm::Exec(_) => Confidence::Medium,
        CommandForm::Shell(_) => Confidence::Low,
    };
    if is_shell_interpreter(&binary) {
        return None;
    }
    Some(ContractAssertion::new(
        AssertionKind::ProcessRunning { name: binary },
        format!("{} {}", provenance_prefix, cmd.to_string_lossy()),
        source_line,
        confidence,
    ))
}

fn resolve_dest_path(
    dest: &str,
    resolver: &crate::parser::VariableResolver,
    current_workdir: &str,
) -> String {
    let resolved_dest = resolver.resolve(dest);
    if resolved_dest.starts_with('/') {
        resolved_dest
    } else {
        format!(
            "{}/{}",
            current_workdir.trim_end_matches('/'),
            resolved_dest
        )
    }
}

fn is_entrypoint_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("entrypoint") || lower.contains("docker-entrypoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyConfig;
    use crate::parser::parse_dockerfile_content;

    #[test]
    fn test_extract_basic_contract() {
        let content = r#"
FROM node:18-alpine
WORKDIR /app
COPY package.json /app/
EXPOSE 3000
CMD ["node", "server.js"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "node:18-alpine");
        assert_eq!(contract.workdir, Some("/app".to_string()));
        assert_eq!(contract.exposed_ports.len(), 1);
        assert_eq!(contract.exposed_ports[0].port, 3000);
        assert!(!contract.assertions.is_empty());
    }

    #[test]
    fn test_extract_with_healthcheck() {
        let content = r#"
FROM nginx:alpine
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.healthcheck.is_some());
        let has_healthcheck_assertion = contract
            .assertions
            .iter()
            .any(|a| matches!(a.kind, AssertionKind::HealthcheckPasses { .. }));
        assert!(has_healthcheck_assertion);
    }

    #[test]
    fn test_extract_multistage_target() {
        let content = r#"
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /src/bin/app /app/app
EXPOSE 8080
ENTRYPOINT ["/app/app"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "alpine:3.18");
        assert_eq!(contract.workdir, Some("/app".to_string()));
    }

    #[test]
    fn test_user_numeric() {
        let content = r#"
FROM alpine
USER 1001
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert!(contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::CommandOutput {
                command,
                expected_output,
                ..
            } if command == "id -u" && expected_output == &vec!["1001".to_string()]
        )));
    }

    #[test]
    fn test_global_arg_resolves_base_image() {
        let content = r#"
ARG BASE_IMAGE=ubuntu:22.04
FROM $BASE_IMAGE
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.base_image, "ubuntu:22.04");
    }

    #[test]
    fn test_build_arg_overrides_global_arg_for_base_image() {
        let content = r#"
ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("BASE_IMAGE".to_string(), "alpine:3.20".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "alpine:3.20");
    }

    fn process_names(contract: &RuntimeContract) -> Vec<String> {
        contract
            .assertions
            .iter()
            .filter_map(|a| match &a.kind {
                AssertionKind::ProcessRunning { name } => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    fn healthcheck_assertions(contract: &RuntimeContract) -> Vec<String> {
        contract
            .assertions
            .iter()
            .filter_map(|a| match &a.kind {
                AssertionKind::HealthcheckPasses { command } => Some(command.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_cmd_before_entrypoint_uses_entrypoint_binary() {
        // Legal Dockerfile ordering: CMD (which supplies entrypoint arguments) appears
        // before ENTRYPOINT. Docker treats `--port`/`8080` as arguments, so the process
        // is the entrypoint binary, never the flag.
        let content = r#"
FROM alpine
CMD ["--port", "8080"]
ENTRYPOINT ["/usr/local/bin/server"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let procs = process_names(&contract);
        assert_eq!(procs, vec!["server".to_string()]);
        assert!(
            !procs.iter().any(|n| n == "--port"),
            "flag must not become a process assertion"
        );
    }

    #[test]
    fn test_repeated_entrypoint_keeps_only_last() {
        let content = r#"
FROM alpine
ENTRYPOINT ["/usr/local/bin/first"]
ENTRYPOINT ["/usr/local/bin/second"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(process_names(&contract), vec!["second".to_string()]);
    }

    #[test]
    fn test_repeated_cmd_keeps_only_last() {
        let content = r#"
FROM alpine
CMD ["/usr/local/bin/first"]
CMD ["/usr/local/bin/second"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(process_names(&contract), vec!["second".to_string()]);
    }

    #[test]
    fn test_repeated_healthcheck_keeps_only_last() {
        let content = r#"
FROM alpine
HEALTHCHECK CMD curl -f http://localhost/first
HEALTHCHECK CMD curl -f http://localhost/second
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let hc = healthcheck_assertions(&contract);
        assert_eq!(hc.len(), 1);
        assert!(
            hc[0].contains("second"),
            "healthcheck should be from the last instruction: {}",
            hc[0]
        );
        assert!(!hc[0].contains("first"));
    }

    #[test]
    fn test_healthcheck_none_clears_earlier_healthcheck() {
        let content = r#"
FROM alpine
HEALTHCHECK --interval=30s CMD curl -f http://localhost/
HEALTHCHECK NONE
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.healthcheck.is_none());
        assert!(healthcheck_assertions(&contract).is_empty());
    }

    #[test]
    fn test_empty_entrypoint_exec_clears_entrypoint_and_falls_back_to_cmd() {
        // `ENTRYPOINT []` resets the entrypoint; the process then derives from CMD.
        let content = r#"
FROM alpine
ENTRYPOINT ["/usr/local/bin/server"]
ENTRYPOINT []
CMD ["/usr/local/bin/app"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.entrypoint.is_none());
        assert_eq!(process_names(&contract), vec!["app".to_string()]);
    }

    #[test]
    fn test_entrypoint_supplies_process_when_cmd_after() {
        // Standard ordering: ENTRYPOINT then CMD. Only the entrypoint names the process.
        let content = r#"
FROM alpine
ENTRYPOINT ["/usr/local/bin/server"]
CMD ["--port", "8080"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(process_names(&contract), vec!["server".to_string()]);
    }

    #[test]
    fn test_expose_resolves_arg_driven_port() {
        let content = r#"
FROM alpine
ARG PORT=8080
EXPOSE ${PORT}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.exposed_ports.len(), 1);
        assert_eq!(contract.exposed_ports[0].port, 8080);
        assert_eq!(contract.exposed_ports[0].protocol, "tcp");
        assert!(contract.warnings.is_empty());

        let port_assertion = contract
            .assertions
            .iter()
            .find(|a| matches!(a.kind, AssertionKind::PortListening { port: 8080, .. }))
            .expect("expected a PortListening assertion for the resolved port");
        assert_eq!(port_assertion.confidence, Confidence::Medium);
    }

    #[test]
    fn test_expose_resolves_env_driven_port() {
        let content = r#"
FROM alpine
ENV PORT=9000
EXPOSE $PORT/udp
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.exposed_ports.len(), 1);
        assert_eq!(contract.exposed_ports[0].port, 9000);
        assert_eq!(contract.exposed_ports[0].protocol, "udp");
        assert!(contract.warnings.is_empty());
    }

    #[test]
    fn test_expose_expands_port_range() {
        let content = r#"
FROM alpine
EXPOSE 8000-8002
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let ports: Vec<u16> = contract.exposed_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8000, 8001, 8002]);
        assert!(contract.warnings.is_empty());
    }

    #[test]
    fn test_expose_expands_port_range_with_protocol() {
        let content = r#"
FROM alpine
EXPOSE 8000-8001/udp
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.exposed_ports.len(), 2);
        assert!(contract.exposed_ports.iter().all(|p| p.protocol == "udp"));
    }

    #[test]
    fn test_expose_undefined_variable_warns_instead_of_dropping_silently() {
        let content = r#"
FROM alpine
EXPOSE $UNDEFINED
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.exposed_ports.is_empty());
        assert_eq!(contract.warnings.len(), 1);
        assert!(contract.warnings[0].contains("UNDEFINED"));
    }

    #[test]
    fn test_expose_overwide_range_is_capped_with_warning() {
        let content = r#"
FROM alpine
EXPOSE 1024-65535
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.exposed_ports.is_empty());
        assert_eq!(contract.warnings.len(), 1);
        assert!(contract.warnings[0].contains("spans"));
    }

    #[test]
    fn test_parse_expose_token_variants() {
        assert_eq!(
            parse_expose_token("8080").0,
            vec![PortSpec {
                port: 8080,
                protocol: "tcp".to_string()
            }]
        );
        assert_eq!(
            parse_expose_token("53/udp").0,
            vec![PortSpec {
                port: 53,
                protocol: "udp".to_string()
            }]
        );
        assert_eq!(parse_expose_token("8000-8002").0.len(), 3);

        let (specs, warning) = parse_expose_token("8010-8000");
        assert!(specs.is_empty());
        assert!(warning.unwrap().contains("inverted"));

        let (specs, warning) = parse_expose_token("notaport");
        assert!(specs.is_empty());
        assert!(warning.unwrap().contains("not a valid port"));
    }

    fn env_value<'a>(contract: &'a RuntimeContract, key: &str) -> Option<&'a str> {
        contract
            .env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn test_env_escaped_dollar_quoted_stays_literal() {
        // `ENV LITERAL="\$ROOT"` must yield the literal `$ROOT`, not the value of
        // ROOT, even though ROOT is defined in scope.
        let content = "FROM alpine\nENV ROOT=/data\nENV LITERAL=\"\\$ROOT\"\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(env_value(&contract, "LITERAL"), Some("$ROOT"));
    }

    #[test]
    fn test_env_escaped_dollar_unquoted_stays_literal() {
        let content = "FROM alpine\nENV ROOT=/data\nENV LITERAL=\\$ROOT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(env_value(&contract, "LITERAL"), Some("$ROOT"));
    }

    #[test]
    fn test_env_normal_expansion_still_works() {
        let content = "FROM alpine\nENV FOO=bar\nENV A=$FOO\nENV B=${FOO}\nENV C=\"$FOO\"\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(env_value(&contract, "A"), Some("bar"));
        assert_eq!(env_value(&contract, "B"), Some("bar"));
        assert_eq!(env_value(&contract, "C"), Some("bar"));
    }

    #[test]
    fn test_env_escaped_dollar_does_not_break_adjacent_expansion() {
        // A literal `$` next to a real expansion in the same value: the escaped
        // one stays literal, the unescaped one expands.
        let content = "FROM alpine\nENV FOO=bar\nENV MIX=\"\\$FOO=$FOO\"\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(env_value(&contract, "MIX"), Some("$FOO=bar"));
    }

    #[test]
    fn test_instruction_resolves_variable_in_effect_at_its_position() {
        // WORKDIR, EXPOSE, and USER each read a variable that is redefined *below* them.
        // Docker resolves each against the value in effect at its own position, so the
        // later redefinitions must not leak upward into the earlier instructions.
        let content = r#"
FROM alpine
ENV APPDIR=/srv/app
WORKDIR $APPDIR
ENV PORT=8080
EXPOSE $PORT
ENV APPUSER=alice
USER $APPUSER
ENV APPDIR=/wrong
ENV PORT=9090
ENV APPUSER=bob
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/srv/app".to_string()));
        assert_eq!(contract.exposed_ports.len(), 1);
        assert_eq!(contract.exposed_ports[0].port, 8080);
        assert_eq!(contract.user, Some("alice".to_string()));
        assert!(contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::UserExists { username } if username == "alice"
        )));
    }

    #[test]
    fn test_later_redefinition_does_not_change_earlier_resolution() {
        // Two EXPOSE instructions straddle a redefinition of PORT. The first resolves
        // against the value above it (8080), the second against the redefined value (9090);
        // the redefinition must not retroactively rewrite the first.
        let content = r#"
FROM alpine
ENV PORT=8080
EXPOSE $PORT
ENV PORT=9090
EXPOSE $PORT
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let ports: Vec<u16> = contract.exposed_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8080, 9090]);
    }

    #[test]
    fn test_escaped_literal_and_instruction_order_resolution_coexist() {
        // Interaction of the two features that landed together: escape-aware `$` and
        // instruction-order resolution. An escaped `\$PORT` stays literal even though
        // PORT is live, while the unescaped EXPOSE instructions resolve against the
        // value in effect above each one (8080 then, after redefinition, 9090).
        let content = "FROM alpine\nENV PORT=8080\nENV LITERAL=\"\\$PORT\"\nEXPOSE $PORT\nENV PORT=9090\nEXPOSE $PORT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(env_value(&contract, "LITERAL"), Some("$PORT"));
        let ports: Vec<u16> = contract.exposed_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8080, 9090]);
    }

    #[test]
    fn test_base_image_ignores_stage_body_env_redefinition() {
        // FROM is the first instruction of a stage; a stage-body ENV that shadows the
        // ARG used in the image reference appears afterward and cannot change how the base
        // image resolved.
        let content = r#"
ARG TAG=1.0
FROM alpine:${TAG}
ENV TAG=2.0
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "alpine:1.0");
    }

    #[test]
    fn test_entrypoint_copy_generates_single_mode_aware_file_assertion() {
        let content = r#"
FROM alpine
COPY docker-entrypoint.sh /docker-entrypoint.sh
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let entrypoint_assertions: Vec<_> = contract
            .assertions
            .iter()
            .filter(|a| {
                matches!(
                    &a.kind,
                    AssertionKind::FileExists { path, .. } if path == "/docker-entrypoint.sh"
                )
            })
            .collect();
        assert_eq!(entrypoint_assertions.len(), 1);
        assert!(matches!(
            &entrypoint_assertions[0].kind,
            AssertionKind::FileExists {
                filetype: Some(ft),
                mode: Some(mode),
                ..
            } if ft == "file" && mode == "0755"
        ));
    }

    #[test]
    fn test_secret_env_value_is_redacted_in_contract() {
        // A key matching the default secret patterns must never keep its real
        // value in the contract; a non-secret key is stored untouched.
        let content = "FROM alpine\nENV DB_PASSWORD=hunter2\nENV APP_PORT=3000\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(
            env_value(&contract, "DB_PASSWORD"),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(env_value(&contract, "APP_PORT"), Some("3000"));
        assert!(
            !contract.env.iter().any(|(_, v)| v.contains("hunter2")),
            "the real secret value must not survive anywhere in contract.env"
        );
    }

    #[test]
    fn test_custom_secret_pattern_drives_redaction() {
        // The user-facing `secret_patterns` knob must feed enforcement: a custom
        // pattern redacts a key the defaults would leave alone, and a default
        // pattern absent from the custom list is no longer treated as secret.
        let policy = PolicyConfig {
            secret_patterns: vec!["INTERNAL".to_string()],
            ..PolicyConfig::default()
        };

        let content = "FROM alpine\nENV INTERNAL_URL=https://svc.internal\nENV API_TOKEN=abc123\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &policy);

        assert_eq!(
            env_value(&contract, "INTERNAL_URL"),
            Some(REDACTED_PLACEHOLDER)
        );
        // TOKEN is a default secret pattern but not in the custom list, so it
        // is now stored as-is — proving the custom list, not the defaults, is used.
        assert_eq!(env_value(&contract, "API_TOKEN"), Some("abc123"));
    }

    #[test]
    fn test_secret_value_does_not_leak_through_dependent_variables() {
        // A non-secret key whose value references a secret-keyed variable must
        // not resurrect the real secret: the resolver holds the placeholder, so
        // the dependent value carries the placeholder, never the cleartext.
        let content =
            "FROM alpine\nENV DB_PASSWORD=hunter2\nENV DATABASE_URL=postgres://u:$DB_PASSWORD@h\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(
            env_value(&contract, "DB_PASSWORD"),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(
            env_value(&contract, "DATABASE_URL"),
            Some("postgres://u:***REDACTED***@h")
        );
        assert!(
            !contract.env.iter().any(|(_, v)| v.contains("hunter2")),
            "the real secret value must not survive anywhere in contract.env"
        );
    }

    #[test]
    fn test_secret_value_does_not_leak_into_derived_assertions_or_warnings() {
        // A secret referenced by WORKDIR (rendered into goss.yml as a FileExists
        // path) or by an unparseable EXPOSE (rendered into a warning) must not
        // carry the cleartext into either derived output.
        let content =
            "FROM alpine\nENV DB_PASSWORD=hunter2\nWORKDIR /data/$DB_PASSWORD\nEXPOSE $DB_PASSWORD\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let workdir = contract.workdir.as_deref().unwrap_or("");
        assert!(
            !workdir.contains("hunter2"),
            "secret leaked into WORKDIR path"
        );
        assert!(workdir.contains(REDACTED_PLACEHOLDER));
        assert!(
            contract.warnings.iter().all(|w| !w.contains("hunter2")),
            "secret leaked into an extraction warning"
        );
        assert!(
            contract
                .assertions
                .iter()
                .all(|a| !a.provenance.contains("hunter2")),
            "secret leaked into an assertion's provenance"
        );
    }
}
