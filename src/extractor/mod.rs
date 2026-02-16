mod heuristics;
mod model;

pub use heuristics::*;
pub use model::*;

use crate::parser::{CommandForm, Dockerfile, Instruction, VariableResolver};
use crate::Confidence;

/// Extract a RuntimeContract from a parsed Dockerfile.
pub fn extract_contract(
    dockerfile: &Dockerfile,
    target: Option<&str>,
    build_args: &[(String, String)],
) -> RuntimeContract {
    let stage = match dockerfile.resolve_target(target) {
        Some(s) => s,
        None => return RuntimeContract::default(),
    };

    let mut resolver = VariableResolver::new();
    resolver.load_build_args(build_args);
    resolver.load_global_args(&dockerfile.global_args);
    resolver.process_stage(stage);

    let mut contract = RuntimeContract {
        base_image: resolver.resolve(&stage.image),
        ..Default::default()
    };

    let mut current_workdir = String::from("/");

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

            Instruction::Expose(ports) => {
                for port_spec in ports {
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

            Instruction::Volume(volumes) => {
                for vol in volumes {
                    let resolved = resolver.resolve(vol);
                    contract.volumes.push(resolved);
                }
            }

            Instruction::Env(pairs) => {
                for (key, value) in pairs {
                    let resolved_val = resolver.resolve(value);
                    contract.env.push((key.clone(), resolved_val));
                }
            }

            Instruction::Entrypoint(cmd) => {
                contract.entrypoint = Some(cmd.clone());
                if let Some(assertion) = make_process_assertion(cmd, "ENTRYPOINT", inst.line_number) {
                    contract.assertions.push(assertion);
                }
            }

            Instruction::Cmd(cmd) => {
                contract.cmd = Some(cmd.clone());
                if contract.entrypoint.is_none() {
                    if let Some(assertion) = make_process_assertion(cmd, "CMD", inst.line_number) {
                        contract.assertions.push(assertion);
                    }
                }
            }

            Instruction::Healthcheck {
                cmd,
                interval,
                timeout,
                start_period,
                retries,
            } => {
                contract.healthcheck = Some(HealthcheckInfo {
                    cmd: cmd.clone(),
                    interval: interval.clone(),
                    timeout: timeout.clone(),
                    start_period: start_period.clone(),
                    retries: *retries,
                });
                // Healthcheck-derived wait assertion
                contract.assertions.push(ContractAssertion::new(
                    AssertionKind::HealthcheckPasses {
                        command: cmd.to_string_lossy(),
                    },
                    format!("HEALTHCHECK CMD {}", cmd.to_string_lossy()),
                    inst.line_number,
                    Confidence::High,
                ));
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

    // Add service-specific assertions based on detected components
    let service_assertions =
        heuristics::generate_service_assertions(&contract.installed_components);
    contract.assertions.extend(service_assertions);

    contract
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

fn resolve_dest_path(dest: &str, resolver: &crate::parser::VariableResolver, current_workdir: &str) -> String {
    let resolved_dest = resolver.resolve(dest);
    if resolved_dest.starts_with('/') {
        resolved_dest
    } else {
        format!("{}/{}", current_workdir.trim_end_matches('/'), resolved_dest)
    }
}

fn is_entrypoint_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("entrypoint") || lower.contains("docker-entrypoint")
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);
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
        let contract = extract_contract(&df, None, &[]);
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
        );
        assert_eq!(contract.base_image, "alpine:3.20");
    }

    #[test]
    fn test_entrypoint_copy_generates_single_mode_aware_file_assertion() {
        let content = r#"
FROM alpine
COPY docker-entrypoint.sh /docker-entrypoint.sh
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
}
