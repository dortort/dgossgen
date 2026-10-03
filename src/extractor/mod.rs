mod heuristics;
mod model;

pub use heuristics::*;
pub use model::*;

use crate::config::{PolicyConfig, REDACTED_PLACEHOLDER};
use crate::parser::{
    escape_literal_dollars, CommandForm, Dockerfile, Instruction, PortSpec, Resolution, Stage,
    VariableResolver,
};
use crate::Confidence;

/// Maximum number of individual ports expanded from a single `EXPOSE low-high`
/// range. Wider ranges are dropped with a warning rather than exploded into
/// thousands of assertions.
const MAX_EXPOSE_RANGE: u32 = 128;

/// Extract a RuntimeContract from a parsed Dockerfile, keeping secret-named values out of it.
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
    resolver.load_build_args(build_args, |k| policy.is_secret_key(k));
    resolver.load_global_args(&dockerfile.global_args);

    // Walk the internal `FROM <alias>` chain so the final stage inherits the base stage's ENV/etc.
    let chain = resolve_stage_chain(dockerfile, stage, &resolver);

    // Report the chain's root image, not the internal alias; a stage-body ARG/ENV can't affect it.
    let root_image = chain
        .first()
        .map(|s| s.image.as_str())
        .unwrap_or(stage.image.as_str());
    let resolved_root = resolver.resolve_image(root_image);
    let mut contract = RuntimeContract {
        base_image: if resolved_root.secret {
            root_image.to_string()
        } else {
            resolved_root.value
        },
        ..Default::default()
    };

    // `None` means the working directory is unknown (an earlier WORKDIR failed to resolve).
    let mut current_workdir: Option<String> = Some(String::from("/"));

    // Fold ENTRYPOINT/CMD/HEALTHCHECK/USER to their last-wins value; emit once, after the walk.
    let mut fold_entrypoint: Option<(CommandForm, usize, usize)> = None;
    let mut fold_cmd: Option<(CommandForm, usize, usize)> = None;
    let mut fold_healthcheck: Option<(HealthcheckInfo, usize)> = None;
    let mut fold_user: Option<FoldedUser> = None;

    // Walk the chain root-first, updating ARG/ENV so later redefinitions can't apply retroactively.
    for (stage_idx, chain_stage) in chain.iter().enumerate() {
        for inst in &chain_stage.instructions {
            match &inst.instruction {
                Instruction::Workdir(dir) => {
                    let Resolution {
                        value: resolved,
                        unresolved,
                        secret,
                    } = resolver.resolve_checked(&escape_literal_dollars(dir));
                    // `None` means unknown (unresolved, secret, or unknown base); never asserted.
                    let new_workdir = if unresolved {
                        contract.warnings.push(format!(
                            "WORKDIR '{dir}' contains an unresolved variable (no ARG/ENV \
                             default in scope); no directory assertion generated"
                        ));
                        None
                    } else if secret {
                        contract.warnings.push(format!(
                            "WORKDIR '{dir}' uses a secret build arg; no directory assertion \
                             generated"
                        ));
                        None
                    } else if resolved.starts_with('/') {
                        Some(resolved.clone())
                    } else {
                        match &current_workdir {
                            Some(base) => {
                                Some(format!("{}/{}", base.trim_end_matches('/'), resolved))
                            }
                            None => {
                                contract.warnings.push(format!(
                                    "WORKDIR '{dir}' is relative to a working directory that \
                                     could not be resolved; no directory assertion generated"
                                ));
                                None
                            }
                        }
                    };

                    current_workdir = new_workdir.clone();
                    contract.workdir = new_workdir.clone();
                    if let Some(path) = new_workdir {
                        contract.assertions.push(ContractAssertion::new(
                            AssertionKind::FileExists {
                                path,
                                filetype: Some("directory".to_string()),
                                mode: None,
                            },
                            format!("WORKDIR {}", dir),
                            inst.line_number,
                            Confidence::High,
                        ));
                    }
                }

                Instruction::User(user) => {
                    // Fold USER to its effective value; avoids keeping a stale parent uid.
                    let Resolution {
                        value: resolved,
                        unresolved,
                        secret,
                    } = resolver.resolve_checked(&escape_literal_dollars(user));
                    fold_user = Some(FoldedUser {
                        raw: user.clone(),
                        resolved,
                        line: inst.line_number,
                        unresolved,
                        secret,
                    });
                }

                Instruction::Expose(tokens) => {
                    for raw_token in tokens {
                        let Resolution {
                            value: resolved,
                            unresolved,
                            secret,
                        } = resolver.resolve_checked(&escape_literal_dollars(raw_token));
                        if unresolved {
                            contract.warnings.push(format!(
                                "EXPOSE '{}' contains an unresolved variable (no ARG/ENV default \
                             in scope); no port assertion generated",
                                raw_token
                            ));
                            continue;
                        }
                        if secret {
                            contract.warnings.push(format!(
                                "EXPOSE '{raw_token}' uses a secret build arg; no port assertion \
                                 generated"
                            ));
                            continue;
                        }

                        let (specs, warning) = parse_expose_token(&resolved);
                        if let Some(w) = warning {
                            contract.warnings.push(w);
                        }
                        for port_spec in specs {
                            if contract.exposed_ports.iter().any(|p| {
                                p.port == port_spec.port && p.protocol == port_spec.protocol
                            }) {
                                continue;
                            }
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
                        let Resolution {
                            value: resolved,
                            secret,
                            ..
                        } = resolver.resolve_checked(&escape_literal_dollars(vol));
                        if secret {
                            contract.warnings.push(format!(
                                "VOLUME '{vol}' uses a secret build arg; volume not recorded"
                            ));
                            continue;
                        }
                        // One entry per path: repeats across the chain are deduped.
                        if !contract.volumes.contains(&resolved) {
                            contract.volumes.push(resolved);
                        }
                    }
                }

                Instruction::Arg { name, default } => {
                    // A supplied --build-arg enters scope here and overrides the default
                    // (which Docker never evaluates), so bind it before touching the default.
                    if resolver.has_supplied_build_arg(name) {
                        resolver.declare_arg(name, None, false);
                    } else {
                        match default.as_deref() {
                            Some(def) => {
                                let resolved_def =
                                    resolver.resolve_checked(&escape_literal_dollars(def));
                                if resolved_def.unresolved {
                                    // Leave the name undefined so later uses drop with a warning.
                                    if !resolver.is_locked(name) {
                                        resolver.unset(name);
                                    }
                                } else {
                                    resolver.declare_arg(
                                        name,
                                        Some(&resolved_def.value),
                                        resolved_def.secret,
                                    );
                                }
                            }
                            None => resolver.declare_arg(name, None, false),
                        }
                    }
                }

                Instruction::Env(pairs) => {
                    for (key, value) in pairs {
                        let resolved_val = resolver.resolve_checked(value);
                        if resolved_val.unresolved {
                            resolver.taint(key);
                            contract.env.retain(|(k, _)| k != key);
                            continue;
                        }
                        // The resolver keeps the real value; only the stored copy is redacted.
                        resolver.set_var(key, &resolved_val.value, resolved_val.secret);
                        let stored_val = if resolved_val.secret || policy.is_secret_key(key) {
                            REDACTED_PLACEHOLDER.to_string()
                        } else {
                            resolved_val.value
                        };
                        match contract.env.iter_mut().find(|(k, _)| k == key) {
                            Some(entry) => entry.1 = stored_val,
                            None => contract.env.push((key.clone(), stored_val)),
                        }
                    }
                }

                Instruction::Entrypoint(cmd) => {
                    // Docker resets an inherited CMD when a derived stage sets any ENTRYPOINT form.
                    if let Some((_, _, cmd_stage)) = &fold_cmd {
                        if *cmd_stage < stage_idx {
                            fold_cmd = None;
                        }
                    }
                    // An empty exec form clears the entrypoint; other forms override (last wins).
                    if is_reset_exec(cmd) {
                        fold_entrypoint = None;
                    } else {
                        fold_entrypoint = Some((cmd.clone(), inst.line_number, stage_idx));
                    }
                }

                Instruction::Cmd(cmd) => {
                    // `CMD []` clears the command; anything else overrides (last wins).
                    if is_reset_exec(cmd) {
                        fold_cmd = None;
                    } else {
                        fold_cmd = Some((cmd.clone(), inst.line_number, stage_idx));
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

                // `HEALTHCHECK NONE` clears the folded state, dropping any pending wait assertion.
                Instruction::HealthcheckNone => {
                    fold_healthcheck = None;
                }

                Instruction::Copy {
                    from_stage,
                    sources: _,
                    dest,
                    chmod,
                } => {
                    // Only assert build-local copies (unknown for other stages) or absolute paths.
                    let full_dest =
                        match resolve_dest_path(dest, &resolver, current_workdir.as_deref()) {
                            DestPath::Resolved(path) => path,
                            DestPath::UnresolvedVar => {
                                contract.warnings.push(format!(
                                    "COPY destination '{dest}' contains an unresolved variable \
                                     (no ARG/ENV default in scope); no file assertion generated"
                                ));
                                continue;
                            }
                            DestPath::UnknownWorkdir => {
                                contract.warnings.push(format!(
                                    "COPY destination '{dest}' is relative to a working directory \
                                     that could not be resolved; no file assertion generated"
                                ));
                                continue;
                            }
                            DestPath::Secret => {
                                contract.warnings.push(format!(
                                    "COPY destination '{dest}' uses a secret build arg; no file \
                                     assertion generated"
                                ));
                                continue;
                            }
                        };

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
                    let full_dest =
                        match resolve_dest_path(dest, &resolver, current_workdir.as_deref()) {
                            DestPath::Resolved(path) => path,
                            DestPath::UnresolvedVar => {
                                contract.warnings.push(format!(
                                    "ADD destination '{dest}' contains an unresolved variable \
                                     (no ARG/ENV default in scope); no file assertion generated"
                                ));
                                continue;
                            }
                            DestPath::UnknownWorkdir => {
                                contract.warnings.push(format!(
                                    "ADD destination '{dest}' is relative to a working directory \
                                     that could not be resolved; no file assertion generated"
                                ));
                                continue;
                            }
                            DestPath::Secret => {
                                contract.warnings.push(format!(
                                    "ADD destination '{dest}' uses a secret build arg; no file \
                                     assertion generated"
                                ));
                                continue;
                            }
                        };

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
    }

    // Emit phase: generate the folded assertions once, from their effective final state.

    // Drop USER if unresolved or empty (can never match the built image); warn instead.
    if let Some(user) = &fold_user {
        contract.user = (!user.secret).then(|| user.resolved.clone());
        if user.unresolved {
            contract.warnings.push(format!(
                "USER '{}' contains an unresolved variable (no ARG/ENV default in \
                 scope); no user assertion generated",
                user.raw
            ));
        } else if user.secret {
            contract.warnings.push(format!(
                "USER '{}' uses a secret build arg; no user assertion generated",
                user.raw
            ));
        } else if user.resolved.is_empty() {
            contract.warnings.push(format!(
                "USER '{}' resolved to an empty value; no user assertion generated",
                user.raw
            ));
        } else {
            contract.assertions.push(make_user_assertion(user));
        }
    }

    // With an ENTRYPOINT set, CMD supplies its args, not the process; else CMD names it.
    contract.entrypoint = fold_entrypoint.as_ref().map(|(cmd, _, _)| cmd.clone());
    contract.cmd = fold_cmd.as_ref().map(|(cmd, _, _)| cmd.clone());

    if let Some((cmd, line, _)) = &fold_entrypoint {
        if let Some(assertion) = make_process_assertion(cmd, "ENTRYPOINT", *line) {
            contract.assertions.push(assertion);
        }
    } else if let Some((cmd, line, _)) = &fold_cmd {
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

/// A USER instruction folded to its effective final value across the stage chain.
struct FoldedUser {
    /// The raw instruction argument, for provenance and warnings.
    raw: String,
    /// The variable-resolved value.
    resolved: String,
    /// Source line of the winning USER instruction.
    line: usize,
    /// Whether resolution left an unresolved variable reference.
    unresolved: bool,
    /// Whether resolution substituted a secret-derived variable.
    secret: bool,
}

/// Build the USER assertion: numeric uid via `id -u`, else user-exists (drops `:group`).
fn make_user_assertion(user: &FoldedUser) -> ContractAssertion {
    if user.resolved.chars().all(|c| c.is_ascii_digit()) {
        ContractAssertion::new(
            AssertionKind::CommandOutput {
                command: "id -u".to_string(),
                exit_status: 0,
                expected_output: vec![user.resolved.clone()],
            },
            format!("USER {}", user.raw),
            user.line,
            Confidence::High,
        )
    } else {
        let username = user.resolved.split(':').next().unwrap_or(&user.resolved);
        ContractAssertion::new(
            AssertionKind::UserExists {
                username: username.to_string(),
            },
            format!("USER {}", user.raw),
            user.line,
            Confidence::High,
        )
    }
}

/// Follow the internal `FROM <alias>` chain, nearest preceding, back to the root ancestor.
fn resolve_stage_chain<'a>(
    dockerfile: &'a Dockerfile,
    target: &'a Stage,
    resolver: &VariableResolver,
) -> Vec<&'a Stage> {
    let mut chain = vec![target];
    let mut current = target;

    loop {
        let resolved_image = resolver.resolve_image(&current.image).value;
        let parent = dockerfile
            .stages
            .iter()
            .filter(|candidate| {
                candidate.from_line < current.from_line
                    && candidate
                        .alias
                        .as_ref()
                        .is_some_and(|alias| alias.eq_ignore_ascii_case(&resolved_image))
            })
            .max_by_key(|candidate| candidate.from_line);

        match parent {
            Some(parent) => {
                chain.push(parent);
                current = parent;
            }
            None => break,
        }
    }

    chain.reverse();
    chain
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

/// Outcome of resolving a COPY/ADD destination.
enum DestPath {
    /// A fully-resolved absolute destination path.
    Resolved(String),
    /// The destination itself contained an unresolved variable.
    UnresolvedVar,
    /// Relative but the current WORKDIR is unknown (an earlier WORKDIR failed to resolve).
    UnknownWorkdir,
    /// The destination substituted a secret-derived variable.
    Secret,
}

/// Resolve a COPY/ADD dest; a relative one joins `current_workdir`, `None` if unknown.
fn resolve_dest_path(
    dest: &str,
    resolver: &crate::parser::VariableResolver,
    current_workdir: Option<&str>,
) -> DestPath {
    let Resolution {
        value: resolved_dest,
        unresolved,
        secret,
    } = resolver.resolve_checked(&escape_literal_dollars(dest));
    if unresolved {
        return DestPath::UnresolvedVar;
    }
    if secret {
        return DestPath::Secret;
    }
    if resolved_dest.starts_with('/') {
        return DestPath::Resolved(resolved_dest);
    }
    match current_workdir {
        Some(workdir) => DestPath::Resolved(format!(
            "{}/{}",
            workdir.trim_end_matches('/'),
            resolved_dest
        )),
        None => DestPath::UnknownWorkdir,
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

    /// Collect every directory path asserted by a WORKDIR/COPY FileExists.
    fn dir_paths(contract: &RuntimeContract) -> Vec<String> {
        contract
            .assertions
            .iter()
            .filter_map(|a| match &a.kind {
                AssertionKind::FileExists { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_workdir_escaped_dollar_is_literal_path() {
        // Regression for #46: an escaped `$` must not be read as an undefined reference.
        let content = "FROM alpine\nWORKDIR /opt/\\$HOME\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/opt/$HOME".to_string()));
        assert!(dir_paths(&contract).contains(&"/opt/$HOME".to_string()));
        assert!(
            contract.warnings.is_empty(),
            "no unresolved-variable warning expected, got: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_workdir_braced_escaped_dollar_is_literal_path() {
        // The `\${VAR}` brace form is escaped identically.
        let content = "FROM alpine\nWORKDIR /opt/\\${HOME}\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/opt/${HOME}".to_string()));
    }

    #[test]
    fn test_workdir_double_backslash_keeps_reference_live() {
        // `\\$APP` is a literal backslash followed by a *live* $APP reference.
        let content = "FROM alpine\nENV APP=myapp\nWORKDIR /opt/\\\\$APP\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/opt/\\myapp".to_string()));
    }

    #[test]
    fn test_copy_dest_escaped_dollar_is_literal_path() {
        // A COPY destination with an escaped `$` resolves to the literal path.
        let content = "FROM alpine\nCOPY app.conf /etc/\\$CONF/app.conf\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(dir_paths(&contract).contains(&"/etc/$CONF/app.conf".to_string()));
    }

    #[test]
    fn test_expose_escaped_dollar_flags_unresolved_not_a_reference() {
        // A literal `$PORT` is an invalid port, not an undefined variable.
        let content = "FROM alpine\nEXPOSE \\$PORT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.exposed_ports.is_empty());
        assert!(
            contract
                .warnings
                .iter()
                .any(|w| w.contains("$PORT") && !w.contains("unresolved variable")),
            "expected an invalid-port warning, got: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_escaped_dollar_in_unresolved_arg_never_leaks_marker() {
        let content = "FROM alpine\nENV T=$MISSING\nUSER ${T:-\\$x}\nVOLUME /data/${T:-\\$y}\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.user, Some("${T:-$x}".to_string()));
        assert_eq!(contract.volumes, vec!["/data/${T:-$y}".to_string()]);
        assert!(!format!("{contract:?}").contains(crate::parser::ESCAPED_DOLLAR));
    }

    #[test]
    fn test_workdir_backslash_edge_cases() {
        let cases = [
            ("/opt/cost\\$", "/opt/cost$"),
            ("/opt/\\\\\\$APP", "/opt/\\$APP"),
            ("/win\\app", "/win\\app"),
            ("/win\\\\app", "/win\\app"),
        ];
        for (dir, expected) in cases {
            let content = format!("FROM alpine\nENV APP=myapp\nWORKDIR {dir}\n");
            let df = parse_dockerfile_content(&content).unwrap();
            let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
            assert_eq!(contract.workdir.as_deref(), Some(expected), "WORKDIR {dir}");
        }
    }

    #[test]
    fn test_env_decoded_value_is_not_unescaped_again() {
        let content = "FROM alpine\nENV UNC=\\\\\\\\srv LIT=\\$HOME\nWORKDIR /mnt/$UNC/$LIT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/mnt/\\\\srv/$HOME".to_string()));
        assert!(contract.warnings.is_empty(), "{:?}", contract.warnings);
    }

    #[test]
    fn test_escaped_secret_reference_is_literal_not_secret() {
        let content = "FROM alpine\nARG DB_PASSWORD\nWORKDIR /opt/\\$DB_PASSWORD\nCOPY a /srv/\\\\$DB_PASSWORD/\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = vec![("DB_PASSWORD".to_string(), "hunter2".to_string())];
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/opt/$DB_PASSWORD".to_string()));
        assert_eq!(
            contract.warnings,
            vec![
                "COPY destination '/srv/\\\\$DB_PASSWORD/' uses a secret build arg; no file \
                 assertion generated"
            ]
        );
        assert!(!format!("{contract:?}").contains("hunter2"));
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
    fn test_internal_from_alias_inherits_parent_env() {
        // `FROM base` must inherit the base stage's ENV, resolving $APP_HOME, not the alias.
        let content = r#"
FROM node:20 AS base
ENV APP_HOME=/app

FROM base
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "node:20");
        assert_eq!(contract.workdir, Some("/app".to_string()));

        let has_app_dir = contract.assertions.iter().any(|a| {
            matches!(
                &a.kind,
                AssertionKind::FileExists { path, filetype, .. }
                    if path == "/app" && filetype.as_deref() == Some("directory")
            )
        });
        assert!(
            has_app_dir,
            "expected a FileExists directory assertion on /app, got: {:?}",
            contract.assertions
        );

        // No assertion may retain a literal, unresolved `$`-bearing path.
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains('$')
            )),
            "an unresolved path leaked into the assertions: {:?}",
            contract.assertions
        );
        assert!(
            contract.warnings.is_empty(),
            "inheritance should resolve cleanly with no warnings: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_internal_from_chain_transits_multiple_hops() {
        // ENV set in root stage `a` must reach the final stage via intermediate stage `b`.
        let content = r#"
FROM debian:12 AS a
ENV ROOT_DIR=/srv/app

FROM a AS b
ENV SUBDIR=data

FROM b
WORKDIR $ROOT_DIR/$SUBDIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "debian:12");
        assert_eq!(contract.workdir, Some("/srv/app/data".to_string()));
    }

    #[test]
    fn test_case_insensitive_from_alias_is_followed() {
        // Docker matches stage aliases case-insensitively; the chain walk must too.
        let content = r#"
FROM alpine:3.19 AS Build
ENV DEST=/opt/tool

FROM build
WORKDIR $DEST
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "alpine:3.19");
        assert_eq!(contract.workdir, Some("/opt/tool".to_string()));
    }

    #[test]
    fn test_unresolved_workdir_path_is_dropped_and_warns() {
        // Independent of chain walking: an unresolvable WORKDIR var drops the assertion, warns.
        let content = r#"
FROM alpine
WORKDIR $UNDECLARED
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains('$')
            )),
            "an unresolved path must not be emitted at all: {:?}",
            contract.assertions
        );
        assert_eq!(contract.workdir, None);
        assert!(
            contract
                .warnings
                .iter()
                .any(|w| w.contains("WORKDIR") && w.contains("unresolved variable")),
            "expected a warning about the unresolved WORKDIR, got: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_no_variable_path_survives_in_any_kind() {
        // Invariant: no FileExists assertion may carry a literal `$` in its path, ever.
        let content = r#"
FROM alpine
WORKDIR /real
WORKDIR $MISSING
COPY app /real/app
COPY other $MISSING/other
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains('$')
            )),
            "no unresolved path should survive: {:?}",
            contract.assertions
        );
        // The resolvable COPY into /real/app is still asserted.
        assert!(contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/real/app"
        )));
    }

    #[test]
    fn test_escaped_literal_dollar_path_is_not_flagged_unresolved() {
        // An escaped `\$` is a literal dollar, not unresolved; keeps High confidence.
        let content = "FROM alpine\nENV LITERAL=\\$HOME\nWORKDIR $LITERAL\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let workdir = contract
            .assertions
            .iter()
            .find(|a| {
                matches!(&a.kind, AssertionKind::FileExists { filetype, .. }
                if filetype.as_deref() == Some("directory"))
            })
            .expect("expected a workdir directory assertion");
        assert_eq!(workdir.confidence, Confidence::High);
        assert_eq!(contract.workdir, Some("/$HOME".to_string()));
        assert!(
            contract.warnings.is_empty(),
            "a legitimate literal-dollar path must not warn: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_from_alias_via_build_arg_is_resolved() {
        // `FROM ${BASE}` resolving to an internal alias must still follow the chain, inherit ENV.
        let content = r#"
ARG BASE=base
FROM node:20 AS base
ENV APP_HOME=/app

FROM ${BASE}
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.base_image, "node:20");
        assert_eq!(contract.workdir, Some("/app".to_string()));
    }

    #[test]
    fn test_effective_user_across_chain_is_emitted_once() {
        // A child USER overriding a parent's yields exactly one id -u assertion, the child's uid.
        let content = r#"
FROM alpine AS base
USER 1000

FROM base
USER 2000
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        let uid_assertions: Vec<&Vec<String>> = contract
            .assertions
            .iter()
            .filter_map(|a| match &a.kind {
                AssertionKind::CommandOutput {
                    command,
                    expected_output,
                    ..
                } if command == "id -u" => Some(expected_output),
                _ => None,
            })
            .collect();
        assert_eq!(
            uid_assertions.len(),
            1,
            "expected exactly one id -u assertion, got: {uid_assertions:?}"
        );
        assert_eq!(uid_assertions[0], &vec!["2000".to_string()]);
        assert_eq!(contract.user, Some("2000".to_string()));
    }

    #[test]
    fn test_unresolved_user_is_dropped_and_warns() {
        let content = r#"
FROM alpine
USER $UNDECLARED
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::UserExists { username } if username.contains('$')
            )),
            "an unresolved USER must not be asserted: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.contains("USER") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_stage_arg_inherited_by_dependent_stage() {
        // Docker inherits a base stage's ARG into a dependent stage, just like ENV.
        let content = r#"
FROM alpine AS base
ARG BUILD_DIR=/build

FROM base
WORKDIR $BUILD_DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/build".to_string()));
    }

    #[test]
    fn test_env_crosses_from_boundary() {
        // ENV also persists across the FROM boundary into a dependent stage.
        let content = r#"
FROM alpine AS base
ENV BUILD_DIR=/build

FROM base
WORKDIR $BUILD_DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.workdir, Some("/build".to_string()));
    }

    #[test]
    fn test_default_with_defined_nested_variable_resolves() {
        // A `${VAR:-default}` default itself referencing a defined variable is expanded.
        let content = r#"
FROM alpine
ENV SUB=inner
WORKDIR ${MISSING:-/opt/$SUB}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.workdir, Some("/opt/inner".to_string()));
    }

    #[test]
    fn test_default_with_undefined_nested_variable_is_dropped() {
        // A default referencing an UNDEFINED variable is flagged unresolved, never shipped.
        let content = r#"
FROM alpine
WORKDIR ${MISSING:-/x$BAR}
COPY app ${DEST:-/opt/$SUB}/a
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains('$')
            )),
            "a nested-default unresolved path must not survive: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_unterminated_brace_path_is_dropped() {
        // A malformed, unterminated `${...}` is treated as unresolved, not shipped literally.
        let content = "FROM alpine\nWORKDIR /a/${UNTERM\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path.contains('$')
        )));
    }

    #[test]
    fn test_relative_copy_after_unresolved_workdir_is_suppressed() {
        // After a WORKDIR fails to resolve, a later relative COPY must not use the stale dir.
        let content = r#"
FROM alpine
WORKDIR /real
WORKDIR $MISSING
COPY app app
COPY other /abs/other
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path == "/real/app"
            )),
            "a relative COPY after an unresolved WORKDIR must not use the stale dir: {:?}",
            contract.assertions
        );
        // The absolute COPY still lands.
        assert!(contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/abs/other"
        )));
    }

    #[test]
    fn test_empty_user_is_dropped_and_warns() {
        // A USER resolving to empty must not be emitted as an `id -u` == "" assertion.
        let content = r#"
FROM alpine
ARG U=
USER $U
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::CommandOutput { command, .. } if command == "id -u"
            )),
            "an empty USER must not produce an id -u assertion: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.contains("USER") && w.contains("empty")));
    }

    #[test]
    fn test_env_referencing_undefined_var_does_not_launder() {
        // An ENV bound to an unresolved value must not launder a `$` value back via reference.
        let content = r#"
FROM alpine
ENV FOO=$UNDEF
WORKDIR $FOO
COPY app $FOO/app
USER $FOO
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains('$')
            )),
            "no `$`-bearing path may ship: {:?}",
            contract.assertions
        );
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::UserExists { username } if username.contains('$')
            )),
            "no `$`-bearing username may ship: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.starts_with("WORKDIR '$FOO'") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_arg_referencing_undefined_var_does_not_launder() {
        let content = r#"
FROM alpine
ARG FOO=$UNDEF
WORKDIR $FOO
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path.contains('$')
        )));
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.starts_with("WORKDIR '$FOO'") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_child_env_overrides_inherited_env_entry() {
        let content = r#"
FROM alpine AS base
ENV MODE=old
ENV GONE=/old

FROM base
ENV MODE=new
ENV GONE=$MISSING
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.env, vec![("MODE".to_string(), "new".to_string())]);
    }

    #[test]
    fn test_env_extending_base_image_var_does_not_warn() {
        let content = r#"
FROM node:20
ENV PATH=$PATH:/app/node_modules/.bin
ENV PYTHONPATH="${PYTHONPATH}:/app"
ARG PIP_CACHE=$HOME/.cache/pip
WORKDIR /app
CMD ["node", "server.js"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert!(contract.warnings.is_empty(), "{:?}", contract.warnings);
        assert_eq!(contract.workdir, Some("/app".to_string()));
    }

    #[test]
    fn test_redeclared_global_arg_takes_later_default() {
        let content = r#"
ARG PICK=old
ARG PICK=base
FROM alpine:3.19 AS base
ENV APP_HOME=/app
FROM ${PICK}
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.base_image, "alpine:3.19");
        assert_eq!(contract.workdir, Some("/app".to_string()));

        let contract = extract_contract(
            &df,
            None,
            &[("PICK".to_string(), "other".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "other");
    }

    #[test]
    fn test_global_arg_with_unresolved_default_is_not_bound() {
        let content = r#"
ARG APP_DIR=${PREFIX}/app
FROM alpine:3.19
ARG APP_DIR
WORKDIR $APP_DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path.contains('$')
        )));
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.starts_with("WORKDIR '$APP_DIR'")));
    }

    #[test]
    fn test_env_reassignment_to_unresolved_invalidates_prior_value() {
        // Reassigning a var to an unresolved value must invalidate its prior binding, not stale.
        let content = "FROM alpine\nENV DIR=/old\nENV DIR=$MISSING\nWORKDIR $DIR\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path == "/old"
            )),
            "the stale /old value must not survive the reassignment: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.contains("ENV") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_env_unresolved_keeps_precedence_over_later_arg() {
        // An unresolved ENV keeps precedence over a later same-name ARG; must not be overridden.
        let content = r#"
FROM alpine
ENV DIR=$MISSING
ARG DIR=new
WORKDIR /app/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("new")
            )),
            "a later ARG must not override an ENV's precedence: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_tainted_env_var_with_dash_default_is_dropped() {
        // A tainted var's `-`/`:-` default isn't substituted (Docker treats it as set-empty).
        let content = "FROM alpine\nENV DIR=$MISSING\nWORKDIR /srv/${DIR-fallback}\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("fallback")
            )),
            "a tainted var's dash-default must not be substituted: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_duplicate_volume_across_chain_deduped() {
        // The same volume declared in an ancestor and its child must appear once.
        let content = r#"
FROM alpine AS base
VOLUME /data

FROM base
VOLUME /data
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(
            contract.volumes,
            vec!["/data".to_string()],
            "duplicate inherited volume should be deduped: {:?}",
            contract.volumes
        );
    }

    #[test]
    fn test_duplicate_exposed_port_across_chain_deduped() {
        // The same port EXPOSEd in an ancestor and its child must appear once.
        let content = r#"
FROM alpine AS base
EXPOSE 8080

FROM base
EXPOSE 8080
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(
            contract.exposed_ports.len(),
            1,
            "duplicate inherited port should be deduped: {:?}",
            contract.exposed_ports
        );
        assert_eq!(contract.exposed_ports[0].port, 8080);
    }

    #[test]
    fn test_arg_default_referencing_defined_var_resolves() {
        // An ARG default referencing an already-defined variable is expanded, not verbatim.
        let content = r#"
FROM alpine
ENV BASE=/opt
ARG DIR=$BASE/sub
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.workdir, Some("/opt/sub".to_string()));
    }

    #[test]
    fn test_child_arg_redeclaration_overrides_inherited_default() {
        // A child's ARG re-declaration with a new default overrides it (last-declared wins).
        let content = r#"
FROM alpine AS base
ARG DIR=/base

FROM base
ARG DIR=/child
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.workdir, Some("/child".to_string()));
    }

    #[test]
    fn test_build_arg_wins_over_redeclared_arg_default() {
        // A command-line build-arg outranks every ARG default, inherited or re-declared.
        let content = r#"
FROM alpine AS base
ARG DIR=/base

FROM base
ARG DIR=/child
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "/cli".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/cli".to_string()));
    }

    #[test]
    fn test_build_arg_not_in_scope_before_arg_declaration_single_stage() {
        // A build arg used before its ARG declaration is out of scope; no assertion is emitted.
        let content = r#"
FROM alpine
WORKDIR /x/$DIR
ARG DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "child".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("child")
            )),
            "a build arg must not be in scope before its ARG declaration: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.starts_with("WORKDIR '/x/$DIR'")));
    }

    #[test]
    fn test_build_arg_in_scope_after_arg_declaration() {
        // Once the ARG declaration is reached, the build arg resolves for later instructions.
        let content = r#"
FROM alpine
ARG DIR
WORKDIR /x/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "child".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/x/child".to_string()));
    }

    #[test]
    fn test_build_arg_not_in_scope_in_earlier_stage() {
        // The issue's example: a later stage's ARG must not retroactively scope the build
        // arg into an earlier stage's WORKDIR.
        let content = r#"
FROM alpine AS base
WORKDIR /base/$DIR
FROM base
ARG DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "child".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("child")
            )),
            "a later stage's ARG must not scope the build arg into an earlier WORKDIR: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_build_arg_not_in_scope_for_from_without_global_arg() {
        // A build arg with no global ARG declaration must not resolve in a FROM image.
        let content = r#"
FROM alpine:$TAG
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TAG".to_string(), "3.18".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "alpine:$TAG");
    }

    #[test]
    fn test_build_arg_in_scope_for_from_with_global_arg() {
        // A build arg declared globally is in scope for the FROM image.
        let content = r#"
ARG TAG=latest
FROM alpine:$TAG
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TAG".to_string(), "3.18".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "alpine:3.18");
    }

    #[test]
    fn test_automatic_platform_build_arg_resolves_from_without_global_arg() {
        // A supplied BuildKit automatic platform arg is in global scope, so a FROM can
        // reference it without an ARG and the base image resolves.
        let content = r#"
FROM alpine:$TARGETARCH
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TARGETARCH".to_string(), "arm64".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "alpine:arm64");
    }

    #[test]
    fn test_global_arg_default_references_platform_arg_for_from() {
        // A global ARG default may reference an automatic platform arg (global scope),
        // and the resolved default then feeds a later FROM.
        let content = r#"
ARG IMG=alpine:$TARGETARCH
FROM $IMG
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TARGETARCH".to_string(), "arm64".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.base_image, "alpine:arm64");
    }

    #[test]
    fn test_automatic_platform_build_arg_not_in_stage_body_without_arg() {
        // A platform arg is global-scope only: referenced in a stage body without an
        // ARG it must not resolve, so no wrong assertion is emitted (Docker leaves it
        // undefined there).
        let content = r#"
FROM alpine
WORKDIR /opt/$TARGETARCH
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TARGETARCH".to_string(), "arm64".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("arm64")
            )),
            "a platform arg must not resolve in a stage body without an ARG: {:?}",
            contract.assertions
        );
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.starts_with("WORKDIR '/opt/$TARGETARCH'")));
    }

    #[test]
    fn test_automatic_platform_build_arg_in_stage_body_after_arg() {
        // Redeclaring the platform arg with a stage ARG brings it into the stage body.
        let content = r#"
FROM alpine
ARG TARGETARCH
WORKDIR /opt/$TARGETARCH
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("TARGETARCH".to_string(), "arm64".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/opt/arm64".to_string()));
    }

    #[test]
    fn test_predefined_proxy_build_arg_resolves_env_without_arg() {
        // A predefined proxy build arg (no ARG declaration) must be in scope for ENV,
        // matching Docker, which predefines the proxy args.
        let content = r#"
FROM alpine
ENV HTTPS_PROXY=$HTTPS_PROXY
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("HTTPS_PROXY".to_string(), "http://proxy:8080".to_string())],
            &PolicyConfig::default(),
        );
        assert!(
            contract
                .env
                .iter()
                .any(|(k, v)| k == "HTTPS_PROXY" && v == "http://proxy:8080"),
            "predefined proxy build arg should resolve the ENV: {:?}",
            contract.env
        );
        assert!(
            !contract
                .warnings
                .iter()
                .any(|w| w.contains("HTTPS_PROXY") && w.contains("unresolved")),
            "no unresolved-variable warning expected: {:?}",
            contract.warnings
        );
    }

    #[test]
    fn test_build_arg_overrides_unresolved_default_before_evaluating_it() {
        // A build arg wins over the default even when the default would be unresolved;
        // Docker never evaluates the default in that case.
        let content = r#"
FROM alpine
ARG DIR=$UNDEF
WORKDIR /x/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "child".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/x/child".to_string()));
    }

    #[test]
    fn test_env_wins_over_same_name_build_arg_bound_arg() {
        // Docker: ENV always overrides a same-name ARG, even with a --build-arg. This
        // pins declare_arg checking `locked` BEFORE binding the supplied build arg;
        // reversing that order would let the build arg wrongly override the ENV.
        let content = r#"
FROM alpine
ENV DIR=/env
ARG DIR
WORKDIR /x/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "cli".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/x//env".to_string()));
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("cli")
            )),
            "the supplied build arg must not override the ENV: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_tainted_env_wins_over_same_name_build_arg_bound_arg() {
        // An unresolved (tainted) ENV also outranks a later same-name ARG bound from a
        // --build-arg, so the reference drops with a warning rather than taking `cli`.
        let content = r#"
FROM alpine
ENV DIR=$MISSING
ARG DIR
WORKDIR /app/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "cli".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, None);
        assert!(
            !contract.assertions.iter().any(|a| matches!(
                &a.kind,
                AssertionKind::FileExists { path, .. } if path.contains("cli")
            )),
            "a tainted ENV must keep precedence over a build-arg-bound ARG: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_arg_redeclared_unresolved_clears_prior_default() {
        // Re-declaring an ARG with an unresolved default invalidates the prior one, not stale.
        let content = r#"
FROM alpine
ARG DIR=/good
ARG DIR=$UNDEF
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path == "/good"
        )));
    }

    #[test]
    fn test_build_arg_survives_unresolved_arg_redeclaration() {
        // A build-arg value must not be cleared by a later unresolved ARG default.
        let content = r#"
FROM alpine
ARG DIR=$UNDEF
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(
            &df,
            None,
            &[("DIR".to_string(), "/cli".to_string())],
            &PolicyConfig::default(),
        );
        assert_eq!(contract.workdir, Some("/cli".to_string()));
    }

    #[test]
    fn test_child_entrypoint_resets_inherited_cmd() {
        // Docker resets a base image's inherited CMD when the child sets its own ENTRYPOINT.
        let content = "FROM alpine AS base\nENTRYPOINT [\"/base-ep\"]\nCMD [\"/base-cmd\"]\n\nFROM base\nENTRYPOINT [\"/child-ep\"]\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert!(contract.cmd.is_none(), "inherited CMD should be reset");
        assert!(contract.entrypoint.is_some());
    }

    #[test]
    fn test_empty_entrypoint_resets_inherited_cmd() {
        // An empty `ENTRYPOINT []` also resets an inherited CMD; it can't survive as process.
        let content = "FROM alpine AS base\nENTRYPOINT [\"/base-ep\"]\nCMD [\"/base-cmd\"]\n\nFROM base\nENTRYPOINT []\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert!(
            contract.cmd.is_none(),
            "inherited CMD should be reset by an empty ENTRYPOINT"
        );
        assert!(
            !contract
                .assertions
                .iter()
                .any(|a| matches!(&a.kind, AssertionKind::ProcessRunning { .. })),
            "no process should be asserted from the reset base CMD: {:?}",
            contract.assertions
        );
    }

    #[test]
    fn test_same_stage_cmd_after_entrypoint_is_kept() {
        // The CMD reset targets only an inherited CMD, not one set in the ENTRYPOINT's own stage.
        let content = "FROM alpine\nENTRYPOINT [\"/ep\"]\nCMD [\"/cmd\"]\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert!(
            contract.cmd.is_some(),
            "a same-stage CMD must not be reset by the stage's ENTRYPOINT"
        );
    }

    #[test]
    fn test_parent_user_and_expose_inherited_by_child() {
        // The child declares neither USER nor EXPOSE; both are inherited from the base stage.
        let content = r#"
FROM alpine AS base
USER 1500
EXPOSE 7000

FROM base
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.user, Some("1500".to_string()));
        assert!(contract
            .assertions
            .iter()
            .any(|a| matches!(&a.kind, AssertionKind::PortListening { port: 7000, .. })));
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
    fn test_global_arg_default_references_earlier_global() {
        // A global ARG default referencing an earlier global expands in declaration order.
        let content = r#"
ARG ACTUAL=alpine:3.20
ARG IMG=${ACTUAL}
FROM ${IMG}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.base_image, "alpine:3.20");
    }

    #[test]
    fn test_global_arg_default_chain_resolves_internal_alias() {
        // The chained global default must resolve an internal alias and inherit its ENV too.
        let content = r#"
ARG ACTUAL=base
ARG PICK=${ACTUAL}
FROM node:20 AS base
ENV APP_HOME=/app

FROM ${PICK}
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());
        assert_eq!(contract.base_image, "node:20");
        assert_eq!(contract.workdir, Some("/app".to_string()));
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
        // A custom list replaces the defaults, so TOKEN is no longer secret.
        assert_eq!(env_value(&contract, "API_TOKEN"), Some("abc123"));
    }

    #[test]
    fn test_secret_value_still_resolves_for_dependent_variables() {
        let content = "FROM alpine\nENV SECRET_BASE=/opt/app\nENV WORKROOT=$SECRET_BASE/data\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(
            env_value(&contract, "SECRET_BASE"),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_eq!(env_value(&contract, "WORKROOT"), Some("/opt/app/data"));
    }

    fn secret_args(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn assert_no_leak(contract: &RuntimeContract, secrets: &[&str]) {
        let dump = format!("{contract:?}");
        for secret in secrets {
            assert!(!dump.contains(secret), "{secret:?} leaked: {dump}");
        }
    }

    #[test]
    fn test_secret_build_arg_drops_derived_assertions_with_raw_warnings() {
        let content = "FROM alpine\nARG DB_PASSWORD\nENV DSN=/srv/$DB_PASSWORD\nWORKDIR $DSN\nCOPY app.conf conf/\nADD app.tgz /opt/$DB_PASSWORD/\nUSER $DB_PASSWORD\nVOLUME /data/$DB_PASSWORD\nEXPOSE $DB_PASSWORD 8080\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = secret_args(&[("DB_PASSWORD", "4242")]);
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert_no_leak(&contract, &["4242"]);
        assert_eq!(contract.workdir, None);
        assert_eq!(contract.user, None);
        assert!(contract.volumes.is_empty());
        assert_eq!(env_value(&contract, "DSN"), Some(REDACTED_PLACEHOLDER));
        let ports: Vec<u16> = contract.exposed_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8080]);
        assert!(!contract
            .assertions
            .iter()
            .any(|a| matches!(&a.kind, AssertionKind::FileExists { .. })));

        let expected = [
            "WORKDIR '$DSN' uses a secret build arg",
            "COPY destination 'conf/' is relative to a working directory",
            "ADD destination '/opt/$DB_PASSWORD/' uses a secret build arg",
            "VOLUME '/data/$DB_PASSWORD' uses a secret build arg",
            "EXPOSE '$DB_PASSWORD' uses a secret build arg",
            "USER '$DB_PASSWORD' uses a secret build arg",
        ];
        assert_eq!(
            contract.warnings.len(),
            expected.len(),
            "{:?}",
            contract.warnings
        );
        for prefix in expected {
            assert!(
                contract.warnings.iter().any(|w| w.starts_with(prefix)),
                "missing warning {prefix:?}: {:?}",
                contract.warnings
            );
        }
    }

    #[test]
    fn test_secret_named_build_arg_port_is_dropped() {
        let content = "FROM alpine\nARG AUTH_PORT\nEXPOSE $AUTH_PORT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = secret_args(&[("AUTH_PORT", "8080")]);
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert!(contract.exposed_ports.is_empty());
        assert_eq!(
            contract.warnings,
            vec!["EXPOSE '$AUTH_PORT' uses a secret build arg; no port assertion generated"]
        );
    }

    #[test]
    fn test_secret_taint_clears_on_literal_rebind() {
        let content =
            "FROM alpine\nARG DB_PASSWORD\nENV DB_PASSWORD=/literal\nWORKDIR $DB_PASSWORD\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = secret_args(&[("DB_PASSWORD", "s3cr3tvalue")]);
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/literal".to_string()));
        assert!(contract.warnings.is_empty(), "{:?}", contract.warnings);
        assert_eq!(
            env_value(&contract, "DB_PASSWORD"),
            Some(REDACTED_PLACEHOLDER)
        );
        assert_no_leak(&contract, &["s3cr3tvalue"]);
    }

    #[test]
    fn test_secret_taint_propagates_across_from_chain() {
        let content = "FROM alpine AS base\nARG DB_PASSWORD\nENV DSN=/srv/$DB_PASSWORD\nARG MIRROR=$DSN\n\nFROM base\nWORKDIR $MIRROR\nUSER app\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = secret_args(&[("DB_PASSWORD", "s3cr3tvalue")]);
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert_eq!(contract.workdir, None);
        assert_eq!(contract.user, Some("app".to_string()));
        assert_eq!(
            contract.warnings,
            vec!["WORKDIR '$MIRROR' uses a secret build arg; no directory assertion generated"]
        );
        assert_no_leak(&contract, &["s3cr3tvalue"]);
    }

    #[test]
    fn test_secret_global_arg_keeps_base_image_unresolved() {
        let content =
            "ARG REGISTRY_TOKEN\nARG IMAGE=registry.example/$REGISTRY_TOKEN/app\nFROM $IMAGE\n";
        let df = parse_dockerfile_content(content).unwrap();
        let args = secret_args(&[("REGISTRY_TOKEN", "s3cr3tvalue")]);
        let contract = extract_contract(&df, None, &args, &PolicyConfig::default());

        assert_eq!(contract.base_image, "$IMAGE");
        assert_no_leak(&contract, &["s3cr3tvalue"]);
    }

    #[test]
    fn test_dockerfile_defaults_with_secret_like_names_resolve_normally() {
        let content = "FROM alpine\nENV KEYCLOAK_HOME=/opt/keycloak\nWORKDIR $KEYCLOAK_HOME\nARG AUTH_PORT=8080\nEXPOSE $AUTH_PORT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[], &PolicyConfig::default());

        assert_eq!(contract.workdir, Some("/opt/keycloak".to_string()));
        let ports: Vec<u16> = contract.exposed_ports.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![8080]);
        assert!(contract.warnings.is_empty(), "{:?}", contract.warnings);
    }
}
