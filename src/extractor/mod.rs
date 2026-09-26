mod heuristics;
mod model;

pub use heuristics::*;
pub use model::*;

use crate::parser::{CommandForm, Dockerfile, Instruction, PortSpec, Stage, VariableResolver};
use crate::Confidence;

/// Maximum number of individual ports expanded from a single `EXPOSE low-high`
/// range. Wider ranges are dropped with a warning rather than exploded into
/// thousands of assertions.
const MAX_EXPOSE_RANGE: u32 = 128;

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

    // A final stage whose `FROM` names an earlier stage in the same file inherits
    // that ancestor's accumulated filesystem and metadata (ENV, WORKDIR, USER,
    // ENTRYPOINT, ...). Walk the internal `FROM <alias>` chain so those ancestors
    // are processed before the target stage; without this, a `WORKDIR $APP_HOME`
    // in the final stage never sees the `ENV APP_HOME` set in its base stage and
    // gets emitted as the literal path `/$APP_HOME`. Image references are resolved
    // against the pre-FROM scope (build args + globals) before alias matching, so
    // `FROM ${BASE}` still finds the `base` stage.
    let chain = resolve_stage_chain(dockerfile, stage, &resolver);

    // Report the chain's root image (the first non-alias FROM), not the internal
    // alias. A stage-body ARG/ENV appears after FROM and cannot influence how the
    // image reference resolved, so the pre-FROM resolver is the right scope.
    let root_image = chain
        .first()
        .map(|s| s.image.as_str())
        .unwrap_or(stage.image.as_str());
    let mut contract = RuntimeContract {
        base_image: resolver.resolve(root_image),
        ..Default::default()
    };

    // `None` marks the working directory as unknown: an earlier WORKDIR referenced
    // a variable we could not resolve, so we cannot compute where a later relative
    // COPY/ADD would land. An absolute, resolvable WORKDIR re-establishes it.
    let mut current_workdir: Option<String> = Some(String::from("/"));

    // A stage started with `FROM <alias>` inherits its ancestor's image config,
    // and Docker inherits both ENV *and* ARG into a stage based on the one that
    // declared them. A single resolver shared across the whole chain therefore
    // models the inheritance directly — a child stage's instructions resolve
    // against the ARG/ENV its base stage established.

    // Docker applies last-wins semantics to ENTRYPOINT, CMD, HEALTHCHECK, and USER:
    // only the final effective occurrence takes effect. Rather than emit an
    // assertion at each encounter (which accumulates stale/duplicate assertions from
    // overridden instructions — and, across a chain, would make de-duplication keep
    // the *parent's* value), we fold these into their effective final state during
    // the walk and emit their assertions once, afterward. Each fold records the
    // chain stage index so cross-stage inheritance rules can be applied.
    let mut fold_entrypoint: Option<(CommandForm, usize, usize)> = None;
    let mut fold_cmd: Option<(CommandForm, usize, usize)> = None;
    let mut fold_healthcheck: Option<(HealthcheckInfo, usize)> = None;
    let mut fold_user: Option<FoldedUser> = None;

    // Walk instructions in source order across the whole inherited chain (root
    // ancestor first, target stage last), updating the variable map as ARG/ENV are
    // seen so every instruction resolves against the variables defined above it. A
    // later ENV redefinition therefore cannot retroactively change how an earlier
    // instruction resolved, and a child stage's instructions resolve against the
    // ARG/ENV its base stage established.
    for (stage_idx, chain_stage) in chain.iter().enumerate() {
        for inst in &chain_stage.instructions {
            match &inst.instruction {
                Instruction::Workdir(dir) => {
                    let (resolved, unresolved) = resolver.resolve_checked(dir);
                    // Determine the new absolute working directory, or `None` if it
                    // cannot be known: an unresolved variable, or a relative WORKDIR
                    // stacked on an already-unknown directory. A directory we cannot
                    // determine must not be asserted (it could never match), and it
                    // also invalidates later relative COPY/ADD destinations.
                    let new_workdir = if unresolved {
                        contract.warnings.push(format!(
                            "WORKDIR '{dir}' contains an unresolved variable (no ARG/ENV \
                             default in scope); no directory assertion generated"
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
                    // Fold USER to its effective final value across the chain; emitting
                    // an assertion at each encounter would leave same-command
                    // duplicates whose de-duplication keeps the overridden (e.g.
                    // parent-stage) value, asserting the wrong uid.
                    let (resolved, unresolved) = resolver.resolve_checked(user);
                    fold_user = Some(FoldedUser {
                        raw: user.clone(),
                        resolved,
                        line: inst.line_number,
                        unresolved,
                    });
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
                            // The image config represents an exposed port as one
                            // effective entry, but walking the chain can encounter the
                            // same port in an ancestor and a child. Deduplicate by
                            // (protocol, port) so a single port is not counted twice
                            // (which would, e.g., make the interactive flow's
                            // `exposed_ports.len() > 1` branch prompt spuriously).
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
                        let resolved = resolver.resolve(vol);
                        // One effective volume entry per path: walking the chain can
                        // meet the same VOLUME in an ancestor and a child, and the
                        // interactive flow iterates contract.volumes directly, so a
                        // duplicate would prompt twice for the same mount.
                        if !contract.volumes.contains(&resolved) {
                            contract.volumes.push(resolved);
                        }
                    }
                }

                Instruction::Arg { name, default } => {
                    // Resolve the default before binding so a default that references
                    // another variable is expanded. If it references an *unresolved*
                    // variable, do not bind a `$`-bearing value — that would launder
                    // the unresolved reference past the resolve_checked guard when a
                    // later instruction reads this ARG. Warn and leave it undefined so
                    // the downstream use is itself flagged and dropped.
                    match default.as_deref() {
                        Some(def) => {
                            let (resolved_def, unresolved) = resolver.resolve_checked(def);
                            if unresolved {
                                // A build-arg/ENV value legitimately wins and is kept
                                // silently. Otherwise the default cannot be resolved:
                                // clear any inherited ARG default this re-declaration
                                // replaces and leave the name undefined, so a
                                // downstream use is itself flagged and dropped.
                                if !resolver.is_locked(name) {
                                    resolver.unset(name);
                                    contract.warnings.push(format!(
                                        "ARG '{name}={def}' references an unresolved variable (no \
                                         ARG/ENV default in scope); '{name}' is left undefined"
                                    ));
                                }
                            } else {
                                resolver.declare_arg(name, Some(&resolved_def));
                            }
                        }
                        None => resolver.declare_arg(name, None),
                    }
                }

                Instruction::Env(pairs) => {
                    for (key, value) in pairs {
                        // Same guard as ARG: never bind a `$`-bearing value, which
                        // would launder an unresolved reference (`ENV FOO=$UNDEF` then
                        // `WORKDIR $FOO`) past the resolve_checked guard and ship a
                        // `$`-path. Warn and leave the variable undefined instead.
                        let (resolved_val, unresolved) = resolver.resolve_checked(value);
                        if unresolved {
                            contract.warnings.push(format!(
                                "ENV '{key}={value}' references an unresolved variable (no \
                                 ARG/ENV default in scope); '{key}' is left undefined"
                            ));
                            // Drop the value but keep the name locked: a
                            // reassignment (`ENV DIR=/old` then `ENV DIR=$MISSING`)
                            // replaced the old value, so a later `$DIR` must be
                            // unresolved and dropped, not resolve to the stale value;
                            // and ENV keeps precedence over any later ARG of the same
                            // name, so the lock must remain.
                            resolver.taint(key);
                            continue;
                        }
                        resolver.set_var(key, &resolved_val);
                        contract.env.push((key.clone(), resolved_val));
                    }
                }

                Instruction::Entrypoint(cmd) => {
                    // Docker resets a CMD inherited from the base image whenever a
                    // derived stage sets ENTRYPOINT — in any form, including the empty
                    // reset form `ENTRYPOINT []`. Clear a CMD that came from an earlier
                    // stage in the chain; a CMD set within this same stage is unaffected.
                    if let Some((_, _, cmd_stage)) = &fold_cmd {
                        if *cmd_stage < stage_idx {
                            fold_cmd = None;
                        }
                    }
                    // An empty exec form clears the entrypoint; any other form
                    // overrides the previous one (last wins).
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

    // Emit phase: generate the folded assertions once, from the effective final
    // state.

    // USER: emit the effective final value. A value that is unresolved (still
    // holds a variable) or empty (e.g. a variable that resolved to "") can never
    // match the built image, so drop it (in every profile) and warn instead.
    if let Some(user) = &fold_user {
        contract.user = Some(user.resolved.clone());
        if user.unresolved {
            contract.warnings.push(format!(
                "USER '{}' contains an unresolved variable (no ARG/ENV default in \
                 scope); no user assertion generated",
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

    // Docker's interaction rule: when an ENTRYPOINT is set, CMD supplies its
    // arguments rather than a process of its own, so a process assertion comes from
    // the entrypoint; only in the absence of an entrypoint does CMD name the process.
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
}

/// Build the assertion for a resolved USER value: a numeric uid is checked via
/// `id -u`, a named user via a user-exists assertion (dropping any `:group`).
fn make_user_assertion(user: &FoldedUser) -> ContractAssertion {
    // An empty value is filtered out before this point; require at least one digit
    // so an empty string is never mistaken for a numeric uid.
    if !user.resolved.is_empty() && user.resolved.chars().all(|c| c.is_ascii_digit()) {
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

/// Resolve the chain of build stages the target stage inherits from, ordered
/// root ancestor first and the target stage last.
///
/// A stage's `FROM` may name an earlier stage's alias (`FROM base`), in which
/// case Docker starts it from that ancestor's final filesystem and metadata.
/// Following the chain lets the extractor process the ancestors' `ARG`/`ENV`/
/// `WORKDIR`/`USER`/... before the target stage so variable references resolve.
///
/// Each stage's `FROM` image is variable-resolved (against `resolver`, which holds
/// the pre-FROM scope of build args + globals) before it is matched, so
/// `FROM ${BASE}` resolves to `base` and still finds the internal stage. Alias
/// matching is case-insensitive, mirroring [`Dockerfile::resolve_target`].
///
/// A stage can only reference stages declared before it, so a candidate parent
/// must have a strictly earlier `from_line`; among matches the nearest preceding
/// one wins (Docker's last-declared-alias-wins). The strictly-decreasing
/// `from_line` also guarantees termination even if a malformed Dockerfile reused
/// an alias. A `FROM` naming an external image (or an unknown alias) ends the
/// walk, so a single-stage build yields just `[stage]`.
fn resolve_stage_chain<'a>(
    dockerfile: &'a Dockerfile,
    target: &'a Stage,
    resolver: &VariableResolver,
) -> Vec<&'a Stage> {
    let mut chain = vec![target];
    let mut current = target;

    loop {
        let resolved_image = resolver.resolve(&current.image);
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
    /// The destination is relative but the current working directory is unknown
    /// (an earlier WORKDIR could not be resolved), so the absolute path is unknown.
    UnknownWorkdir,
}

/// Resolve a COPY/ADD destination against variables and the current WORKDIR. An
/// absolute destination stands on its own; a relative one is joined onto
/// `current_workdir`, which is `None` when an earlier WORKDIR could not be
/// resolved. Either failure means the real path is unknown and the caller must
/// not emit an assertion for it.
fn resolve_dest_path(
    dest: &str,
    resolver: &crate::parser::VariableResolver,
    current_workdir: Option<&str>,
) -> DestPath {
    let (resolved_dest, unresolved) = resolver.resolve_checked(dest);
    if unresolved {
        return DestPath::UnresolvedVar;
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
    fn test_internal_from_alias_inherits_parent_env() {
        // The final stage is `FROM base`, an internal alias; it must inherit the
        // ENV declared in the base stage so `WORKDIR $APP_HOME` resolves to /app
        // and base_image reports the underlying image, not the alias.
        let content = r#"
FROM node:20 AS base
ENV APP_HOME=/app

FROM base
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // ENV set in the root stage `a` must reach the final stage through the
        // intermediate stage `b` (a -> b -> final).
        let content = r#"
FROM debian:12 AS a
ENV ROOT_DIR=/srv/app

FROM a AS b
ENV SUBDIR=data

FROM b
WORKDIR $ROOT_DIR/$SUBDIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

        assert_eq!(contract.base_image, "alpine:3.19");
        assert_eq!(contract.workdir, Some("/opt/tool".to_string()));
    }

    #[test]
    fn test_unresolved_workdir_path_is_dropped_and_warns() {
        // Safety net, independent of chain walking: a WORKDIR referencing a
        // variable that no ARG/ENV in scope defines cannot match the built image,
        // so no assertion is emitted (in any profile) and a warning is surfaced.
        let content = r#"
FROM alpine
WORKDIR $UNDECLARED
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // Invariant: across a Dockerfile that mixes resolvable and unresolvable
        // paths, no FileExists assertion carries a `$` in its path at all — the
        // unresolvable ones are dropped, the resolvable one survives.
        let content = r#"
FROM alpine
WORKDIR /real
WORKDIR $MISSING
COPY app /real/app
COPY other $MISSING/other
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // `\$` produces a legitimate literal `$` in the value; resolving a WORKDIR
        // that references it must NOT be mistaken for an unresolved variable, so
        // the assertion is kept at High confidence with no warning.
        let content = "FROM alpine\nENV LITERAL=\\$HOME\nWORKDIR $LITERAL\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // `FROM ${BASE}` where BASE resolves to an internal stage alias must still
        // follow the chain, inherit its ENV, and report the underlying image.
        let content = r#"
ARG BASE=base
FROM node:20 AS base
ENV APP_HOME=/app

FROM ${BASE}
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

        assert_eq!(contract.base_image, "node:20");
        assert_eq!(contract.workdir, Some("/app".to_string()));
    }

    #[test]
    fn test_effective_user_across_chain_is_emitted_once() {
        // A parent USER overridden by a child USER must yield exactly one id -u
        // assertion carrying the child's (effective) uid, not the parent's.
        let content = r#"
FROM alpine AS base
USER 1000

FROM base
USER 2000
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        // Docker inherits an ARG declared in a base stage into a stage based on it
        // (a `FROM <that-stage>`), just like ENV. So `WORKDIR $BUILD_DIR` in the
        // child resolves to the base stage's ARG value.
        let content = r#"
FROM alpine AS base
ARG BUILD_DIR=/build

FROM base
WORKDIR $BUILD_DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(contract.workdir, Some("/build".to_string()));
    }

    #[test]
    fn test_default_with_defined_nested_variable_resolves() {
        // A `${VAR:-default}` default that itself references a defined variable is
        // expanded, not emitted verbatim.
        let content = r#"
FROM alpine
ENV SUB=inner
WORKDIR ${MISSING:-/opt/$SUB}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(contract.workdir, Some("/opt/inner".to_string()));
    }

    #[test]
    fn test_default_with_undefined_nested_variable_is_dropped() {
        // A `${VAR:-default}` default that references an UNDEFINED variable must be
        // flagged unresolved and dropped — never shipped as a literal `$`-path.
        let content = r#"
FROM alpine
WORKDIR ${MISSING:-/x$BAR}
COPY app ${DEST:-/opt/$SUB}/a
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // A malformed, unterminated `${...}` must be treated as unresolved, not
        // shipped as a literal `$`-path.
        let content = "FROM alpine\nWORKDIR /a/${UNTERM\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path.contains('$')
        )));
    }

    #[test]
    fn test_relative_copy_after_unresolved_workdir_is_suppressed() {
        // Once a WORKDIR fails to resolve, the working directory is unknown, so a
        // later *relative* COPY must not be asserted against the stale directory.
        // An absolute COPY is still fine.
        let content = r#"
FROM alpine
WORKDIR /real
WORKDIR $MISSING
COPY app app
COPY other /abs/other
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // A USER whose variable resolves to an empty string must not be emitted as
        // an `id -u` == "" assertion.
        let content = r#"
FROM alpine
ARG U=
USER $U
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // `ENV FOO=$UNDEF` must not bind a `$`-bearing value that a later `$FOO`
        // would then substitute back in, laundering the unresolved reference past
        // the drop guard into a shipped `/$UNDEF` path/user.
        let content = r#"
FROM alpine
ENV FOO=$UNDEF
WORKDIR $FOO
COPY app $FOO/app
USER $FOO
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
            .any(|w| w.contains("ENV") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_arg_referencing_undefined_var_does_not_launder() {
        let content = r#"
FROM alpine
ARG FOO=$UNDEF
WORKDIR $FOO
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

        assert_eq!(contract.workdir, None);
        assert!(!contract.assertions.iter().any(|a| matches!(
            &a.kind,
            AssertionKind::FileExists { path, .. } if path.contains('$')
        )));
        assert!(contract
            .warnings
            .iter()
            .any(|w| w.contains("ARG") && w.contains("unresolved variable")));
    }

    #[test]
    fn test_env_reassignment_to_unresolved_invalidates_prior_value() {
        // Reassigning a variable to an unresolved value must invalidate its prior
        // binding, not leave the stale value for a later reference to pick up.
        let content = "FROM alpine\nENV DIR=/old\nENV DIR=$MISSING\nWORKDIR $DIR\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // An unresolved ENV assignment still holds ENV precedence: a later ARG of
        // the same name must NOT override it, so the value stays unknown (dropped),
        // never the ARG's value.
        let content = r#"
FROM alpine
ENV DIR=$MISSING
ARG DIR=new
WORKDIR /app/$DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        // `ENV DIR=$MISSING` leaves DIR set-but-unknown; a later `${DIR-fallback}`
        // must not substitute the fallback (Docker keeps DIR set-empty, so `-`
        // yields empty). We drop the assertion rather than ship `/srv/fallback`.
        let content = "FROM alpine\nENV DIR=$MISSING\nWORKDIR /srv/${DIR-fallback}\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        // An ARG default that references an already-defined variable is expanded,
        // not stored verbatim.
        let content = r#"
FROM alpine
ENV BASE=/opt
ARG DIR=$BASE/sub
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(contract.workdir, Some("/opt/sub".to_string()));
    }

    #[test]
    fn test_child_arg_redeclaration_overrides_inherited_default() {
        // A child stage that re-declares an inherited ARG with a new default takes
        // that new default (Docker's last-declared default wins, absent a build-arg).
        let content = r#"
FROM alpine AS base
ARG DIR=/base

FROM base
ARG DIR=/child
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(contract.workdir, Some("/child".to_string()));
    }

    #[test]
    fn test_build_arg_wins_over_redeclared_arg_default() {
        // A command-line build-arg outranks every ARG default, inherited or
        // re-declared, in every stage.
        let content = r#"
FROM alpine AS base
ARG DIR=/base

FROM base
ARG DIR=/child
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[("DIR".to_string(), "/cli".to_string())]);
        assert_eq!(contract.workdir, Some("/cli".to_string()));
    }

    #[test]
    fn test_arg_redeclared_unresolved_clears_prior_default() {
        // Re-declaring an ARG with an unresolved default invalidates the inherited
        // default (Docker would set it empty) rather than keeping the stale value.
        let content = r#"
FROM alpine
ARG DIR=/good
ARG DIR=$UNDEF
WORKDIR $DIR
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
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
        let contract = extract_contract(&df, None, &[("DIR".to_string(), "/cli".to_string())]);
        assert_eq!(contract.workdir, Some("/cli".to_string()));
    }

    #[test]
    fn test_child_entrypoint_resets_inherited_cmd() {
        // Docker resets a CMD inherited from the base image when the child stage
        // sets its own ENTRYPOINT.
        let content = "FROM alpine AS base\nENTRYPOINT [\"/base-ep\"]\nCMD [\"/base-cmd\"]\n\nFROM base\nENTRYPOINT [\"/child-ep\"]\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert!(contract.cmd.is_none(), "inherited CMD should be reset");
        assert!(contract.entrypoint.is_some());
    }

    #[test]
    fn test_empty_entrypoint_resets_inherited_cmd() {
        // Docker resets an inherited CMD when a derived stage sets ENTRYPOINT in any
        // form, including the empty reset form `ENTRYPOINT []`. The inherited CMD
        // must therefore not survive to become the process assertion.
        let content = "FROM alpine AS base\nENTRYPOINT [\"/base-ep\"]\nCMD [\"/base-cmd\"]\n\nFROM base\nENTRYPOINT []\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
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
        // The reset targets a CMD inherited from an earlier stage, not a CMD set in
        // the same stage as the ENTRYPOINT.
        let content = "FROM alpine\nENTRYPOINT [\"/ep\"]\nCMD [\"/cmd\"]\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert!(
            contract.cmd.is_some(),
            "a same-stage CMD must not be reset by the stage's ENTRYPOINT"
        );
    }

    #[test]
    fn test_parent_user_and_expose_inherited_by_child() {
        // The child declares neither USER nor EXPOSE; both come from the base
        // stage and must appear in the child's contract.
        let content = r#"
FROM alpine AS base
USER 1500
EXPOSE 7000

FROM base
WORKDIR /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);

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
    fn test_global_arg_default_references_earlier_global() {
        // A global ARG default that references an earlier global ARG is expanded in
        // declaration order, so the FROM image reference resolves correctly.
        let content = r#"
ARG ACTUAL=alpine:3.20
ARG IMG=${ACTUAL}
FROM ${IMG}
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(contract.base_image, "alpine:3.20");
    }

    #[test]
    fn test_global_arg_default_chain_resolves_internal_alias() {
        // The chained global default also resolves an internal-stage alias so the
        // FROM chain is followed and the base stage's ENV is inherited.
        let content = r#"
ARG ACTUAL=base
ARG PICK=${ACTUAL}
FROM node:20 AS base
ENV APP_HOME=/app

FROM ${PICK}
WORKDIR $APP_HOME
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(env_value(&contract, "LITERAL"), Some("$ROOT"));
    }

    #[test]
    fn test_env_escaped_dollar_unquoted_stays_literal() {
        let content = "FROM alpine\nENV ROOT=/data\nENV LITERAL=\\$ROOT\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
        assert_eq!(env_value(&contract, "LITERAL"), Some("$ROOT"));
    }

    #[test]
    fn test_env_normal_expansion_still_works() {
        let content = "FROM alpine\nENV FOO=bar\nENV A=$FOO\nENV B=${FOO}\nENV C=\"$FOO\"\n";
        let df = parse_dockerfile_content(content).unwrap();
        let contract = extract_contract(&df, None, &[]);
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
        let contract = extract_contract(&df, None, &[]);
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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

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
        let contract = extract_contract(&df, None, &[]);

        assert_eq!(contract.base_image, "alpine:1.0");
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
