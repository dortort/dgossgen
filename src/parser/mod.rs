mod ast;
mod resolver;

pub use ast::*;
pub use resolver::*;

use anyhow::{Context, Result};
use std::path::Path;

/// Parse a Dockerfile from a file path into a list of stages.
pub fn parse_dockerfile(path: &Path) -> Result<Dockerfile> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_dockerfile_content(&content)
}

/// Parse Dockerfile content string into a structured Dockerfile.
pub fn parse_dockerfile_content(content: &str) -> Result<Dockerfile> {
    let raw_instructions = parse_raw_instructions(content)?;
    let (global_args, stages) = build_stages(raw_instructions)?;
    Ok(Dockerfile {
        global_args,
        stages,
    })
}

/// Merge continuation lines (trailing backslash) into single logical lines,
/// tracking the original source line number for each instruction.
fn merge_continuation_lines(content: &str) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut current_line = String::new();
    let mut start_line_num = 0;
    let mut in_continuation = false;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1; // 1-based
        let trimmed = line.trim_end();

        if !in_continuation {
            start_line_num = line_num;
            current_line.clear();
        }

        if let Some(without_backslash) = trimmed.strip_suffix('\\') {
            // Remove the backslash and accumulate
            if in_continuation {
                current_line.push(' ');
                current_line.push_str(without_backslash.trim());
            } else {
                current_line.push_str(without_backslash);
            }
            in_continuation = true;
        } else {
            if in_continuation {
                current_line.push(' ');
                current_line.push_str(trimmed.trim());
            } else {
                current_line.push_str(trimmed);
            }
            in_continuation = false;
            let merged = current_line.trim().to_string();
            if !merged.is_empty() {
                result.push((start_line_num, merged));
            }
            current_line.clear();
        }
    }

    // Handle case where file ends with continuation
    if in_continuation && !current_line.trim().is_empty() {
        result.push((start_line_num, current_line.trim().to_string()));
    }

    result
}

/// Parse raw instructions from merged lines.
fn parse_raw_instructions(content: &str) -> Result<Vec<RawInstruction>> {
    let merged = merge_continuation_lines(content);
    let mut instructions = Vec::new();

    for (line_num, line) in merged {
        // Skip comments and empty lines
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Split into instruction keyword and arguments
        let (keyword, args) = match line.find(|c: char| c.is_whitespace()) {
            Some(pos) => (line[..pos].to_uppercase(), line[pos..].trim().to_string()),
            None => (line.to_uppercase(), String::new()),
        };

        let instruction = match keyword.as_str() {
            "FROM" => parse_from(&args, line_num)?,
            "ARG" => parse_arg(&args, line_num),
            "ENV" => parse_env(&args, line_num),
            "WORKDIR" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::Workdir(args.clone()),
                raw: line.clone(),
            },
            "USER" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::User(args.clone()),
                raw: line.clone(),
            },
            "EXPOSE" => parse_expose(&args, line_num, &line),
            "VOLUME" => parse_volume(&args, line_num, &line),
            "COPY" => parse_copy(&args, line_num, &line),
            "ADD" => parse_add(&args, line_num, &line),
            "RUN" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::Run(parse_command_form(&args)),
                raw: line.clone(),
            },
            "ENTRYPOINT" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::Entrypoint(parse_command_form(&args)),
                raw: line.clone(),
            },
            "CMD" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::Cmd(parse_command_form(&args)),
                raw: line.clone(),
            },
            "HEALTHCHECK" => parse_healthcheck(&args, line_num, &line),
            "SHELL" => RawInstruction {
                line_number: line_num,
                instruction: Instruction::Shell(parse_json_array(&args)),
                raw: line.clone(),
            },
            "LABEL" | "STOPSIGNAL" | "ONBUILD" | "MAINTAINER" => {
                // Recognized but not used for contract extraction
                continue;
            }
            _ => {
                // Unknown instruction, skip
                continue;
            }
        };

        instructions.push(instruction);
    }

    Ok(instructions)
}

fn parse_from(args: &str, line_num: usize) -> Result<RawInstruction> {
    // FROM [--platform=...] image[:tag] [AS name]
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut idx = 0;

    // Skip --platform flag
    while idx < parts.len() && parts[idx].starts_with("--") {
        idx += 1;
    }

    let image = parts.get(idx).unwrap_or(&"scratch").to_string();
    idx += 1;

    let alias = if idx < parts.len() && parts[idx].eq_ignore_ascii_case("AS") {
        parts.get(idx + 1).map(|s| s.to_string())
    } else {
        None
    };

    Ok(RawInstruction {
        line_number: line_num,
        instruction: Instruction::From {
            image: image.clone(),
            alias,
        },
        raw: format!("FROM {args}"),
    })
}

fn parse_arg(args: &str, line_num: usize) -> RawInstruction {
    let (name, default) = if let Some(eq_pos) = args.find('=') {
        let name = args[..eq_pos].trim().to_string();
        let val = args[eq_pos + 1..].trim().trim_matches('"').to_string();
        (name, Some(val))
    } else {
        (args.trim().to_string(), None)
    };

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Arg { name, default },
        raw: format!("ARG {args}"),
    }
}

fn parse_env(args: &str, line_num: usize) -> RawInstruction {
    let mut pairs = Vec::new();

    // ENV supports two forms:
    // ENV KEY=VALUE KEY2=VALUE2
    // ENV KEY VALUE (legacy single pair)
    if args.contains('=') {
        // Modern form with = sign(s)
        let mut remaining = args.to_string();
        while !remaining.is_empty() {
            remaining = remaining.trim_start().to_string();
            if remaining.is_empty() {
                break;
            }

            if let Some(eq_pos) = remaining.find('=') {
                let key = remaining[..eq_pos].trim().to_string();
                let after_eq = &remaining[eq_pos + 1..];

                let (value, rest) = if let Some(stripped) = after_eq.strip_prefix('"') {
                    // Quoted value
                    if let Some(end_quote) = stripped.find('"') {
                        let val = stripped[..end_quote].to_string();
                        let rest = stripped[end_quote + 1..].to_string();
                        (val, rest)
                    } else {
                        (stripped.to_string(), String::new())
                    }
                } else {
                    // Unquoted value - goes until next whitespace
                    match after_eq.find(|c: char| c.is_whitespace()) {
                        Some(pos) => {
                            let val = after_eq[..pos].to_string();
                            let rest = after_eq[pos..].to_string();
                            (val, rest)
                        }
                        None => (after_eq.to_string(), String::new()),
                    }
                };

                pairs.push((key, value));
                remaining = rest;
            } else {
                break;
            }
        }
    } else {
        // Legacy form: ENV KEY VALUE
        let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            pairs.push((parts[0].to_string(), parts[1].trim().to_string()));
        } else if parts.len() == 1 {
            pairs.push((parts[0].to_string(), String::new()));
        }
    }

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Env(pairs),
        raw: format!("ENV {args}"),
    }
}

fn parse_expose(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    let ports: Vec<PortSpec> = args
        .split_whitespace()
        .filter_map(|p| {
            let (port_str, protocol) = if let Some(slash) = p.find('/') {
                (&p[..slash], p[slash + 1..].to_lowercase())
            } else {
                (p, "tcp".to_string())
            };

            port_str
                .parse::<u16>()
                .ok()
                .map(|port| PortSpec { port, protocol })
        })
        .collect();

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Expose(ports),
        raw: raw.to_string(),
    }
}

fn parse_volume(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    let volumes = if args.starts_with('[') {
        // JSON array form
        parse_json_array(args)
    } else {
        args.split_whitespace().map(|s| s.to_string()).collect()
    };

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Volume(volumes),
        raw: raw.to_string(),
    }
}

fn parse_copy(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut from_stage = None;
    let mut chmod = None;
    let mut sources = Vec::new();
    let mut idx = 0;

    // Parse flags
    while idx < parts.len() {
        if let Some(val) = parts[idx].strip_prefix("--from=") {
            from_stage = Some(val.to_string());
            idx += 1;
        } else if let Some(val) = parts[idx].strip_prefix("--chmod=") {
            chmod = Some(val.to_string());
            idx += 1;
        } else if parts[idx].starts_with("--") {
            // Skip other flags (--chown, --link, etc.)
            idx += 1;
        } else {
            break;
        }
    }

    // Remaining parts: sources... dest
    let file_parts = &parts[idx..];
    let dest = if file_parts.len() > 1 {
        file_parts.last().unwrap_or(&".").to_string()
    } else if file_parts.len() == 1 {
        file_parts[0].to_string()
    } else {
        ".".to_string()
    };

    if file_parts.len() > 1 {
        for s in &file_parts[..file_parts.len() - 1] {
            sources.push(s.to_string());
        }
    }

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Copy {
            from_stage,
            sources,
            dest,
            chmod,
        },
        raw: raw.to_string(),
    }
}

fn parse_add(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut chmod = None;
    let mut sources = Vec::new();
    let mut idx = 0;

    while idx < parts.len() {
        if let Some(val) = parts[idx].strip_prefix("--chmod=") {
            chmod = Some(val.to_string());
            idx += 1;
        } else if parts[idx].starts_with("--") {
            idx += 1;
        } else {
            break;
        }
    }

    let file_parts = &parts[idx..];
    let dest = if file_parts.len() > 1 {
        file_parts.last().unwrap_or(&".").to_string()
    } else if file_parts.len() == 1 {
        file_parts[0].to_string()
    } else {
        ".".to_string()
    };

    if file_parts.len() > 1 {
        for s in &file_parts[..file_parts.len() - 1] {
            sources.push(s.to_string());
        }
    }

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Add {
            sources,
            dest,
            chmod,
        },
        raw: raw.to_string(),
    }
}

fn parse_healthcheck(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    if args.trim().eq_ignore_ascii_case("NONE") {
        return RawInstruction {
            line_number: line_num,
            instruction: Instruction::HealthcheckNone,
            raw: raw.to_string(),
        };
    }

    let mut interval = None;
    let mut timeout = None;
    let mut start_period = None;
    let mut retries = None;
    let mut remaining = args.to_string();

    // Parse optional flags before CMD
    loop {
        remaining = remaining.trim_start().to_string();
        if remaining.is_empty() {
            break;
        }

        let end = remaining.find(' ').unwrap_or(remaining.len());
        if remaining.starts_with("--interval=") {
            interval = Some(remaining[11..end].to_string());
            remaining = remaining[end..].to_string();
        } else if remaining.starts_with("--timeout=") {
            timeout = Some(remaining[10..end].to_string());
            remaining = remaining[end..].to_string();
        } else if remaining.starts_with("--start-period=") {
            start_period = Some(remaining[15..end].to_string());
            remaining = remaining[end..].to_string();
        } else if remaining.starts_with("--retries=") {
            retries = remaining[10..end].parse().ok();
            remaining = remaining[end..].to_string();
        } else {
            break;
        }
    }

    // After flags, expect CMD
    let cmd = if remaining.starts_with("CMD") || remaining.starts_with("cmd") {
        let cmd_args = remaining[3..].trim();
        parse_command_form(cmd_args)
    } else {
        parse_command_form(&remaining)
    };

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Healthcheck {
            cmd,
            interval,
            timeout,
            start_period,
            retries,
        },
        raw: raw.to_string(),
    }
}

/// Parse exec form ["a", "b", "c"] or shell form "a b c"
fn parse_command_form(args: &str) -> CommandForm {
    let trimmed = args.trim();
    if trimmed.starts_with('[') {
        let parts = parse_json_array(trimmed);
        if parts.is_empty() {
            CommandForm::Shell(trimmed.to_string())
        } else {
            CommandForm::Exec(parts)
        }
    } else {
        CommandForm::Shell(trimmed.to_string())
    }
}

/// Parse a JSON-style array of strings: ["a", "b"]
fn parse_json_array(s: &str) -> Vec<String> {
    let trimmed = s.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return vec![s.to_string()];
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_string {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if ch == ',' && !in_string {
            items.push(current.trim().to_string());
            current.clear();
            continue;
        }
        if in_string {
            current.push(ch);
        }
    }

    let last = current.trim().to_string();
    if !last.is_empty() {
        items.push(last);
    }

    items
}

/// Build stages from raw instructions.
fn build_stages(instructions: Vec<RawInstruction>) -> Result<(Vec<ArgInstruction>, Vec<Stage>)> {
    let mut global_args = Vec::new();
    let mut stages: Vec<Stage> = Vec::new();
    let mut current_instructions: Vec<RawInstruction> = Vec::new();
    let mut current_from: Option<RawInstruction> = None;

    for inst in instructions {
        if matches!(inst.instruction, Instruction::From { .. }) {
            // Start a new stage
            if let Some(from_inst) = current_from.take() {
                stages.push(build_single_stage(
                    from_inst,
                    std::mem::take(&mut current_instructions),
                ));
            }
            current_from = Some(inst);
        } else if current_from.is_some() {
            current_instructions.push(inst);
        } else if let Instruction::Arg { name, default } = &inst.instruction {
            global_args.push(ArgInstruction {
                name: name.clone(),
                default: default.clone(),
            });
        }
    }

    // Last stage
    if let Some(from_inst) = current_from {
        stages.push(build_single_stage(from_inst, current_instructions));
    }

    Ok((global_args, stages))
}

fn build_single_stage(from_inst: RawInstruction, instructions: Vec<RawInstruction>) -> Stage {
    let (image, alias) = match &from_inst.instruction {
        Instruction::From { image, alias } => (image.clone(), alias.clone()),
        _ => unreachable!(),
    };

    Stage {
        image,
        alias,
        from_line: from_inst.line_number,
        instructions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_dockerfile() {
        let content = r#"
FROM ubuntu:22.04

ENV APP_PORT=8080
WORKDIR /app
COPY . /app
EXPOSE 8080
CMD ["./server"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        assert_eq!(df.stages.len(), 1);
        assert_eq!(df.stages[0].image, "ubuntu:22.04");
    }

    #[test]
    fn test_parse_multistage() {
        let content = r#"
FROM golang:1.21 AS builder
WORKDIR /src
COPY . .
RUN go build -o /app

FROM alpine:3.18
COPY --from=builder /app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
"#;
        let df = parse_dockerfile_content(content).unwrap();
        assert_eq!(df.stages.len(), 2);
        assert_eq!(df.stages[0].alias, Some("builder".to_string()));
        assert_eq!(df.stages[1].image, "alpine:3.18");
    }

    #[test]
    fn test_parse_continuation_lines() {
        let content = r#"
FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*
EXPOSE 80
"#;
        let df = parse_dockerfile_content(content).unwrap();
        assert_eq!(df.stages.len(), 1);
        // The RUN instruction should be merged
        let run_count = df.stages[0]
            .instructions
            .iter()
            .filter(|i| matches!(i.instruction, Instruction::Run(_)))
            .count();
        assert_eq!(run_count, 1);
    }

    #[test]
    fn test_parse_env_forms() {
        let content = r#"
FROM alpine
ENV KEY1=value1 KEY2="value two"
ENV OLD_STYLE value
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let envs: Vec<_> = df.stages[0]
            .instructions
            .iter()
            .filter_map(|i| match &i.instruction {
                Instruction::Env(pairs) => Some(pairs.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(envs.len(), 2);
        assert_eq!(
            envs[0],
            vec![
                ("KEY1".to_string(), "value1".to_string()),
                ("KEY2".to_string(), "value two".to_string())
            ]
        );
        assert_eq!(
            envs[1],
            vec![("OLD_STYLE".to_string(), "value".to_string())]
        );
    }

    #[test]
    fn test_parse_healthcheck() {
        let content = r#"
FROM nginx
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let hc = df.stages[0]
            .instructions
            .iter()
            .find(|i| matches!(i.instruction, Instruction::Healthcheck { .. }));
        assert!(hc.is_some());
    }

    #[test]
    fn test_parse_healthcheck_trailing_flag_without_cmd() {
        let content = r#"
FROM nginx
HEALTHCHECK --retries=3
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let hc = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Healthcheck { retries, .. } => Some(*retries),
                _ => None,
            });
        assert_eq!(hc, Some(Some(3)));
    }

    #[test]
    fn test_parse_global_args_before_first_from() {
        let content = r#"
ARG BASE_IMAGE=ubuntu:22.04
ARG APP_VERSION
FROM $BASE_IMAGE
"#;
        let df = parse_dockerfile_content(content).unwrap();
        assert_eq!(df.global_args.len(), 2);
        assert_eq!(df.global_args[0].name, "BASE_IMAGE");
        assert_eq!(
            df.global_args[0].default.as_deref(),
            Some("ubuntu:22.04")
        );
        assert_eq!(df.global_args[1].name, "APP_VERSION");
        assert_eq!(df.global_args[1].default, None);
    }

    #[test]
    fn test_parse_expose_with_protocol() {
        let content = r#"
FROM alpine
EXPOSE 8080/tcp 9090/udp 3000
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let expose = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Expose(ports) => Some(ports.clone()),
                _ => None,
            });
        assert!(expose.is_some());
        let ports = expose.unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[1].port, 9090);
        assert_eq!(ports[1].protocol, "udp");
    }

    #[test]
    fn test_parse_copy_from() {
        let content = r#"
FROM golang AS builder
RUN echo hello

FROM alpine
COPY --from=builder /app /app
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let copy_inst = df.stages[1]
            .instructions
            .iter()
            .find(|i| matches!(i.instruction, Instruction::Copy { .. }))
            .unwrap();
        match &copy_inst.instruction {
            Instruction::Copy {
                from_stage, dest, ..
            } => {
                assert_eq!(from_stage.as_deref(), Some("builder"));
                assert_eq!(dest, "/app");
            }
            _ => panic!("expected Copy"),
        }
    }
}
