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

        // Strip whole-line comments before joining continuations, matching
        // BuildKit's order of operations (remove comment lines first, then join).
        // A comment line neither opens nor extends a continuation, regardless of
        // whether it ends in a backslash. Only whole-line comments are stripped:
        // a `#` appearing mid-line inside shell text is not a Dockerfile comment.
        // Parser directives (`# syntax=`, `# escape=`) are comment-shaped and are
        // harmlessly ignored here as well.
        if trimmed.trim_start().starts_with('#') {
            continue;
        }

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
    //   ENV KEY=VALUE KEY2=VALUE2   (modern)
    //   ENV KEY VALUE               (legacy single pair)
    //
    // Docker selects the modern form iff the FIRST whitespace-delimited token
    // contains '='. Testing for '=' *anywhere* in the args is wrong: a legacy
    // value may itself contain '=' (e.g. `ENV JAVA_OPTS -Dfoo=bar`, which
    // Docker parses as key `JAVA_OPTS`, value `-Dfoo=bar`).
    let first_token = args.split_whitespace().next().unwrap_or("");
    if first_token.contains('=') {
        // Modern form with = sign(s)
        let mut remaining = args;
        loop {
            remaining = remaining.trim_start();
            if remaining.is_empty() {
                break;
            }

            let Some(eq_pos) = remaining.find('=') else {
                break;
            };
            let key = remaining[..eq_pos].trim().to_string();
            let after_eq = &remaining[eq_pos + 1..];
            let (value, rest) = parse_env_value(after_eq);
            pairs.push((key, value));
            remaining = rest;
        }
    } else {
        // Legacy form: ENV KEY VALUE — the value is the entire remainder,
        // verbatim, even if it contains '='.
        let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            pairs.push((parts[0].to_string(), parts[1].trim().to_string()));
        } else if parts.len() == 1 && !parts[0].is_empty() {
            pairs.push((parts[0].to_string(), String::new()));
        }
    }

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Env(pairs),
        raw: format!("ENV {args}"),
    }
}

/// Parse a single modern-form ENV value beginning immediately after the `=`.
///
/// Handles three cases and returns the decoded value plus the unconsumed
/// remainder (which holds any further `KEY=VALUE` pairs):
///   - double-quoted, honoring backslash escapes (`"say \"hi\""` → `say "hi"`)
///   - single-quoted, taken literally (`'a b'` → `a b`)
///   - unquoted, where `\` escapes the next char and an unescaped whitespace
///     ends the value (`Rex\ The\ Dog` → `Rex The Dog`)
fn parse_env_value(after_eq: &str) -> (String, &str) {
    if let Some(stripped) = after_eq.strip_prefix('"') {
        let mut val = String::new();
        let mut chars = stripped.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    // Inside double quotes, a backslash escapes only `"`, `\`
                    // and `$` (matching Docker/BuildKit); before any other
                    // character it is a literal backslash, so a value such as
                    // `"\d+\w"` is preserved rather than mangled to `d+w`.
                    match chars.clone().next() {
                        Some((_, next)) if matches!(next, '"' | '\\' | '$') => {
                            val.push(next);
                            chars.next();
                        }
                        _ => val.push('\\'),
                    }
                }
                '"' => return (val, &stripped[i + 1..]),
                _ => val.push(c),
            }
        }
        // Unterminated quote: take the rest as the value.
        (val, "")
    } else if let Some(stripped) = after_eq.strip_prefix('\'') {
        match stripped.find('\'') {
            Some(end) => (stripped[..end].to_string(), &stripped[end + 1..]),
            None => (stripped.to_string(), ""),
        }
    } else {
        // Unquoted: a backslash escapes the following character (so the
        // documented `ENV MY_DOG=Rex\ The\ Dog` idiom keeps its spaces); the
        // value ends at the first *unescaped* whitespace.
        let mut val = String::new();
        let mut chars = after_eq.char_indices();
        while let Some((i, c)) = chars.next() {
            if c == '\\' {
                if let Some((_, next)) = chars.next() {
                    val.push(next);
                }
                // A trailing backslash with nothing after it is dropped.
            } else if c.is_whitespace() {
                return (val, &after_eq[i..]);
            } else {
                val.push(c);
            }
        }
        (val, "")
    }
}

fn parse_expose(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    // Keep the raw tokens intact. Port parsing, variable resolution, and range
    // expansion all happen later at extraction time, once ARG/ENV values are known.
    let tokens: Vec<String> = args.split_whitespace().map(|t| t.to_string()).collect();

    RawInstruction {
        line_number: line_num,
        instruction: Instruction::Expose(tokens),
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

/// Parse source files and destination from COPY/ADD arguments after flags have been consumed.
fn parse_sources_and_dest(parts: &[&str], start_idx: usize) -> (Vec<String>, String) {
    let file_parts = &parts[start_idx..];
    let dest = if file_parts.len() > 1 {
        file_parts.last().unwrap_or(&".").to_string()
    } else if file_parts.len() == 1 {
        file_parts[0].to_string()
    } else {
        ".".to_string()
    };

    let mut sources = Vec::new();
    if file_parts.len() > 1 {
        for s in &file_parts[..file_parts.len() - 1] {
            sources.push(s.to_string());
        }
    }

    (sources, dest)
}

fn parse_copy(args: &str, line_num: usize, raw: &str) -> RawInstruction {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut from_stage = None;
    let mut chmod = None;
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

    let (sources, dest) = parse_sources_and_dest(&parts, idx);

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

    let (sources, dest) = parse_sources_and_dest(&parts, idx);

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

    // Parse optional flags before CMD. Consume ANY leading `--name[=value]`
    // token: the four flags below are recorded, and any other flag (e.g.
    // `--start-interval=`, added in Docker Engine 25) is dropped rather than
    // left to leak into the command string.
    loop {
        remaining = remaining.trim_start().to_string();
        if remaining.is_empty() || !remaining.starts_with("--") {
            break;
        }

        let end = remaining
            .find(char::is_whitespace)
            .unwrap_or(remaining.len());
        let token = &remaining[..end];
        let (name, value) = match token.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (token, None),
        };

        match name {
            "--interval" => interval = value.map(|v| v.to_string()),
            "--timeout" => timeout = value.map(|v| v.to_string()),
            "--start-period" => start_period = value.map(|v| v.to_string()),
            "--retries" => retries = value.and_then(|v| v.parse().ok()),
            // Unknown flag (e.g. --start-interval): ignore so it does not
            // corrupt the parsed command.
            _ => {}
        }
        remaining = remaining[end..].to_string();
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
    fn test_comment_inside_continuation_is_stripped() {
        // A comment line inside a backslash-continued RUN must be removed, not
        // terminate the continuation. Otherwise the trailing physical line
        // (`apt-get install ...`) is dropped and package evidence is lost.
        let content = r#"
FROM ubuntu:22.04
RUN apt-get update && \
    # install deps
    apt-get install -y nginx
EXPOSE 80
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let runs: Vec<String> = df.stages[0]
            .instructions
            .iter()
            .filter_map(|i| match &i.instruction {
                Instruction::Run(cmd) => Some(cmd.to_string_lossy()),
                _ => None,
            })
            .collect();
        assert_eq!(runs.len(), 1, "the RUN must remain a single instruction");
        // Both halves of the continuation must survive the comment.
        assert!(
            runs[0].contains("apt-get update"),
            "first half lost: {}",
            runs[0]
        );
        assert!(
            runs[0].contains("apt-get install -y nginx"),
            "second half (after the comment) was dropped: {}",
            runs[0]
        );
        // The comment text itself must not leak into the merged command.
        assert!(
            !runs[0].contains("install deps"),
            "comment text leaked into the command: {}",
            runs[0]
        );
        // EXPOSE that follows must still parse.
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_comment_ending_in_backslash_does_not_open_continuation() {
        // `# ... \` is a whole-line comment; Docker never continues a comment
        // line, so the following instruction must not be swallowed.
        let content = r#"
FROM nginx
# pin base image \
EXPOSE 8080
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let expose = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Expose(ports) => Some(ports.clone()),
                _ => None,
            });
        assert!(
            expose.is_some(),
            "EXPOSE after a backslash-terminated comment was swallowed"
        );
        assert_eq!(expose.unwrap()[0], "8080");
    }

    #[test]
    fn test_continuation_body_after_comment_is_not_a_phantom_instruction() {
        // The more insidious variant of the comment-in-continuation bug: when the
        // dropped body line happens to start with a Dockerfile keyword, the old
        // parser fabricated a phantom instruction (e.g. `env FOO=bar` -> ENV).
        // The body line must stay part of the single RUN, and no ENV may appear.
        let content = r#"
FROM alpine
RUN echo start && \
    # note
    env FOO=bar
"#;
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::Env(_))),
            "continuation body line was fabricated into a phantom ENV instruction"
        );
        let runs: Vec<String> = df.stages[0]
            .instructions
            .iter()
            .filter_map(|i| match &i.instruction {
                Instruction::Run(cmd) => Some(cmd.to_string_lossy()),
                _ => None,
            })
            .collect();
        assert_eq!(runs.len(), 1, "the RUN must remain a single instruction");
        assert!(
            runs[0].contains("echo start"),
            "first half lost: {}",
            runs[0]
        );
        assert!(
            runs[0].contains("env FOO=bar"),
            "continuation body after the comment was dropped: {}",
            runs[0]
        );
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

    /// Collect all `ENV` pairs from the first stage of a parsed Dockerfile.
    fn env_pairs(content: &str) -> Vec<Vec<(String, String)>> {
        let df = parse_dockerfile_content(content).unwrap();
        df.stages[0]
            .instructions
            .iter()
            .filter_map(|i| match &i.instruction {
                Instruction::Env(pairs) => Some(pairs.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_parse_env_legacy_value_with_equals() {
        // Legacy form: value itself contains '='; must not be split mid-value.
        let envs = env_pairs("FROM alpine\nENV JAVA_OPTS -Dfoo=bar\n");
        assert_eq!(
            envs,
            vec![vec![("JAVA_OPTS".to_string(), "-Dfoo=bar".to_string())]]
        );
    }

    #[test]
    fn test_parse_env_legacy_value_with_multiple_tokens_and_equals() {
        let envs = env_pairs(
            "FROM alpine\nENV JAVA_TOOL_OPTIONS -Xmx512m -Dspring.profiles.active=prod\n",
        );
        assert_eq!(
            envs,
            vec![vec![(
                "JAVA_TOOL_OPTIONS".to_string(),
                "-Xmx512m -Dspring.profiles.active=prod".to_string()
            )]]
        );
    }

    #[test]
    fn test_parse_env_double_quoted_value_with_escaped_quotes() {
        let envs = env_pairs("FROM alpine\nENV MSG=\"say \\\"hi\\\"\"\n");
        assert_eq!(
            envs,
            vec![vec![("MSG".to_string(), "say \"hi\"".to_string())]]
        );
    }

    #[test]
    fn test_parse_env_double_quoted_value_keeps_literal_backslashes() {
        // A backslash before an ordinary char is literal (not an escape), so
        // regex/path-like values survive intact.
        let envs = env_pairs("FROM alpine\nENV RE=\"\\d+\\w\"\n");
        assert_eq!(envs, vec![vec![("RE".to_string(), "\\d+\\w".to_string())]]);
    }

    #[test]
    fn test_parse_env_double_quoted_value_escapes_backslash_and_dollar() {
        // `\\` collapses to one backslash; `\$` drops the escape.
        let envs = env_pairs("FROM alpine\nENV P=\"a\\\\b\\$c\"\n");
        assert_eq!(envs, vec![vec![("P".to_string(), "a\\b$c".to_string())]]);
    }

    #[test]
    fn test_parse_env_single_quoted_value_with_spaces() {
        let envs = env_pairs("FROM alpine\nENV KEY='a b'\n");
        assert_eq!(envs, vec![vec![("KEY".to_string(), "a b".to_string())]]);
    }

    #[test]
    fn test_parse_env_unquoted_backslash_escaped_space() {
        // Documented Dockerfile idiom: a backslash escapes a space in an
        // unquoted value, so the whole thing is a single pair.
        let envs = env_pairs("FROM alpine\nENV MY_DOG=Rex\\ The\\ Dog\n");
        assert_eq!(
            envs,
            vec![vec![("MY_DOG".to_string(), "Rex The Dog".to_string())]]
        );
    }

    #[test]
    fn test_parse_env_unquoted_escape_does_not_bleed_into_next_pair() {
        // An escaped space must not corrupt a following KEY=VALUE pair.
        let envs = env_pairs("FROM alpine\nENV A=x\\ y B=z\n");
        assert_eq!(
            envs,
            vec![vec![
                ("A".to_string(), "x y".to_string()),
                ("B".to_string(), "z".to_string())
            ]]
        );
    }

    #[test]
    fn test_parse_env_empty_value() {
        let envs = env_pairs("FROM alpine\nENV KEY=\n");
        assert_eq!(envs, vec![vec![("KEY".to_string(), String::new())]]);
    }

    #[test]
    fn test_parse_env_multiple_pairs_after_quoted_value() {
        let envs = env_pairs("FROM alpine\nENV A=\"x y\" B=z\n");
        assert_eq!(
            envs,
            vec![vec![
                ("A".to_string(), "x y".to_string()),
                ("B".to_string(), "z".to_string())
            ]]
        );
    }

    #[test]
    fn test_parse_env_legacy_single_token() {
        // `ENV KEY` (no value) is a legacy single pair with an empty value.
        let envs = env_pairs("FROM alpine\nENV STANDALONE\n");
        assert_eq!(envs, vec![vec![("STANDALONE".to_string(), String::new())]]);
    }

    #[test]
    fn test_parse_healthcheck_unknown_flag_does_not_leak_into_command() {
        // --start-interval (Docker Engine 25+) is unknown to us; it and the
        // literal `CMD` keyword must not leak into the parsed command, and the
        // later known --interval flag must still be captured.
        let content = r#"
FROM nginx
HEALTHCHECK --start-interval=5s --interval=30s CMD curl -f http://localhost/
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let hc = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Healthcheck { cmd, interval, .. } => {
                    Some((cmd.clone(), interval.clone()))
                }
                _ => None,
            })
            .expect("healthcheck instruction");

        let (cmd, interval) = hc;
        assert_eq!(interval, Some("30s".to_string()));
        let cmd_str = cmd.to_string_lossy();
        assert_eq!(cmd_str, "curl -f http://localhost/");
        assert!(
            !cmd_str.contains("--"),
            "command must not contain flag tokens: {cmd_str}"
        );
        assert!(
            !cmd_str.contains("CMD"),
            "command must not contain the CMD keyword: {cmd_str}"
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
        assert_eq!(df.global_args[0].default.as_deref(), Some("ubuntu:22.04"));
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
                Instruction::Expose(tokens) => Some(tokens.clone()),
                _ => None,
            });
        assert!(expose.is_some());
        // Tokens are preserved verbatim; port/protocol parsing happens at extraction time.
        let tokens = expose.unwrap();
        assert_eq!(tokens, vec!["8080/tcp", "9090/udp", "3000"]);
    }

    #[test]
    fn test_parse_expose_preserves_variable_and_range_tokens() {
        let content = r#"
FROM alpine
EXPOSE ${PORT} 8000-8010/udp $APP_PORT
"#;
        let df = parse_dockerfile_content(content).unwrap();
        let tokens = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Expose(tokens) => Some(tokens.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(tokens, vec!["${PORT}", "8000-8010/udp", "$APP_PORT"]);
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
