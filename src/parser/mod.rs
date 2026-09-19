mod ast;
mod resolver;

pub use ast::*;
pub use resolver::*;

use anyhow::{Context, Result};
use std::path::Path;

/// A BuildKit heredoc redirection opened on an instruction line.
struct Heredoc {
    /// The terminator word (unquoted).
    delim: String,
    /// Whether this is the `<<-` form, which strips leading tabs from the
    /// terminator line (and, in Docker, from the body — irrelevant to our
    /// textual scan).
    strip_tabs: bool,
}

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
    // Indexed over physical lines so that once a logical line is finalized we can
    // look ahead and consume any BuildKit heredoc body it opens.
    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();
    let mut current_line = String::new();
    let mut start_line_num = 0;
    let mut in_continuation = false;
    let mut idx = 0;

    while idx < lines.len() {
        let line = lines[idx];
        let line_num = idx + 1; // 1-based
        idx += 1;
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
                // If this instruction opens one or more heredocs, consume the
                // body lines that follow so they are not re-parsed as top-level
                // instructions, and (for a shell-script RUN heredoc) fold the
                // body into the command.
                if let Some((heredocs, opener, fold_body)) = heredoc_openers(&merged) {
                    let (assembled, next_idx) =
                        consume_heredoc(&opener, heredocs, fold_body, &lines, idx);
                    result.push((start_line_num, assembled));
                    idx = next_idx;
                } else {
                    result.push((start_line_num, merged));
                }
            }
            current_line.clear();
        }
    }

    // Handle case where file ends with continuation. A dangling continuation has
    // no following lines, so it cannot open a heredoc body.
    if in_continuation && !current_line.trim().is_empty() {
        result.push((start_line_num, current_line.trim().to_string()));
    }

    result
}

/// If the merged instruction line opens one or more BuildKit heredocs, return the
/// ordered heredocs, the opener with the `<<DELIM` markers removed, and whether
/// the body is a shell script that should be folded into the RUN command. Only
/// `RUN`, `COPY`, and `ADD` support heredocs, so other instructions never match.
/// Returns `None` when the line opens no heredoc.
fn heredoc_openers(line: &str) -> Option<(Vec<Heredoc>, String, bool)> {
    let keyword = line.split_whitespace().next()?.to_uppercase();
    if !matches!(keyword.as_str(), "RUN" | "COPY" | "ADD") {
        return None;
    }

    let (heredocs, stripped) = scan_heredocs(line);
    if heredocs.is_empty() {
        return None;
    }

    // Collapse the whitespace left where the `<<DELIM` markers were removed so
    // the remaining opener parses as an ordinary instruction (e.g. `COPY <<EOF
    // /dest` becomes `COPY /dest`).
    let opener = stripped.split_whitespace().collect::<Vec<_>>().join(" ");

    // The body is an executable shell script only for the bare `RUN <<DELIM`
    // form (optionally preceded by `--flags`). When a command word precedes the
    // heredoc (`RUN cat <<EOF > /f`, `RUN python3 <<EOF`) the body is data fed to
    // that command — file content or program source — not shell, so it must not
    // be scanned for installs.
    let fold_body = keyword == "RUN" && run_heredoc_is_script(line);

    Some((heredocs, opener, fold_body))
}

/// Scan an instruction line for BuildKit heredoc redirections, tracking shell
/// quote state so that `<<WORD` appearing inside a quoted string (e.g.
/// `RUN echo "use <<EOF"`) is not mistaken for a heredoc. Returns the heredocs in
/// declaration order and the line with the `<<DELIM` markers removed. A `<<` is
/// only treated as a redirection when it sits at a token boundary (start of line
/// or after whitespace) and the delimiter word immediately follows, so shell
/// arithmetic like `$(( 1 << 2 ))` is not matched.
fn scan_heredocs(line: &str) -> (Vec<Heredoc>, String) {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut heredocs = Vec::new();
    let mut stripped = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_boundary = true; // start of line is a boundary
    let mut i = 0;

    while i < n {
        let c = chars[i];

        if in_single {
            stripped.push(c);
            if c == '\'' {
                in_single = false;
            }
            prev_boundary = false;
            i += 1;
            continue;
        }
        if in_double {
            // Inside double quotes a backslash escapes the next character (this
            // also covers JSON exec-form strings), so it can't end the quote.
            if c == '\\' && i + 1 < n {
                stripped.push(c);
                stripped.push(chars[i + 1]);
                prev_boundary = false;
                i += 2;
                continue;
            }
            stripped.push(c);
            if c == '"' {
                in_double = false;
            }
            prev_boundary = false;
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            stripped.push(c);
            prev_boundary = false;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            stripped.push(c);
            prev_boundary = false;
            i += 1;
            continue;
        }

        if c == '<' && prev_boundary && i + 1 < n && chars[i + 1] == '<' {
            if let Some((heredoc, next)) = parse_heredoc_marker(&chars, i) {
                heredocs.push(heredoc);
                // Drop the marker from the stripped opener.
                prev_boundary = false;
                i = next;
                continue;
            }
        }

        stripped.push(c);
        prev_boundary = c.is_whitespace();
        i += 1;
    }

    (heredocs, stripped)
}

/// Parse a heredoc marker starting at `start` (which points at the first `<`).
/// Returns the parsed heredoc and the index just past the marker, or `None` if
/// the text at `start` is not a well-formed `<<[-][quote]WORD[quote]`.
fn parse_heredoc_marker(chars: &[char], start: usize) -> Option<(Heredoc, usize)> {
    let n = chars.len();
    let mut j = start + 2; // skip `<<`

    let strip_tabs = j < n && chars[j] == '-';
    if strip_tabs {
        j += 1;
    }

    let quote = if j < n && (chars[j] == '"' || chars[j] == '\'') {
        let q = chars[j];
        j += 1;
        Some(q)
    } else {
        None
    };

    // Delimiter word: `[A-Za-z_][A-Za-z0-9_]*`.
    let word_start = j;
    if !(j < n && (chars[j].is_ascii_alphabetic() || chars[j] == '_')) {
        return None;
    }
    j += 1;
    while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
        j += 1;
    }
    let delim: String = chars[word_start..j].iter().collect();

    if let Some(q) = quote {
        if j < n && chars[j] == q {
            j += 1;
        } else {
            return None; // unbalanced quote around the delimiter
        }
    }

    Some((Heredoc { delim, strip_tabs }, j))
}

/// Whether a `RUN` heredoc opener is the bare shell-script form — the first
/// non-flag token after `RUN` is a `<<` marker — as opposed to feeding a command
/// (`RUN cat <<EOF`, `RUN python3 <<EOF`).
fn run_heredoc_is_script(line: &str) -> bool {
    line.split_whitespace()
        .skip(1) // the RUN keyword
        .find(|tok| !tok.starts_with("--"))
        .is_some_and(|tok| tok.starts_with("<<"))
}

/// Consume the physical body lines of a heredoc block starting at `start_idx`,
/// stopping after the last delimiter is matched (or at end of file). Returns the
/// assembled logical instruction line and the index of the first line after the
/// consumed body.
fn consume_heredoc(
    opener: &str,
    heredocs: Vec<Heredoc>,
    fold_body: bool,
    lines: &[&str],
    start_idx: usize,
) -> (String, usize) {
    let mut idx = start_idx;
    let mut body: Vec<&str> = Vec::new();
    let mut delim_pos = 0;

    // Delimiters terminate in declaration order. A plain `<<EOF` terminator must
    // match the line exactly; only the `<<-EOF` form permits leading tabs to be
    // stripped, so an indented `EOF` inside a plain heredoc body does not close
    // it early.
    while idx < lines.len() && delim_pos < heredocs.len() {
        let raw = lines[idx];
        idx += 1;
        let hd = &heredocs[delim_pos];
        let candidate = if hd.strip_tabs {
            raw.trim_start_matches('\t')
        } else {
            raw
        };
        if candidate == hd.delim {
            delim_pos += 1;
            continue;
        }
        body.push(raw);
    }

    if fold_body {
        // Fold the heredoc body into the shell command so the RUN heuristics
        // (package/service detection) can see installs inside the heredoc. The
        // body is itself a shell script, so join its own backslash continuations
        // first, then join the resulting commands with ` && ` — a shell
        // separator the install regexes recognize — so each stays bounded.
        let body_joined = merge_body_continuations(&body)
            .into_iter()
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" && ");
        if body_joined.is_empty() {
            (opener.to_string(), idx)
        } else {
            (format!("{} {}", opener, body_joined), idx)
        }
    } else {
        // COPY/ADD bodies (file content) and command-fed RUN bodies (file
        // content or program source) are not shell. Drop the body (it must not
        // leak into the instruction stream) and keep only the opener so a COPY
        // destination still yields a FileExists assertion.
        (opener.to_string(), idx)
    }
}

/// Join a heredoc body's own backslash line-continuations into logical commands,
/// mirroring shell continuation semantics. Without this, folding with ` && `
/// would turn `apk add \` / `nginx` into `apk add \ && nginx`, capturing a bogus
/// package named `\` and dropping the real ones.
fn merge_body_continuations(body: &[&str]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_continuation = false;

    for line in body {
        let trimmed = line.trim_end();
        if let Some(without_backslash) = trimmed.strip_suffix('\\') {
            if in_continuation {
                current.push(' ');
                current.push_str(without_backslash.trim());
            } else {
                current.push_str(without_backslash.trim());
            }
            in_continuation = true;
        } else {
            if in_continuation {
                current.push(' ');
                current.push_str(trimmed.trim());
            } else {
                current.push_str(trimmed.trim());
            }
            in_continuation = false;
            result.push(std::mem::take(&mut current));
        }
    }

    if !current.trim().is_empty() {
        result.push(current.trim().to_string());
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
                    // An escaped `$` becomes a marker so later variable
                    // resolution keeps it literal instead of expanding it.
                    match chars.clone().next() {
                        Some((_, '$')) => {
                            val.push(ESCAPED_DOLLAR);
                            chars.next();
                        }
                        Some((_, next)) if matches!(next, '"' | '\\') => {
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
                    // An escaped `$` becomes a marker so later variable
                    // resolution keeps it literal instead of expanding it.
                    val.push(if next == '$' { ESCAPED_DOLLAR } else { next });
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
    fn test_parse_env_double_quoted_value_marks_escaped_dollar() {
        // `\\` collapses to one backslash; `\$` becomes the internal marker so
        // resolution later keeps it a literal `$` rather than expanding it.
        let envs = env_pairs("FROM alpine\nENV P=\"a\\\\b\\$c\"\n");
        assert_eq!(
            envs,
            vec![vec![("P".to_string(), format!("a\\b{ESCAPED_DOLLAR}c"))]]
        );
    }

    #[test]
    fn test_parse_env_unquoted_marks_escaped_dollar() {
        let envs = env_pairs("FROM alpine\nENV LITERAL=\\$ROOT\n");
        assert_eq!(
            envs,
            vec![vec![(
                "LITERAL".to_string(),
                format!("{ESCAPED_DOLLAR}ROOT")
            )]]
        );
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

    /// Collect the shell text of every RUN instruction in the first stage.
    fn run_commands(content: &str) -> Vec<String> {
        let df = parse_dockerfile_content(content).unwrap();
        df.stages[0]
            .instructions
            .iter()
            .filter_map(|i| match &i.instruction {
                Instruction::Run(cmd) => Some(cmd.to_string_lossy()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_run_heredoc_body_folded_into_command() {
        // A `RUN <<EOF` heredoc: the body carries the real install and must be
        // folded into the single RUN command; no body line may be re-parsed as a
        // top-level instruction.
        let content = "\
FROM alpine
RUN <<EOF
apk add --no-cache nginx
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(
            runs.len(),
            1,
            "heredoc RUN must remain a single instruction"
        );
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "heredoc body was not folded into the RUN command: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains("<<"),
            "the heredoc marker must be stripped from the command: {}",
            runs[0]
        );
        // The EXPOSE that follows the terminator must still parse cleanly.
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_run_heredoc_multiple_body_lines_stay_bounded() {
        // Multiple installs on separate body lines are joined with a shell
        // separator so each command stays bounded for the install heuristics.
        let content = "\
FROM alpine
RUN <<EOF
apk add --no-cache nginx
apk add --no-cache curl
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].contains("apk add --no-cache nginx"));
        assert!(runs[0].contains("apk add --no-cache curl"));
        assert!(
            runs[0].contains("&&"),
            "body lines should be joined with a shell separator: {}",
            runs[0]
        );
    }

    #[test]
    fn test_copy_heredoc_body_is_not_reparsed() {
        // A `COPY <<CONF /dest` heredoc: the body is file content. A body line
        // that starts with a Dockerfile keyword (`user nginx;`) must not be
        // fabricated into a USER instruction.
        let content = "\
FROM alpine
COPY <<CONF /etc/nginx/nginx.conf
user nginx;
worker_processes auto;
CONF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "COPY heredoc body line was fabricated into a USER instruction"
        );

        // The COPY itself is preserved with the correct destination and no
        // heredoc marker recorded as a source.
        let copy = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Copy { sources, dest, .. } => Some((sources.clone(), dest.clone())),
                _ => None,
            })
            .expect("COPY instruction");
        assert_eq!(copy.1, "/etc/nginx/nginx.conf");
        assert!(
            !copy.0.iter().any(|s| s.contains("<<")),
            "heredoc marker leaked into COPY sources: {:?}",
            copy.0
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_heredoc_quoted_delimiters() {
        // Quoted delimiters (`<<"EOF"`, `<<'EOF'`) are recognized. Their bodies
        // are terminated by an exact (unindented) `EOF`.
        for opener in ["<<\"EOF\"", "<<'EOF'"] {
            let content =
                format!("FROM alpine\nRUN {opener}\napk add --no-cache nginx\nEOF\nEXPOSE 80\n");
            let df = parse_dockerfile_content(&content).unwrap();
            let runs = run_commands(&content);
            assert_eq!(runs.len(), 1, "opener {opener}: one RUN expected");
            assert!(
                runs[0].contains("apk add --no-cache nginx"),
                "opener {opener}: body not folded: {}",
                runs[0]
            );
            assert!(
                df.stages[0]
                    .instructions
                    .iter()
                    .any(|i| matches!(i.instruction, Instruction::Expose(_))),
                "opener {opener}: EXPOSE after terminator was swallowed"
            );
        }
    }

    #[test]
    fn test_heredoc_dash_form_strips_tabs_from_terminator() {
        // The `<<-EOF` form permits the terminator to be indented with tabs.
        let content = "FROM alpine\nRUN <<-EOF\napk add --no-cache nginx\n\tEOF\nEXPOSE 80\n";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "body: {}",
            runs[0]
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_plain_heredoc_terminator_must_match_exactly() {
        // A plain `<<EOF` is only closed by an exact `EOF`; an indented `EOF`
        // inside the body must not terminate it early (which would leak the rest
        // of the body as instructions).
        let content = "\
FROM alpine
RUN <<EOF
echo one
  EOF
echo two && apk add --no-cache nginx
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("echo two"),
            "indented `EOF` wrongly terminated the plain heredoc: {}",
            runs[0]
        );
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "body after the indented `EOF` was lost: {}",
            runs[0]
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_multiple_data_heredocs_on_one_run_are_consumed() {
        // `cmd <<A <<B` feeds both bodies to a command as data, so neither is
        // folded into the shell text; both terminators must still be consumed so
        // the instruction stream resumes cleanly.
        let content = "\
FROM alpine
RUN cat <<A <<B
apk add --no-cache nginx
A
some config text
B
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apk add"),
            "data-heredoc body must not be folded into the command: {}",
            runs[0]
        );
        assert!(
            df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::Expose(_))),
            "EXPOSE after both terminators was swallowed"
        );
    }

    #[test]
    fn test_run_heredoc_body_backslash_continuation_is_joined() {
        // A backslash line-continuation inside the heredoc body is a shell
        // continuation. It must be joined into one logical command before the
        // ` && ` fold, or the fold captures a bogus package named `\`.
        let content = "\
FROM alpine
RUN <<EOF
apk add --no-cache \\
    nginx \\
    curl
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx curl"),
            "backslash continuation in the heredoc body was not joined: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains('\\'),
            "a stray backslash leaked into the folded command: {}",
            runs[0]
        );
    }

    #[test]
    fn test_heredoc_marker_inside_quotes_is_not_a_heredoc() {
        // `<<WORD` inside a quoted shell string is literal text, not a heredoc.
        // It must not consume following lines or strip the marker from the
        // command.
        let content = "\
FROM alpine
RUN echo \"see docs: use <<HELP for input\" > /README
RUN apk add --no-cache nginx
EXPOSE 8080
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(
            runs.len(),
            2,
            "quoted `<<HELP` wrongly swallowed later lines"
        );
        assert!(
            runs[0].contains("<<HELP"),
            "quoted heredoc marker was stripped from the command: {}",
            runs[0]
        );
        assert!(runs[1].contains("apk add --no-cache nginx"));
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_run_interpreter_heredoc_body_is_not_scanned() {
        // `RUN python3 <<EOF` feeds the body to python as program source, not to
        // the shell. It must be consumed without folding, so no install evidence
        // is fabricated from program text.
        let content = "\
FROM alpine
RUN python3 <<EOF
subprocess.run('apt-get install -y totally-not-installed')
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apt-get"),
            "interpreter heredoc body was folded into the shell command: {}",
            runs[0]
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_run_redirected_heredoc_body_is_not_scanned() {
        // `RUN cat <<EOF > /file` writes the body to a file; the body is data,
        // not shell, so it must not be scanned for installs/services.
        let content = "\
FROM alpine
RUN cat <<EOF > /etc/motd
welcome to nginx
apt-get install -y ghost-package
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apt-get") && !runs[0].contains("welcome"),
            "redirected heredoc body was folded into the command: {}",
            runs[0]
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_shell_left_shift_is_not_a_heredoc() {
        // `$(( 1 << 2 ))` and `a<<b` are not heredocs: `<<` must sit at a token
        // boundary with the delimiter immediately following. Nothing after the
        // RUN may be consumed as a body.
        let content = "\
FROM alpine
RUN echo $(( 1 << 2 ))
EXPOSE 80
CMD [\"true\"]
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("1 << 2"),
            "left-shift text was altered: {}",
            runs[0]
        );
        // The instructions after the RUN must survive.
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Cmd(_))));
    }

    #[test]
    fn test_heredoc_without_terminator_consumes_to_eof() {
        // A heredoc whose terminator never appears consumes the rest of the file
        // rather than leaking body lines as instructions.
        let content = "\
FROM alpine
RUN <<EOF
apk add --no-cache nginx
USER root
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "unterminated heredoc body leaked a USER instruction"
        );
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(runs[0].contains("apk add --no-cache nginx"));
    }
}
