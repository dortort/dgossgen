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
    /// The file descriptor the heredoc targets (`3<<EOF` → `Some(3)`), or `None`
    /// when unprefixed. Only an unprefixed or fd-0 heredoc supplies the command's
    /// stdin, and thus a shell's script.
    fd: Option<u32>,
}

impl Heredoc {
    /// Whether this heredoc feeds the command's standard input (and so a shell's
    /// script): unprefixed or explicitly fd 0.
    fn is_stdin(&self) -> bool {
        self.fd.is_none_or(|fd| fd == 0)
    }
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

    // Only `RUN` runs a shell, so an unquoted `#` is a comment only there; for
    // `COPY`/`ADD` a `#`-prefixed token is a literal source path.
    let (heredocs, stripped) = scan_heredocs(line, keyword == "RUN");
    if heredocs.is_empty() {
        return None;
    }

    // Trim the opener left after the `<<DELIM` markers were removed so it parses
    // as an ordinary instruction (e.g. `COPY <<EOF /dest` becomes `COPY /dest`).
    // Only ends are trimmed — internal whitespace, including runs inside quoted
    // arguments, is preserved; the downstream instruction parsers already treat
    // runs of whitespace between tokens as a single separator.
    let opener = stripped.trim().to_string();

    // The body is an executable shell script only for the bare `RUN <<DELIM`
    // form (optionally preceded by `--flags`/redirections). When a command word
    // is present — before or after the marker (`RUN cat <<EOF > /f`, `RUN python3
    // <<EOF`, `RUN <<EOF cat > /f`) — the body is data fed to that command (file
    // content or program source), not shell, so it must not be scanned.
    let fold_body = keyword == "RUN" && run_heredoc_is_script(&opener);

    Some((heredocs, opener, fold_body))
}

/// Scan an instruction line for BuildKit heredoc redirections, tracking shell
/// quote state so that `<<WORD` appearing inside a quoted string (e.g.
/// `RUN echo "use <<EOF"`) is not mistaken for a heredoc. Returns the heredocs in
/// declaration order and the line with the `<<DELIM` markers removed. A `<<` is
/// only treated as a redirection when it sits at a token boundary (start of line
/// or after whitespace) and the delimiter word immediately follows, so shell
/// arithmetic like `$(( 1 << 2 ))` is not matched.
fn scan_heredocs(line: &str, shell_comments: bool) -> (Vec<Heredoc>, String) {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut heredocs = Vec::new();
    let mut stripped = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_boundary = true; // start of line is a boundary
    let mut arith_depth: usize = 0; // depth of `$((`/`((` arithmetic expansion
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
        // Outside quotes, a backslash escapes the next character, so an escaped
        // quote (`\"`) is literal and must not open a quoted span, and `\#` /
        // `\<` are not a comment / redirection.
        if c == '\\' && i + 1 < n {
            stripped.push(c);
            stripped.push(chars[i + 1]);
            prev_boundary = false;
            i += 2;
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

        // `$((`/`((` open an arithmetic-expansion context, where `<<` is a left
        // shift, not a heredoc; `))` closes it. Detection is suppressed while
        // inside, so `$(( 1 <<BITS ))` is not mistaken for a heredoc.
        if c == '(' && i + 1 < n && chars[i + 1] == '(' {
            arith_depth += 1;
            stripped.push(c);
            stripped.push(chars[i + 1]);
            prev_boundary = true;
            i += 2;
            continue;
        }
        if arith_depth > 0 && c == ')' && i + 1 < n && chars[i + 1] == ')' {
            arith_depth -= 1;
            stripped.push(c);
            stripped.push(chars[i + 1]);
            prev_boundary = true;
            i += 2;
            continue;
        }

        if arith_depth == 0 && shell_comments && c == '#' && prev_boundary {
            // In a shell command (`RUN`), an unquoted `#` at a token boundary
            // begins a comment; the rest of the line (including any `<<WORD`) is
            // not executed, so no heredoc can be opened there. Keep the text but
            // stop scanning. `COPY`/`ADD` do not run a shell, so a `#`-prefixed
            // token there is a literal source path, not a comment.
            stripped.extend(chars[i..].iter());
            break;
        }

        if arith_depth == 0 && prev_boundary {
            // A heredoc redirection may carry an optional leading file-descriptor
            // (`0<<EOF`, `3<<EOF`); capture those digits before matching `<<`.
            let mut m = i;
            while m < n && chars[m].is_ascii_digit() {
                m += 1;
            }
            if m + 1 < n && chars[m] == '<' && chars[m + 1] == '<' {
                if let Some((mut heredoc, next)) = parse_heredoc_marker(&chars, m) {
                    if m > i {
                        let fd: String = chars[i..m].iter().collect();
                        heredoc.fd = fd.parse::<u32>().ok();
                    }
                    heredocs.push(heredoc);
                    // Drop the fd prefix and the marker from the stripped opener.
                    prev_boundary = false;
                    i = next;
                    continue;
                }
            }
        }

        stripped.push(c);
        prev_boundary = is_shell_boundary(c);
        i += 1;
    }

    (heredocs, stripped)
}

/// Return `line` truncated before an unquoted `#` shell comment. The `#` starts a
/// comment only at a token boundary (start of line or after whitespace) and
/// outside single/double quotes, so `echo "a#b"` and `url#frag` are preserved
/// while `echo ok # note` loses its comment.
fn strip_inline_shell_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_boundary = true;
    let mut escaped_in_double = false;
    let mut escaped = false; // an unquoted backslash escapes the next character

    for (idx, c) in line.char_indices() {
        if escaped {
            escaped = false;
            prev_boundary = false;
        } else if in_single {
            in_single = c != '\'';
            prev_boundary = false;
        } else if in_double {
            if escaped_in_double {
                escaped_in_double = false;
            } else if c == '\\' {
                escaped_in_double = true;
            } else if c == '"' {
                in_double = false;
            }
            prev_boundary = false;
        } else if c == '\\' {
            escaped = true;
            prev_boundary = false;
        } else if c == '\'' {
            in_single = true;
            prev_boundary = false;
        } else if c == '"' {
            in_double = true;
            prev_boundary = false;
        } else if c == '#' && prev_boundary {
            return &line[..idx];
        } else {
            prev_boundary = is_shell_boundary(c);
        }
    }
    line
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

    // A leading backslash quotes the delimiter (`<<\EOF`), disabling expansion —
    // equivalent to `<<'EOF'`. Skip it; the terminator is the bare word `EOF`.
    if j < n && chars[j] == '\\' {
        j += 1;
    } else if j < n && (chars[j] == '"' || chars[j] == '\'') {
        // Quoted delimiter: the terminator word is everything up to the matching
        // quote, which may contain punctuation or spaces.
        let q = chars[j];
        j += 1;
        let word_start = j;
        while j < n && chars[j] != q {
            j += 1;
        }
        if j >= n {
            return None; // unbalanced quote around the delimiter
        }
        let delim: String = chars[word_start..j].iter().collect();
        j += 1; // consume the closing quote
        if delim.is_empty() {
            return None;
        }
        return Some((
            Heredoc {
                delim,
                strip_tabs,
                fd: None,
            },
            j,
        ));
    }

    // Unquoted delimiter: BuildKit delimiters are ordinary shell words and may
    // carry punctuation (e.g. `<<robots.txt`). The first character must be a
    // letter or underscore so that shell arithmetic (`1 <<2`) is not mistaken
    // for a heredoc; the rest runs until whitespace or a shell operator.
    let word_start = j;
    if !(j < n && (chars[j].is_ascii_alphabetic() || chars[j] == '_')) {
        return None;
    }
    j += 1;
    while j < n && is_delim_char(chars[j]) {
        j += 1;
    }
    let delim: String = chars[word_start..j].iter().collect();

    Some((
        Heredoc {
            delim,
            strip_tabs,
            fd: None,
        },
        j,
    ))
}

/// Characters allowed after the first in an unquoted heredoc delimiter: anything
/// that is not whitespace, a shell redirection/control operator, or a quote.
fn is_delim_char(c: char) -> bool {
    !c.is_whitespace() && !matches!(c, '<' | '>' | '|' | '&' | ';' | '(' | ')' | '"' | '\'')
}

/// Whether a `RUN` heredoc opener (with the `<<DELIM` markers already removed)
/// runs the heredoc body as a shell script. This holds in two cases:
///
/// - the bare form, where no command word remains after `RUN` (just flags and
///   redirections), e.g. `RUN <<EOF` or `RUN --mount=... <<EOF`; and
/// - a lone shell interpreter reading the heredoc as its script, e.g.
///   `RUN bash <<EOF` or `RUN /bin/sh <<EOF`.
///
/// Any other command word — including a shell with extra arguments (`sh -c ...`)
/// or a non-shell interpreter (`python3 <<EOF`, `cat <<EOF > /f`) — means the
/// body is data fed to that command, not shell, and must not be scanned.
fn run_heredoc_is_script(opener: &str) -> bool {
    let toks: Vec<&str> = opener.split_whitespace().collect();
    // Skip the RUN keyword; a bare heredoc (no command word) runs the body as a
    // script.
    heredoc_body_is_script(&toks[1..], true)
}

/// Decide whether a heredoc body is executed as a shell script, given the opener
/// tokens (RUN keyword already removed for the top level). `bare_is_script` says
/// what a heredoc with no command word means: for a top-level `RUN <<EOF` the
/// body is the script, but a nested `<<EOF` with no command is a no-op reading
/// stdin, so its body is data.
fn heredoc_body_is_script(tokens: &[&str], bare_is_script: bool) -> bool {
    match command_and_args(tokens) {
        // No command word. `RUN <<EOF` runs the body, but an assignment-only null
        // command (`RUN FOO=bar <<EOF`) does not execute its stdin, so its body is
        // data.
        None => bare_is_script && !leading_assignment(tokens),
        // A lone shell interpreter (optionally with an env-assignment prefix)
        // reads the heredoc as its script — unless a `-c` flag supplies the script
        // instead (then the heredoc is stdin data) or a non-option operand names a
        // script file to run.
        Some((cmd, args)) => is_shell_command(cmd) && shell_runs_stdin_script(&args),
    }
}

/// Whether the first command-position token (after any leading flags and
/// redirections) is a `VAR=value` environment assignment.
fn leading_assignment(tokens: &[&str]) -> bool {
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        if tok.starts_with("--") {
            i += 1;
            continue;
        }
        match classify_redirection(tok) {
            Some(true) => i += 2,
            Some(false) => i += 1,
            None => return is_env_assignment(tok),
        }
    }
    false
}

/// Whether a token is a `NAME=value` shell environment assignment.
fn is_env_assignment(tok: &str) -> bool {
    match tok.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Given a shell command's argument tokens (redirections already removed),
/// whether the shell would run its script from stdin — i.e. from the heredoc.
/// A `-c` flag redirects the script to that option's value, and a non-option
/// operand names a script file; either means the heredoc is stdin data instead.
/// Recognized options like `-e`/`-x`/`-euo` (and the word consumed by `-o`, e.g.
/// `set -o pipefail`) do not count as operands.
fn shell_runs_stdin_script(args: &[&str]) -> bool {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if is_command_source_flag(arg) {
            return false; // `-c` → script comes from the option value
        }
        if arg.starts_with("--") {
            continue; // long option, ignored
        }
        if let Some(short) = arg.strip_prefix('-') {
            // `-s` forces the script to be read from stdin (the heredoc); any
            // following non-option tokens are positional parameters, not a file.
            if short.contains('s') {
                return true;
            }
            // A short-flag bundle ending in `o` consumes the next token as its
            // setting name (`-o pipefail`, `-euo pipefail`).
            if short.ends_with('o') {
                it.next();
            }
            continue;
        }
        return false; // a non-option operand names a script file → stdin is data
    }
    true
}

/// Split opener tokens into the command word and its following argument tokens,
/// skipping leading `--flags` and redirections (before the command) and
/// redirections interspersed with the arguments. Returns `None` when there is no
/// command word (only flags/redirections).
fn command_and_args<'a>(tokens: &[&'a str]) -> Option<(&'a str, Vec<&'a str>)> {
    let mut i = 0;
    // Skip leading `--flags`, redirections, and `VAR=value` env-assignment
    // prefixes to reach the actual command word.
    while i < tokens.len() {
        let tok = tokens[i];
        if tok.starts_with("--") || is_env_assignment(tok) {
            i += 1;
            continue;
        }
        match classify_redirection(tok) {
            Some(true) => i += 2,
            Some(false) => i += 1,
            None => break,
        }
    }
    if i >= tokens.len() {
        return None;
    }
    let cmd = tokens[i];
    i += 1;
    let mut args = Vec::new();
    while i < tokens.len() {
        let tok = tokens[i];
        // A control operator ends this simple command; the heredoc feeds the
        // command before it, so stop collecting its arguments here (`bash <<EOF
        // && echo done` → command is `bash` with no operands).
        if is_control_operator(tok) {
            break;
        }
        match classify_redirection(tok) {
            Some(true) => i += 2,
            Some(false) => i += 1,
            None => {
                args.push(tok);
                i += 1;
            }
        }
    }
    Some((cmd, args))
}

/// Whether a token is a shell control operator that separates simple commands.
fn is_control_operator(tok: &str) -> bool {
    matches!(tok, "&&" | "||" | "|" | "|&" | "&" | ";" | ";;")
}

/// Whether a character ends a shell token — whitespace or a control/list
/// metacharacter — so the next `#` starts a comment and the next `<<` is a
/// redirection at a command boundary.
fn is_shell_boundary(c: char) -> bool {
    c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')')
}

/// Whether a command word is a shell that executes a heredoc fed on stdin as a
/// script (matched on the basename so `/bin/sh` counts).
fn is_shell_command(word: &str) -> bool {
    let base = word.rsplit('/').next().unwrap_or(word);
    matches!(base, "sh" | "bash" | "dash" | "ash" | "zsh" | "ksh")
}

/// Whether a shell argument is a `-c` option (possibly bundled, e.g. `-xc`),
/// which makes the shell take its script from that option's value rather than
/// from the heredoc on stdin.
fn is_command_source_flag(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c')
}

/// Classify a token as a shell redirection. Returns `Some(true)` for a bare
/// operator whose target is the next token (`>`, `>>`, `2>`, `<`), `Some(false)`
/// for a redirection with the target attached (`>/f`, `>>log`, `2>&1`), or `None`
/// when the token is not a redirection.
fn classify_redirection(tok: &str) -> Option<bool> {
    let rest = tok.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix('&').unwrap_or(rest);
    if !(rest.starts_with('>') || rest.starts_with('<')) {
        return None;
    }
    let after = rest.trim_start_matches(['>', '<']);
    Some(after.is_empty())
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
    let (bodies, idx) = collect_heredoc_bodies(&heredocs, lines, start_idx);

    if fold_body {
        // Fold only the heredoc that supplies the command's stdin (the last
        // unprefixed/fd-0 one — later redirections win) so the RUN heuristics see
        // installs inside the executed script. Other heredocs (fd 3, shadowed
        // duplicates) are data and are dropped.
        // A non-shell shebang only selects the interpreter for the *bare* `RUN
        // <<EOF` form, where BuildKit reads it. When a shell is invoked
        // explicitly (`RUN bash <<EOF`), a leading `#!` line is just a shell
        // comment and the body still runs as shell.
        let opener_toks: Vec<&str> = opener.split_whitespace().collect();
        let is_bare = command_and_args(&opener_toks[1..]).is_none();

        if let Some(body) = stdin_heredoc_body(&heredocs, &bodies) {
            if !(is_bare && body_has_non_shell_shebang(body)) {
                let body_joined = fold_script_body(body);
                if !body_joined.is_empty() {
                    return (format!("{} {}", opener, body_joined), idx);
                }
            }
        }
        (opener.to_string(), idx)
    } else {
        // COPY/ADD bodies (file content) and command-fed RUN bodies (file
        // content or program source) are not shell. Drop every body (it must not
        // leak into the instruction stream) and keep only the opener so a COPY
        // destination still yields a FileExists assertion.
        (opener.to_string(), idx)
    }
}

/// Collect one physical body per heredoc, in declaration order, from `lines`
/// starting at `start_idx`. Returns the per-heredoc bodies and the index of the
/// first line after the last consumed body. A plain `<<EOF` terminator must match
/// the line exactly; only the `<<-EOF` form permits leading tabs to be stripped,
/// so an indented `EOF` inside a plain heredoc body does not close it early.
fn collect_heredoc_bodies<'a>(
    heredocs: &[Heredoc],
    lines: &[&'a str],
    start_idx: usize,
) -> (Vec<Vec<&'a str>>, usize) {
    let mut idx = start_idx;
    let mut bodies: Vec<Vec<&str>> = heredocs.iter().map(|_| Vec::new()).collect();
    let mut delim_pos = 0;

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
        bodies[delim_pos].push(raw);
    }

    (bodies, idx)
}

/// The body of the heredoc that supplies the command's stdin — the last
/// unprefixed or fd-0 heredoc, since later redirections to a descriptor win.
/// Returns `None` when no heredoc targets stdin (e.g. only `3<<EOF`).
fn stdin_heredoc_body<'a>(
    heredocs: &[Heredoc],
    bodies: &'a [Vec<&'a str>],
) -> Option<&'a [&'a str]> {
    heredocs
        .iter()
        .rposition(Heredoc::is_stdin)
        .map(|k| bodies[k].as_slice())
}

/// Fold a shell-script heredoc body into a single ` && `-joined command string
/// for the RUN install heuristics. The body is a shell script, so this:
///
/// - joins its own backslash line-continuations (otherwise `apk add \` / `nginx`
///   folds to `apk add \ && nginx`, capturing a bogus package named `\`);
/// - strips `#` shell comments — whole-line and inline (`echo ok # note`),
///   quote-aware — so commented-out text does not fabricate evidence;
/// - recognizes nested heredocs (`cat <<INNER > /f`) and drops their payloads —
///   that content is data written to a file, not executed — while keeping the
///   surrounding executable lines.
fn fold_script_body(body: &[&str]) -> String {
    let mut commands: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_continuation = false;
    let mut i = 0;

    while i < body.len() {
        let line = body[i];
        i += 1;

        // Remove any `#` shell comment (whole-line or inline) before processing.
        let uncommented = strip_inline_shell_comment(line);
        let trimmed = uncommented.trim_end();

        if trimmed.trim_start().is_empty() {
            // A blank or comment-only line. If a continuation was open, the `\`
            // already joined onto this line and the `#`/blank ends the command,
            // so finalize what was accumulated rather than joining across it.
            if in_continuation {
                in_continuation = false;
                let logical = std::mem::take(&mut current);
                i = push_script_command(&mut commands, logical, body, i);
            }
            continue;
        }

        if let Some(without_backslash) = trimmed.strip_suffix('\\') {
            if in_continuation {
                current.push(' ');
                current.push_str(without_backslash.trim());
            } else {
                current.push_str(without_backslash.trim());
            }
            in_continuation = true;
            continue;
        }

        if in_continuation {
            current.push(' ');
            current.push_str(trimmed.trim());
        } else {
            current.push_str(trimmed.trim());
        }
        in_continuation = false;

        let logical = std::mem::take(&mut current);
        i = push_script_command(&mut commands, logical, body, i);
    }

    if in_continuation && !current.trim().is_empty() {
        let logical = current.trim().to_string();
        push_script_command(&mut commands, logical, body, i);
    }

    commands
        .into_iter()
        .filter(|c| !c.is_empty())
        .collect::<Vec<_>>()
        .join(" && ")
}

/// Record one logical command line from a folded heredoc body. If the line opens
/// its own (nested) heredocs, consume their bodies from `body`: an executable
/// nested heredoc (bare or a shell interpreter, e.g. `sh <<INNER`) is folded
/// recursively so its installs are kept, while a data nested heredoc (`cat
/// <<INNER > /f`) has its payload dropped. Returns the body index to continue
/// scanning from.
fn push_script_command(
    commands: &mut Vec<String>,
    logical: String,
    body: &[&str],
    mut i: usize,
) -> usize {
    if logical.is_empty() {
        return i;
    }

    let (inner, stripped) = scan_heredocs(&logical, true);
    if inner.is_empty() {
        commands.push(logical);
        return i;
    }

    // Collect one body per nested heredoc, in declaration order.
    let (inner_bodies, next) = collect_heredoc_bodies(&inner, body, i);
    i = next;

    commands.push(stripped.trim().to_string());

    // A nested heredoc feeding a shell executes its stdin body; fold that one
    // recursively so its installs are detected. A data nested heredoc (`cat
    // <<INNER > /f`) and a nested bare heredoc (a no-op, hence `bare_is_script =
    // false`) have their payloads dropped.
    // Only an explicit-shell nested heredoc is folded here (a nested bare heredoc
    // is a no-op — `bare_is_script = false` — and its body is dropped). With the
    // shell explicit, a leading `#!` line is just a comment, so no shebang
    // suppression applies.
    let inner_tokens: Vec<&str> = stripped.split_whitespace().collect();
    if heredoc_body_is_script(&inner_tokens, false) {
        if let Some(stdin_body) = stdin_heredoc_body(&inner, &inner_bodies) {
            let folded = fold_script_body(stdin_body);
            if !folded.is_empty() {
                commands.push(folded);
            }
        }
    }

    i
}

/// Whether the very first line of a bare `RUN <<EOF` body is a shebang for a
/// non-shell interpreter (e.g. `#!/usr/bin/env python3`). BuildKit runs such a
/// body with that interpreter, so it is program source, not shell, and must not
/// be scanned for installs. A shebang is only honored on the first line: a blank
/// or any other content before it makes it an ordinary comment.
fn body_has_non_shell_shebang(body: &[&str]) -> bool {
    let Some(first_line) = body.first() else {
        return false;
    };
    let Some(rest) = first_line.strip_prefix("#!") else {
        return false; // the body does not start with a shebang
    };
    let mut parts = rest.split_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };
    // `#!/usr/bin/env python3` → the interpreter is the argument to `env`.
    let interp = if first.rsplit('/').next() == Some("env") {
        parts.next().unwrap_or("")
    } else {
        first
    };
    let base = interp.rsplit('/').next().unwrap_or(interp);
    !base.is_empty() && !is_shell_command(base)
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
    fn test_run_shell_interpreter_heredoc_body_is_folded() {
        // A lone shell interpreter reads the heredoc as its script, so installs
        // in the body are real and must be detected.
        for interp in ["bash", "sh", "/bin/sh", "dash"] {
            let content =
                format!("FROM alpine\nRUN {interp} <<EOF\napk add --no-cache nginx\nEOF\n");
            let runs = run_commands(&content);
            assert_eq!(runs.len(), 1, "interp {interp}: one RUN expected");
            assert!(
                runs[0].contains("apk add --no-cache nginx"),
                "interp {interp}: shell heredoc body was not folded: {}",
                runs[0]
            );
        }
    }

    #[test]
    fn test_run_shell_interpreter_with_args_heredoc_is_data() {
        // `sh -c '...'` runs the -c command; the heredoc is stdin to it (data),
        // so the body must not be folded.
        let content = "\
FROM alpine
RUN sh -c 'echo hi' <<EOF
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apk add"),
            "`sh -c` heredoc body must be treated as data: {}",
            runs[0]
        );
    }

    #[test]
    fn test_escaped_quote_in_opener_does_not_hide_heredoc() {
        // An escaped quote (`\"`) outside quotes is literal and must not open a
        // quoted span that hides a following `<<EOF`. The heredoc must still be
        // detected so its body does not leak as instructions.
        let content =
            "FROM alpine\nRUN printf \\\"x\\\" <<EOF > /tmp/x\nUSER phantom\nEOF\nEXPOSE 80\n";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "escaped quote hid the heredoc, leaking a phantom USER instruction"
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_backslash_quoted_heredoc_delimiter_is_recognized() {
        // `<<\EOF` quotes the delimiter (like `<<'EOF'`); the terminator is `EOF`.
        // The heredoc must be consumed so its body does not leak as instructions.
        let content = "\
FROM alpine
RUN cat <<\\EOF > /tmp/x
USER phantom
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "backslash-quoted heredoc body leaked a phantom USER instruction"
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_nested_shell_heredoc_with_shebang_is_folded() {
        // A nested `bash <<INNER` runs its body as bash; a first `#!` line is a
        // comment, so a following install is still detected.
        let content = "\
FROM alpine
RUN <<OUTER
bash <<INNER
#!/usr/bin/env python3
apk add --no-cache nginx
INNER
OUTER
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "nested explicit-shell heredoc body was dropped over a shebang: {}",
            runs[0]
        );
    }

    #[test]
    fn test_opener_comment_after_control_operator_disables_heredoc() {
        // `#` begins a shell comment after a `;` control operator (not only after
        // whitespace), so a following `<<EOF` is not a heredoc.
        let content = "\
FROM alpine
RUN echo ok;# mention <<EOF here
RUN apk add --no-cache nginx
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(
            runs.len(),
            2,
            "commented `<<EOF` after `;` wrongly swallowed later lines"
        );
        assert!(runs[1].contains("apk add --no-cache nginx"));
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_explicit_shell_heredoc_ignores_shebang_line() {
        // With an explicit shell (`RUN bash <<EOF`), a `#!` first line is just a
        // bash comment; the body still runs as shell, so installs are detected.
        let content = "\
FROM alpine
RUN bash <<EOF
#!/usr/bin/env python3
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "explicit-shell heredoc body was dropped over a shebang comment: {}",
            runs[0]
        );
    }

    #[test]
    fn test_shell_heredoc_with_trailing_control_list_is_folded() {
        // `RUN bash <<EOF && echo done`: the heredoc feeds bash's stdin and
        // `&& echo done` is a separate command, so the body still folds.
        let content = "\
FROM alpine
RUN bash <<EOF && echo done
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "heredoc body was dropped because of a trailing `&&` list: {}",
            runs[0]
        );
    }

    #[test]
    fn test_copy_heredoc_hash_source_is_not_a_comment() {
        // `COPY` does not run a shell, so a `#`-prefixed token is a literal source
        // path, not a comment; the following heredoc must still be detected and
        // its body must not leak as instructions.
        let content = "\
FROM alpine
COPY #defaults <<CONF /etc/app/
user nginx;
CONF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "COPY heredoc after a `#`-prefixed source leaked a phantom USER"
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_run_heredoc_body_inline_comment_is_stripped() {
        // An inline `#` in a folded body is a shell comment; text after it must
        // not be scanned for installs.
        let content = "\
FROM alpine
RUN <<EOF
echo ok # apt-get install -y ghost-package
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "real install lost: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains("ghost-package") && !runs[0].contains("apt-get"),
            "inline-commented text was folded into the command: {}",
            runs[0]
        );
    }

    #[test]
    fn test_run_shell_dash_s_heredoc_is_folded() {
        // `bash -s release <<EOF` reads the script from stdin (the heredoc) and
        // treats `release` as a positional argument, so installs must be detected.
        let content = "\
FROM alpine
RUN bash -s release <<EOF
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "`bash -s` stdin-script heredoc body was not folded: {}",
            runs[0]
        );
    }

    #[test]
    fn test_blank_line_before_shebang_is_treated_as_shell() {
        // A shebang is only honored on the very first line; a leading blank line
        // makes it an ordinary comment, so the body runs as shell and installs are
        // detected.
        let content = "\
FROM alpine
RUN <<EOF

#!/usr/bin/env python3
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "body with a non-first-line shebang should fold as shell: {}",
            runs[0]
        );
    }

    #[test]
    fn test_run_env_assignment_prefix_before_shell_is_folded() {
        // `RUN DEBIAN_FRONTEND=noninteractive bash <<EOF` runs the body as bash's
        // script; the assignment prefix must not be mistaken for the command.
        let content = "\
FROM alpine
RUN DEBIAN_FRONTEND=noninteractive bash <<EOF
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "assignment-prefixed shell heredoc body was not folded: {}",
            runs[0]
        );
    }

    #[test]
    fn test_run_env_assignment_only_heredoc_is_data() {
        // `RUN FOO=bar <<EOF` is an assignment-only null command; it does not
        // execute the heredoc, so the body is data and must not be scanned.
        let content = "\
FROM alpine
RUN FOO=bar <<EOF
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apk add"),
            "assignment-only heredoc body must be treated as data: {}",
            runs[0]
        );
    }

    #[test]
    fn test_heredoc_on_nonzero_fd_is_not_shell_script() {
        // `RUN bash 3<<EOF` puts the heredoc on fd 3, not stdin, so bash does not
        // run it as its script; the body is data.
        let content = "\
FROM alpine
RUN bash 3<<EOF
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apk add"),
            "fd-3 heredoc body must not be folded as the shell script: {}",
            runs[0]
        );
    }

    #[test]
    fn test_multiple_stdin_heredocs_last_one_wins() {
        // With `bash <<IGNORED <<SCRIPT`, later redirections win, so only SCRIPT
        // becomes bash's stdin; the shadowed IGNORED payload is not executed.
        let content = "\
FROM alpine
RUN bash <<IGNORED <<SCRIPT
apt-get install -y ghost-package
IGNORED
apk add --no-cache nginx
SCRIPT
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "the stdin heredoc (SCRIPT) install was lost: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains("ghost-package"),
            "the shadowed heredoc (IGNORED) payload was scanned: {}",
            runs[0]
        );
    }

    #[test]
    fn test_run_shell_interpreter_with_options_is_folded() {
        // A shell with only option flags still runs the heredoc body as its
        // script (`bash -euo pipefail <<EOF` is a common idiom), so installs must
        // be detected.
        for opener in ["bash -euo pipefail", "bash -x", "sh -e"] {
            let content =
                format!("FROM alpine\nRUN {opener} <<EOF\napk add --no-cache nginx\nEOF\n");
            let runs = run_commands(&content);
            assert_eq!(runs.len(), 1, "opener `{opener}`: one RUN expected");
            assert!(
                runs[0].contains("apk add --no-cache nginx"),
                "opener `{opener}`: shell-with-options heredoc body was not folded: {}",
                runs[0]
            );
        }
    }

    #[test]
    fn test_opener_shell_comment_disables_heredoc_detection() {
        // An unquoted `#` on the opener begins a shell comment, so a following
        // `<<EOF` is not a heredoc and must not swallow the rest of the file.
        let content = "\
FROM alpine
RUN echo ok # mention <<EOF here
RUN apk add --no-cache nginx
EXPOSE 80
CMD [\"true\"]
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(
            runs.len(),
            2,
            "commented `<<EOF` wrongly swallowed later lines"
        );
        assert!(runs[1].contains("apk add --no-cache nginx"));
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
    fn test_non_shell_shebang_body_is_not_scanned() {
        // A bare `RUN <<EOF` whose first body line is a non-shell shebang is run
        // by that interpreter; the body is program source, not shell, and must
        // not be scanned for installs.
        let content = "\
FROM alpine
RUN <<EOF
#!/usr/bin/env python3
subprocess.run('apt-get install -y ghost-package')
print('nginx')
EOF
EXPOSE 80
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apt-get") && !runs[0].contains("ghost"),
            "python heredoc body (non-shell shebang) was folded into the command: {}",
            runs[0]
        );
    }

    #[test]
    fn test_shell_shebang_body_is_folded() {
        // A shell shebang keeps the body as a script, so installs are detected.
        let content = "\
FROM alpine
RUN <<EOF
#!/bin/bash
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "shell-shebang heredoc body was not folded: {}",
            runs[0]
        );
    }

    #[test]
    fn test_nested_shell_heredoc_payload_is_scanned() {
        // A nested heredoc feeding a shell (`bash <<INNER`) is executable, so its
        // installs must be detected (unlike a data heredoc, whose payload is
        // dropped).
        let content = "\
FROM alpine
RUN <<OUTER
echo start
bash <<INNER
apk add --no-cache nginx
INNER
echo done
OUTER
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "nested shell heredoc install was dropped: {}",
            runs[0]
        );
    }

    #[test]
    fn test_body_comment_after_continuation_terminates_command() {
        // In shell, a `\`-continued line joins onto the next physical line, but a
        // whole-line `#` there comments out the remainder. The command must end
        // at the accumulated text, so `nginx` is a separate command and no
        // `apk add nginx` package is fabricated.
        let content = "\
FROM alpine
RUN <<EOF
apk add \\
# commented out
nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apk add nginx") && !runs[0].contains("apk add --no-cache nginx"),
            "continuation joined across a comment, fabricating a package: {}",
            runs[0]
        );
    }

    #[test]
    fn test_run_heredoc_body_comment_lines_are_stripped() {
        // A whole-line `#` comment inside a folded heredoc body is a shell
        // comment (a no-op) and must not be folded into the command, or it
        // fabricates a package from commented-out text.
        let content = "\
FROM alpine
RUN <<EOF
# apt-get install -y evilpkg
apk add --no-cache nginx
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "real install lost: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains("evilpkg"),
            "commented-out install leaked into the folded command: {}",
            runs[0]
        );
    }

    #[test]
    fn test_data_heredoc_opener_preserves_quoted_spaces() {
        // Removing the marker must not collapse whitespace inside quoted opener
        // arguments (only ends are trimmed).
        let content = "\
FROM alpine
RUN cat <<EOF > \"/x  y\"
some content
EOF
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("/x  y"),
            "double space inside a quoted redirect target was collapsed: {}",
            runs[0]
        );
    }

    #[test]
    fn test_nested_heredoc_payload_is_not_scanned() {
        // An executable outer `RUN <<OUTER` may contain an inner heredoc that
        // writes a config file. The inner payload is data, not executed shell, so
        // it must be dropped — only the surrounding executable lines are scanned.
        let content = "\
FROM alpine
RUN <<OUTER
apk add --no-cache nginx
cat <<INNER > /etc/nginx/nginx.conf
apt-get install -y ghost-package
server { listen 80; }
INNER
nginx -t
OUTER
";
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("apk add --no-cache nginx"),
            "outer executable install lost: {}",
            runs[0]
        );
        assert!(
            runs[0].contains("nginx -t"),
            "executable line after the nested heredoc lost: {}",
            runs[0]
        );
        assert!(
            !runs[0].contains("ghost-package") && !runs[0].contains("listen 80"),
            "nested heredoc payload leaked into the folded command: {}",
            runs[0]
        );
    }

    #[test]
    fn test_fd_dup_and_prefixed_heredoc_is_detected() {
        // `RUN cat <&3 3<<EOF` combines an fd duplication and an fd-prefixed
        // heredoc; the heredoc must still be recognized so its body is consumed.
        let content = "\
FROM alpine
RUN cat <&3 3<<EOF > /f
USER phantom
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "fd-dup + fd-prefixed heredoc body leaked a phantom USER instruction"
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_fd_prefixed_heredoc_is_detected() {
        // A heredoc may carry a leading file descriptor (`0<<EOF`). It must still
        // be recognized so the body is consumed rather than leaking as
        // instructions.
        let content = "\
FROM alpine
RUN cat 0<<EOF > /f
USER phantom
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        assert!(
            !df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::User(_))),
            "fd-prefixed heredoc body leaked a phantom USER instruction"
        );
        assert!(df.stages[0]
            .instructions
            .iter()
            .any(|i| matches!(i.instruction, Instruction::Expose(_))));
    }

    #[test]
    fn test_copy_heredoc_delimiter_with_punctuation() {
        // Heredoc delimiters may carry punctuation (`<<robots.txt`). The full
        // token must be captured so the terminator matches and the body does not
        // swallow the rest of the file.
        let content = "\
FROM alpine
COPY <<robots.txt /usr/share/nginx/html/
User-agent: *
Disallow:
robots.txt
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let copy = df.stages[0]
            .instructions
            .iter()
            .find_map(|i| match &i.instruction {
                Instruction::Copy { dest, .. } => Some(dest.clone()),
                _ => None,
            })
            .expect("COPY instruction");
        assert_eq!(copy, "/usr/share/nginx/html/");
        // The body between the opener and the `robots.txt` terminator must not
        // leak as instructions, and the EXPOSE afterward must survive.
        assert!(
            df.stages[0]
                .instructions
                .iter()
                .any(|i| matches!(i.instruction, Instruction::Expose(_))),
            "EXPOSE after a punctuation-delimited heredoc was swallowed"
        );
    }

    #[test]
    fn test_run_redirection_before_command_is_data() {
        // A redirection may precede its command (`RUN <<EOF cat > /f`), so `cat`
        // is the command and the body is data. It must not be folded/scanned.
        let content = "\
FROM alpine
RUN <<EOF cat > /etc/motd
apt-get install -y ghost-package
welcome to nginx
EOF
EXPOSE 80
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            !runs[0].contains("apt-get") && !runs[0].contains("welcome"),
            "redirection-before-command heredoc body was folded into the command: {}",
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
    fn test_arithmetic_shift_with_variable_operand_is_not_heredoc() {
        // `$((1 <<BITS))` is an arithmetic left shift by a variable, not a
        // heredoc, even though `BITS` immediately follows `<<`. Arithmetic
        // context suppresses heredoc detection, so nothing after is consumed.
        let content = "\
FROM alpine
RUN echo $((1 <<BITS))
EXPOSE 80
CMD [\"true\"]
";
        let df = parse_dockerfile_content(content).unwrap();
        let runs = run_commands(content);
        assert_eq!(runs.len(), 1);
        assert!(
            runs[0].contains("1 <<BITS"),
            "arithmetic shift text was altered: {}",
            runs[0]
        );
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
