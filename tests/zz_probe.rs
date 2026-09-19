use dgossgen::extractor::{self, AssertionKind};
use dgossgen::parser;

fn run(name: &str, content: &str) {
    println!("===== CASE: {name} =====");
    let df = match parser::parse_dockerfile_content(content) {
        Ok(d) => d,
        Err(e) => {
            println!("  PARSE ERROR: {e}");
            return;
        }
    };
    let contract = extractor::extract_contract(&df, None, &[]);
    for a in &contract.assertions {
        match &a.kind {
            AssertionKind::PackageInstalled {
                package, manager, ..
            } => {
                println!("  PKG[{:?}] {}", manager, package);
            }
            AssertionKind::FileExists { path, .. } => println!("  FILE {}", path),
            AssertionKind::ProcessRunning { name } => println!("  PROC {}", name),
            AssertionKind::PortListening { port, .. } => println!("  PORT {}", port),
            AssertionKind::CommandExit { command, .. } => println!("  CMDEXIT {}", command),
            AssertionKind::CommandOutput { command, .. } => println!("  CMDOUT {}", command),
            AssertionKind::UserExists { username } => println!("  USER {}", username),
            AssertionKind::HealthcheckPasses { command } => println!("  HC {}", command),
            AssertionKind::HttpStatus { url, status } => println!("  HTTP {} {}", url, status),
        }
    }
    println!("  (total {} assertions)", contract.assertions.len());
}

#[test]
fn probe_all() {
    // 1. RUN bash <<EOF should be SCRIPT (fold, detect nginx)
    run(
        "bash-script",
        "FROM alpine\nRUN bash <<EOF\napk add nginx\nEOF\n",
    );

    // 2. RUN bash script.sh <<EOF should be DATA (no fold, no nginx)
    run(
        "bash-with-arg-data",
        "FROM alpine\nRUN bash script.sh <<EOF\napk add nginx\nEOF\n",
    );

    // 3. env-assignment prefix: RUN FOO=bar <<EOF -- is this script? bash treats FOO=bar as assignment then heredoc to null cmd
    run(
        "env-assign-prefix",
        "FROM alpine\nRUN FOO=bar <<EOF\napk add nginx\nEOF\n",
    );

    // 4. shell as redirection target vs command
    run(
        "shell-as-redir-target",
        "FROM alpine\nRUN cat <<EOF > bash\napk add nginx\nEOF\n",
    );

    // 5. fd-prefix with heredoc
    run("fd-prefix", "FROM alpine\nRUN 0<<EOF\napk add nginx\nEOF\n");

    // 6. fd-prefix with non-heredoc digits (a plain number token)
    run("nonheredoc-digits", "FROM alpine\nRUN echo 123 nginx\n");

    // 7. #-line skipping interacting with backslash continuation in folded body
    run(
        "comment-after-backslash",
        "FROM alpine\nRUN <<EOF\napk add \\\n# comment\nnginx\nEOF\n",
    );

    // 8. body line legitimately starting with # meant as content but in DATA heredoc (dropped anyway)
    run(
        "hash-content-data",
        "FROM alpine\nRUN cat <<EOF > /f\n#!/bin/sh\napk add nginx\nEOF\n",
    );

    // 9. classify_redirection: 2>&1 in folded body opener
    run(
        "redir-2>&1",
        "FROM alpine\nRUN <<EOF 2>&1\napk add nginx\nEOF\n",
    );

    // 10. multi-heredoc + fd
    run(
        "multi-heredoc-fd",
        "FROM alpine\nRUN cat 0<<EOF1 1<<EOF2\ndata1\nEOF1\ndata2\nEOF2\n",
    );

    // 11. shell interpreter with -c arg (should be data)
    run(
        "sh-dash-c",
        "FROM alpine\nRUN sh -c <<EOF\napk add nginx\nEOF\n",
    );

    // 12. redirection before command with shell target
    run(
        "redir-before-cmd",
        "FROM alpine\nRUN >out.txt cat <<EOF\napk add nginx\nEOF\n",
    );

    // 13. adversarial: bare > then word (no command)
    run(
        "bare-redir-only",
        "FROM alpine\nRUN > cat <<EOF\napk add nginx\nEOF\n",
    );

    // 14. python3 heredoc = data
    run(
        "python-data",
        "FROM alpine\nRUN python3 <<EOF\napk add nginx\nEOF\n",
    );

    // 15. quoted delimiter fold
    run(
        "quoted-delim",
        "FROM alpine\nRUN <<'EOF'\napk add nginx\nEOF\n",
    );

    // 16. heredoc marker inside single quotes should not match
    run("quoted-marker", "FROM alpine\nRUN echo 'uses <<EOF here'\n");

    // 17. arithmetic shift not matched
    run("arith-shift", "FROM alpine\nRUN echo $(( 1 << 2 ))\n");

    // 18. panic probe: empty heredoc body, EOF at file end without terminator
    run("unterminated", "FROM alpine\nRUN <<EOF\napk add nginx\n");

    // 19. fd digits then single < (not heredoc)
    run(
        "fd-single-lt",
        "FROM alpine\nRUN cat 2<file <<EOF\ndata\nEOF\n",
    );

    // 20. env-assign + shell? RUN FOO=bar bash <<EOF
    run(
        "env-assign-then-bash",
        "FROM alpine\nRUN FOO=bar bash <<EOF\napk add nginx\nEOF\n",
    );

    // 21. backslash continuation in body ending file (dangling)
    run(
        "dangling-backslash-body",
        "FROM alpine\nRUN <<EOF\napk add nginx \\\nEOF\n",
    );

    // 22. tab-strip delimiter <<- with tabbed terminator
    run(
        "dash-heredoc",
        "FROM alpine\nRUN <<-EOF\n\tapk add nginx\n\tEOF\n",
    );

    // 23. comment line at very start of folded body
    run(
        "leading-comment-body",
        "FROM alpine\nRUN <<EOF\n# just a comment\napk add nginx\nEOF\n",
    );

    // 24. Two command words → data
    run(
        "two-commands",
        "FROM alpine\nRUN foo bar <<EOF\napk add nginx\nEOF\n",
    );

    // 25. redirection with digit target attached like 1>&2 as only token besides RUN
    run(
        "only-redir-1>&2",
        "FROM alpine\nRUN 1>&2 <<EOF\napk add nginx\nEOF\n",
    );
}
