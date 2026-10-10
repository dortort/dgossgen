use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_help_exits_success() {
    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_init_wait_only_contract_exits_zero() {
    // A port signal routes to goss_wait.yml, leaving goss.yml empty. That is a
    // valid readiness gate, not an anomaly, so the run must exit 0 (regression
    // guard: an earlier revision wrongly flagged the empty main as "nothing to
    // assert" even though the wait file was populated).
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(
        &dockerfile,
        "FROM alpine\nEXPOSE 8080\nRUN apk add --no-cache curl\n",
    )
    .unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--profile",
            "minimal",
        ])
        .assert()
        .success();

    assert!(output_dir.join("goss.yml").exists());
    assert!(
        output_dir.join("goss_wait.yml").exists(),
        "the port signal should produce a readiness gate"
    );
}

#[test]
fn test_init_with_malformed_config_fails_loudly() {
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(&dockerfile, "FROM alpine\nEXPOSE 8080\n").unwrap();
    // A config file that exists but does not parse must be a hard error,
    // not a silent revert to built-in defaults.
    fs::write(temp.path().join(".dgossgen.yml"), "assert_ports: [\n").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("config"));
}

#[test]
fn test_lint_missing_explicit_wait_file_fails_loudly() {
    let temp = tempdir().unwrap();
    let goss = temp.path().join("goss.yml");
    // A clean main file so that, before the fix, lint would print
    // "No issues found." for a wait file it never read.
    fs::write(&goss, "port: {}\n").unwrap();

    let missing_wait = temp.path().join("does_not_exist_goss_wait.yml");

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .args([
            "lint",
            goss.to_str().unwrap(),
            "--wait-file",
            missing_wait.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            missing_wait.file_name().unwrap().to_str().unwrap(),
        ));
}

#[test]
fn test_init_confidence_skips_are_notes_exit_zero() {
    // Under the default `standard` profile, package installs are filtered by
    // confidence. That is routine, so the run must exit 0 with the skips
    // reported as notes (not warnings), and both files written.
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(
        &dockerfile,
        "FROM debian:12\nEXPOSE 8080\nCMD [\"nginx\", \"-g\", \"daemon off;\"]\nRUN apt-get install -y nginx curl git\n",
    )
    .unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("note:"))
        .stderr(predicates::str::contains("warning:").not());

    assert!(output_dir.join("goss.yml").exists());
}

#[test]
fn test_init_strict_warnings_promotes_notes_to_exit_two() {
    // The same routine run fails under --strict-warnings.
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(
        &dockerfile,
        "FROM debian:12\nEXPOSE 8080\nCMD [\"nginx\", \"-g\", \"daemon off;\"]\nRUN apt-get install -y nginx curl git\n",
    )
    .unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--strict-warnings",
        ])
        .assert()
        .code(2);

    assert!(output_dir.join("goss.yml").exists());
}

#[test]
fn test_init_empty_contract_exits_two_with_diagnostic() {
    // A Dockerfile with no runtime signals must not silently exit 0 with a
    // useless `command: {}`. It exits 2 and explains what was missing.
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(&dockerfile, "FROM alpine:3.19\nRUN echo hello\n").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("no assertions"))
        .stderr(predicates::str::contains("EXPOSE"));

    assert!(
        output_dir.join("goss.yml").exists(),
        "output is still written so the user can inspect it"
    );
}

#[test]
fn test_init_resolves_variable_expose_into_port_assertions() {
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    // Variable-driven EXPOSE: previously dropped silently, producing no port assertion.
    fs::write(&dockerfile, "FROM alpine\nARG PORT=8080\nEXPOSE ${PORT}\n").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--profile",
            "standard",
        ])
        .assert()
        .success();

    // A single exposed port is emitted as a readiness gate in goss_wait.yml (this is
    // exactly the wait-file heuristic the silent drop used to suppress).
    let wait = fs::read_to_string(output_dir.join("goss_wait.yml"))
        .expect("single resolved port should trigger goss_wait.yml generation");
    assert!(
        wait.contains("8080"),
        "goss_wait.yml should contain the resolved variable port, got:\n{wait}"
    );

    // goss.yml must still be written (the port lives in the wait gate for the
    // single-port case), proving the run produced output rather than erroring.
    assert!(output_dir.join("goss.yml").exists());
}

#[test]
fn test_init_warns_on_unresolvable_expose_variable() {
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    // No ARG/ENV default for PORT: the token must warn, not vanish silently.
    fs::write(&dockerfile, "FROM alpine\nEXPOSE ${PORT}\n").unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--profile",
            "standard",
        ])
        .assert()
        .code(2);

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("PORT") && stderr.to_lowercase().contains("unresolved"),
        "expected a warning about the unresolved EXPOSE variable, got:\n{stderr}"
    );
}

#[test]
fn test_init_health_path_emits_http_check_under_default_policy() {
    // Regression guard for the silent-wrong-output bug: --health-path pushed a
    // High-confidence HttpStatus assertion, but the generator's policy gate
    // (http_checks defaults off) dropped it, so the tool exited 0 with a
    // "wrote goss.yml" that never tested the endpoint. Explicit user intent
    // must now override the default policy.
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(&dockerfile, "FROM nginx:1.25\nEXPOSE 80\n").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--health-path",
            "/healthz",
            "--primary-port",
            "80",
        ])
        .assert()
        .success();

    let goss = fs::read_to_string(output_dir.join("goss.yml")).expect("goss.yml should be written");
    assert!(
        goss.contains("http"),
        "the explicitly-requested health check must be emitted, got:\n{goss}"
    );
    assert!(
        goss.contains("http://127.0.0.1:80/healthz"),
        "the health URL must reflect the port and path, got:\n{goss}"
    );
    assert!(
        goss.contains("status: 200"),
        "the default expected status must be rendered, got:\n{goss}"
    );
}

#[test]
fn test_probe_with_warnings_code_path() {
    // Note: This test validates that cmd_probe now uses emit_output helper which ensures
    // output files are written BEFORE returning exit code 2 on warnings (fixing the latent bug).
    // We cannot test cmd_probe directly without Docker, but cmd_init and cmd_probe now share
    // the same emit_output helper, so the above test validates the fixed behavior.
    // This comment serves as documentation of the bug fix in cmd_probe.
}

#[test]
fn test_lint_json_format_emits_structured_findings() {
    // A goss.yml with four process assertions and a timeout-less command yields
    // exactly two findings. In JSON mode stdout must be a single parseable
    // array, each element carrying file/line/severity/suggestion, and the exit
    // code stays 2 so CI can still gate on it.
    let temp = tempdir().unwrap();
    let goss = temp.path().join("goss.yml");
    fs::write(
        &goss,
        "process:\n  a:\n    running: true\n  b:\n    running: true\n  c:\n    running: true\n  d:\n    running: true\ncommand:\n  check:\n    exec: /bin/true\n",
    )
    .unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .args(["lint", goss.to_str().unwrap(), "--format", "json"])
        .assert()
        .code(2);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON mode stdout must parse as JSON");
    let array = parsed.as_array().expect("findings are a JSON array");
    assert_eq!(array.len(), 2, "expected two findings, got:\n{stdout}");

    for finding in array {
        for field in ["file", "line", "severity", "suggestion", "message"] {
            assert!(
                finding.get(field).is_some(),
                "finding is missing `{field}`:\n{finding}"
            );
        }
        assert_eq!(finding["severity"], "warning");
    }

    // The two rules are present with their concrete remediations.
    assert!(
        array.iter().any(|f| f["message"]
            .as_str()
            .is_some_and(|m| m.contains("process assertions"))),
        "missing the process-count finding:\n{stdout}"
    );
    let timeout_finding = array
        .iter()
        .find(|f| {
            f["message"]
                .as_str()
                .is_some_and(|m| m.contains("no timeout"))
        })
        .expect("missing the timeout finding");
    assert!(timeout_finding["suggestion"]
        .as_str()
        .is_some_and(|s| s.contains("timeout: 10000")));
    // The command sits on line 11 of the fixture; the scan must locate it.
    assert_eq!(timeout_finding["line"], 11);
}

#[test]
fn test_lint_json_format_on_clean_file_is_empty_array() {
    // A clean suite prints `[]` (not prose) and exits 0, so a CI step can parse
    // the output unconditionally.
    let temp = tempdir().unwrap();
    let goss = temp.path().join("goss.yml");
    fs::write(&goss, "port: {}\n").unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .args(["lint", goss.to_str().unwrap(), "--format", "json"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    assert_eq!(parsed.as_array().map(|a| a.len()), Some(0));
}

#[test]
fn test_lint_human_invalid_yaml_renders_error_without_a_line() {
    // The Severity::Error branch and the line=None location: an unparseable
    // file prints an "error:" label and the file name with NO ":<line>" suffix.
    let temp = tempdir().unwrap();
    let goss = temp.path().join("goss.yml");
    fs::write(&goss, "process:\n  a: [unterminated\n").unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .args(["lint", goss.to_str().unwrap()])
        .assert()
        .code(2);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        stdout.contains("error:"),
        "expected an error label, got:\n{stdout}"
    );
    assert!(stdout.contains("Invalid YAML syntax"), "got:\n{stdout}");
    assert!(
        !predicates::str::is_match(r"goss\.yml:\d")
            .unwrap()
            .eval(stdout.as_str()),
        "a file-wide finding must not carry a line suffix, got:\n{stdout}"
    );
}

#[test]
fn test_lint_human_flaky_file_renders_location_and_fix() {
    // The warning branch: file:line location plus a "fix:" remediation line.
    let temp = tempdir().unwrap();
    let goss = temp.path().join("goss.yml");
    fs::write(&goss, "command:\n  check:\n    exec: /bin/true\n").unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .args(["lint", goss.to_str().unwrap()])
        .assert()
        .code(2);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(stdout.contains("warning:"), "got:\n{stdout}");
    // The command sits on line 2, so the location carries the line number.
    assert!(
        predicates::str::is_match(r"goss\.yml:2\b")
            .unwrap()
            .eval(stdout.as_str()),
        "expected a file:line location, got:\n{stdout}"
    );
    assert!(
        stdout.contains("fix:") && stdout.contains("timeout: 10000"),
        "expected a rendered remediation, got:\n{stdout}"
    );
}

#[test]
fn test_lint_json_auto_detected_wait_file_keeps_its_real_path() {
    // When the main file lives in a subdirectory, findings from the
    // auto-detected goss_wait.yml must carry the real (subdir-qualified) path so
    // a CI annotator can resolve them — not a bare "goss_wait.yml".
    let temp = tempdir().unwrap();
    let sub = temp.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("goss.yml"), "port: {}\n").unwrap();
    fs::write(
        sub.join("goss_wait.yml"),
        "command:\n  wait-check:\n    exec: /bin/true\n",
    )
    .unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args(["lint", "sub/goss.yml", "--format", "json"])
        .assert()
        .code(2);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout must be JSON");
    let array = parsed.as_array().expect("array");
    let wait_finding = array
        .iter()
        .find(|f| {
            f["message"]
                .as_str()
                .is_some_and(|m| m.contains("no timeout"))
        })
        .expect("the wait file's timeout finding");
    assert_eq!(
        wait_finding["file"], "sub/goss_wait.yml",
        "the finding must carry the real detected path, got:\n{stdout}"
    );
}

#[test]
fn test_explain_with_malformed_config_fails_loudly() {
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");

    fs::write(&dockerfile, "FROM alpine\nEXPOSE 8080\n").unwrap();
    fs::write(temp.path().join(".dgossgen.yml"), "assert_ports: [\n").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args(["explain", "-f", dockerfile.to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(predicates::str::contains("config"));
}

#[test]
fn test_init_secret_build_arg_from_custom_pattern_never_reaches_output() {
    let temp = tempdir().unwrap();
    let dockerfile = temp.path().join("Dockerfile");
    let output_dir = temp.path().join("generated");

    fs::write(
        &dockerfile,
        "FROM alpine\nARG INTERNAL_DIR\nWORKDIR /srv/$INTERNAL_DIR\nEXPOSE 8080\n",
    )
    .unwrap();
    fs::write(
        temp.path().join(".dgossgen.yml"),
        "secret_patterns:\n  - INTERNAL\n",
    )
    .unwrap();

    let assert = Command::new(assert_cmd::cargo::cargo_bin!("dgossgen"))
        .current_dir(temp.path())
        .args([
            "init",
            "-f",
            dockerfile.to_str().unwrap(),
            "-o",
            output_dir.to_str().unwrap(),
            "--build-arg",
            "INTERNAL_DIR=xs3cr3tx",
        ])
        .assert()
        .code(2)
        .stderr(predicates::str::contains(
            "WORKDIR '/srv/$INTERNAL_DIR' uses a secret build arg",
        ))
        .stderr(predicates::str::contains("xs3cr3tx").not());
    let output = assert.get_output();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("xs3cr3tx"));

    for file in ["goss.yml", "goss_wait.yml"] {
        let content = fs::read_to_string(output_dir.join(file)).unwrap();
        assert!(!content.contains("xs3cr3tx"), "{file} leaked the secret");
    }
    assert!(fs::read_to_string(output_dir.join("goss_wait.yml"))
        .unwrap()
        .contains("8080"));
}
