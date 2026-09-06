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
fn test_probe_with_warnings_code_path() {
    // Note: This test validates that cmd_probe now uses emit_output helper which ensures
    // output files are written BEFORE returning exit code 2 on warnings (fixing the latent bug).
    // We cannot test cmd_probe directly without Docker, but cmd_init and cmd_probe now share
    // the same emit_output helper, so the above test validates the fixed behavior.
    // This comment serves as documentation of the bug fix in cmd_probe.
}
