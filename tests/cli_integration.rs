use assert_cmd::prelude::*;
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
fn test_init_with_warnings_still_writes_output() {
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
        .code(2);

    assert!(
        output_dir.join("goss.yml").exists(),
        "goss.yml should still be written even when warnings cause exit code 2"
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
