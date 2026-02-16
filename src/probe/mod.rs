use anyhow::{bail, Context, Result};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::extractor::{AssertionKind, ContractAssertion, RuntimeContract};
use crate::Confidence;

/// Runtime to use for container operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl std::fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerRuntime::Docker => write!(f, "docker"),
            ContainerRuntime::Podman => write!(f, "podman"),
        }
    }
}

impl std::str::FromStr for ContainerRuntime {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(ContainerRuntime::Docker),
            "podman" => Ok(ContainerRuntime::Podman),
            _ => Err(format!("unknown runtime: {s} (expected docker or podman)")),
        }
    }
}

/// Configuration for the probe pipeline.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub runtime: ContainerRuntime,
    pub dockerfile: String,
    pub context: String,
    pub target: Option<String>,
    pub build_args: Vec<(String, String)>,
    pub run_args: Vec<String>,
    pub allow_unsafe_run_args: bool,
    pub timeout: Duration,
    pub network_isolation: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            runtime: ContainerRuntime::Docker,
            dockerfile: "Dockerfile".to_string(),
            context: ".".to_string(),
            target: None,
            build_args: Vec::new(),
            run_args: Vec::new(),
            allow_unsafe_run_args: false,
            timeout: Duration::from_secs(60),
            network_isolation: true,
        }
    }
}

/// Evidence collected from a running container.
#[derive(Debug, Clone, Default)]
pub struct ProbeEvidence {
    /// Ports that are actually listening
    pub listening_ports: Vec<(u16, String)>,
    /// Running processes
    pub running_processes: Vec<String>,
    /// Files that exist
    pub existing_files: Vec<String>,
    /// User info
    pub user: Option<String>,
    pub uid: Option<u32>,
    /// Environment variables (filtered)
    pub env_vars: Vec<(String, String)>,
    /// Image inspect data
    pub image_config: Option<serde_json::Value>,
}

/// Run the probe pipeline: build, run, inspect, collect evidence.
pub fn run_probe(config: &ProbeConfig) -> Result<ProbeEvidence> {
    validate_run_args(&config.run_args, config.allow_unsafe_run_args)?;

    let rt = config.runtime.to_string();
    let image_tag = format!("dgossgen-probe-{}", std::process::id());
    let container_name = format!("dgossgen-probe-{}", std::process::id());
    let cleanup = ProbeCleanup::new(rt.clone(), container_name.clone(), image_tag.clone());

    // Step 1: Build the image
    let mut build_cmd = Command::new(&rt);
    build_cmd.arg("build");

    if let Some(target) = &config.target {
        build_cmd.args(["--target", target]);
    }

    for (key, val) in &config.build_args {
        build_cmd.arg("--build-arg");
        build_cmd.arg(format!("{}={}", key, val));
    }

    build_cmd
        .args(["-f", &config.dockerfile])
        .args(["-t", &image_tag])
        .arg(&config.context);

    let build_output = build_cmd
        .output()
        .with_context(|| format!("running {} build", rt))?;

    if !build_output.status.success() {
        bail!(
            "{} build failed:\n{}",
            rt,
            String::from_utf8_lossy(&build_output.stderr)
        );
    }
    cleanup.mark_image_created();

    // Step 2: Run the container
    let mut run_cmd = Command::new(&rt);
    run_cmd.args(["run", "-d", "--name", &container_name]);

    if config.network_isolation {
        run_cmd.args(["--network", "none"]);
    }

    // Add any extra run args
    for arg in &config.run_args {
        run_cmd.arg(arg);
    }

    run_cmd.arg(&image_tag);

    let run_output = run_cmd
        .output()
        .with_context(|| format!("running {} run", rt))?;

    if !run_output.status.success() {
        bail!(
            "{} run failed:\n{}",
            rt,
            String::from_utf8_lossy(&run_output.stderr)
        );
    }
    cleanup.mark_container_created();

    // Step 3: Collect evidence (with timeout)
    collect_evidence(&rt, &container_name, &image_tag, config.timeout)
}

fn validate_run_args(run_args: &[String], allow_unsafe: bool) -> Result<()> {
    if allow_unsafe {
        return Ok(());
    }

    for arg in run_args {
        validate_single_run_arg(arg)?;
    }
    Ok(())
}

fn validate_single_run_arg(arg: &str) -> Result<()> {
    if arg.trim() != arg || arg.chars().any(char::is_whitespace) {
        bail!(
            "invalid --run-arg '{}': only single-token flags are accepted in safe mode; use --unsafe-run-arg to bypass",
            arg
        );
    }

    if arg == "--read-only" || arg == "--init" {
        return Ok(());
    }

    if let Some(value) = arg.strip_prefix("--env=") {
        if is_valid_key_value(value) {
            return Ok(());
        }
        bail!(
            "invalid --run-arg '{}': expected --env=KEY=VALUE format; use --unsafe-run-arg to bypass",
            arg
        );
    }

    if let Some(value) = arg.strip_prefix("--env-file=") {
        if !value.is_empty() && !value.starts_with('/') && !value.starts_with("..") {
            return Ok(());
        }
        bail!(
            "invalid --run-arg '{}': unsafe --env-file path; use --unsafe-run-arg to bypass",
            arg
        );
    }

    if arg.starts_with("--cpus=")
        || arg.starts_with("--memory=")
        || arg.starts_with("--memory-swap=")
        || arg.starts_with("--cpuset-cpus=")
        || arg.starts_with("--cpuset-mems=")
        || arg.starts_with("--pids-limit=")
        || arg.starts_with("--ulimit=")
        || arg.starts_with("--tmpfs=")
        || arg.starts_with("--user=")
        || arg.starts_with("--workdir=")
        || arg.starts_with("--hostname=")
        || arg.starts_with("--shm-size=")
    {
        return Ok(());
    }

    if let Some(value) = arg.strip_prefix("--security-opt=") {
        if value == "no-new-privileges" || value == "no-new-privileges:true" {
            return Ok(());
        }
        bail!(
            "invalid --run-arg '{}': only --security-opt=no-new-privileges is allowed in safe mode; use --unsafe-run-arg to bypass",
            arg
        );
    }

    if arg == "--ipc=private" {
        return Ok(());
    }

    bail!(
        "blocked --run-arg '{}': not allowlisted in safe mode; use --unsafe-run-arg to bypass",
        arg
    );
}

fn is_valid_key_value(value: &str) -> bool {
    let Some((key, _)) = value.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
}

fn run_command_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::Output> {
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| "spawning command")?;
    let started = Instant::now();

    loop {
        if let Some(_status) = child.try_wait().with_context(|| "polling command status")? {
            return child
                .wait_with_output()
                .with_context(|| "collecting command output");
        }

        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("command timed out after {:?}", timeout);
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Debug)]
struct ProbeCleanup {
    runtime: String,
    container_name: String,
    image_tag: String,
    container_created: AtomicBool,
    image_created: AtomicBool,
}

impl ProbeCleanup {
    fn new(runtime: String, container_name: String, image_tag: String) -> Self {
        Self {
            runtime,
            container_name,
            image_tag,
            container_created: AtomicBool::new(false),
            image_created: AtomicBool::new(false),
        }
    }

    fn mark_container_created(&self) {
        self.container_created.store(true, Ordering::Relaxed);
    }

    fn mark_image_created(&self) {
        self.image_created.store(true, Ordering::Relaxed);
    }
}

impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        if self.container_created.load(Ordering::Relaxed) {
            let _ = Command::new(&self.runtime)
                .args(["rm", "-f", &self.container_name])
                .output();
        }

        if self.image_created.load(Ordering::Relaxed) {
            let _ = Command::new(&self.runtime)
                .args(["rmi", &self.image_tag])
                .output();
        }
    }
}

fn collect_evidence(
    runtime: &str,
    container: &str,
    image: &str,
    timeout: Duration,
) -> Result<ProbeEvidence> {
    let mut evidence = ProbeEvidence::default();

    // Inspect the image
    let mut inspect_cmd = Command::new(runtime);
    inspect_cmd.args(["image", "inspect", image]);
    let inspect_output =
        run_command_with_timeout(inspect_cmd, timeout).with_context(|| "image inspect")?;

    if inspect_output.status.success() {
        let json_str = String::from_utf8_lossy(&inspect_output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            evidence.image_config = Some(val);
        }
    }

    // Check running processes
    let mut ps_cmd = Command::new(runtime);
    ps_cmd.args(["exec", container, "ps", "aux"]);
    let ps_output = run_command_with_timeout(ps_cmd, timeout);

    if let Ok(output) = ps_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines().skip(1) {
                // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 {
                    evidence.running_processes.push(parts[10].to_string());
                }
            }
        }
    }

    // Check open ports (via ss or netstat)
    let mut ss_cmd = Command::new(runtime);
    ss_cmd.args(["exec", container, "ss", "-tlnp"]);
    let ss_output = run_command_with_timeout(ss_cmd, timeout);

    if let Ok(output) = ss_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines().skip(1) {
                if let Some(port) = parse_ss_port(line) {
                    evidence.listening_ports.push((port, "tcp".to_string()));
                }
            }
        }
    }

    // Check user
    let mut id_cmd = Command::new(runtime);
    id_cmd.args(["exec", container, "id"]);
    let id_output = run_command_with_timeout(id_cmd, timeout);

    if let Ok(output) = id_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            evidence.user = Some(text);
        }
    }

    // Check env (filtered)
    let mut env_cmd = Command::new(runtime);
    env_cmd.args(["exec", container, "env"]);
    let env_output = run_command_with_timeout(env_cmd, timeout);

    if let Ok(output) = env_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if let Some((key, val)) = line.split_once('=') {
                    evidence.env_vars.push((key.to_string(), val.to_string()));
                }
            }
        }
    }

    Ok(evidence)
}

/// Parse a port number from ss -tlnp output.
fn parse_ss_port(line: &str) -> Option<u16> {
    // ss output: State Recv-Q Send-Q Local Address:Port ...
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 {
        let addr_port = parts[3];
        if let Some(colon_pos) = addr_port.rfind(':') {
            return addr_port[colon_pos + 1..].parse().ok();
        }
    }
    None
}

/// Merge probe evidence into an existing RuntimeContract, raising confidence
/// where evidence confirms static analysis.
pub fn merge_evidence(contract: &mut RuntimeContract, evidence: &ProbeEvidence) {
    // Raise confidence on port assertions that are confirmed
    for assertion in &mut contract.assertions {
        match &assertion.kind {
            AssertionKind::PortListening { port, .. } => {
                if evidence.listening_ports.iter().any(|(p, _)| p == port) {
                    assertion.confidence = Confidence::High;
                }
            }
            AssertionKind::ProcessRunning { name } => {
                if evidence
                    .running_processes
                    .iter()
                    .any(|p| p.contains(name.as_str()))
                {
                    assertion.confidence = Confidence::High;
                }
            }
            _ => {}
        }
    }

    // Add new evidence-based assertions for discovered ports not in static analysis
    for (port, proto) in &evidence.listening_ports {
        let already_exists = contract
            .assertions
            .iter()
            .any(|a| matches!(&a.kind, AssertionKind::PortListening { port: p, .. } if p == port));
        if !already_exists {
            contract.assertions.push(ContractAssertion::new(
                AssertionKind::PortListening {
                    protocol: proto.clone(),
                    port: *port,
                },
                "probe: discovered listening port",
                0,
                Confidence::High,
            ));
        }
    }
}

/// Check if a container runtime is available.
pub fn check_runtime(runtime: ContainerRuntime) -> Result<()> {
    let rt = runtime.to_string();
    let output = Command::new(&rt)
        .arg("version")
        .output()
        .with_context(|| format!("{} not found or not accessible", rt))?;

    if !output.status.success() {
        bail!("{} is not running or not accessible", rt);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_port() {
        assert_eq!(parse_ss_port("LISTEN 0 128 *:8080 *:*"), Some(8080));
        assert_eq!(parse_ss_port("LISTEN 0 128 0.0.0.0:3000 *:*"), Some(3000));
    }

    #[test]
    fn test_runtime_from_str() {
        assert_eq!(
            "docker".parse::<ContainerRuntime>().unwrap(),
            ContainerRuntime::Docker
        );
        assert_eq!(
            "podman".parse::<ContainerRuntime>().unwrap(),
            ContainerRuntime::Podman
        );
        assert!("invalid".parse::<ContainerRuntime>().is_err());
    }

    #[test]
    fn test_merge_evidence_raises_confidence() {
        use crate::parser::PortSpec;

        let mut contract = RuntimeContract {
            exposed_ports: vec![PortSpec {
                port: 8080,
                protocol: "tcp".to_string(),
            }],
            assertions: vec![ContractAssertion::new(
                AssertionKind::PortListening {
                    protocol: "tcp".to_string(),
                    port: 8080,
                },
                "EXPOSE 8080",
                5,
                Confidence::Medium,
            )],
            ..Default::default()
        };

        let evidence = ProbeEvidence {
            listening_ports: vec![(8080, "tcp".to_string())],
            ..Default::default()
        };

        merge_evidence(&mut contract, &evidence);
        assert_eq!(contract.assertions[0].confidence, Confidence::High);
    }

    #[test]
    fn test_validate_run_args_accepts_allowlisted_flags() {
        let args = vec![
            "--read-only".to_string(),
            "--init".to_string(),
            "--env=APP_ENV=prod".to_string(),
            "--cpus=1.5".to_string(),
            "--memory=256m".to_string(),
            "--security-opt=no-new-privileges".to_string(),
            "--ipc=private".to_string(),
        ];
        assert!(validate_run_args(&args, false).is_ok());
    }

    #[test]
    fn test_validate_run_args_rejects_dangerous_flags_in_safe_mode() {
        let args = vec![
            "--privileged".to_string(),
            "--network=host".to_string(),
            "-v=/:/host".to_string(),
        ];
        for arg in args {
            let err = validate_run_args(&[arg], false).unwrap_err().to_string();
            assert!(err.contains("unsafe-run-arg"));
        }
    }

    #[test]
    fn test_validate_run_args_unsafe_mode_allows_anything() {
        let args = vec![
            "--privileged".to_string(),
            "--network=host".to_string(),
            "--volume=/tmp:/tmp".to_string(),
        ];
        assert!(validate_run_args(&args, true).is_ok());
    }

    #[test]
    fn test_run_command_with_timeout_success() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf ok"]);
        let output = run_command_with_timeout(cmd, Duration::from_secs(1)).unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "ok");
    }

    #[test]
    fn test_run_command_with_timeout_kills_hanging_command() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 1"]);
        let err = run_command_with_timeout(cmd, Duration::from_millis(10))
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"));
    }

    #[test]
    fn test_probe_cleanup_drop_is_non_fatal_without_runtime() {
        let cleanup = ProbeCleanup::new(
            "runtime-does-not-exist".to_string(),
            "container".to_string(),
            "image".to_string(),
        );
        cleanup.mark_container_created();
        cleanup.mark_image_created();
    }
}
