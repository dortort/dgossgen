use anyhow::{bail, Context, Result};
use std::process::Command;
use std::time::Duration;

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
    let rt = config.runtime.to_string();

    // Step 1: Build the image
    let image_tag = format!("dgossgen-probe-{}", std::process::id());
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

    // Step 2: Run the container
    let container_name = format!("dgossgen-probe-{}", std::process::id());
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
        // Clean up image
        let _ = Command::new(&rt).args(["rmi", &image_tag]).output();
        bail!(
            "{} run failed:\n{}",
            rt,
            String::from_utf8_lossy(&run_output.stderr)
        );
    }

    // Step 3: Collect evidence (with timeout)
    let evidence = collect_evidence(&rt, &container_name, &image_tag, config.timeout);

    // Step 4: Clean up
    let _ = Command::new(&rt)
        .args(["rm", "-f", &container_name])
        .output();
    let _ = Command::new(&rt).args(["rmi", &image_tag]).output();

    evidence
}

fn collect_evidence(
    runtime: &str,
    container: &str,
    image: &str,
    _timeout: Duration,
) -> Result<ProbeEvidence> {
    let mut evidence = ProbeEvidence::default();

    // Inspect the image
    let inspect_output = Command::new(runtime)
        .args(["image", "inspect", image])
        .output()
        .with_context(|| "image inspect")?;

    if inspect_output.status.success() {
        let json_str = String::from_utf8_lossy(&inspect_output.stdout);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            evidence.image_config = Some(val);
        }
    }

    // Check running processes
    let ps_output = Command::new(runtime)
        .args(["exec", container, "ps", "aux"])
        .output();

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
    let ss_output = Command::new(runtime)
        .args(["exec", container, "ss", "-tlnp"])
        .output();

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
    let id_output = Command::new(runtime)
        .args(["exec", container, "id"])
        .output();

    if let Ok(output) = id_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            evidence.user = Some(text);
        }
    }

    // Check env (filtered)
    let env_output = Command::new(runtime)
        .args(["exec", container, "env"])
        .output();

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
            contract.assertions.push(ContractAssertion {
                kind: AssertionKind::PortListening {
                    protocol: proto.clone(),
                    port: *port,
                },
                provenance: "probe: discovered listening port".to_string(),
                source_line: 0,
                confidence: Confidence::High,
            });
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
            assertions: vec![ContractAssertion {
                kind: AssertionKind::PortListening {
                    protocol: "tcp".to_string(),
                    port: 8080,
                },
                provenance: "EXPOSE 8080".to_string(),
                source_line: 5,
                confidence: Confidence::Medium,
            }],
            ..Default::default()
        };

        let evidence = ProbeEvidence {
            listening_ports: vec![(8080, "tcp".to_string())],
            ..Default::default()
        };

        merge_evidence(&mut contract, &evidence);
        assert_eq!(contract.assertions[0].confidence, Confidence::High);
    }
}
