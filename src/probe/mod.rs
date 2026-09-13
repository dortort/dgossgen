use anyhow::{bail, Context, Result};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::{PolicyConfig, REDACTED_PLACEHOLDER};
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
    /// Policy governing secret redaction of collected environment variables.
    pub policy: PolicyConfig,
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
            policy: PolicyConfig::default(),
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
    /// Environment variables, with values redacted for keys the policy
    /// classifies as secrets (see [`collect_evidence`]). The container's
    /// runtime env can include secrets injected via `--env`/`--env-file`, so
    /// this collection is sanitized at the point of capture.
    pub env_vars: Vec<(String, String)>,
    /// Image inspect data, sanitized before storage: `Env` arrays are redacted
    /// by key and any secret value collected from the container's env is
    /// scrubbed from all string fields (see `collect_evidence`), so no cleartext
    /// secret is retained even in secret-derived fields such as `WorkingDir`.
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
    collect_evidence(
        &rt,
        &container_name,
        &image_tag,
        config.timeout,
        &config.policy,
    )
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
    policy: &PolicyConfig,
) -> Result<ProbeEvidence> {
    let mut evidence = ProbeEvidence::default();

    // Inspect the image. Redaction of the parsed JSON is deferred to the end of
    // this function: `image inspect` can echo secret values both structurally
    // (`Config.Env`) and as substrings of *derived* fields (e.g. a
    // `Config.WorkingDir` of `/hunter2` produced by `WORKDIR /$DB_PASSWORD`),
    // and scrubbing the latter needs the concrete secret values, which are only
    // known once the container's env has been collected below.
    let mut inspect_val: Option<serde_json::Value> = None;
    let mut inspect_cmd = Command::new(runtime);
    inspect_cmd.args(["image", "inspect", image]);
    let inspect_output =
        run_command_with_timeout(inspect_cmd, timeout).with_context(|| "image inspect")?;

    if inspect_output.status.success() {
        let json_str = String::from_utf8_lossy(&inspect_output.stdout);
        inspect_val = serde_json::from_str::<serde_json::Value>(&json_str).ok();
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

    // Check env, redacting secret values at the point of capture. The concrete
    // secret values are also retained (locally, never stored) so they can be
    // scrubbed out of the image-inspect JSON below.
    let mut secret_values: Vec<String> = Vec::new();
    let mut env_cmd = Command::new(runtime);
    env_cmd.args(["exec", container, "env"]);
    let env_output = run_command_with_timeout(env_cmd, timeout);

    if let Ok(output) = env_output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            evidence.env_vars = parse_env_output(&text, policy);
            secret_values = secret_values_from_env(&text, policy);
        }
    }

    // Now that the secret values are known, sanitize the deferred inspect JSON
    // both structurally (Env arrays) and by value (derived fields such as
    // WorkingDir) before it is stored, so `image_config` carries no cleartext.
    if let Some(mut val) = inspect_val.take() {
        // Also harvest secret values baked into the image's own `Env` arrays,
        // so derived fields (WorkingDir, ExposedPorts, ...) are scrubbed even
        // when the runtime value was overridden via `--env`, or when the exec
        // `env` failed entirely (e.g. a scratch/distroless image).
        collect_secret_values_from_inspect(&val, policy, &mut secret_values);
        let secret_values = dedup_longest_first(secret_values);

        redact_inspect_env(&mut val, policy);
        scrub_secret_values(&mut val, &secret_values);
        evidence.image_config = Some(val);
    }

    Ok(evidence)
}

/// Collect the concrete cleartext values of secret-keyed entries found in any
/// `Env` array within `image inspect` JSON, appending them to `out`. These are
/// the secrets baked into the image itself, which may differ from (or be absent
/// in) the container's runtime env.
fn collect_secret_values_from_inspect(
    value: &serde_json::Value,
    policy: &PolicyConfig,
    out: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "Env" {
                    if let serde_json::Value::Array(items) = child {
                        for item in items {
                            if let serde_json::Value::String(pair) = item {
                                if let Some((k, v)) = pair.split_once('=') {
                                    if !v.is_empty() && policy.is_secret_key(k) {
                                        out.push(v.to_string());
                                    }
                                }
                            }
                        }
                    }
                } else {
                    collect_secret_values_from_inspect(child, policy, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_values_from_inspect(item, policy, out);
            }
        }
        _ => {}
    }
}

/// Deduplicate secret needles and order them longest-first. Longest-first makes
/// substring replacement overlap-safe: when one secret is a prefix of another
/// (`abc` and `abcdef`), replacing the longer one first prevents a partial
/// redaction (`***REDACTED***def`) that could leak the tail of the longer secret.
fn dedup_longest_first(mut secrets: Vec<String>) -> Vec<String> {
    secrets.sort();
    secrets.dedup();
    secrets.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    secrets
}

/// Extract the concrete cleartext values of secret-keyed environment variables
/// from raw `env` output. Empty values are skipped (nothing to scrub, and an
/// empty needle would match everywhere). Used only to scrub secrets out of the
/// image-inspect JSON; the returned values are never stored in evidence.
fn secret_values_from_env(text: &str, policy: &PolicyConfig) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, value)| !value.is_empty() && policy.is_secret_key(key))
        .map(|(_, value)| value.to_string())
        .collect()
}

/// Replace every occurrence of a known secret value with [`REDACTED_PLACEHOLDER`]
/// across all string values *and object keys* of a JSON tree. This catches
/// secret-*derived* fields that key-based redaction cannot see — a
/// `Config.WorkingDir` of `/hunter2` from `WORKDIR /$DB_PASSWORD`, or an
/// `ExposedPorts` map keyed `8123/tcp` from `EXPOSE $SECRET_PORT`. `secrets`
/// must be ordered longest-first (see [`dedup_longest_first`]) so overlapping
/// needles redact fully. It may over-redact when a secret value coincides with
/// an unrelated substring, which is the safe direction for an evidence blob that
/// is retained but never emitted.
fn scrub_secret_values(value: &mut serde_json::Value, secrets: &[String]) {
    if secrets.is_empty() {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            // Rebuild the map so secret substrings in keys are redacted too.
            let mut rebuilt = serde_json::Map::with_capacity(map.len());
            for (key, mut child) in std::mem::take(map) {
                scrub_secret_values(&mut child, secrets);
                rebuilt.insert(redact_secrets_in_str(&key, secrets), child);
            }
            *map = rebuilt;
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                scrub_secret_values(item, secrets);
            }
        }
        serde_json::Value::String(s) => {
            *s = redact_secrets_in_str(s, secrets);
        }
        _ => {}
    }
}

/// Replace every occurrence of each secret needle in `s` with the placeholder.
/// `secrets` is expected longest-first so overlapping needles redact fully.
fn redact_secrets_in_str(s: &str, secrets: &[String]) -> String {
    let mut out = s.to_string();
    for secret in secrets {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), REDACTED_PLACEHOLDER);
        }
    }
    out
}

/// Recursively redact secret values inside `image inspect` JSON. Any object key
/// named `Env` holding an array of `KEY=VALUE` strings (Docker exposes the image
/// env at `Config.Env` and `ContainerConfig.Env`) has each secret-keyed entry's
/// value replaced with [`REDACTED_PLACEHOLDER`], leaving keys and structure
/// intact. This keeps [`ProbeEvidence::image_config`] free of cleartext secrets.
fn redact_inspect_env(value: &mut serde_json::Value, policy: &PolicyConfig) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key == "Env" {
                    if let serde_json::Value::Array(items) = child {
                        for item in items.iter_mut() {
                            if let serde_json::Value::String(pair) = item {
                                if let Some((k, _)) = pair.split_once('=') {
                                    if policy.is_secret_key(k) {
                                        *pair = format!("{k}={REDACTED_PLACEHOLDER}");
                                    }
                                }
                            }
                        }
                    }
                } else {
                    redact_inspect_env(child, policy);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_inspect_env(item, policy);
            }
        }
        _ => {}
    }
}

/// Parse `env` command output into key/value pairs, redacting the value of any
/// key the policy classifies as a secret. This is the enforcement point that
/// keeps [`ProbeEvidence::env_vars`] sanitized regardless of what the container
/// exposes (Dockerfile `ENV` values or secrets injected via `--env`/`--env-file`).
fn parse_env_output(text: &str, policy: &PolicyConfig) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, val)| {
            let value = if policy.is_secret_key(key) {
                REDACTED_PLACEHOLDER.to_string()
            } else {
                val.to_string()
            };
            (key.to_string(), value)
        })
        .collect()
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
            AssertionKind::ProcessRunning { name }
                if evidence
                    .running_processes
                    .iter()
                    .any(|p| p.contains(name.as_str())) =>
            {
                assertion.confidence = Confidence::High;
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
    fn test_parse_env_output_redacts_secrets() {
        // A value whose whole line contains '=' (e.g. a base64 token) must split
        // only on the first '='; non-secret keys are preserved verbatim while
        // secret-keyed values are replaced, never stored.
        let raw = "PATH=/usr/bin\nAPI_TOKEN=abc123\nDB_PASSWORD=p=a=ss\nLANG=C.UTF-8\n";
        let vars = parse_env_output(raw, &PolicyConfig::default());

        let get = |k: &str| {
            vars.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("PATH"), Some("/usr/bin"));
        assert_eq!(get("LANG"), Some("C.UTF-8"));
        assert_eq!(get("API_TOKEN"), Some(REDACTED_PLACEHOLDER));
        assert_eq!(get("DB_PASSWORD"), Some(REDACTED_PLACEHOLDER));
        assert!(
            !vars
                .iter()
                .any(|(_, v)| v.contains("abc123") || v.contains("p=a=ss")),
            "no secret value may survive in collected env_vars"
        );
    }

    #[test]
    fn test_redact_inspect_env_sanitizes_config_env() {
        // Mirrors `docker image inspect` shape: a top-level array of objects,
        // each with Config.Env and ContainerConfig.Env holding KEY=VALUE strings.
        let mut val = serde_json::json!([{
            "Config": { "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2"] },
            "ContainerConfig": { "Env": ["API_TOKEN=abc123", "LANG=C.UTF-8"] }
        }]);
        redact_inspect_env(&mut val, &PolicyConfig::default());

        let dumped = serde_json::to_string(&val).unwrap();
        assert!(!dumped.contains("hunter2"), "secret leaked in Config.Env");
        assert!(
            !dumped.contains("abc123"),
            "secret leaked in ContainerConfig.Env"
        );
        // Non-secret entries and the keys of secret entries are preserved.
        assert!(dumped.contains("PATH=/usr/bin"));
        assert!(dumped.contains("LANG=C.UTF-8"));
        assert!(dumped.contains("DB_PASSWORD=***REDACTED***"));
        assert!(dumped.contains("API_TOKEN=***REDACTED***"));
    }

    #[test]
    fn test_secret_values_from_env_extracts_nonempty_secret_values() {
        let raw = "PATH=/usr/bin\nDB_PASSWORD=hunter2\nAPI_TOKEN=abc123\nEMPTY_SECRET_KEY=\n";
        let mut values = secret_values_from_env(raw, &PolicyConfig::default());
        values.sort();
        // Only non-empty, secret-keyed values; PATH excluded, empty value skipped.
        assert_eq!(values, vec!["abc123".to_string(), "hunter2".to_string()]);
    }

    #[test]
    fn test_scrub_secret_values_redacts_derived_inspect_fields() {
        // A secret substituted into a non-Env field (WorkingDir from
        // `WORKDIR /$DB_PASSWORD`) must be scrubbed even though its key is not "Env".
        let mut val = serde_json::json!([{
            "Config": {
                "WorkingDir": "/hunter2",
                "Env": ["PATH=/usr/bin"],
                "Labels": { "build": "commit-hunter2-1" }
            }
        }]);
        scrub_secret_values(&mut val, &["hunter2".to_string()]);

        let dumped = serde_json::to_string(&val).unwrap();
        assert!(
            !dumped.contains("hunter2"),
            "secret leaked in a derived field"
        );
        assert!(dumped.contains("/***REDACTED***"));
        assert!(dumped.contains("commit-***REDACTED***-1"));
        // Unrelated data is preserved.
        assert!(dumped.contains("PATH=/usr/bin"));
    }

    #[test]
    fn test_scrub_secret_values_noop_when_no_secrets() {
        let mut val = serde_json::json!({"WorkingDir": "/app"});
        scrub_secret_values(&mut val, &[]);
        assert_eq!(val, serde_json::json!({"WorkingDir": "/app"}));
    }

    #[test]
    fn test_collect_secret_values_from_inspect_harvests_baked_env() {
        // Baked image secrets must be harvested from Config.Env and
        // ContainerConfig.Env (used to scrub derived fields even when the
        // runtime env differs or the exec `env` failed). Empty values skipped.
        let val = serde_json::json!([{
            "Config": { "Env": ["PATH=/usr/bin", "DB_PASSWORD=baked1", "EMPTY_TOKEN="] },
            "ContainerConfig": { "Env": ["API_TOKEN=baked2"] }
        }]);
        let mut out = Vec::new();
        collect_secret_values_from_inspect(&val, &PolicyConfig::default(), &mut out);
        out.sort();
        assert_eq!(out, vec!["baked1".to_string(), "baked2".to_string()]);
    }

    #[test]
    fn test_dedup_longest_first_orders_and_dedups() {
        let ordered = dedup_longest_first(vec![
            "abc".to_string(),
            "abcdef".to_string(),
            "abc".to_string(),
        ]);
        assert_eq!(ordered, vec!["abcdef".to_string(), "abc".to_string()]);
    }

    #[test]
    fn test_scrub_secret_values_handles_overlapping_secrets() {
        // With `abc` a prefix of `abcdef`, naive in-order replacement would
        // leave `***REDACTED***def`, leaking the tail. Longest-first ordering
        // (dedup_longest_first) must fully redact the longer secret.
        let secrets = dedup_longest_first(vec!["abc".to_string(), "abcdef".to_string()]);
        let mut val = serde_json::json!({ "WorkingDir": "/abcdef" });
        scrub_secret_values(&mut val, &secrets);
        assert_eq!(val, serde_json::json!({ "WorkingDir": "/***REDACTED***" }));
    }

    #[test]
    fn test_scrub_secret_values_redacts_object_keys() {
        // `EXPOSE $SECRET_PORT` lands the secret value in an ExposedPorts map
        // *key* (e.g. "8123/tcp"), which value-only traversal would miss.
        let secrets = dedup_longest_first(vec!["8123".to_string()]);
        let mut val = serde_json::json!({
            "Config": { "ExposedPorts": { "8123/tcp": {} } }
        });
        scrub_secret_values(&mut val, &secrets);
        let dumped = serde_json::to_string(&val).unwrap();
        assert!(!dumped.contains("8123"), "secret leaked in an object key");
        assert!(dumped.contains("***REDACTED***/tcp"));
    }

    #[test]
    fn test_parse_env_output_honors_custom_patterns() {
        let policy = PolicyConfig {
            secret_patterns: vec!["INTERNAL".to_string()],
            ..PolicyConfig::default()
        };
        let raw = "INTERNAL_URL=https://svc.internal\nAPI_TOKEN=abc123\n";
        let vars = parse_env_output(raw, &policy);

        let get = |k: &str| {
            vars.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("INTERNAL_URL"), Some(REDACTED_PLACEHOLDER));
        // TOKEN is a default pattern but not in the custom list, so it is kept.
        assert_eq!(get("API_TOKEN"), Some("abc123"));
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
