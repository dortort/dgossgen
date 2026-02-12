use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;

use dgossgen::config::PolicyConfig;
use dgossgen::extractor::{self, AssertionKind};
use dgossgen::generator;
use dgossgen::interactive;
use dgossgen::parser;
use dgossgen::probe::{self, ContainerRuntime, ProbeConfig};
use dgossgen::{Confidence, Profile};

#[derive(Parser)]
#[command(
    name = "dgossgen",
    about = "Generate dgoss-ready test suites from Dockerfiles",
    version,
    long_about = "dgossgen ingests a Dockerfile and outputs a dgoss-ready test suite (goss.yml + optional goss_wait.yml).\n\nIt supports both non-interactive (CI-friendly) and interactive (developer-friendly) modes."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate goss.yml (+ optional goss_wait.yml) from static analysis only
    Init {
        #[command(flatten)]
        common: CommonArgs,

        /// Run in interactive mode (guided Q&A + preview)
        #[arg(short, long)]
        interactive: bool,
    },

    /// Build and run container to collect evidence, then generate test files
    Probe {
        #[command(flatten)]
        common: CommonArgs,

        /// Container runtime to use
        #[arg(long, default_value = "docker")]
        runtime: String,

        /// Additional docker run arguments (quoted string)
        #[arg(long = "run-arg", num_args = 1)]
        run_args: Vec<String>,

        /// Allow unrestricted run arguments (disables safe-mode allowlist)
        #[arg(long)]
        unsafe_run_arg: bool,

        /// Disable network isolation for probe container
        #[arg(long)]
        allow_network: bool,
    },

    /// Print derivation report explaining each assertion
    Explain {
        #[command(flatten)]
        common: CommonArgs,
    },

    /// Validate existing goss YAML and detect likely flakes
    Lint {
        /// Path to goss.yml to lint
        #[arg(default_value = "goss.yml")]
        file: PathBuf,

        /// Path to goss_wait.yml to lint (optional)
        #[arg(long)]
        wait_file: Option<PathBuf>,
    },
}

#[derive(Parser)]
struct CommonArgs {
    /// Path to Dockerfile
    #[arg(short = 'f', long = "dockerfile", default_value = "Dockerfile")]
    dockerfile: PathBuf,

    /// Build context directory
    #[arg(short = 'c', long = "context", default_value = ".")]
    context: PathBuf,

    /// Target build stage
    #[arg(long)]
    target: Option<String>,

    /// Build arguments (KEY=VALUE, repeatable)
    #[arg(long = "build-arg", num_args = 1)]
    build_args: Vec<String>,

    /// Output directory for generated files
    #[arg(short = 'o', long = "output-dir", default_value = ".")]
    output_dir: PathBuf,

    /// Generation profile
    #[arg(long, default_value = "standard")]
    profile: String,

    /// Do not generate goss_wait.yml
    #[arg(long)]
    no_wait: bool,

    /// Force generation of goss_wait.yml even without strong signals
    #[arg(long)]
    force_wait: bool,

    /// Override primary service port
    #[arg(long)]
    primary_port: Option<u16>,

    /// Health check endpoint path (e.g., /healthz)
    #[arg(long)]
    health_path: Option<String>,

    /// Expected HTTP status for health endpoint
    #[arg(long, default_value = "200")]
    health_status: u16,

    /// Force open $EDITOR after generation
    #[arg(long)]
    editor: bool,

    /// Wait retries override
    #[arg(long)]
    wait_retries: Option<u32>,

    /// Wait sleep duration override (e.g., 1s)
    #[arg(long)]
    wait_sleep: Option<String>,

    /// Wait timeout override (e.g., 60s)
    #[arg(long)]
    wait_timeout: Option<String>,
}

fn main() -> ExitCode {
    env_logger::init();

    let cli = Cli::parse();

    match run(cli) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!("{} {:#}", style("error:").red().bold(), err);
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Init {
            common,
            interactive,
        } => cmd_init(common, interactive),
        Commands::Probe {
            common,
            runtime,
            run_args,
            unsafe_run_arg,
            allow_network,
        } => cmd_probe(common, runtime, run_args, unsafe_run_arg, allow_network),
        Commands::Explain { common } => cmd_explain(common),
        Commands::Lint { file, wait_file } => cmd_lint(file, wait_file),
    }
}

fn parse_build_args(args: &[String]) -> Vec<(String, String)> {
    args.iter()
        .filter_map(|a| {
            a.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn parse_profile(s: &str) -> Result<Profile> {
    s.parse::<Profile>().map_err(|e| anyhow::anyhow!("{}", e))
}

fn cmd_init(common: CommonArgs, interactive: bool) -> Result<ExitCode> {
    let profile = parse_profile(&common.profile)?;
    let build_args = parse_build_args(&common.build_args);

    // Parse Dockerfile
    let dockerfile = parser::parse_dockerfile(&common.dockerfile)
        .with_context(|| format!("parsing {}", common.dockerfile.display()))?;

    // Extract contract
    let mut contract =
        extractor::extract_contract(&dockerfile, common.target.as_deref(), &build_args);

    // Load policy
    let policy = PolicyConfig::load_or_default(&common.context);

    // Apply interactive refinement if requested
    let force_wait = if common.no_wait {
        Some(false)
    } else if common.force_wait {
        Some(true)
    } else {
        None
    };

    if interactive {
        let session = interactive::run_interactive(&contract)?;

        // Apply session overrides
        if !session.confirm_process {
            contract
                .assertions
                .retain(|a| !matches!(a.kind, AssertionKind::ProcessRunning { .. }));
        }

        if let Some(path) = &session.health_path {
            let status = session.health_status.unwrap_or(200);
            contract.assertions.push(extractor::ContractAssertion {
                kind: AssertionKind::HttpStatus {
                    url: format!(
                        "http://127.0.0.1:{}{path}",
                        session.primary_port.unwrap_or(80)
                    ),
                    status,
                },
                provenance: "interactive: user-provided health endpoint".to_string(),
                source_line: 0,
                confidence: Confidence::High,
            });
        }

        // Generate
        let output = generator::generate(&contract, profile, &policy, force_wait);

        // Preview and confirm
        match interactive::preview_and_confirm(&output)? {
            interactive::UserAction::Accept => {}
            interactive::UserAction::Edit => {
                write_output(&common.output_dir, &output)?;
                let goss_path = common.output_dir.join("goss.yml");
                interactive::open_in_editor(goss_path.to_str().unwrap_or("goss.yml"))?;
                return Ok(ExitCode::SUCCESS);
            }
            interactive::UserAction::Regenerate => {
                eprintln!("Regeneration with different profiles is available via --profile flag.");
            }
        }

        write_output(&common.output_dir, &output)?;
    } else {
        // Apply CLI overrides for health path
        if let Some(path) = &common.health_path {
            let port = common
                .primary_port
                .unwrap_or_else(|| contract.exposed_ports.first().map(|p| p.port).unwrap_or(80));
            contract.assertions.push(extractor::ContractAssertion {
                kind: AssertionKind::HttpStatus {
                    url: format!("http://127.0.0.1:{}{path}", port),
                    status: common.health_status,
                },
                provenance: "CLI: --health-path flag".to_string(),
                source_line: 0,
                confidence: Confidence::High,
            });
        }

        // Non-interactive generation
        let output = generator::generate(&contract, profile, &policy, force_wait);
        write_output(&common.output_dir, &output)?;

        if !output.warnings.is_empty() {
            for w in &output.warnings {
                eprintln!("{} {}", style("warning:").yellow(), w);
            }
            return Ok(ExitCode::from(2));
        }
    }

    if common.editor {
        let goss_path = common.output_dir.join("goss.yml");
        interactive::open_in_editor(goss_path.to_str().unwrap_or("goss.yml"))?;
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_probe(
    common: CommonArgs,
    runtime: String,
    run_args: Vec<String>,
    unsafe_run_arg: bool,
    allow_network: bool,
) -> Result<ExitCode> {
    let profile = parse_profile(&common.profile)?;
    let build_args = parse_build_args(&common.build_args);

    let rt: ContainerRuntime = runtime
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;

    // Check runtime availability
    probe::check_runtime(rt)?;

    // Phase A: Static analysis
    let dockerfile = parser::parse_dockerfile(&common.dockerfile)?;
    let mut contract =
        extractor::extract_contract(&dockerfile, common.target.as_deref(), &build_args);

    eprintln!(
        "{} Phase A (static analysis) complete: {} assertions",
        style("[1/2]").bold(),
        contract.assertions.len()
    );

    // Phase B: Dynamic probe
    let probe_config = ProbeConfig {
        runtime: rt,
        dockerfile: common.dockerfile.to_string_lossy().to_string(),
        context: common.context.to_string_lossy().to_string(),
        target: common.target.clone(),
        build_args: build_args.clone(),
        run_args,
        allow_unsafe_run_args: unsafe_run_arg,
        network_isolation: !allow_network,
        ..Default::default()
    };

    eprintln!(
        "{} Running probe (build + run + inspect)...",
        style("[2/2]").bold()
    );

    let evidence = probe::run_probe(&probe_config)?;
    probe::merge_evidence(&mut contract, &evidence);

    eprintln!("{}", style("Probe complete. Evidence merged.").green());

    // Generate
    let policy = PolicyConfig::load_or_default(&common.context);
    let force_wait = if common.no_wait {
        Some(false)
    } else if common.force_wait {
        Some(true)
    } else {
        None
    };

    let output = generator::generate(&contract, profile, &policy, force_wait);
    write_output(&common.output_dir, &output)?;

    if !output.warnings.is_empty() {
        for w in &output.warnings {
            eprintln!("{} {}", style("warning:").yellow(), w);
        }
        return Ok(ExitCode::from(2));
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_explain(common: CommonArgs) -> Result<ExitCode> {
    let build_args = parse_build_args(&common.build_args);

    let dockerfile = parser::parse_dockerfile(&common.dockerfile)?;
    let contract = extractor::extract_contract(&dockerfile, common.target.as_deref(), &build_args);

    println!("{}", style("=== dgossgen explain ===").bold().cyan());
    println!();
    println!("{} {}", style("Base image:").bold(), contract.base_image);
    println!(
        "{} {}",
        style("Total assertions:").bold(),
        contract.assertions.len()
    );
    println!();

    for (i, assertion) in contract.assertions.iter().enumerate() {
        println!("{}", style(format!("--- Assertion #{} ---", i + 1)).bold());
        println!(
            "  {}: {}",
            style("Type").dim(),
            assertion_type_name(&assertion.kind)
        );
        println!("  {}: {}", style("Provenance").dim(), assertion.provenance);
        println!(
            "  {}: line {}",
            style("Source").dim(),
            assertion.source_line
        );
        println!("  {}: {}", style("Confidence").dim(), assertion.confidence);
        println!(
            "  {}: {}",
            style("Description").dim(),
            assertion_description(&assertion.kind)
        );
        println!();
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_lint(file: PathBuf, wait_file: Option<PathBuf>) -> Result<ExitCode> {
    println!("{}", style("=== dgossgen lint ===").bold().cyan());

    let mut issues = Vec::new();

    // Lint main goss.yml
    let content =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;

    lint_goss_content(&content, file.to_str().unwrap_or("goss.yml"), &mut issues);

    // Lint wait file if present
    if let Some(wait_path) = &wait_file {
        if wait_path.exists() {
            let wait_content = std::fs::read_to_string(wait_path)
                .with_context(|| format!("reading {}", wait_path.display()))?;
            lint_goss_content(
                &wait_content,
                wait_path.to_str().unwrap_or("goss_wait.yml"),
                &mut issues,
            );
        }
    } else {
        // Auto-detect goss_wait.yml next to the main file
        let wait_path = file
            .parent()
            .unwrap_or(Path::new("."))
            .join("goss_wait.yml");
        if wait_path.exists() {
            let wait_content = std::fs::read_to_string(&wait_path)?;
            lint_goss_content(&wait_content, "goss_wait.yml", &mut issues);
        }
    }

    if issues.is_empty() {
        println!("{}", style("No issues found.").green());
        Ok(ExitCode::SUCCESS)
    } else {
        for issue in &issues {
            println!(
                "{} [{}] {}",
                style("warning:").yellow(),
                issue.file,
                issue.message
            );
        }
        println!(
            "\n{} issue(s) found.",
            style(issues.len().to_string()).yellow().bold()
        );
        Ok(ExitCode::from(2))
    }
}

struct LintIssue {
    file: String,
    message: String,
}

fn lint_goss_content(content: &str, filename: &str, issues: &mut Vec<LintIssue>) {
    // Check YAML validity
    let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(content);
    if parsed.is_err() {
        issues.push(LintIssue {
            file: filename.to_string(),
            message: "Invalid YAML syntax".to_string(),
        });
        return;
    }

    let doc = parsed.unwrap();

    // Check for common flake patterns
    if let Some(mapping) = doc.as_mapping() {
        // Check for ephemeral paths
        if let Some(files) = mapping.get(serde_yaml::Value::String("file".to_string())) {
            if let Some(file_map) = files.as_mapping() {
                for (key, _) in file_map {
                    if let Some(path) = key.as_str() {
                        if path.contains("/tmp/")
                            || path.contains("/var/cache/")
                            || path.contains("/proc/")
                        {
                            issues.push(LintIssue {
                                file: filename.to_string(),
                                message: format!(
                                    "File assertion on ephemeral path '{}' may be flaky",
                                    path
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Check for process assertions (often flaky)
        if let Some(processes) = mapping.get(serde_yaml::Value::String("process".to_string())) {
            if let Some(proc_map) = processes.as_mapping() {
                if proc_map.len() > 3 {
                    issues.push(LintIssue {
                        file: filename.to_string(),
                        message: "Many process assertions (>3) increase flake risk".to_string(),
                    });
                }
            }
        }

        // Check command timeouts
        if let Some(commands) = mapping.get(serde_yaml::Value::String("command".to_string())) {
            if let Some(cmd_map) = commands.as_mapping() {
                for (key, val) in cmd_map {
                    if let Some(cmd_val) = val.as_mapping() {
                        let timeout = cmd_val
                            .get(serde_yaml::Value::String("timeout".to_string()))
                            .and_then(|v| v.as_u64());

                        if timeout.is_none() || timeout == Some(0) {
                            if let Some(name) = key.as_str() {
                                issues.push(LintIssue {
                                    file: filename.to_string(),
                                    message: format!(
                                        "Command '{}' has no timeout (may hang)",
                                        name
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

fn assertion_type_name(kind: &AssertionKind) -> &'static str {
    match kind {
        AssertionKind::FileExists { .. } => "file",
        AssertionKind::PortListening { .. } => "port",
        AssertionKind::ProcessRunning { .. } => "process",
        AssertionKind::CommandExit { .. } => "command",
        AssertionKind::CommandOutput { .. } => "command (with output)",
        AssertionKind::UserExists { .. } => "user",
        AssertionKind::HealthcheckPasses { .. } => "healthcheck",
        AssertionKind::HttpStatus { .. } => "http",
        AssertionKind::PackageInstalled { .. } => "package",
    }
}

fn assertion_description(kind: &AssertionKind) -> String {
    match kind {
        AssertionKind::FileExists {
            path,
            filetype,
            mode,
        } => {
            let mut desc = format!("File '{}' exists", path);
            if let Some(ft) = filetype {
                desc.push_str(&format!(" (type: {})", ft));
            }
            if let Some(m) = mode {
                desc.push_str(&format!(" (mode: {})", m));
            }
            desc
        }
        AssertionKind::PortListening { protocol, port } => {
            format!("Port {}/{} is listening", port, protocol)
        }
        AssertionKind::ProcessRunning { name } => {
            format!("Process '{}' is running", name)
        }
        AssertionKind::CommandExit {
            command,
            exit_status,
        } => {
            format!("Command '{}' exits with status {}", command, exit_status)
        }
        AssertionKind::CommandOutput {
            command,
            exit_status,
            expected_output,
        } => {
            format!(
                "Command '{}' exits with status {} and outputs {:?}",
                command, exit_status, expected_output
            )
        }
        AssertionKind::UserExists { username } => {
            format!("User '{}' exists", username)
        }
        AssertionKind::HealthcheckPasses { command } => {
            format!("Healthcheck '{}' passes", command)
        }
        AssertionKind::HttpStatus { url, status } => {
            format!("HTTP {} returns status {}", url, status)
        }
        AssertionKind::PackageInstalled {
            package, manager, ..
        } => {
            format!("Package '{}' installed via {:?}", package, manager)
        }
    }
}

fn write_output(output_dir: &Path, output: &generator::GeneratorOutput) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating output directory {}", output_dir.display()))?;

    let goss_path = output_dir.join("goss.yml");
    std::fs::write(&goss_path, &output.goss_yml)
        .with_context(|| format!("writing {}", goss_path.display()))?;
    eprintln!("{} {}", style("wrote").green(), goss_path.display());

    if let Some(wait_content) = &output.goss_wait_yml {
        let wait_path = output_dir.join("goss_wait.yml");
        std::fs::write(&wait_path, wait_content)
            .with_context(|| format!("writing {}", wait_path.display()))?;
        eprintln!("{} {}", style("wrote").green(), wait_path.display());
    }

    Ok(())
}
