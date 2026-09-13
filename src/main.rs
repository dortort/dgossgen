use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::style;

use dgossgen::cli::{explain, lint, output};
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

    /// Treat informational notes (e.g. confidence-filtered assertions) as
    /// warnings, so any note also yields exit code 2
    #[arg(long)]
    strict_warnings: bool,

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

fn resolve_force_wait(no_wait: bool, force_wait: bool) -> Option<bool> {
    if no_wait {
        Some(false)
    } else if force_wait {
        Some(true)
    } else {
        None
    }
}

type LoadedContract = (
    Profile,
    Vec<(String, String)>,
    PolicyConfig,
    extractor::RuntimeContract,
);

fn load_contract(common: &CommonArgs) -> Result<LoadedContract> {
    let profile = parse_profile(&common.profile)?;
    let build_args = parse_build_args(&common.build_args);
    // Load the policy before extraction so secret redaction is applied as ENV
    // values enter the contract, and validate it up front — a malformed
    // .dgossgen.yml is a hard error, never a silent revert to defaults. The
    // loaded policy is returned so callers reuse it rather than re-reading it.
    let policy = PolicyConfig::load_or_default(&common.context)?;
    let dockerfile = parser::parse_dockerfile(&common.dockerfile)
        .with_context(|| format!("parsing {}", common.dockerfile.display()))?;
    let contract =
        extractor::extract_contract(&dockerfile, common.target.as_deref(), &build_args, &policy);
    Ok((profile, build_args, policy, contract))
}

/// Write the generated files and report notes/warnings on stderr.
///
/// Exit code 2 is reserved for genuine anomalies (`output.warnings`), such as a
/// contract that produced no assertions. Routine confidence-filter skips are
/// carried as `output.notes` and are purely informational — unless the user
/// opts into `strict_warnings`, which promotes notes to warnings for the exit
/// code. Files are always written before the exit code is decided.
fn emit_output(
    output_dir: &Path,
    output: &generator::GeneratorOutput,
    strict_warnings: bool,
) -> Result<ExitCode> {
    for n in &output.notes {
        eprintln!("{} {}", style("note:").cyan(), n);
    }
    for w in &output.warnings {
        eprintln!("{} {}", style("warning:").yellow(), w);
    }

    output::write_output(output_dir, output)?;

    Ok(warning_exit_code(output, strict_warnings))
}

/// Decide the process exit code from a generator result: 2 for a genuine
/// warning (or, under `strict_warnings`, any informational note), else success.
/// This is the single source of truth shared by the interactive and
/// non-interactive paths so they cannot drift.
fn warning_exit_code(output: &generator::GeneratorOutput, strict_warnings: bool) -> ExitCode {
    let anomalous = !output.warnings.is_empty() || (strict_warnings && !output.notes.is_empty());
    if anomalous {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_init(common: CommonArgs, interactive: bool) -> Result<ExitCode> {
    let (profile, _build_args, policy, mut contract) = load_contract(&common)?;
    let force_wait = resolve_force_wait(common.no_wait, common.force_wait);

    let exit_code = if interactive {
        let session = interactive::run_interactive(&contract)?;

        // Apply session overrides
        if !session.confirm_process {
            contract
                .assertions
                .retain(|a| !matches!(a.kind, AssertionKind::ProcessRunning { .. }));
        }

        if let Some(path) = &session.health_path {
            let status = session.health_status.unwrap_or(200);
            contract.assertions.push(extractor::ContractAssertion::new(
                AssertionKind::HttpStatus {
                    url: format!(
                        "http://127.0.0.1:{}{path}",
                        session.primary_port.unwrap_or(80)
                    ),
                    status,
                },
                "interactive: user-provided health endpoint",
                0,
                Confidence::High,
            ));
        }

        // Generate
        let output = generator::generate(&contract, profile, &policy, force_wait);

        // Preview and confirm
        match interactive::preview_and_confirm(&output)? {
            interactive::UserAction::Accept => {}
            interactive::UserAction::Edit => {
                output::write_output(&common.output_dir, &output)?;
                let goss_path = common.output_dir.join("goss.yml");
                interactive::open_in_editor(goss_path.to_str().unwrap_or("goss.yml"))?;
                return Ok(ExitCode::SUCCESS);
            }
            interactive::UserAction::Regenerate => {
                eprintln!("Regeneration with different profiles is available via --profile flag.");
            }
        }

        // The preview already displayed notes and warnings; write the accepted
        // output and let the same exit-code rule as non-interactive mode apply,
        // so --strict-warnings and the empty-contract anomaly are honored here
        // too.
        output::write_output(&common.output_dir, &output)?;
        warning_exit_code(&output, common.strict_warnings)
    } else {
        // Apply CLI overrides for health path
        if let Some(path) = &common.health_path {
            let port = common
                .primary_port
                .unwrap_or_else(|| contract.exposed_ports.first().map(|p| p.port).unwrap_or(80));
            contract.assertions.push(extractor::ContractAssertion::new(
                AssertionKind::HttpStatus {
                    url: format!("http://127.0.0.1:{}{path}", port),
                    status: common.health_status,
                },
                "CLI: --health-path flag",
                0,
                Confidence::High,
            ));
        }

        // Non-interactive generation
        let output = generator::generate(&contract, profile, &policy, force_wait);
        emit_output(&common.output_dir, &output, common.strict_warnings)?
    };

    if common.editor {
        let goss_path = common.output_dir.join("goss.yml");
        interactive::open_in_editor(goss_path.to_str().unwrap_or("goss.yml"))?;
    }

    Ok(exit_code)
}

fn cmd_probe(
    common: CommonArgs,
    runtime: String,
    run_args: Vec<String>,
    unsafe_run_arg: bool,
    allow_network: bool,
) -> Result<ExitCode> {
    // load_contract validates the policy (a malformed .dgossgen.yml is a hard
    // error) before any expensive, side-effecting container work.
    let (profile, build_args, policy, mut contract) = load_contract(&common)?;

    let rt: ContainerRuntime = runtime
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;

    probe::check_runtime(rt)?;

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
        policy: policy.clone(),
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
    let force_wait = resolve_force_wait(common.no_wait, common.force_wait);

    let output = generator::generate(&contract, profile, &policy, force_wait);
    emit_output(&common.output_dir, &output, common.strict_warnings)
}

fn cmd_explain(common: CommonArgs) -> Result<ExitCode> {
    let (_profile, _build_args, _policy, contract) = load_contract(&common)?;

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
            explain::assertion_type_name(&assertion.kind)
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
            explain::assertion_description(&assertion.kind)
        );
        println!();
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_lint(file: PathBuf, wait_file: Option<PathBuf>) -> Result<ExitCode> {
    println!("{}", style("=== dgossgen lint ===").bold().cyan());

    let mut issues: Vec<lint::LintIssue> = Vec::new();

    // Lint main goss.yml
    let content =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;

    lint::lint_goss_content(&content, file.to_str().unwrap_or("goss.yml"), &mut issues);

    // Lint wait file if present
    if let Some(wait_path) = &wait_file {
        // An explicit --wait-file path is a user instruction: a missing file is
        // an error, not a silent skip that would print a false "No issues found."
        let wait_content = std::fs::read_to_string(wait_path)
            .with_context(|| format!("reading {}", wait_path.display()))?;
        lint::lint_goss_content(
            &wait_content,
            wait_path.to_str().unwrap_or("goss_wait.yml"),
            &mut issues,
        );
    } else {
        // Auto-detect goss_wait.yml next to the main file
        let wait_path = file
            .parent()
            .unwrap_or(Path::new("."))
            .join("goss_wait.yml");
        if wait_path.exists() {
            let wait_content = std::fs::read_to_string(&wait_path)?;
            lint::lint_goss_content(&wait_content, "goss_wait.yml", &mut issues);
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
