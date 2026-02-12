use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input, Select};

use crate::extractor::{AssertionKind, RuntimeContract};
use crate::generator::GeneratorOutput;
use crate::Confidence;

/// Interactive session state.
pub struct InteractiveSession {
    pub primary_port: Option<u16>,
    pub health_path: Option<String>,
    pub health_status: Option<u16>,
    pub confirm_process: bool,
    pub volume_mounts: Vec<String>,
}

/// Run interactive Q&A to refine the contract and generation.
pub fn run_interactive(contract: &RuntimeContract) -> Result<InteractiveSession> {
    println!();
    println!("{}", style("=== dgossgen interactive mode ===").bold().cyan());
    println!();

    // Show inferred contract summary
    print_contract_summary(contract);

    println!();
    println!(
        "{}",
        style("Let's refine the test configuration:").bold()
    );
    println!();

    let mut session = InteractiveSession {
        primary_port: None,
        health_path: None,
        health_status: None,
        confirm_process: true,
        volume_mounts: Vec::new(),
    };

    // Q1: Primary port selection (if multiple)
    if contract.exposed_ports.len() > 1 {
        let port_names: Vec<String> = contract
            .exposed_ports
            .iter()
            .map(|p| format!("{}/{}", p.port, p.protocol))
            .collect();

        let selection = Select::new()
            .with_prompt("Which port is the primary service port?")
            .items(&port_names)
            .default(0)
            .interact()?;

        session.primary_port = Some(contract.exposed_ports[selection].port);
    } else if contract.exposed_ports.len() == 1 {
        session.primary_port = Some(contract.exposed_ports[0].port);
    }

    // Q2: Health endpoint
    if contract.healthcheck.is_none() {
        let has_health = Confirm::new()
            .with_prompt("Does the service have a health endpoint?")
            .default(false)
            .interact()?;

        if has_health {
            let path: String = Input::new()
                .with_prompt("Health endpoint path")
                .default("/healthz".to_string())
                .interact_text()?;

            let status: String = Input::new()
                .with_prompt("Expected HTTP status code")
                .default("200".to_string())
                .interact_text()?;

            session.health_path = Some(path);
            session.health_status = status.parse().ok();
        }
    }

    // Q3: Process assertion
    let process_names: Vec<String> = contract
        .assertions
        .iter()
        .filter_map(|a| match &a.kind {
            AssertionKind::ProcessRunning { name } => Some(name.clone()),
            _ => None,
        })
        .collect();

    if !process_names.is_empty() {
        let confirm = Confirm::new()
            .with_prompt(format!(
                "Assert process is running: {}?",
                process_names.join(", ")
            ))
            .default(true)
            .interact()?;

        session.confirm_process = confirm;
    }

    // Q4: Volume mounts
    if !contract.volumes.is_empty() {
        println!(
            "\n{}",
            style("Declared volumes:").dim()
        );
        for vol in &contract.volumes {
            println!("  - {}", vol);
        }

        let needs_mounts = Confirm::new()
            .with_prompt("Do any volumes require test mounts (to avoid false failures)?")
            .default(false)
            .interact()?;

        if needs_mounts {
            for vol in &contract.volumes {
                let mount = Confirm::new()
                    .with_prompt(format!("Mount {}?", vol))
                    .default(false)
                    .interact()?;

                if mount {
                    session.volume_mounts.push(vol.clone());
                }
            }
        }
    }

    Ok(session)
}

/// Preview generated output and offer accept/edit/regenerate.
pub fn preview_and_confirm(output: &GeneratorOutput) -> Result<UserAction> {
    println!();
    println!(
        "{}",
        style("=== Generated goss.yml ===").bold().green()
    );
    println!("{}", &output.goss_yml);

    if let Some(wait) = &output.goss_wait_yml {
        println!(
            "{}",
            style("=== Generated goss_wait.yml ===").bold().green()
        );
        println!("{}", wait);
    }

    if !output.warnings.is_empty() {
        println!(
            "\n{}",
            style("Warnings:").bold().yellow()
        );
        for w in &output.warnings {
            println!("  - {}", w);
        }
    }

    println!();

    let actions = vec!["Accept", "Edit in $EDITOR", "Regenerate (different strictness)"];
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(&actions)
        .default(0)
        .interact()?;

    match selection {
        0 => Ok(UserAction::Accept),
        1 => Ok(UserAction::Edit),
        2 => Ok(UserAction::Regenerate),
        _ => Ok(UserAction::Accept),
    }
}

/// Actions available after previewing output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAction {
    Accept,
    Edit,
    Regenerate,
}

/// Print a summary of the inferred contract.
fn print_contract_summary(contract: &RuntimeContract) {
    println!(
        "{} {}",
        style("Base image:").dim(),
        contract.base_image
    );

    if let Some(workdir) = &contract.workdir {
        println!("{} {}", style("Working dir:").dim(), workdir);
    }

    if let Some(user) = &contract.user {
        println!("{} {}", style("User:").dim(), user);
    }

    if !contract.exposed_ports.is_empty() {
        let ports: Vec<String> = contract
            .exposed_ports
            .iter()
            .map(|p| format!("{}/{}", p.port, p.protocol))
            .collect();
        println!(
            "{} {}",
            style("Exposed ports:").dim(),
            ports.join(", ")
        );
    }

    if let Some(ep) = &contract.entrypoint {
        println!(
            "{} {}",
            style("Entrypoint:").dim(),
            ep.to_string_lossy()
        );
    }

    if let Some(cmd) = &contract.cmd {
        println!("{} {}", style("CMD:").dim(), cmd.to_string_lossy());
    }

    if contract.healthcheck.is_some() {
        println!(
            "{} {}",
            style("Healthcheck:").dim(),
            style("present").green()
        );
    }

    if !contract.volumes.is_empty() {
        println!(
            "{} {}",
            style("Volumes:").dim(),
            contract.volumes.join(", ")
        );
    }

    let assertion_count = contract.assertions.len();
    let high_confidence = contract
        .assertions
        .iter()
        .filter(|a| a.confidence >= Confidence::High)
        .count();
    println!(
        "{} {} ({} high confidence)",
        style("Assertions:").dim(),
        assertion_count,
        high_confidence
    );
}

/// Open a file in the user's preferred editor.
pub fn open_in_editor(path: &str) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    std::process::Command::new(&editor)
        .arg(path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to open editor '{}': {}", editor, e))?;
    Ok(())
}
