use crate::parser::{CommandForm, PortSpec};
use crate::Confidence;

/// The Runtime Contract Model (RCM) extracted from a Dockerfile.
/// Represents everything we know about the container's expected runtime behavior.
#[derive(Debug, Clone, Default)]
pub struct RuntimeContract {
    /// Base image of the target stage
    pub base_image: String,
    /// Working directory
    pub workdir: Option<String>,
    /// Runtime user
    pub user: Option<String>,
    /// Environment variables (key, value)
    pub env: Vec<(String, String)>,
    /// Exposed ports
    pub exposed_ports: Vec<PortSpec>,
    /// Declared volumes
    pub volumes: Vec<String>,
    /// ENTRYPOINT command
    pub entrypoint: Option<CommandForm>,
    /// CMD command
    pub cmd: Option<CommandForm>,
    /// Healthcheck configuration
    pub healthcheck: Option<HealthcheckInfo>,
    /// Filesystem paths that should exist
    pub filesystem_paths: Vec<String>,
    /// Detected installed components (nginx, node, python, etc.)
    pub installed_components: Vec<InstalledComponent>,
    /// All generated assertions with provenance
    pub assertions: Vec<ContractAssertion>,
}

/// Healthcheck details from the Dockerfile.
#[derive(Debug, Clone)]
pub struct HealthcheckInfo {
    pub cmd: CommandForm,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub start_period: Option<String>,
    pub retries: Option<u32>,
}

/// A detected installed component.
#[derive(Debug, Clone)]
pub struct InstalledComponent {
    pub name: String,
    pub kind: ComponentKind,
    pub source_line: usize,
}

/// Kind of installed component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentKind {
    WebServer,
    Runtime,
    Database,
    Tool,
    Package,
}

/// A single assertion in the contract with metadata.
#[derive(Debug, Clone)]
pub struct ContractAssertion {
    /// What to assert
    pub kind: AssertionKind,
    /// Where this assertion was derived from (e.g., "EXPOSE 8080")
    pub provenance: String,
    /// Source line number in the Dockerfile
    pub source_line: usize,
    /// Confidence level
    pub confidence: Confidence,
}

impl ContractAssertion {
    pub fn new(
        kind: AssertionKind,
        provenance: impl Into<String>,
        source_line: usize,
        confidence: Confidence,
    ) -> Self {
        Self {
            kind,
            provenance: provenance.into(),
            source_line,
            confidence,
        }
    }
}

/// Types of assertions that can be generated.
#[derive(Debug, Clone)]
pub enum AssertionKind {
    FileExists {
        path: String,
        filetype: Option<String>,
        mode: Option<String>,
    },
    PortListening {
        protocol: String,
        port: u16,
    },
    ProcessRunning {
        name: String,
    },
    CommandExit {
        command: String,
        exit_status: i32,
    },
    CommandOutput {
        command: String,
        exit_status: i32,
        expected_output: Vec<String>,
    },
    UserExists {
        username: String,
    },
    HealthcheckPasses {
        command: String,
    },
    HttpStatus {
        url: String,
        status: u16,
    },
    /// A package that should be installed, verified via the package manager.
    PackageInstalled {
        /// Package name as given to the package manager
        package: String,
        /// Package manager used to install it (apt, apk, pip, npm)
        manager: PackageManager,
        /// Optional enrichment: a known version-check command (e.g. "nginx -v")
        version_cmd: Option<String>,
    },
}

/// Supported package managers for installed-package assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Apk,
    Pip,
    Npm,
    Composer,
}

/// Check whether a binary name refers to a shell interpreter.
/// Handles both bare names ("sh", "bash") and absolute paths ("/bin/sh", "/usr/bin/bash").
pub(crate) fn is_shell_interpreter(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    matches!(base, "sh" | "bash" | "dash" | "zsh" | "ash")
}
