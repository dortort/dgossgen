/// Represents a parsed Dockerfile.
#[derive(Debug, Clone)]
pub struct Dockerfile {
    pub stages: Vec<Stage>,
}

impl Dockerfile {
    /// Get the final (target) stage, or a named stage.
    pub fn resolve_target(&self, target: Option<&str>) -> Option<&Stage> {
        match target {
            Some(name) => self.stages.iter().find(|s| {
                s.alias
                    .as_ref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(name))
            }),
            None => self.stages.last(),
        }
    }

    /// Get all stage aliases for COPY --from resolution.
    pub fn stage_aliases(&self) -> Vec<String> {
        self.stages.iter().filter_map(|s| s.alias.clone()).collect()
    }
}

/// A single build stage (one FROM ... block).
#[derive(Debug, Clone)]
pub struct Stage {
    pub image: String,
    pub alias: Option<String>,
    pub from_line: usize,
    pub instructions: Vec<RawInstruction>,
}

/// A parsed Dockerfile instruction with its source line number and raw text.
#[derive(Debug, Clone)]
pub struct RawInstruction {
    pub line_number: usize,
    pub instruction: Instruction,
    pub raw: String,
}

/// The instruction types we handle for contract extraction.
#[derive(Debug, Clone)]
pub enum Instruction {
    From {
        image: String,
        alias: Option<String>,
    },
    Arg {
        name: String,
        default: Option<String>,
    },
    Env(Vec<(String, String)>),
    Workdir(String),
    User(String),
    Expose(Vec<PortSpec>),
    Volume(Vec<String>),
    Copy {
        from_stage: Option<String>,
        sources: Vec<String>,
        dest: String,
        chmod: Option<String>,
    },
    Add {
        sources: Vec<String>,
        dest: String,
        chmod: Option<String>,
    },
    Run(CommandForm),
    Entrypoint(CommandForm),
    Cmd(CommandForm),
    Healthcheck {
        cmd: CommandForm,
        interval: Option<String>,
        timeout: Option<String>,
        start_period: Option<String>,
        retries: Option<u32>,
    },
    HealthcheckNone,
    Shell(Vec<String>),
}

/// EXPOSE port specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub port: u16,
    pub protocol: String,
}

/// Exec form vs shell form for CMD/ENTRYPOINT/RUN.
#[derive(Debug, Clone)]
pub enum CommandForm {
    Exec(Vec<String>),
    Shell(String),
}

impl CommandForm {
    /// Get the command as a flat string.
    pub fn to_string_lossy(&self) -> String {
        match self {
            CommandForm::Exec(parts) => parts.join(" "),
            CommandForm::Shell(s) => s.clone(),
        }
    }

    /// Try to extract the primary binary name.
    pub fn primary_binary(&self) -> Option<String> {
        match self {
            CommandForm::Exec(parts) => parts.first().and_then(|p| {
                std::path::Path::new(p)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            }),
            CommandForm::Shell(s) => {
                // Try to find the first command in a shell string
                let trimmed = s.trim();
                let first_word = trimmed.split_whitespace().next()?;
                std::path::Path::new(first_word)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            }
        }
    }
}
