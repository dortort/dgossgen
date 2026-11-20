pub mod cli;
pub mod config;
pub mod extractor;
pub mod generator;
pub mod interactive;
pub mod parser;
pub mod probe;

/// Confidence level for generated assertions.
/// Higher confidence means lower risk of flaky tests.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}

/// Strictness profile for generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Profile {
    Minimal,
    Standard,
    Strict,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Minimal => write!(f, "minimal"),
            Profile::Standard => write!(f, "standard"),
            Profile::Strict => write!(f, "strict"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(Profile::Minimal),
            "standard" => Ok(Profile::Standard),
            "strict" => Ok(Profile::Strict),
            _ => Err(format!("unknown profile: {s}")),
        }
    }
}

/// Transport protocol for an exposed port. goss port addresses only understand
/// `tcp` and `udp`, so this enum replaces the previously stringly-typed
/// protocol suffix and guarantees a valid address key is always emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(format!("unknown protocol: {s}")),
        }
    }
}

/// Whether a `FileExists` assertion targets a regular file or a directory.
/// `Display` emits the exact strings goss expects in a `filetype:` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::File => write!(f, "file"),
            FileType::Directory => write!(f, "directory"),
        }
    }
}
