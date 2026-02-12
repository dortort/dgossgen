pub mod config;
pub mod extractor;
pub mod generator;
pub mod interactive;
pub mod parser;
pub mod probe;

/// Confidence level for generated assertions.
/// Higher confidence means lower risk of flaky tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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
