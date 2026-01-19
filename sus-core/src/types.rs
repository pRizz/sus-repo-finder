//! Shared type definitions for Sus Repo Finder

use serde::{Deserialize, Serialize};

/// Severity level for detected patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity - commonly benign patterns worth noting
    Low,
    /// Medium severity - suspicious but possibly legitimate
    Medium,
    /// High severity - potentially malicious behavior
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Types of suspicious patterns that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueType {
    /// Network calls (reqwest, std::net, hyper, curl)
    Network,
    /// File system access outside expected paths
    FileAccess,
    /// Shell command execution
    ShellCommand,
    /// Process spawning
    ProcessSpawn,
    /// Environment variable access
    EnvAccess,
    /// Dynamic library loading
    DynamicLib,
    /// Unsafe blocks (especially large or suspicious ones)
    UnsafeBlock,
    /// Build-time downloads
    BuildDownload,
    /// Sensitive path access (~/.ssh, ~/.aws, etc.)
    SensitivePath,
    /// Obfuscation patterns (base64, hex encoding)
    Obfuscation,
    /// Compiler/linker flag manipulation
    CompilerFlags,
    /// Macro-based code generation that writes files
    MacroCodegen,
}

impl std::fmt::Display for IssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueType::Network => write!(f, "network"),
            IssueType::FileAccess => write!(f, "file_access"),
            IssueType::ShellCommand => write!(f, "shell_command"),
            IssueType::ProcessSpawn => write!(f, "process_spawn"),
            IssueType::EnvAccess => write!(f, "env_access"),
            IssueType::DynamicLib => write!(f, "dynamic_lib"),
            IssueType::UnsafeBlock => write!(f, "unsafe_block"),
            IssueType::BuildDownload => write!(f, "build_download"),
            IssueType::SensitivePath => write!(f, "sensitive_path"),
            IssueType::Obfuscation => write!(f, "obfuscation"),
            IssueType::CompilerFlags => write!(f, "compiler_flags"),
            IssueType::MacroCodegen => write!(f, "macro_codegen"),
        }
    }
}

impl std::str::FromStr for IssueType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "network" => Ok(IssueType::Network),
            "file_access" => Ok(IssueType::FileAccess),
            "shell_command" => Ok(IssueType::ShellCommand),
            "process_spawn" => Ok(IssueType::ProcessSpawn),
            "env_access" => Ok(IssueType::EnvAccess),
            "dynamic_lib" => Ok(IssueType::DynamicLib),
            "unsafe_block" => Ok(IssueType::UnsafeBlock),
            "build_download" => Ok(IssueType::BuildDownload),
            "sensitive_path" => Ok(IssueType::SensitivePath),
            "obfuscation" => Ok(IssueType::Obfuscation),
            "compiler_flags" => Ok(IssueType::CompilerFlags),
            "macro_codegen" => Ok(IssueType::MacroCodegen),
            _ => Err(format!("Unknown issue type: {}", s)),
        }
    }
}

/// Status of a crate version analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl std::fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisStatus::Pending => write!(f, "pending"),
            AnalysisStatus::InProgress => write!(f, "in_progress"),
            AnalysisStatus::Completed => write!(f, "completed"),
            AnalysisStatus::Failed => write!(f, "failed"),
        }
    }
}

/// Status of the crawler
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlerStatus {
    Running,
    Paused,
    Completed,
    Crashed,
}

impl std::fmt::Display for CrawlerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrawlerStatus::Running => write!(f, "running"),
            CrawlerStatus::Paused => write!(f, "paused"),
            CrawlerStatus::Completed => write!(f, "completed"),
            CrawlerStatus::Crashed => write!(f, "crashed"),
        }
    }
}
