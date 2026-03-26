use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq, Display, EnumString, Default,
)]
#[strum(serialize_all = "lowercase")]
pub enum SourceLang {
    C,
    Python,
    Java,
    Rust,
    Go,
    Kernel,
    #[default]
    Unknown,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq, Display, EnumString, PartialOrd,
)]
#[strum(serialize_all = "lowercase")]
pub enum SymbolConfidence {
    Low,
    Medium,
    High,
}

impl SymbolConfidence {
    /// Returns the next higher confidence level, capped at `High`.
    pub fn boost(self) -> Self {
        match self {
            SymbolConfidence::Low => SymbolConfidence::Medium,
            SymbolConfidence::Medium => SymbolConfidence::High,
            SymbolConfidence::High => SymbolConfidence::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub source_lang: SourceLang,
    pub confidence: SymbolConfidence,
    pub cve_id: String,
    pub source: String, // Description, git diff, etc.
    pub context: String,
    pub binary_path: Option<String>,
    pub probe_type: Option<String>, // "kprobe" or "uprobe"
    pub validated: bool,
}
