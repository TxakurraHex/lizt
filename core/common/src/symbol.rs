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
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub source_lang: SourceLang,
    pub confidence: SymbolConfidence,
    pub cve_id: String,
    pub source: String, // Description, git diff, etc.
    pub context: String,
}
