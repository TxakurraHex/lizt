use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum SymbolType {
    Function,
    Struct,
    Variable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum SymbolConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub symbol_type: SymbolType,
    pub confidence: SymbolConfidence,
    pub cve_id: String,
    pub source: String, // Description, git diff, etc.
    pub context: String,
}
