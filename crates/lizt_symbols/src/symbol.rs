use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum SymbolType {
    Function,
    Struct,
    Variable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
pub struct Symbol {
    pub name: String,
    pub symbol_type: SymbolType,
    pub confidence: Confidence,
    pub cve_id: String,
    pub source: String,     // Description, git diff, etc.
    pub context: String,
}
