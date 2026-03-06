use chrono::{DateTime, Utc};
use lizt_core::symbol::{Symbol, SymbolConfidence, SymbolType};
use sqlx::FromRow;
use std::str::FromStr;

#[derive(Debug, FromRow)]
pub struct CveSymbolsRow {
    pub id: i64,
    pub cve_id: String,
    pub name: String,
    pub source: String, // Description, git diff, etc.
    pub confidence: String,
    pub symbol_type: String,
    pub context: String,
}

impl From<CveSymbolsRow> for Symbol {
    fn from(row: CveSymbolsRow) -> Self {
        Symbol {
            name: row.name,
            symbol_type: SymbolType::from_str(&row.symbol_type).unwrap_or(SymbolType::Unknown),
            confidence: SymbolConfidence::from_str(&row.confidence)
                .unwrap_or(SymbolConfidence::Low),
            cve_id: row.cve_id,
            source: row.source,
            context: row.context,
        }
    }
}

#[derive(Debug, FromRow)]
pub struct SymbolObservationsRow {
    pub id: i64,
    pub cve_symbol_id: i64,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub call_count: i64,
}
