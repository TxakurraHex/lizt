use chrono::{DateTime, Utc};
use common::symbol::{SourceLang, Symbol, SymbolConfidence};
use sqlx::FromRow;
use std::str::FromStr;

/// Base columns shared by every `cve_symbols` query.
#[derive(Debug, FromRow)]
pub struct CveSymbolsRow {
    pub id: i64,
    pub cve_id: String,
    pub name: String,
    pub source: String, // Description, git diff, etc.
    pub confidence: String,
    pub source_lang: String,
    pub context: String,
    pub binary_path: Option<String>,
    pub probe_type: Option<String>,
    pub validated: bool,
}

impl CveSymbolsRow {
    /// Convert the row's fields into a domain `Symbol`.
    pub fn into_symbol(self) -> Symbol {
        Symbol {
            name: self.name,
            source_lang: SourceLang::from_str(&self.source_lang).unwrap_or(SourceLang::Unknown),
            confidence: SymbolConfidence::from_str(&self.confidence)
                .unwrap_or(SymbolConfidence::Low),
            cve_id: self.cve_id,
            source: self.source,
            context: self.context,
            binary_path: self.binary_path,
            probe_type: self.probe_type,
            validated: self.validated,
        }
    }
}

impl From<CveSymbolsRow> for Symbol {
    fn from(row: CveSymbolsRow) -> Self {
        row.into_symbol()
    }
}

#[derive(Debug, FromRow)]
pub struct CveSymbolWithCpeRow {
    #[sqlx(flatten)]
    pub base: CveSymbolsRow,
    pub cpe_product: Option<String>,
    pub cpe_source: Option<String>,
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

#[derive(Debug, FromRow)]
pub struct CveSymbolWithActivityRow {
    #[sqlx(flatten)]
    pub base: CveSymbolsRow,
    pub total_calls: Option<i64>,
    pub distinct_pids: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
}
