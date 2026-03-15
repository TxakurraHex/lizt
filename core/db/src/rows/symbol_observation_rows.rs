use chrono::{DateTime, Utc};
use common::symbol_observation::SymbolObservation;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct SymbolObservationRow {
    pub cve_symbol_id: i64,
    pub symbol_name: String,
    pub cve_id: String,
    pub total_calls: Option<i64>,
    pub distinct_pids: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
    pub recent_processes: Option<String>,
}

impl From<SymbolObservationRow> for SymbolObservation {
    fn from(row: SymbolObservationRow) -> Self {
        SymbolObservation {
            cve_symbol_id: row.cve_symbol_id,
            symbol_name: row.symbol_name,
            cve_id: row.cve_id,
            total_calls: row.total_calls.unwrap_or(0),
            distinct_pids: row.distinct_pids.unwrap_or(0),
            last_seen: row.last_seen.unwrap_or_default(),
            recent_processes: row.recent_processes,
        }
    }
}
