use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct CveSymbolsRow {
    pub id: i64,
    pub cve_id: String,
    pub symbol: String,
    pub source: String,
    pub confidence: f64,
}

#[derive(Debug, FromRow)]
pub struct SymbolObservationsRow {
    pub id: i64,
    pub symbol: String,
    pub pid: Option<i32>,
    pub process_name: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub call_count: i64,
}
