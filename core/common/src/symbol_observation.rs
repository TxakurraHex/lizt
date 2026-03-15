use chrono::{DateTime, Utc};

pub struct SymbolObservation {
    pub cve_symbol_id: i64,
    pub symbol_name: String,
    pub cve_id: String,
    pub total_calls: i64,
    pub distinct_pids: i64,
    pub last_seen: DateTime<Utc>,
    pub recent_processes: Option<String>,
}
