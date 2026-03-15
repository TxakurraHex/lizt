use chrono::{DateTime, Utc};

pub struct InventoryEntry {
    pub name: String,
    pub product: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub source: String,
    pub cpe: Option<String>,
    pub cpe_confidence: String,
    pub cve_count: u64,
    pub last_seen: DateTime<Utc>,
}
