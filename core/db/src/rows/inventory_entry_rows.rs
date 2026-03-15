use chrono::{DateTime, Utc};
use common::inventory_entry::InventoryEntry;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct InventoryEntryRow {
    pub name: String,
    pub product: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub source: String,
    pub cpe: Option<String>,
    pub cpe_confidence: String,
    pub cve_count: Option<i64>,
    pub last_seen: DateTime<Utc>,
}

impl From<InventoryEntryRow> for InventoryEntry {
    fn from(row: InventoryEntryRow) -> Self {
        InventoryEntry {
            name: row.name,
            product: row.product,
            vendor: row.vendor,
            source: row.source,
            cpe: row.cpe,
            cpe_confidence: row.cpe_confidence,
            cve_count: row.cve_count.unwrap_or(0) as u64,
            last_seen: row.last_seen,
        }
    }
}
