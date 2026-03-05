use chrono::{DateTime, Utc};
use lizt_core::cpe::{Cpe, CpeEntry, InventoryItemConfidence, InventorySource};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct CpeRow {
    pub id: Uuid,
    pub name: String,
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<String>,
    pub source: String,
    pub cpe: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub cpe_confidence: String, // 'high', 'medium', 'low'
}

#[derive(Debug, FromRow)]
pub struct CpeEventRow {
    pub id: i64,
    pub package_id: Uuid,
    pub scan_id: Uuid,
    pub event: String,
    pub old_value: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
pub struct CpeMatchRow {
    pub id: i64,
    pub package_id: String,
    pub cve_id: String,
    pub matched_at: DateTime<Utc>,
}

impl From<CpeRow> for CpeEntry {
    fn from(row: CpeRow) -> Self {
        CpeEntry {
            cpe: Cpe::from_cpe_string(row.cpe.as_deref().unwrap()),
            source: row
                .source
                .parse::<InventorySource>()
                .unwrap_or(InventorySource::Unknown(row.source.clone())),
            cpe_confidence: row
                .cpe_confidence
                .parse::<InventoryItemConfidence>()
                .unwrap_or(InventoryItemConfidence::Low),
        }
    }
}
