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
