use chrono::{DateTime, Utc};
use lizt_core::inventory_item::{
    CpeEntry, InventoryItem, InventoryItemConfidence, InventorySource,
};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug)]
pub struct NewInventoryItem {
    pub name: String,
    pub version: Option<String>,
    pub source: String,
    pub cpe: Option<String>,
    pub cpe_confidence: String,
}

#[derive(Debug, FromRow)]
pub struct InventoryItemRow {
    pub id: Uuid,
    pub name: String,
    pub version: Option<String>,
    pub source: String,
    pub cpe: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub cpe_confidence: String, // 'high', 'medium', 'low'
}

#[derive(Debug, FromRow)]
pub struct InventoryEventRow {
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

impl NewInventoryItem {
    pub fn from_item(item: &InventoryItem) -> Self {
        NewInventoryItem {
            name: item.cpe.product.clone(),
            version: item.cpe.version.clone(),
            source: item.source.to_string(),
            cpe: Some(item.cpe.to_cpe_string()),
            cpe_confidence: item.cpe_confidence.to_string(),
        }
    }
}

impl From<InventoryItemRow> for InventoryItem {
    fn from(row: InventoryItemRow) -> Self {
        InventoryItem {
            cpe: CpeEntry::from_cpe_string(row.cpe.as_deref().unwrap()),
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
