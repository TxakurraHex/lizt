use super::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use common::inventory_entry::InventoryEntry;
use serde::Serialize;

#[derive(Serialize)]
pub struct InventoryEntryResponse {
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

impl From<InventoryEntry> for InventoryEntryResponse {
    fn from(e: InventoryEntry) -> Self {
        InventoryEntryResponse {
            name: e.name,
            product: e.product,
            vendor: e.vendor,
            version: e.version,
            source: e.source,
            cpe: e.cpe,
            cpe_confidence: e.cpe_confidence,
            cve_count: e.cve_count,
            last_seen: e.last_seen,
        }
    }
}

pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<InventoryEntryResponse>>, (StatusCode, String)> {
    let entries = db::cpe_tables::get_inventory_entries(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        entries
            .into_iter()
            .map(InventoryEntryResponse::from)
            .collect(),
    ))
}
