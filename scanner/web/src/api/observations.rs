use super::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use common::symbol_observation::SymbolObservation;
use serde::Serialize;

#[derive(Serialize)]
pub struct SymbolObservationResponse {
    pub cve_symbol_id: i64,
    pub symbol_name: String,
    pub cve_id: String,
    pub total_calls: i64,
    pub distinct_pids: i64,
    pub last_seen: DateTime<Utc>,
    pub recent_processes: Option<String>,
}

impl From<SymbolObservation> for SymbolObservationResponse {
    fn from(s: SymbolObservation) -> Self {
        SymbolObservationResponse {
            cve_symbol_id: s.cve_symbol_id,
            symbol_name: s.symbol_name,
            cve_id: s.cve_id,
            total_calls: s.total_calls,
            distinct_pids: s.distinct_pids,
            last_seen: s.last_seen,
            recent_processes: s.recent_processes,
        }
    }
}

pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<SymbolObservationResponse>>, (StatusCode, String)> {
    let observations = db::symbol_tables::get_symbol_observations(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        observations
            .into_iter()
            .map(SymbolObservationResponse::from)
            .collect(),
    ))
}
