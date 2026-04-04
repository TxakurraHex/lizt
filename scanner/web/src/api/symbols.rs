use super::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use chrono::{DateTime, Utc};
use common::symbol::{SourceLang, Symbol, SymbolConfidence};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SymbolListResponse {
    pub id: i64,
    pub name: String,
    pub cve_id: String,
    pub source: String,
    pub confidence: String,
    pub source_lang: String,
    pub binary_path: Option<String>,
    pub probe_type: Option<String>,
    pub validated: bool,
    pub total_calls: Option<i64>,
    pub distinct_pids: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct CreateSymbolRequest {
    pub cve_id: String,
    pub name: String,
    pub binary_path: String,
}

pub async fn list(
    State(state): State<AppState>,
) -> Result<Json<Vec<SymbolListResponse>>, (StatusCode, String)> {
    let rows = db::symbol_tables::get_all_symbols_with_activity(&state.pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, sym, total_calls, distinct_pids, last_seen)| SymbolListResponse {
                    id,
                    name: sym.name,
                    cve_id: sym.cve_id,
                    source: sym.source,
                    confidence: sym.confidence.to_string(),
                    source_lang: sym.source_lang.to_string(),
                    binary_path: sym.binary_path,
                    probe_type: sym.probe_type,
                    validated: sym.validated,
                    total_calls,
                    distinct_pids,
                    last_seen,
                },
            )
            .collect(),
    ))
}

pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<CreateSymbolRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let probe_type =
        if req.binary_path.contains("/lib/modules/") || req.binary_path.contains("/boot/") {
            "kprobe"
        } else {
            "uprobe"
        };

    let symbol = Symbol {
        name: req.name,
        cve_id: req.cve_id,
        source: "manual".into(),
        confidence: SymbolConfidence::High,
        source_lang: SourceLang::Unknown,
        context: "Manually added via dashboard".into(),
        binary_path: Some(req.binary_path),
        probe_type: Some(probe_type.into()),
        validated: true,
    };

    let id = db::symbol_tables::insert_symbol(&state.pool, &symbol)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|db_err| db_err.code().as_deref() == Some("23503"))
            {
                (
                    StatusCode::BAD_REQUEST,
                    format!("CVE '{}' does not exist in the database. Run a scan first or use a known CVE ID.", symbol.cve_id),
                )
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

    Ok(Json(serde_json::json!({ "id": id })))
}
