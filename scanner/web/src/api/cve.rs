use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use common::cve::Cve;
use common::symbol::Symbol;
use rust_decimal::Decimal;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Serialize)]
pub struct CveResponse {
    pub cve_id: String,
    pub description: Option<String>,
    pub cvss_score: Option<Decimal>,
    pub cvss_vector: Option<String>,
    pub cvss_version: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub kev_listed: bool,
}

impl CveResponse {
    fn from_cve_and_kev(cve: Cve, kev_listed: bool) -> Self {
        CveResponse {
            cve_id: cve.id,
            description: cve.descriptions,
            cvss_score: cve.cvss_score,
            cvss_vector: cve.cvss_vector,
            cvss_version: cve.cvss_version,
            published_at: cve.published,
            kev_listed,
        }
    }
}

#[derive(Serialize)]
pub struct SymbolResponse {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub confidence: String,
    pub source_lang: String,
    pub context: String,
    pub total_calls: Option<i64>,
    pub distinct_pids: Option<i64>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl From<(i64, Symbol, Option<i64>, Option<i64>, Option<DateTime<Utc>>)> for SymbolResponse {
    fn from(
        (id, s, total_calls, distinct_pids, last_seen): (
            i64,
            Symbol,
            Option<i64>,
            Option<i64>,
            Option<DateTime<Utc>>,
        ),
    ) -> Self {
        SymbolResponse {
            id,
            name: s.name,
            source: s.source,
            confidence: s.confidence.to_string(),
            source_lang: s.source_lang.to_string(),
            context: s.context,
            total_calls,
            distinct_pids,
            last_seen,
        }
    }
}

#[derive(Serialize)]
pub struct CveDetailResponse {
    pub cve: CveResponse,
    pub symbols: Vec<SymbolResponse>,
}

pub async fn detail(
    State(pool): State<PgPool>,
    Path(cve_id): Path<String>,
) -> Result<Json<CveDetailResponse>, (StatusCode, String)> {
    let (cve, kev_listed) = db::cve_tables::get_cve_with_kev(&pool, &cve_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("{cve_id} not found")))?;

    let symbols = db::symbol_tables::get_symbols_for_cve_with_activity(&pool, &cve_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CveDetailResponse {
        cve: CveResponse::from_cve_and_kev(cve, kev_listed),
        symbols: symbols.into_iter().map(SymbolResponse::from).collect(),
    }))
}
