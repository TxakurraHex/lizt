use axum::{Json, extract::State, http::StatusCode};
use common::finding_summary::FindingSummary;
use rust_decimal::Decimal;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Serialize)]
pub struct FindingSummaryResponse {
    pub id: i64,
    pub scan_id: Uuid,
    pub cve_id: String,
    pub cpe_name: String,
    pub cpe_product: String,
    pub description: Option<String>,
    pub cvss_score: Option<Decimal>,
    pub cvss_version: Option<String>,
    pub kev_listed: bool,
    pub symbol_present: Option<bool>,
    pub symbol_called: Option<bool>,
    pub rank_score: Option<Decimal>,
}

impl From<FindingSummary> for FindingSummaryResponse {
    fn from(s: FindingSummary) -> Self {
        FindingSummaryResponse {
            id: s.id,
            scan_id: s.scan_id,
            cve_id: s.cve_id,
            cpe_name: s.cpe_name,
            cpe_product: s.cpe_product,
            description: s.description,
            cvss_score: s.cvss_score,
            cvss_version: s.cvss_version,
            kev_listed: s.kev_listed,
            symbol_present: s.symbol_present,
            symbol_called: s.symbol_called,
            rank_score: s.rank_score,
        }
    }
}

pub async fn list(
    State(pool): State<PgPool>,
) -> Result<Json<Vec<FindingSummaryResponse>>, (StatusCode, String)> {
    let summaries = db::findings_table::get_finding_summaries(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        summaries
            .into_iter()
            .map(FindingSummaryResponse::from)
            .collect(),
    ))
}
