use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub struct FindingSummary {
    pub id: i64,
    pub scan_id: Uuid,
    pub cve_id: String,
    pub cpe_name: String,
    pub cpe_product: String,
    pub cpe_version: Option<String>,
    pub description: Option<String>,
    pub cvss_score: Option<Decimal>,
    pub cvss_version: Option<String>,
    pub kev_listed: bool,
    pub symbol_present: Option<bool>,
    pub symbol_called: Option<bool>,
    pub rank_score: Option<Decimal>,
    pub epss_score: Option<Decimal>,
}
