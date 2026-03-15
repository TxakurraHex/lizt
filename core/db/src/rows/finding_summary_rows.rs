use common::finding_summary::FindingSummary;
use rust_decimal::Decimal;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct FindingSummaryRow {
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

impl From<FindingSummaryRow> for FindingSummary {
    fn from(row: FindingSummaryRow) -> Self {
        FindingSummary {
            id: row.id,
            scan_id: row.scan_id,
            cve_id: row.cve_id,
            cpe_name: row.cpe_name,
            cpe_product: row.cpe_product,
            description: row.description,
            cvss_score: row.cvss_score,
            cvss_version: row.cvss_version,
            kev_listed: row.kev_listed,
            symbol_present: row.symbol_present,
            symbol_called: row.symbol_called,
            rank_score: row.rank_score,
        }
    }
}
