use chrono::{DateTime, Utc};
use common::cve::{Cve, CveRef};
use rust_decimal::Decimal;
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub struct CveRow {
    pub cve_id: String,
    pub description: Option<String>,
    pub refs: Option<sqlx::types::Json<Vec<CveRef>>>,
    pub cvss_score: Option<Decimal>,
    pub cvss_vector: Option<String>,
    pub cvss_version: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl From<CveRow> for Cve {
    fn from(row: CveRow) -> Self {
        Cve {
            id: row.cve_id.clone(),
            descriptions: row.description.clone(),
            published: row.published_at,
            refs: row.refs.map(|j| j.0),
            cvss_score: row.cvss_score,
            cvss_vector: row.cvss_vector.clone(),
            cvss_version: row.cvss_version.clone(),
            cpes: None, // Fetched separately, from another table
        }
    }
}
